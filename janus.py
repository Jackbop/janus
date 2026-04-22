"""
Janus - Main CLI v0.3
Novità:
- Auth type "cookies" per REI/Akamai
- Modulo mass_assignment (Mass Assignment / Parameter Pollution)
- Output più leggibile con colori ANSI
"""

import argparse
import json
import sys
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.session_manager import SessionManager
from modules.idor.detector import IDORDetector
from modules.business_logic.analyzer import BusinessLogicAnalyzer
from reporting.impact_reporter import ImpactReporter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)

# Colori ANSI per output più leggibile
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
RESET  = "\033[0m"

BANNER = r"""
     ██╗ █████╗ ███╗   ██╗██╗   ██╗███████╗
     ██║██╔══██╗████╗  ██║██║   ██║██╔════╝
     ██║███████║██╔██╗ ██║██║   ██║███████╗
██   ██║██╔══██║██║╚██╗██║██║   ██║╚════██║
╚█████╔╝██║  ██║██║ ╚████║╚██████╔╝███████║
 ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝
  Bug Bounty Intelligence Engine v0.3
  [!] Use only on authorized targets (HackerOne BBP)
"""


def load_config(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def authenticate(config: dict, sm: SessionManager) -> bool:
    """Gestisce tutti i tipi di autenticazione."""
    auth_cfg   = config.get("auth", {})
    login_type = auth_cfg.get("type", "form")
    login_path = auth_cfg.get("path", "/login")

    print(f"\n{CYAN}[*] Autenticazione {len(sm.accounts)} account via {login_type}...{RESET}")

    if login_type == "cookies":
        # ── Metodo REI: inietta cookie da Burp ──────────────────────────
        sessions_list = auth_cfg.get("sessions", [])
        if len(sessions_list) < len(sm.accounts):
            print(f"{RED}[!] Mancano i cookie in auth.sessions nel config.{RESET}")
            print("    Leggi la GUIDA: devi copiare REI_SSL_SESSION_ID e JSESSIONID da Burp.")
            return False
        sm.login_all_cookies(sessions_list)
        return True

    elif login_type == "form":
        return sm.login_all_form(
            login_path,
            user_field=auth_cfg.get("user_field", "username"),
            pass_field=auth_cfg.get("pass_field", "password"),
        )

    elif login_type == "json":
        return sm.login_all_json(
            login_path,
            user_field=auth_cfg.get("user_field", "email"),
            pass_field=auth_cfg.get("pass_field", "password"),
        )

    else:
        print(f"{RED}[!] Tipo auth non supportato: {login_type}{RESET}")
        return False


def run_idor_scan(config: dict, sm: SessionManager, reporter: ImpactReporter):
    idor_cfg = config.get("idor", {})
    if not idor_cfg.get("enabled", True):
        return

    print(f"\n{CYAN}[*] ═══ IDOR DETECTION ═══{RESET}")
    detector = IDORDetector(sm)
    accounts = sm.accounts

    if len(accounts) < 2:
        print(f"{YELLOW}[!] IDOR richiede 2 account. Skipping.{RESET}")
        return

    owner, attacker = accounts[0], accounts[1]

    for endpoint in idor_cfg.get("endpoints", []):
        nome     = endpoint.get("_nome", endpoint["path"])
        path     = endpoint["path"]
        method   = endpoint.get("method", "GET").upper()
        victim_id = endpoint.get("victim_id", "")

        print(f"\n  → {nome}")

        if not victim_id or "SOSTITUISCI" in victim_id:
            print(f"    {YELLOW}[SKIP] victim_id non configurato{RESET}")
            continue

        if method == "GET" and "{id}" in path:
            detector.test_path_param(path, owner, attacker, victim_id)
        elif method == "GET":
            for param in endpoint.get("params", ["id", "user_id"]):
                detector.test_get_param(path, param, owner, attacker, victim_id)
        elif method == "POST":
            detector.test_post_json(
                path, endpoint.get("payload_template", {}),
                owner, attacker, victim_id, endpoint.get("id_field", "id")
            )

    n = len(detector.findings)
    color = RED if n > 0 else GREEN
    print(f"\n{color}[*] IDOR scan completo — {n} finding trovati{RESET}")
    reporter.add_idor_findings(detector.findings)


def run_mass_assignment_scan(config: dict, sm: SessionManager, reporter: ImpactReporter):
    """
    Mass Assignment / Parameter Pollution.
    Prova ad aggiungere campi privilegiati (role, memberType, isAdmin)
    nelle richieste di aggiornamento profilo.
    """
    ma_cfg = config.get("mass_assignment", {})
    if not ma_cfg.get("enabled", False):
        return

    print(f"\n{CYAN}[*] ═══ MASS ASSIGNMENT ═══{RESET}")
    account = sm.accounts[0]

    privileged_params = ma_cfg.get("params", [
        {"field": "role",         "values": ["admin", "superuser", "staff"]},
        {"field": "memberType",   "values": ["employee", "co-op", "lifetime"]},
        {"field": "isAdmin",      "values": [True, 1, "true"]},
        {"field": "isPremium",    "values": [True, 1]},
        {"field": "kyc_level",    "values": [3, 4, 5]},
        {"field": "verified",     "values": [True, 1]},
    ])

    for endpoint_cfg in ma_cfg.get("endpoints", []):
        path   = endpoint_cfg["path"]
        method = endpoint_cfg.get("method", "PUT").upper()
        print(f"\n  → Mass Assignment su {path}")

        for param_cfg in privileged_params:
            field_name = param_cfg["field"]
            for value in param_cfg["values"]:
                payload = {field_name: value}
                try:
                    if method == "PUT":
                        resp = sm.put(account, path, json=payload)
                    elif method == "POST":
                        resp = sm.post(account, path, json=payload)
                    elif method == "PATCH":
                        resp = sm.post(account, path, json=payload)
                    else:
                        continue

                    body_lower = resp.text.lower()
                    # Successo se il valore compare nella risposta
                    if resp.status_code in (200, 204) and (
                        str(value).lower() in body_lower or
                        field_name.lower() in body_lower
                    ):
                        print(f"    {RED}🚨 POTENZIALE MASS ASSIGNMENT: "
                              f"{field_name}={value} | status={resp.status_code}{RESET}")
                        print(f"       Body snippet: {resp.text[:200]}")

                        # Aggiungi come finding manuale al reporter
                        from modules.business_logic.analyzer import BizLogicFinding, BizLogicType
                        finding = BizLogicFinding(
                            vuln_type=BizLogicType.PRIVILEGE_ESCALATION,
                            endpoint=path, method=method,
                            description=f"Mass Assignment: parametro {field_name} impostabile a '{value}'",
                            evidence=f"Risposta {resp.status_code} con {field_name}={value}",
                            severity="CRITICAL",
                            request_payload=f"{method} {path} {json.dumps(payload)}",
                            response_snippet=resp.text[:400],
                            impact=f"Qualsiasi utente può impostare {field_name}={value} senza autorizzazione.",
                            reproduction_steps=[
                                f"1. Autenticati come utente normale",
                                f"2. Invia {method} {path} con body: {json.dumps(payload)}",
                                f"3. Verifica che il parametro sia stato modificato",
                            ]
                        )
                        reporter.add_bizlogic_findings([finding])
                    else:
                        print(f"    ✓ {field_name}={value} → {resp.status_code} (protetto)")

                except Exception as e:
                    print(f"    {YELLOW}[ERR] {field_name}={value}: {e}{RESET}")

    print(f"\n{CYAN}[*] Mass Assignment scan completo{RESET}")


def run_bizlogic_scan(config: dict, sm: SessionManager, reporter: ImpactReporter):
    biz_cfg = config.get("business_logic", {})
    if not biz_cfg.get("enabled", True):
        return

    print(f"\n{CYAN}[*] ═══ BUSINESS LOGIC ═══{RESET}")
    analyzer = BusinessLogicAnalyzer(sm)
    account  = sm.accounts[0]

    for test in biz_cfg.get("price_tests", []):
        analyzer.test_price_manipulation(
            test["path"], account, test["item_id"], test["original_price"])

    for test in biz_cfg.get("coupon_tests", []):
        analyzer.test_coupon_reuse(test["path"], account, test["coupon_code"])

    for test in biz_cfg.get("race_tests", []):
        analyzer.test_race_condition(
            test["path"], account, test.get("payload", {}), test.get("threads", 20))

    for test in biz_cfg.get("privilege_tests", []):
        analyzer.test_role_escalation(
            test["path"], account, test.get("role_field", "role"))

    n = len(analyzer.findings)
    color = RED if n > 0 else GREEN
    print(f"\n{color}[*] Business Logic scan completo — {n} finding{RESET}")
    reporter.add_bizlogic_findings(analyzer.findings)


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description="Janus v0.3 — Bug Bounty Intelligence Engine")
    parser.add_argument("-c", "--config", required=True, help="Path config JSON")
    parser.add_argument("--proxy",  default=None, help="Proxy Burp (es. http://127.0.0.1:8080)")
    parser.add_argument("--output-md",   default="janus_report.md")
    parser.add_argument("--output-html", default="janus_report.html")
    parser.add_argument("--module",
                        choices=["idor", "bizlogic", "mass_assignment", "all"],
                        default="all")
    parser.add_argument("--verbose", action="store_true", help="Log di debug dettagliati")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        config = load_config(args.config)
    except FileNotFoundError:
        print(f"{RED}[!] Config non trovato: {args.config}{RESET}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"{RED}[!] Errore JSON nel config: {e}{RESET}")
        sys.exit(1)

    target  = config["target"]["base_url"]
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else {}

    print(f"{CYAN}[*] Target : {target}{RESET}")
    print(f"{CYAN}[*] Proxy  : {args.proxy or 'nessuno'}{RESET}")
    print(f"{CYAN}[*] Modulo : {args.module}{RESET}")

    sm       = SessionManager(target, proxies=proxies)
    reporter = ImpactReporter(target)

    for acc_cfg in config.get("accounts", []):
        sm.add_account(
            acc_cfg["username"],
            acc_cfg["password"],
            acc_cfg.get("role", "user")
        )

    if not authenticate(config, sm):
        print(f"{RED}[!] Autenticazione fallita. Controlla i cookie nel config.{RESET}")
        sys.exit(1)

    print(f"{GREEN}[✅] Tutti gli account autenticati. Inizio scan...{RESET}")

    if args.module in ("idor", "all"):
        run_idor_scan(config, sm, reporter)

    if args.module in ("bizlogic", "all"):
        run_bizlogic_scan(config, sm, reporter)

    if args.module in ("mass_assignment", "all"):
        run_mass_assignment_scan(config, sm, reporter)

    # ── Report ──────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    if reporter.all_findings:
        total = len(reporter.all_findings)
        crit  = sum(1 for f in reporter.all_findings if reporter._severity(f) == "CRITICAL")
        high  = sum(1 for f in reporter.all_findings if reporter._severity(f) == "HIGH")
        med   = sum(1 for f in reporter.all_findings if reporter._severity(f) == "MEDIUM")

        print(f"{RED}[!] TROVATI {total} FINDING:{RESET}")
        print(f"    🔴 Critical : {crit}")
        print(f"    🟠 High     : {high}")
        print(f"    🟡 Medium   : {med}")

        reporter.generate_markdown(args.output_md)
        reporter.generate_html(args.output_html)
        print(f"\n{GREEN}[✅] Report salvati: {args.output_md} | {args.output_html}{RESET}")

        critical_findings = [f for f in reporter.all_findings if reporter._severity(f) == "CRITICAL"]
        if critical_findings:
            reporter.all_findings = critical_findings
            print(f"\n{'='*60}")
            print("📋 HACKERONE SUBMISSION DRAFT (primo finding critico):")
            print(f"{'='*60}")
            print(reporter.generate_hackerone_submission(0))
    else:
        print(f"{GREEN}[*] Nessun finding. Target sicuro su questi vettori.{RESET}")

    print(f"\n{GREEN}[✅] Janus v0.3 scan completato.{RESET}")


if __name__ == "__main__":
    main()
