"""
Janus - Business Logic Analyzer
Rileva falle di logica: prezzi negativi, step skipping, race conditions, ecc.
"""

import time
import threading
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.session_manager import SessionManager, Account

log = logging.getLogger("janus.bizlogic")


class BizLogicType(Enum):
    PRICE_MANIPULATION   = "Price Manipulation"
    NEGATIVE_BALANCE     = "Negative Balance"
    COUPON_REUSE         = "Coupon / Discount Reuse"
    STEP_SKIP            = "Workflow Step Skip"
    RACE_CONDITION       = "Race Condition"
    LIMIT_BYPASS         = "Rate / Quantity Limit Bypass"
    PRIVILEGE_ESCALATION = "Privilege Escalation via Param Tampering"
    FREE_ITEM            = "Free Item / Zero Price"


@dataclass
class BizLogicFinding:
    vuln_type: BizLogicType
    endpoint: str
    method: str
    description: str
    evidence: str
    severity: str  # CRITICAL | HIGH | MEDIUM
    request_payload: str = ""
    response_snippet: str = ""
    impact: str = ""
    reproduction_steps: list[str] = field(default_factory=list)


class BusinessLogicAnalyzer:
    """
    Suite di test per vulnerabilità di logica di business.
    Ogni metodo corrisponde a una categoria di attacco.
    """

    def __init__(self, session_manager: SessionManager):
        self.sm = session_manager
        self.findings: list[BizLogicFinding] = []

    # ──────────────────────────────────────────────
    # 1. PRICE MANIPULATION
    # ──────────────────────────────────────────────

    def test_price_manipulation(self, checkout_path: str, account: Account,
                                item_id: str, original_price: float) -> Optional[BizLogicFinding]:
        """
        Testa se è possibile modificare il prezzo nell'ordine lato client.
        Prova: price=0, price=-1, price=0.01
        """
        tampered_prices = [0, -1, 0.001, -999]
        for price in tampered_prices:
            payload = {"item_id": item_id, "price": price, "quantity": 1}
            resp = self.sm.post(account, checkout_path, json=payload)

            if resp.status_code in (200, 201) and self._order_accepted(resp.text):
                finding = BizLogicFinding(
                    vuln_type=BizLogicType.PRICE_MANIPULATION,
                    endpoint=checkout_path, method="POST",
                    description=f"Il server accetta ordini con prezzo={price} senza validazione.",
                    evidence=f"Prezzo originale: {original_price} → Inviato: {price} → Ordine accettato (status {resp.status_code})",
                    severity="CRITICAL",
                    request_payload=str(payload),
                    response_snippet=resp.text[:400],
                    impact=f"Un attaccante può acquistare articoli da {original_price}€ a {price}€ o gratis.",
                    reproduction_steps=[
                        f"1. Aggiungi l'articolo {item_id} al carrello",
                        "2. Intercetta la richiesta di checkout con Burp Suite",
                        f"3. Modifica il campo `price` a {price}",
                        "4. Invia la richiesta → Ordine completato con prezzo manipolato",
                    ]
                )
                self.findings.append(finding)
                log.warning(f"🚨 [CRITICAL] Price Manipulation: prezzo {price} accettato su {checkout_path}")
                return finding
        return None

    # ──────────────────────────────────────────────
    # 2. COUPON / DISCOUNT REUSE
    # ──────────────────────────────────────────────

    def test_coupon_reuse(self, apply_coupon_path: str, account: Account,
                          coupon_code: str, attempts: int = 5) -> Optional[BizLogicFinding]:
        """
        Testa se un coupon monouso può essere riutilizzato.
        """
        successes = []
        for i in range(attempts):
            resp = self.sm.post(account, apply_coupon_path, json={"code": coupon_code})
            if resp.status_code == 200 and self._discount_applied(resp.text):
                successes.append(i + 1)

        if len(successes) > 1:
            finding = BizLogicFinding(
                vuln_type=BizLogicType.COUPON_REUSE,
                endpoint=apply_coupon_path, method="POST",
                description=f"Il coupon '{coupon_code}' può essere applicato {len(successes)} volte dallo stesso account.",
                evidence=f"Applicato con successo ai tentativi: {successes}",
                severity="HIGH",
                request_payload=f'{{"code": "{coupon_code}"}}',
                impact="Un utente può ottenere sconti multipli con un singolo coupon.",
                reproduction_steps=[
                    f"1. Applica il coupon '{coupon_code}' al carrello",
                    "2. Riapplica lo stesso coupon senza rimuoverlo",
                    f"3. Ripeti {attempts} volte → Sconto applicato {len(successes)} volte",
                ]
            )
            self.findings.append(finding)
            log.warning(f"🚨 [HIGH] Coupon Reuse: '{coupon_code}' applicato {len(successes)}x")
            return finding
        return None

    # ──────────────────────────────────────────────
    # 3. RACE CONDITION
    # ──────────────────────────────────────────────

    def test_race_condition(self, endpoint: str, account: Account,
                            payload: dict, threads: int = 20,
                            success_condition: Optional[Callable] = None) -> Optional[BizLogicFinding]:
        """
        Invia N richieste in parallelo per sfruttare race conditions.
        Utile per: riscattare premi, trasferimenti, coupon, click-once actions.
        """
        results = []
        lock = threading.Lock()

        def make_request():
            resp = self.sm.post(account, endpoint, json=payload)
            with lock:
                results.append(resp)

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(make_request) for _ in range(threads)]
            for f in as_completed(futures):
                f.result()

        successes = [r for r in results if r.status_code == 200 and
                     (success_condition(r.text) if success_condition else True)]

        if len(successes) > 1:
            finding = BizLogicFinding(
                vuln_type=BizLogicType.RACE_CONDITION,
                endpoint=endpoint, method="POST",
                description=f"Race condition: {len(successes)}/{threads} richieste parallele hanno avuto successo.",
                evidence=f"Inviato {threads} richieste concorrenti → {len(successes)} successi",
                severity="CRITICAL" if len(successes) > 3 else "HIGH",
                request_payload=str(payload),
                impact=f"Un attaccante può eseguire l'azione {len(successes)} volte invece di 1 inviando richieste parallele.",
                reproduction_steps=[
                    f"1. Prepara {threads} richieste identiche a {endpoint}",
                    "2. Invia tutte simultaneamente (Burp Repeater in 'Send group in parallel')",
                    f"3. Osserva {len(successes)} risposte 200 → Race condition confermata",
                ]
            )
            self.findings.append(finding)
            log.warning(f"🚨 Race Condition su {endpoint}: {len(successes)}/{threads} successi")
            return finding
        return None

    # ──────────────────────────────────────────────
    # 4. WORKFLOW STEP SKIP
    # ──────────────────────────────────────────────

    def test_step_skip(self, steps: list[tuple[str, dict]], account: Account,
                       skip_to_step: int) -> Optional[BizLogicFinding]:
        """
        Testa se è possibile saltare step intermedi di un workflow.
        Es. checkout: aggiunta articolo → inserimento indirizzo → pagamento → conferma
        Prova a saltare direttamente al pagamento senza l'indirizzo.
        """
        if skip_to_step >= len(steps):
            return None

        skipped_steps = [s[0] for s in steps[:skip_to_step]]
        target_path, target_payload = steps[skip_to_step]

        resp = self.sm.post(account, target_path, json=target_payload)

        if resp.status_code in (200, 201) and not self._is_error_response(resp.text):
            finding = BizLogicFinding(
                vuln_type=BizLogicType.STEP_SKIP,
                endpoint=target_path, method="POST",
                description=f"È possibile saltare gli step: {skipped_steps}",
                evidence=f"Richiesta diretta a step {skip_to_step} ({target_path}) senza completare i precedenti → status {resp.status_code}",
                severity="HIGH",
                request_payload=str(target_payload),
                response_snippet=resp.text[:400],
                impact="Un attaccante può bypassare verifiche, pagamenti o validazioni saltando step obbligatori.",
                reproduction_steps=[
                    f"1. Avvia il workflow normalmente",
                    f"2. Salta gli step: {skipped_steps}",
                    f"3. Invia direttamente la richiesta a {target_path}",
                    "4. Il server accetta la richiesta senza verificare i prerequisiti",
                ]
            )
            self.findings.append(finding)
            log.warning(f"🚨 [HIGH] Step Skip: saltati {skipped_steps} → accesso a {target_path}")
            return finding
        return None

    # ──────────────────────────────────────────────
    # 5. PRIVILEGE ESCALATION VIA PARAM TAMPERING
    # ──────────────────────────────────────────────

    def test_role_escalation(self, update_path: str, account: Account,
                             role_field: str = "role",
                             target_roles: Optional[list] = None) -> Optional[BizLogicFinding]:
        """
        Testa se un utente normale può assegnarsi un ruolo privilegiato.
        """
        target_roles = target_roles or ["admin", "administrator", "superuser", "root", "mod"]
        for role in target_roles:
            payload = {role_field: role}
            resp = self.sm.put(account, update_path, json=payload)
            if resp.status_code in (200, 204) and role in resp.text.lower():
                finding = BizLogicFinding(
                    vuln_type=BizLogicType.PRIVILEGE_ESCALATION,
                    endpoint=update_path, method="PUT",
                    description=f"Un utente normale può auto-assegnarsi il ruolo '{role}'.",
                    evidence=f"PUT {update_path} {payload} → status {resp.status_code}, ruolo '{role}' nella risposta",
                    severity="CRITICAL",
                    request_payload=str(payload),
                    response_snippet=resp.text[:400],
                    impact=f"Chiunque può diventare '{role}' modificando un singolo parametro nella richiesta.",
                    reproduction_steps=[
                        f"1. Autenticati come utente normale",
                        f"2. Invia PUT a {update_path} con body: {payload}",
                        f"3. Verifica che il tuo account sia ora '{role}'",
                    ]
                )
                self.findings.append(finding)
                log.warning(f"🚨 [CRITICAL] Privilege Escalation: ruolo '{role}' assegnato via param tampering")
                return finding
        return None

    # ──────────────────────────────────────────────
    # HELPERS
    # ──────────────────────────────────────────────

    def _order_accepted(self, body: str) -> bool:
        signals = ["success", "order_id", "confirmed", "thank you", "grazie",
                   "confermato", "ordine", "purchased"]
        return any(s in body.lower() for s in signals)

    def _discount_applied(self, body: str) -> bool:
        signals = ["discount", "applied", "sconto", "applicato", "success", "saved"]
        return any(s in body.lower() for s in signals)

    def _is_error_response(self, body: str) -> bool:
        signals = ["error", "invalid", "missing", "required", "not found",
                   "unauthorized", "forbidden", "errore", "mancante"]
        return any(s in body.lower() for s in signals)
