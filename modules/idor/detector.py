"""
Janus - IDOR Detector v0.3
Miglioramenti REI:
- Rilevamento false positive (200 OK ma "Access Denied" nel body)
- Supporto ID esadecimali/UUID (non solo numerici)
- Analisi lunghezza risposta per rilevare leak silenziosi
- Parametri nascosti REI-specifici (customerNumber, emailAddress, orderNumber)
"""

import re
import json
import difflib
import logging
from typing import Optional
from dataclasses import dataclass, field
from enum import Enum

from core.session_manager import SessionManager, Account

log = logging.getLogger("janus.idor")


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    INFO     = "INFO"


@dataclass
class IDORFinding:
    endpoint: str
    method: str
    param: str
    attacker_id: str
    victim_id: str
    attacker_account: str
    victim_account: str
    status_code: int
    severity: Severity
    evidence: str
    leaked_fields: list[str] = field(default_factory=list)
    request_payload: str = ""
    response_snippet: str = ""


class IDORDetector:

    SENSITIVE_FIELDS = [
        "email", "phone", "password", "token", "secret", "address",
        "credit_card", "ssn", "bank", "iban", "balance", "wallet",
        "private_key", "api_key", "birth", "gender", "national_id",
        "document", "passport", "salary", "income", "tax",
        "firstName", "lastName", "fullName", "dateOfBirth",
        "membershipNumber", "loyaltyPoints",
    ]

    # Parametri comuni + specifici REI
    IDOR_PARAMS = [
        # Generici
        "id", "user_id", "userId", "account_id", "uid", "pid",
        "order_id", "invoice_id", "transaction_id", "resource_id",
        "file_id", "doc_id", "record_id", "uuid", "guid", "ref",
        "profile_id", "customer_id", "member_id",
        # REI-specifici (da Smart Fuzzer di Gemini)
        "customerNumber", "orderNumber", "emailAddress",
        "memberId", "customerId", "accountNumber",
    ]

    # Segnali di accesso negato nel body — false positive killer
    ACCESS_DENIED_SIGNALS = [
        "access denied", "forbidden", "unauthorized", "not authorized",
        "you don't have permission", "invalid session", "please login",
        "sign in to", "authentication required", "403", "401",
        "accesso negato", "non autorizzato",
    ]

    def __init__(self, session_manager: SessionManager):
        self.sm = session_manager
        self.findings: list[IDORFinding] = []

    # ─────────────────────────────────────────
    # API PUBBLICA
    # ─────────────────────────────────────────

    def test_get_param(self, path: str, param: str,
                       owner: Account, attacker: Account,
                       owner_id: str, attacker_id: Optional[str] = None) -> Optional[IDORFinding]:
        """Testa IDOR su query parameter GET."""
        owner_path   = f"{path}?{param}={owner_id}"
        attack_path  = f"{path}?{param}={owner_id}"

        owner_resp  = self.sm.get(owner, owner_path)
        attack_resp = self.sm.get(attacker, attack_path)

        log.info(f"IDOR GET | {path}?{param}={owner_id} | "
                 f"attacker={attacker.username} | status={attack_resp.status_code}")

        return self._analyze(
            endpoint=path, method="GET", param=param,
            owner_resp=owner_resp, attack_resp=attack_resp,
            owner=owner, attacker=attacker,
            victim_id=owner_id, attacker_id=attacker_id or "N/A",
            request_payload=f"GET {attack_path}",
        )

    def test_path_param(self, path_template: str,
                        owner: Account, attacker: Account,
                        owner_id: str) -> Optional[IDORFinding]:
        """Testa IDOR su path parameter (es. /orders/{id})."""
        path = path_template.format(id=owner_id, user_id=owner_id, uid=owner_id)
        owner_resp  = self.sm.get(owner, path)
        attack_resp = self.sm.get(attacker, path)

        log.info(f"IDOR PATH | {path} | attacker={attacker.username} | "
                 f"status={attack_resp.status_code}")

        return self._analyze(
            endpoint=path_template, method="GET", param="path_id",
            owner_resp=owner_resp, attack_resp=attack_resp,
            owner=owner, attacker=attacker,
            victim_id=owner_id, attacker_id="N/A",
            request_payload=f"GET {path}",
        )

    def test_post_json(self, path: str, payload_template: dict,
                       owner: Account, attacker: Account,
                       owner_id: str, id_field: str = "id") -> Optional[IDORFinding]:
        """Testa IDOR su body JSON POST."""
        owner_payload  = {**payload_template, id_field: owner_id}
        attack_payload = {**payload_template, id_field: owner_id}

        owner_resp  = self.sm.post(owner,   path, json=owner_payload)
        attack_resp = self.sm.post(attacker, path, json=attack_payload)

        log.info(f"IDOR POST | {path} | attacker={attacker.username} | "
                 f"status={attack_resp.status_code}")

        return self._analyze(
            endpoint=path, method="POST", param=id_field,
            owner_resp=owner_resp, attack_resp=attack_resp,
            owner=owner, attacker=attacker,
            victim_id=owner_id, attacker_id="N/A",
            request_payload=f"POST {path} {json.dumps(attack_payload)}",
        )

    def scan_endpoint_params(self, path: str, owner: Account, attacker: Account,
                              owner_id: str) -> list[IDORFinding]:
        """Prova automaticamente tutti i parametri IDOR comuni."""
        results = []
        for param in self.IDOR_PARAMS:
            finding = self.test_get_param(path, param, owner, attacker, owner_id)
            if finding and finding.severity != Severity.INFO:
                results.append(finding)
        return results

    # ─────────────────────────────────────────
    # ANALISI RISPOSTA
    # ─────────────────────────────────────────

    def _analyze(self, endpoint, method, param,
                 owner_resp, attack_resp,
                 owner, attacker, victim_id, attacker_id,
                 request_payload) -> Optional[IDORFinding]:

        status = attack_resp.status_code

        # 401/403 = protetto
        if status in (401, 403):
            log.debug(f"  → Accesso negato ({status})")
            return None

        owner_body  = self._safe_text(owner_resp)
        attack_body = self._safe_text(attack_resp)

        # ── False Positive Check ──────────────────
        # REI risponde spesso 200 ma con "Access Denied" nel body
        if self._is_access_denied(attack_body):
            log.debug(f"  → False positive: 200 ma body contiene segnale di accesso negato")
            return None

        # ── Analisi contenuto ────────────────────
        similarity    = self._similarity(owner_body, attack_body)
        leaked_fields = self._find_sensitive_fields(attack_body)

        # Controlla se il body della vittima è presente nella risposta attaccante
        # (es. email vittima nel body dell'attaccante → IDOR confermato)
        victim_data_leaked = self._check_victim_data_leaked(attack_body, owner_body)

        # Controlla differenza di lunghezza — un body molto più lungo dell'atteso
        # può indicare leak di dati (anche senza campi sensibili riconoscibili)
        size_anomaly = self._size_anomaly(owner_body, attack_body)

        # ── Severity ─────────────────────────────
        if leaked_fields and (similarity > 0.5 or victim_data_leaked):
            severity = Severity.CRITICAL
            evidence = (f"Dati sensibili dell'account vittima accessibili dall'attaccante. "
                        f"Campi esposti: {leaked_fields}. Similarità risposta: {similarity:.0%}")
        elif leaked_fields:
            severity = Severity.HIGH
            evidence = f"Campi sensibili nel body: {leaked_fields}"
        elif victim_data_leaked:
            severity = Severity.HIGH
            evidence = "Dati della vittima rilevati nella risposta dell'attaccante"
        elif similarity > 0.7 and status == 200 and size_anomaly:
            severity = Severity.MEDIUM
            evidence = f"Risposta simile ({similarity:.0%}) e dimensione anomala rispetto all'atteso"
        else:
            return None

        finding = IDORFinding(
            endpoint=endpoint, method=method, param=param,
            attacker_id=attacker_id, victim_id=victim_id,
            attacker_account=attacker.username, victim_account=owner.username,
            status_code=status, severity=severity, evidence=evidence,
            leaked_fields=leaked_fields, request_payload=request_payload,
            response_snippet=attack_body[:600],
        )
        self.findings.append(finding)
        log.warning(f"🚨 [{severity.value}] IDOR trovato su {endpoint} | {evidence}")
        return finding

    # ─────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────

    def _is_access_denied(self, body: str) -> bool:
        """Rileva false positive: 200 OK ma accesso realmente negato."""
        body_lower = body.lower()
        return any(signal in body_lower for signal in self.ACCESS_DENIED_SIGNALS)

    def _similarity(self, a: str, b: str) -> float:
        if not a or not b:
            return 0.0
        return difflib.SequenceMatcher(None, a[:3000], b[:3000]).ratio()

    def _find_sensitive_fields(self, body: str) -> list[str]:
        body_lower = body.lower()
        return [f for f in self.SENSITIVE_FIELDS if f.lower() in body_lower]

    def _check_victim_data_leaked(self, attack_body: str, owner_body: str) -> bool:
        """
        Cerca se pezzi significativi del body della vittima
        appaiono nella risposta dell'attaccante.
        """
        if not owner_body or len(owner_body) < 20:
            return False
        # Estrai token significativi dalla risposta owner (parole > 8 char)
        tokens = re.findall(r'"([^"]{8,})"', owner_body)
        matches = sum(1 for t in tokens if t in attack_body)
        return matches >= 3  # 3+ campi coincidenti = probabile leak

    def _size_anomaly(self, owner_body: str, attack_body: str) -> bool:
        """Risposta dell'attaccante molto diversa da quella attesa (vuota o errore)."""
        if not attack_body:
            return False
        expected_empty = len(attack_body) < 50  # risposta quasi vuota
        much_larger    = len(attack_body) > len(owner_body) * 1.5
        return not expected_empty or much_larger

    def _safe_text(self, resp) -> str:
        try:
            return resp.text
        except Exception:
            return ""
