"""
Janus - Session Manager v0.3
Miglioramenti REI/Akamai:
- Header anti-fingerprinting completi (Sec-Fetch, Priority, Accept-Language)
- Cookie injection per bypassare bot detection
- Timeout aumentati a 30s
- Rate limiting per evitare ban
"""

import re
import time
import requests
import logging
from typing import Optional
from dataclasses import dataclass, field
from urllib.parse import urljoin

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger("janus.session")

RATE_LIMIT_DELAY = 0.8  # secondi tra una richiesta e l'altra — sicuro per Akamai


def _rate_limit():
    time.sleep(RATE_LIMIT_DELAY)


@dataclass
class Account:
    username: str
    password: str
    role: str = "user"
    session: requests.Session = field(default_factory=requests.Session)
    user_id: Optional[str] = None
    cookies: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    logged_in: bool = False

    def __post_init__(self):
        # Header identici a Firefox 149 su Windows — quello che usa Giacomo
        # Akamai confronta questi header con i cookie bm_sz/_abck
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:149.0) Gecko/20100101 Firefox/149.0",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "Priority": "u=1",
            "Te": "trailers",
        })


class SessionManager:

    def __init__(self, base_url: str, proxies: Optional[dict] = None):
        self.base_url = base_url.rstrip("/")
        self.accounts: list[Account] = []
        self.proxies = proxies or {}

    def add_account(self, username: str, password: str, role: str = "user") -> Account:
        account = Account(username=username, password=password, role=role)
        if self.proxies:
            account.session.proxies = self.proxies
            account.session.verify = False
        self.accounts.append(account)
        log.info(f"Account aggiunto: {username} [{role}]")
        return account

    # ─────────────────────────────────────────
    # METODO PRINCIPALE PER REI: Cookie Injection
    # ─────────────────────────────────────────

    def login_cookies(self, account: Account, cookies: dict) -> bool:
        """
        Inietta direttamente i cookie catturati da Burp Suite.
        È il metodo più affidabile per siti con bot detection (REI/Akamai).

        Come ottenere i cookie:
        1. Apri Firefox con Burp proxy attivo
        2. Fai login manualmente su rei.com
        3. Vai su rei.com/account
        4. In Burp HTTP History, copia i valori di:
           - REI_SSL_SESSION_ID
           - JSESSIONID
           - bm_sz, bm_sv (opzionali ma aiutano)
        """
        account.session.cookies.update(cookies)
        account.cookies = cookies
        account.logged_in = True
        log.info(f"✅ Sessione cookie iniettata: {account.username}")
        return True

    def login_all_cookies(self, sessions_list: list[dict]) -> bool:
        """Inietta i cookie per tutti gli account dalla lista sessions nel config."""
        for account, cookies in zip(self.accounts, sessions_list):
            # Rimuovi campi che iniziano con _ (sono commenti del config)
            clean = {k: v for k, v in cookies.items() if not k.startswith("_")}
            self.login_cookies(account, clean)
        return True

    # ─────────────────────────────────────────
    # LOGIN TRADIZIONALI (per altri target)
    # ─────────────────────────────────────────

    def login_form(self, account: Account, login_path: str,
                   user_field: str = "username", pass_field: str = "password",
                   extra_fields: Optional[dict] = None) -> bool:
        url = urljoin(self.base_url, login_path)
        try:
            resp = account.session.get(url, timeout=30)
            csrf_token = self._extract_csrf(resp.text)
        except requests.RequestException as e:
            log.error(f"GET login fallito per {account.username}: {e}")
            return False

        data = {user_field: account.username, pass_field: account.password}
        if csrf_token:
            data["_token"] = csrf_token
            data["csrf_token"] = csrf_token
        if extra_fields:
            data.update(extra_fields)

        try:
            _rate_limit()
            resp = account.session.post(url, data=data, timeout=30, allow_redirects=True)
            if self._is_logged_in(resp, account.username):
                account.logged_in = True
                account.cookies = dict(account.session.cookies)
                log.info(f"✅ Login form riuscito: {account.username}")
                return True
            else:
                log.warning(f"❌ Login fallito: {account.username} | Status: {resp.status_code}")
                return False
        except requests.RequestException as e:
            log.error(f"POST login fallito: {e}")
            return False

    def login_json(self, account: Account, login_path: str,
                   user_field: str = "email", pass_field: str = "password",
                   token_field: str = "token") -> bool:
        url = urljoin(self.base_url, login_path)
        payload = {user_field: account.username, pass_field: account.password}
        try:
            _rate_limit()
            resp = account.session.post(url, json=payload, timeout=30)
            if not resp.text.strip():
                log.error(f"❌ Risposta vuota per {account.username}. Bot detection attivo — usa cookies.")
                return False
            data = resp.json()
            token = (data.get(token_field) or data.get("access_token") or
                     data.get("jwt") or data.get("auth_token"))
            if token:
                account.headers["Authorization"] = f"Bearer {token}"
                account.session.headers.update(account.headers)
                account.logged_in = True
                log.info(f"✅ JWT login riuscito: {account.username}")
                return True
            else:
                log.warning(f"❌ Token non trovato per {account.username}")
                return False
        except Exception as e:
            log.error(f"JSON login fallito: {e}")
            return False

    def login_all_form(self, login_path: str, **kwargs) -> bool:
        return all(self.login_form(acc, login_path, **kwargs) for acc in self.accounts)

    def login_all_json(self, login_path: str, **kwargs) -> bool:
        return all(self.login_json(acc, login_path, **kwargs) for acc in self.accounts)

    # ─────────────────────────────────────────
    # HTTP METHODS con rate limiting
    # ─────────────────────────────────────────

    def get(self, account: Account, path: str, **kwargs) -> requests.Response:
        _rate_limit()
        url = urljoin(self.base_url, path)
        return account.session.get(url, timeout=30, **kwargs)

    def post(self, account: Account, path: str, data=None, json=None, **kwargs) -> requests.Response:
        _rate_limit()
        url = urljoin(self.base_url, path)
        return account.session.post(url, data=data, json=json, timeout=30, **kwargs)

    def put(self, account: Account, path: str, json=None, **kwargs) -> requests.Response:
        _rate_limit()
        url = urljoin(self.base_url, path)
        return account.session.put(url, json=json, timeout=30, **kwargs)

    def delete(self, account: Account, path: str, **kwargs) -> requests.Response:
        _rate_limit()
        url = urljoin(self.base_url, path)
        return account.session.delete(url, timeout=30, **kwargs)

    def _extract_csrf(self, html: str) -> Optional[str]:
        patterns = [
            r'name=["\'](?:_token|csrf_token|csrfmiddlewaretoken)["\'][^>]+value=["\']([^"\']+)',
            r'value=["\']([^"\']+)["\'][^>]+name=["\'](?:_token|csrf_token|csrfmiddlewaretoken)["\']',
            r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def _is_logged_in(self, resp: requests.Response, username: str) -> bool:
        fail_signals = ["invalid", "wrong password", "incorrect", "login failed",
                        "credenziali", "errore", "error"]
        resp_lower = resp.text.lower()
        if any(s in resp_lower for s in fail_signals):
            return False
        success_signals = ["dashboard", "logout", "profile", "account", "welcome",
                           "benvenuto", username.lower().split("@")[0]]
        return any(s in resp_lower for s in success_signals) or resp.status_code == 200
