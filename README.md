# 🕵️ Janus – Bug Bounty Intelligence Engine

**Janus** è un tool semi-automatico per la scoperta di vulnerabilità **IDOR** (Insecure Direct Object Reference), **Mass Assignment** e **Business Logic Flaws**.  
Progettato per l'uso esclusivo su programmi di bug bounty autorizzati (es. HackerOne, Bugcrowd).

> ⚠️ **AVVERTENZA LEGALE:** Usa Janus **esclusivamente** su target per cui hai un'autorizzazione scritta. L'uso non autorizzato è illegale. L'autore non è responsabile per eventuali usi impropri.

---

## ✨ Funzionalità

- 🔍 **IDOR Detection** – test su parametri GET, path params, body JSON con supporto UUID/hexadecimal ID.
- 🎭 **Multi‑account** – supporto attaccante/vittima con iniezione cookie per bypassare bot detection (Akamai, Cloudflare).
- 🧪 **Mass Assignment** – tentativo di assegnazione ruoli privilegiati (admin, employee) via parameter pollution.
- ⚙️ **Business Logic** – price manipulation, coupon reuse, race condition, step skip.
- 📄 **Report automatici** – output in Markdown (pronto per HackerOne) e HTML visuale con severity badges.
- 🚀 **Proxy integration** – supporto Burp Suite per analisi traffico e debugging.

---

## 📦 Installazione

```bash
git clone https://github.com/Jackbop/janus.git
cd janus
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt

Requisiti: Python 3.8+, requests, beautifulsoup4.
⚙️ Configurazione

Copia il file di esempio e personalizzalo:
bash

cp config_example.json config_rei_bbp.json
nano config_rei_bbp.json

Per target con protezione anti‑bot (es. REI con Akamai)

    Crea due account di test su Mailinator (es. attacker@mailinator.com, victim@mailinator.com).

    Ottieni i cookie con Burp Suite:

        Accedi con l’account attaccante su target.com.

        In Burp → Proxy → HTTP History, copia i cookie REI_SSL_SESSION_ID, JSESSIONID, loggedin=1, check=true.

        Ripeti per l’account vittima.

    Trova l’ID della vittima – cerca una risposta JSON a /rest/account/profile e prendi userId o sub.

    Inserisci cookie e ID nel file config_rei_bbp.json (vedi il campo auth.sessions e idor.endpoints[].victim_id).

🚀 Utilizzo
bash

# Scan IDOR di base
python janus.py -c config_rei_bbp.json --module idor

# Tutti i moduli (IDOR + Mass Assignment + Business Logic)
python janus.py -c config_rei_bbp.json --module all

# Con proxy Burp (per vedere il traffico)
python janus.py -c config_rei_bbp.json --proxy http://127.0.0.1:8080

# Output personalizzato
python janus.py -c config_rei_bbp.json --output-md report.md --output-html report.html

Moduli disponibili: idor, mass_assignment, bizlogic, all.
📊 Output

    janus_report.md – report in Markdown, pronto per essere incollato su HackerOne/Bugcrowd.

    janus_report.html – report visuale con badge di severità, CVSS score, stima del bounty.

    In console: riepilogo colorato dei finding (Critical/High/Medium).

🏗️ Architettura
text

janus/
├── core/
│   └── session_manager.py      # Gestione sessioni (cookie injection, form login, JSON login)
├── modules/
│   ├── idor/
│   │   └── detector.py         # IDOR con analisi similarità e leak sensitive fields
│   └── business_logic/
│       └── analyzer.py         # Price manip., coupon reuse, race condition, step skip
├── reporting/
│   └── impact_reporter.py      # Report Markdown + HTML + HackerOne submission draft
├── janus.py                    # CLI entry point
└── config_example.json         # Template di configurazione

🧪 Esempio di finding
text

🚨 [CRITICAL] IDOR trovato su /rest/account/profile
Campi sensibili esposti: ['email', 'address', 'phone']
Similarità risposta: 87%

Il report HTML generato conterrà la richiesta, la risposta e i passi per riprodurre la vulnerabilità.
🤝 Contributi

Pull request, bug report e suggerimenti sono benvenuti! Per modifiche importanti, apri prima una issue per discuterle.
📄 Licenza

MIT © Jackbop
