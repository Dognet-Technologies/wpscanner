# WENDY – WordPress ENDpoint discoverY

**v0.3.0** | Dognet Technologies srl | `info@dognet.tech`

WENDY è uno scanner di sicurezza per WordPress che automatizza endpoint
discovery, CVE matching, analisi security headers, user enumeration e
verifica di misconfigurazioni comuni. Progettato per **authorized penetration
testing** e **bug bounty** su ambienti WordPress.

> **For authorized security testing only.**

---

## Features

### Core (tutte le modalità)
- **WordPress Detection** – versione, tema attivo, plugin attivi
- **Plugin/Theme Discovery** – 80+ plugin, 16+ temi comuni; versione letta
  direttamente da `readme.txt`
- **CVE Matching** – confronto versione installata vs database vulnerabilità;
  riporta CVE ID, CVSS score, severità, descrizione
- **Security Headers** – verifica HSTS, CSP, X-Frame-Options, Referrer-Policy
  e altri 5 header; distingue CRITICAL vs OPTIONAL
- **User Enumeration** – REST API `/wp-json/wp/v2/users`, author archives
  `/?author=N`, RSS feed, login error differential
- **XML-RPC** – verifica accesso, pingback (DDoS amplification), multicall
  (brute-force amplification)
- **Hardening Checks** – `wp-config.php`, `.env`, `debug.log`, `readme.html`,
  `install.php`, `xmlrpc.php`, directory listing su `wp-content/uploads/`

### Aggressive mode (`--aggressive`)
- User enumeration estesa (fino a 20 author ID; login error differential)
- Plugin discovery estesa (50+ plugin aggiuntivi)
- Theme discovery estesa
- WPScan API enrichment (richiede `WPSCAN_API_TOKEN` – vedi sotto)

---

## CVE Database

WENDY usa **due livelli** di database vulnerabilità:

| Livello | Fonte | Aggiornamento | Auth |
|---|---|---|---|
| **Embedded** | Curato manualmente | Con il codice | Nessuna |
| **Live** (`cve_db.json`) | Wordfence Intelligence | Settimanale con `update_db.py` | Nessuna |
| **WPScan API** | wpscan.com/api/v3 | Real-time (aggressive mode) | Token gratuito |

### Wordfence Intelligence (feed pubblico)
Il feed `cve_db.json` viene generato da `wendy/update_db.py` che scarica
da `https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production/`
— pubblico, senza autenticazione.

**Aggiornamento settimanale consigliato:**
```bash
python -m wendy.update_db
# oppure
python wendy/update_db.py
```

Cron settimanale (es. ogni martedì alle 07:00):
```cron
0 7 * * 2  cd /path/to/wpscanner && python wendy/update_db.py >> /var/log/wendy-db.log 2>&1
```

Il file `cve_db.json` è gitignored — va rigenerato localmente dopo ogni clone.

### WPScan API (aggressive mode)
Con `--aggressive` e la variabile d'ambiente `WPSCAN_API_TOKEN`, WENDY arricchisce
i risultati interrogando la WPScan API per ogni plugin rilevato.

Token gratuito (25 req/giorno): https://wpscan.com/api

```bash
export WPSCAN_API_TOKEN="your_token_here"
python wendy/endpoint_discovery.py https://target.com --aggressive
```

---

## Installazione

**Requisiti:** Python 3.9+, `requests`

```bash
git clone https://github.com/Dognet-Technologies/wpscanner.git
cd wpscanner
pip install requests

# (Opzionale ma raccomandato) Aggiorna il database CVE live
python wendy/update_db.py
```

Nessun altro package richiesto. WENDY funziona offline anche senza `cve_db.json`
(usa il database embedded come fallback).

---

## Utilizzo

```
python wendy/endpoint_discovery.py <URL> [opzioni]

Argomenti:
  URL                   URL base del sito WordPress (es. https://example.com)

Opzioni:
  -v                    Verboso: mostra endpoint testati, plugin non trovati, ecc.
  -vv                   Molto verboso: include dettagli di ogni request
  --aggressive          Modalità estesa: più plugin/temi, user enum completa,
                        WPScan API enrichment (se WPSCAN_API_TOKEN impostato)
```

### Esempi

```bash
# Scansione base
python wendy/endpoint_discovery.py https://example.com

# Verbosa
python wendy/endpoint_discovery.py https://example.com -v

# Aggressive con WPScan API
export WPSCAN_API_TOKEN="tok_xxxxxxxxxxxx"
python wendy/endpoint_discovery.py https://example.com --aggressive -v

# Dry-run aggiornamento DB (fetch senza salvare)
python wendy/update_db.py --dry-run
```

### Output tipico

```
══════════════════════════════════════════════════════════
  WENDY v0.3.0 – WordPress Security Scanner
  Target : https://example.com
  Mode   : aggressive | verbosity: 1
══════════════════════════════════════════════════════════

[1/7] WordPress Detection
  ✓ WordPress detected
  ✓ Version: 6.4.3  (source: readme.html)
  ✓ Theme: Astra

[2/7] Plugin & Theme Discovery
  ✓ 4 plugin(s) detected
  ✓ 1 theme(s) detected

[3/7] CVE Analysis
  ⚠ CRITICAL contact-form-7 v5.2.0
     CVE-2020-35489  CVSS 9.8  Unrestricted file upload allows uploading PHP shells
  ⚠ HIGH    elementor v3.4.0
     CVE-2022-1329   CVSS 9.9  Contributor+ RCE via template import functionality

[4/7] Security Headers
  ✗ Strict-Transport-Security         [CRITICAL]  HSTS missing
  ✗ Content-Security-Policy           [CRITICAL]  No CSP - XSS mitigation severely weakened
  ✓ X-Content-Type-Options

[5/7] User Enumeration
  ⚠ 2 user(s) enumerated:
     • admin      [REST API]
     • john.doe   [Author archive]

[6/7] XML-RPC
  ⚠ xmlrpc.php accessible
  ⚠ Pingback enabled (DDoS amplification risk)

[7/7] Hardening Checks
  ⚠ readme.html publicly accessible (WordPress version disclosure)
  ✓ wp-config.php not accessible
```

---

## Struttura del progetto

```
wpscanner/
├── wendy/
│   ├── endpoint_discovery.py   # Scanner principale (v0.3.0)
│   └── update_db.py            # Updater database CVE da Wordfence Intelligence
├── bypass_wordfence/
│   └── waf_bypass_tester.py    # WAF bypass tester standalone
├── CVE-2023-5360-RoyalElementorAddons/
│   └── royal_elementor_rce_tester.py
├── CVE-2025-30567-WP01-PathTraversal/
│   └── CVE-2025-30567.py
├── LICENSE
└── README.md
```

File generati localmente (gitignored):
- `wendy/cve_db.json` – database CVE live (generato da `update_db.py`)
- `HISTORY.md` – log decisioni architetturali

---

## Variabili d'ambiente

| Variabile | Utilizzo |
|---|---|
| `WPSCAN_API_TOKEN` | Token WPScan API per enrichment in `--aggressive` mode |

---

## Avvertenze legali

Questo tool è fornito **esclusivamente per:**
- Penetration testing su sistemi di propria proprietà o con esplicita autorizzazione scritta
- Attività di bug bounty nei limiti del programma autorizzato
- Ricerca e formazione in ambienti isolati

**L'uso non autorizzato su sistemi di terzi è illegale** e può configurare
reati ai sensi del D.Lgs. 231/2001, art. 615-ter c.p. e normative equivalenti.
Gli autori declinano ogni responsabilità per usi impropri.

---

## Changelog

### v0.3.0
- Aggiunto `wendy/update_db.py`: aggiornamento settimanale CVE da Wordfence
  Intelligence (pubblico, no auth, nessun token richiesto)
- Database CVE ora a due livelli: embedded (fallback offline) + `cve_db.json` (live)
- Merge intelligente: deduplicazione per CVE ID, embedded ha priorità sul live
- Fix: WPScan API response parsing (la chiave top-level è lo slug del plugin)
- Fix: WPScan API severity derivata dal CVSS score numerico, non dal vettore
- Fix: Author archive enumeration non cattura più il titolo homepage come username
- Rimosso codice morto nel blocco security headers

### v0.2.0
- Scanner di sicurezza completo (CVE, headers, user enum, XML-RPC, hardening)
- Modalità aggressive con WPScan API enrichment

### v0.1.0
- 403 bypass scanner per endpoint WordPress
- Path variation, header-based bypass, cache poisoning probes
