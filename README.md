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
- **Plugin/Theme Discovery** – fino a 15 000+ plugin e temi da database CVE
  live (Wordfence Intelligence); versione letta direttamente da `readme.txt`
- **Smart Probing** – in modalità normale proba i top 3 000 slug ordinati per
  score di priorità (popolarità WP.org × CVE recenti × severità); modalità
  aggressive proba tutto il database
- **CVE Matching** – confronto versione installata vs database vulnerabilità;
  riporta CVE ID, CVSS score, severità, descrizione; supporta plugin e temi
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
- Plugin e theme discovery senza limiti (tutti i 15 000+ slug CVE-DB)
- WPScan API enrichment (richiede `WPSCAN_API_TOKEN` – vedi sotto)

---

## CVE Database

WENDY usa **tre livelli** di database vulnerabilità:

| Livello | Fonte | Aggiornamento | Auth |
|---|---|---|---|
| **Embedded** | Curato manualmente | Con il codice | Nessuna |
| **Live** (`cve_db.json`) | Wordfence Intelligence v3 | Settimanale con `-u` | API key gratuita |
| **WPScan API** | wpscan.com/api/v3 | Real-time (aggressive mode) | Token gratuito |

### Wordfence Intelligence v3 (feed live)
Il feed `cve_db.json` scarica da
`https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production/`
e richiede una **API key gratuita** di Wordfence.

In aggiunta, l'updater recupera in parallelo dal **WordPress.org public API**
(no auth) la lista dei plugin e temi più popolari per installs — usata per
prioritizzare il probing. L'indice viene memorizzato in `cve_db.json` e
aggiornato ad ogni `-u`.

**Setup iniziale:**
```bash
# 1. Copia il file di configurazione
cp wendy/.keys.example wendy/.keys

# 2. Aggiungi la tua API key Wordfence (gratuita su wordfence.com/intelligence)
echo "WORDFENCE_API_KEY=your_key_here" >> wendy/.keys

# 3. Aggiorna il database
python wendy/endpoint_discovery.py -u
```

**Aggiornamento settimanale consigliato:**
```bash
python wendy/endpoint_discovery.py -u
```

Cron settimanale (es. ogni martedì alle 07:00):
```cron
0 7 * * 2  cd /path/to/wpscanner && python wendy/endpoint_discovery.py -u >> /var/log/wendy-db.log 2>&1
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
python wendy/endpoint_discovery.py -u
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
  -u, --update          Aggiorna WENDY (git pull) e il CVE database, poi esce
                        (se combinato con URL, aggiorna prima poi scansiona)
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

# Solo aggiornamento DB (poi esce)
python wendy/endpoint_discovery.py -u

# Aggiorna DB e scansiona in un solo comando
python wendy/endpoint_discovery.py https://example.com -u
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
│   ├── endpoint_discovery.py   # Scanner principale
│   ├── update_db.py            # Updater CVE DB (Wordfence v3 + WP.org installs)
│   ├── config.py               # Loader API keys e probe tuning da .keys
│   ├── .keys.example           # Template configurazione (copiare in .keys)
│   └── .keys                   # Configurazione locale (gitignored)
├── bypass_wordfence/
│   └── waf_bypass_tester.py    # WAF bypass tester standalone
├── CVE-2023-5360-RoyalElementorAddons/
│   └── royal_elementor_rce_tester.py
├── CVE-2025-30567-WP01-PathTraversal/
│   └── CVE-2025-30567.py
├── HISTORY.md                  # Log decisioni architetturali (gitignored)
├── LICENSE
└── README.md
```

File generati localmente (gitignored):
- `wendy/cve_db.json` – database CVE live + indice installs (generato con `-u`)
- `wendy/.keys` – configurazione API key e probe tuning

---

## Configurazione (`wendy/.keys`)

Copia `wendy/.keys.example` in `wendy/.keys` e compila i valori:

| Chiave | Tipo | Utilizzo |
|---|---|---|
| `WORDFENCE_API_KEY` | **API key** | Feed CVE Wordfence Intelligence v3 (richiesto per `-u`) |
| `WPSCAN_API_TOKEN` | **API token** | WPScan enrichment in `--aggressive` mode |
| `MIN_ACTIVE_INSTALLS` | int | Minimo installazioni per includere un plugin in normal mode (default: `0` = nessun filtro) |
| `PROBE_NORMAL_LIMIT` | int | Max plugin testati in modalità normale (default: `3000`) |
| `PROBE_THEME_LIMIT` | int | Max temi testati in modalità normale (default: `100`) |
| `INSTALLS_INDEX_LIMIT` | int | Plugin da indicizzare da WP.org per scoring (default: `10000`) |
| `CVE_YEARS` | stringa | Anni CVE considerati "recenti" per lo scoring (default: `2024,2025,2026`) |

Tutti i valori supportano anche variabili d'ambiente standard (utile in CI/CD).

### Esempi di tuning `MIN_ACTIVE_INSTALLS`

| Valore | Effetto |
|---|---|
| `0` | Nessun filtro — proba tutti i ~15 000 slug CVE-DB in aggressive, top 3000 in normal |
| `1000` | Salta plugin ultra-niche; riduzione significativa della lista |
| `10000` | Copre ~95% dei target reali; scan rapido |
| `100000` | Solo plugin molto diffusi; scan velocissimo, copertura ridotta |

> **Nota sicurezza:** plugin con CVE CRITICAL degli anni in `CVE_YEARS` sono sempre
> testati, indipendentemente da `MIN_ACTIVE_INSTALLS`.

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
- **Smart probe prioritization**: in normal mode proba i top 3 000 plugin/temi
  ordinati per score (popolarità WP.org × CVE recenti × severità CVSS)
- **WordPress.org installs index**: durante `-u` vengono scaricati in parallelo
  i top 10 000 plugin e 500 temi per `active_installs`; memorizzati in `cve_db.json`
- **Filtro installazioni configurabile** (`MIN_ACTIVE_INSTALLS`): esclude plugin
  troppo rari in normal mode; plugin con CVE CRITICAL recenti sono sempre inclusi
- **Theme CVE DB**: include anche le vulnerabilità dei temi (tipo `theme` nel feed
  Wordfence); lista temi probe ora dinamica (CVE + popular + baseline)
- **Probe tuning via `.keys`**: tutti i limiti configurabili senza modificare il codice
  (`PROBE_NORMAL_LIMIT`, `PROBE_THEME_LIMIT`, `CVE_YEARS`, `INSTALLS_INDEX_LIMIT`)
- **Aggiornamento DB integrato** (`-u`): aggiorna CVE database e indice installazioni
  direttamente dallo scanner; nessun script separato da eseguire manualmente
- **Feed Wordfence v3**: richiede API key gratuita (precedentemente v2 pubblica)
- **`config.py`**: nuovo modulo `load_probe_config()` — legge e valida i parametri
  di tuning da `.keys` / env con defaults sensati
- Database CVE a due livelli: embedded (fallback offline) + `cve_db.json` (live)
- Merge intelligente: deduplicazione per CVE ID, embedded ha priorità sul live
- Fix: WPScan API response parsing (chiave top-level = slug del plugin)
- Fix: WPScan API severity derivata da CVSS score numerico, non dal vettore
- Fix: Author archive enumeration non cattura più il titolo homepage come username

### v0.2.0
- Scanner di sicurezza completo (CVE, headers, user enum, XML-RPC, hardening)
- Modalità aggressive con WPScan API enrichment

### v0.1.0
- 403 bypass scanner per endpoint WordPress
- Path variation, header-based bypass, cache poisoning probes
