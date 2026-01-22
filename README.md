# WENDY – WordPress ENDpoint discoverY

WENDY è un tool di **endpoint discovery e 403 bypass analysis** progettato specificamente per ambienti **WordPress**, con un focus su **sicurezza applicativa, misconfigurazioni e controlli di accesso deboli**.

Il tool automatizza la scoperta di endpoint sensibili e verifica tecniche di **403 Forbidden bypass**, distinguendo tra protezioni **endpoint-specific** e **generic/WAF-based**, senza scartare bypass potenzialmente validi.

---

## ✨ Features

- 🔍 **WordPress Endpoint Discovery**
  - REST API (`/wp-json/`)
  - Feed, sitemap, file well-known
  - Endpoint comuni di configurazione e metadata

- 🚪 **403 Forbidden Bypass Detection**
  - Path variation (`/.`, `/./`, `..;/`, `;`, `//`)
  - Case variation
  - Header-based bypass (X-Original-URL, X-Rewrite-URL, ecc.)
  - Cache poisoning probes

- 🧠 **403 Intelligence Analysis**
  - Distingue tra:
    - 403 endpoint-specific
    - 403 generici (WAF / global rules)
  - Assegna **confidence level** al risultato
  - NON elimina bypass reali: li contestualizza

- 📊 **Meaningful Results**
  - Ogni bypass include:
    - tecnica utilizzata
    - URL
    - status code
    - preview del contenuto
    - analisi del 403 originale

---

## 🧠 Filosofia del tool

> **Un bypass è valido se prima era 403 e ora non lo è più.**  
> Tutto il resto è analisi, non filtraggio.

WENDY **non scarta risultati solo perché il 403 originale era generico**.  
Questo approccio evita falsi negativi e rispecchia il comportamento reale di:
- penetration test
- bug bounty
- analisi di misconfigurazioni WAF

---

## 🧰 Tecniche di Bypass Implementate

- Path normalization abuse
- Dot / slash confusion
- Semicolon parsing
- Case sensitivity issues
- Alternative routing headers
- Cache poisoning probes
- Directory traversal edge cases (`..;/`)

---

## 📦 Requisiti

- Python 3.9+
- `requests`

---

## 🚀 Utilizzo

```bash
python wendy.py https://target-site.com

Output tipico:

🚨 403 BYPASS SUMMARY
==================================================
✅ Found 2 successful bypasses!

📊 Bypass techniques that worked:
   - Path Variation (/.env/..): 1 endpoint
   - Path Variation (/./.env/..): 1 endpoint

📄 Output Structure (Esempio)

{
  "method": "Path Variation (/.env/..)",
  "url": "https://target/.env/..",
  "status": 200,
  "preview": "...",
  "403_analysis": {
    "endpoint_specific": true,
    "confidence": "high",
    "note": "403 is endpoint-specific"
  }
}
```
⚠️ Disclaimer

Questo tool è fornito solo per scopi educativi e di security testing autorizzato.

L'autore non si assume alcuna responsabilità per usi impropri o non autorizzati.
📌 Roadmap (possibili estensioni)

    Supporto multi-thread

    Output JSON / HTML report

    Scoring del rischio

    Integrazione con wordlists personalizzate

    Modalità bug bounty report

🧑‍💻 Autore

Sviluppato per attività di:

    Web Application Security

    WordPress Security Assessment

    403 / Access Control Testing
