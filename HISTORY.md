# WENDY – Design Decision History

This file documents the key architectural and implementation decisions made
during development, including the reasoning behind them.
**Not committed to git** (covered by `.gitignore`).

---

## 2025-03 — v0.1.0: Initial architecture

### Decision: Single-file module (`wendy/endpoint_discovery.py`)
**Why:** The tool started as a focused 403-bypass scanner with minimal scope.
A single file avoids premature package complexity and makes it easy to drop
into any pentest environment with just `python endpoint_discovery.py`.

### Decision: No external dependencies beyond `requests`
**Why:** Pentesting environments often have restricted package access.
`requests` is almost universally available. urllib3 comes bundled with it.
No `packaging`, `lxml`, or other non-stdlib deps.

### Decision: Random User-Agent rotation + bypass headers
**Why:** Many WP sites and WAFs fingerprint scanners by UA. Rotation reduces
detection probability. Bypass headers (X-Forwarded-For, X-Real-IP, etc.) are
included because they are standard in authorized pentest tooling.

---

## 2025-03 — v0.2.0: Security analysis expansion

### Decision: Embedded CVE database (`CVE_DATABASE` dict in source)
**Why:** Enables offline use and zero-dependency CVE matching.
The embedded DB is intentionally small (curated, well-documented CVEs only)
and serves as a guaranteed fallback. It is NOT the primary data source — that
role is given to the live feed (see v0.3.0).

**Tradeoff:** Becomes stale quickly. Accepted because the live DB (`cve_db.json`)
is the primary source; embedded is fallback-only.

### Decision: WPScan API as optional aggressive-mode enrichment
**Why:** WPScan API (wpscan.com) is the most comprehensive WP-specific
vulnerability database. Free tier: 25 req/day. Requiring a token keeps it
opt-in and avoids unexpected API calls during routine scans.
Activated only with `--aggressive` + `WPSCAN_API_TOKEN` env var.

### Decision: Severity derived from CVSS score, not vector string prefix
**Why (bug fix):** The WPScan API CVSS vector looks like
`CVSS:3.1/AV:N/AC:L/PR:N/...`. Splitting by `/` and taking index 0 gives
`"CVSS:3.1"` — not a severity label. Replaced with `_cvss_score_to_severity()`
mapping numeric score to CRITICAL/HIGH/MEDIUM/LOW per CVSS v3.1 thresholds.

### Decision: Author-archive enumeration fallback only on redirect
**Why (bug fix):** When `/?author=N` returns 200 directly (user doesn't exist
or author archives disabled), the page is the homepage. Capturing its `<title>`
registers the site name as a username. Fixed to only trigger the title fallback
when `r2.url != original_url` (a redirect actually occurred).

---

## 2025-03 — v0.3.0: Live CVE database via Wordfence Intelligence

### Decision: Wordfence Intelligence as the live CVE feed source
**Why:** Wordfence publishes their vulnerability database as a free, public,
unauthenticated JSON feed at:
`https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production/`

Considered alternatives:
| Source | Auth needed | WP-specific | Notes |
|---|---|---|---|
| NVD NIST API v2 | No | No | Broad; slug extraction hard |
| WPScan API | Yes (token) | Yes | 25 req/day free; already used in aggressive mode |
| Patchstack | Partial | Yes | Less complete public tier |
| **Wordfence Intelligence** | **No** | **Yes** | **Best fit: free, public, WP-specific** |

Wordfence terms allow use for security tooling. See:
https://www.wordfence.com/wordfence-intelligence-terms-and-conditions/

### Decision: Weekly update cadence
**Why:** Most WP CVEs are disclosed on Tuesdays (following responsible
disclosure). Weekly is frequent enough to stay current without hammering
the Wordfence API. Daily would also work but is unnecessary.

### Decision: `cve_db.json` is gitignored (generated artifact)
**Why:** The JSON file is produced by running `update_db.py` locally and
changes every week. Committing it would create noisy diffs and conflicts on
every update. Each developer/user generates it once locally after clone.

**Alternative considered:** Commit a pre-generated `cve_db.json` and update
via CI weekly PR. Rejected: adds CI complexity and forces a commit per update.

### Decision: Merge strategy: embedded DB wins on duplicate CVE IDs
**Why:** The embedded DB entries are manually curated with verified data.
If the same CVE appears in both, the embedded version is kept and the JSON
version is silently skipped. This prevents a corrupted or wrong live feed
from overwriting known-good baseline data.

### Decision: Skip entries with `to_version == "*"` in live feed
**Why:** Some vulnerabilities affect all versions (unpatched plugin,
discontinued). With no concrete version cap, our `_is_vulnerable(installed,
max_vuln)` comparison cannot work. These entries would always fire regardless
of installed version, creating excessive false positives.
**Accepted tradeoff:** Occasional missed CVE for plugins with open, unpatched
vulnerabilities.

### Decision: `re` import inside `update_db.py` main scope only
**Why:** `parse_feed()` calls `_parse_ver()` which uses `re`. Since `re` is
stdlib and always available, it's imported at the top of `main()` via a global
assignment. Kept slightly unconventional to avoid polluting the module namespace
when `update_db` is imported programmatically rather than run as a script.

> **Superseded in v0.4.0:** `import re` moved to module level (top of file)
> — the global-assignment hack was fragile and unnecessary.

---

## 2026-03 — v0.4.0: Smart probe prioritization & installs-based filtering

### Decision: WordPress.org public API as source for active_installs index
**Why:** The Wordfence CVE feed tracks ~15 000 plugin slugs. Probing all of
them in normal mode generates ~15 000 HTTP requests and takes tens of minutes —
unusable in practice. We needed a signal for real-world deployment probability
to rank slugs and cut the list to a manageable size.

WordPress.org exposes a free, unauthenticated paginated API
(`/plugins/info/1.2/` and `/themes/info/1.2/`) that returns entries ordered by
`active_installs`. Fetching top 10 000 (~100 pages × 100 per page) covers
virtually the entire WP.org catalog. The installs data is stored in
`cve_db.json._meta.installs_index` and refreshed weekly with the CVE feed.

**Alternatives considered:**

| Option | Reason rejected |
|---|---|
| Rank purely by CVE count / CVSS | Ignores deployment probability — a plugin with 3 CRITICAL CVEs but 10 installs is irrelevant on most targets |
| Hardcoded curated list (~200 slugs) | Already existed; too static, misses newly-popular plugins and fresh CVEs |
| WPScan API for popularity data | Requires a token; rate-limited to 25 req/day on free tier — not suitable for bulk indexing |
| Per-slug individual WP.org queries during scan | One HTTP request per slug × 15 000 = worse than the original problem |
| Wappalyzer / built-in tech-detection datasets | Not WP-specific, stale, not freely redistributable |

**Tradeoff:** Adds ~20–50 s to `update_db.py` runtime (was ~5 s for CVE feed
alone). Mitigated by running plugin and theme fetches in parallel via
`ThreadPoolExecutor`. Acceptable because update runs weekly, not per-scan.

---

### Decision: Hybrid priority score (installs × recency × severity)
**Why:** Any single-dimension ranking misses important cases:
- **Pure installs only**: would always probe WooCommerce first but skip a
  plugin with 500 installs and a CVE-2025 CRITICAL RCE being actively exploited.
- **Pure CVSS severity only**: an old CRITICAL CVE for a plugin with 30 installs
  wastes probes while high-install plugins with only MEDIUM CVEs go unchecked.
- **Pure recency only**: recent MEDIUM CVEs for obscure plugins rank above old
  CRITICAL CVEs for widely-deployed ones.

The hybrid score combines all signals:
```
score = _installs_score(n)        # 0–10 by WP.org active_installs bands
      + 3 per CVE in RECENT_CVE_YEARS   # recency bonus
      + 2 per CRITICAL CVE              # severity bonus
      + 1 per HIGH CVE
```

A widely-deployed plugin with a fresh CRITICAL CVE scores highest (10+5+3+2=20).
A popular plugin with only old LOW CVEs still scores moderately (10) and gets
probed ahead of obscure plugins with no recent activity. A niche plugin with a
fresh CRITICAL scores enough (0+3+2=5) to survive `MIN_ACTIVE_INSTALLS` filtering
via the override rule (see below).

**Alternatives considered:**

| Approach | Reason rejected |
|---|---|
| Binary popular/not flag (+4 flat) | Loses granularity — 100K installs and 5M installs are treated identically |
| Percentile rank (0–100 based on position in WP.org list) | More precise but requires knowing the total catalog size, which varies |
| Machine-learning model on historical scan hit rates | No training data available; overkill for this use case |

**Tradeoff:** Score weights (3/2/1 for recency/critical/high) are heuristic,
not empirically calibrated. Installs data from WP.org may lag real deployment
by weeks. Accepted — weekly refresh is sufficient and the order matters far
more than the absolute values.

---

### Decision: `MIN_ACTIVE_INSTALLS` filter with override for recent CRITICAL CVEs
**Why:** A hard installs floor without exceptions would silently drop a plugin
with 50 installs and a CVE-2025 CRITICAL RCE from the probe list. That is a
false economy: if the plugin is installed on the target, missing it is a scan
failure regardless of its rarity.

The security invariant is: _no recent CRITICAL CVE is ever silently skipped_.
Implementation: a slug below `min_installs` is still included if it has at
least one CVE whose year is in `CVE_YEARS` AND whose severity is CRITICAL
(`has_recent_crit == True`).

**Alternatives considered:**

| Option | Reason rejected |
|---|---|
| Hard floor — no exceptions, ever | Unacceptable: would miss actively-exploited obscure plugins |
| Override for all CRITICAL CVEs (not just recent) | A 2019 CRITICAL for a discontinued plugin with 0 installs is not a priority; the recency gate keeps the list focused |
| Override for CRITICAL + HIGH | HIGH CVEs are numerous (~30–40% of the feed); this would defeat the filter entirely for most sets |
| Two separate limits: `MIN_INSTALLS_NORMAL` and `MIN_INSTALLS_CRITICAL` | More granular but requires two config keys; single key + override rule is simpler and covers the important case |

**Tradeoff:** `MIN_ACTIVE_INSTALLS=0` (default) disables the filter entirely,
so out-of-the-box behavior is unchanged. Operators who want fast scans must
consciously set a threshold. This is intentional — a conservative default
avoids surprising users with missed detections.

---

### Decision: Pre-build `RECENT_CVE_IDS` frozenset at module load
**Why:** The scoring hot-loop iterates over ~15 000 slugs × N CVE entries each.
The original implementation called `re.search(r'CVE-(\d{4})-', cve_id)` on
every entry — easily 150 000+ regex executions per full scan. Since
`RECENT_CVE_YEARS` is fixed at import time, all CVE IDs that qualify as
"recent" can be computed once and stored in a frozenset. The scoring loop
then uses `cve_id in RECENT_CVE_IDS` — a single hash lookup with no regex,
no string parsing, no allocation.

**Alternatives considered:**

| Option | Reason rejected |
|---|---|
| Compile regex once (`_CVE_YEAR_RE = re.compile(...)`) and reuse | Still O(n) regex per CVE entry; frozenset is O(1) |
| Pre-tag entries with `is_recent` boolean at DB load time | Would require changing the stored entry format (tuple length changes); complicates embedded DB compatibility |
| LRU cache on the regex function | Adds memory overhead; CVE IDs are high-cardinality (thousands of unique values), cache hit rate would be low |

**Tradeoff:** Building `RECENT_CVE_IDS` at module load adds a small one-time
cost (~1–5 ms for 50 000 CVE entries). This is negligible compared to the
savings during scoring. The frozenset is never mutated after creation.

---

### Decision: `_installs_score(n)` takes an install count (int), not a slug
**Why:** The original signature `_installs_score(slug)` did
`INSTALLS_INDEX.get(slug, 0)` internally, then the caller did
`INSTALLS_INDEX.get(slug, 0)` again immediately after for the `min_installs`
filter check — two dict lookups for the same key per slug per scoring call.

Changing the signature to accept `n` (the already-looked-up int) means the
caller does one lookup and reuses it for both score computation and filtering.
The function also becomes a pure computation with no dependency on global state,
making it trivially testable.

**Alternative considered:** Keep `_installs_score(slug)` and have it return a
`(score, installs)` tuple so both values are available to the caller. Rejected:
returning a tuple from a function named `*_score` is surprising; a scalar
argument is cleaner.

---

### Decision: Theme CVEs stored under `_themes` key in `cve_db.json`
**Why:** Wordfence Intelligence v3 includes theme vulnerabilities alongside
plugin vulnerabilities (distinguished by `type == 'theme'`). Previously WENDY
silently dropped them. Including themes improves detection coverage — popular
themes like Divi, Avada, and OceanWP have had numerous CRITICAL CVEs.

Themes require a different probe mechanism (check `style.css`, not `readme.txt`)
so they must be stored and retrieved separately from plugin slugs.

**Alternatives considered:**

| Option | Reason rejected |
|---|---|
| Separate `theme_cve_db.json` file | Two files to manage, two update commands, more complex load logic |
| Top-level keys prefixed with `theme:` | Breaks backward compatibility with any existing consumers of `cve_db.json` |
| Merge themes into the same dict as plugins | Cannot distinguish probe strategy (readme.txt vs style.css) at load time |
| Keep hardcoded theme list only | Static; misses CVE-known themes not in the hardcoded list; updated only with code changes |

**Tradeoff:** Adds `_themes` key at top level of `cve_db.json` — a reserved
namespace. Plugin slugs starting with `_` are illegal on WP.org so collision
is impossible. The `_meta` reserved key follows the same convention.

---

### Decision: Probe tuning via `wendy/.keys`, not CLI flags
**Why:** Parameters like `MIN_ACTIVE_INSTALLS`, `PROBE_NORMAL_LIMIT`, and
`CVE_YEARS` are per-operator preferences, not per-scan options. An operator
running WENDY on an engagement will keep the same settings across dozens of
scans. Requiring them as CLI flags every invocation is error-prone and verbose.

Storing them in `.keys` (alongside API keys) keeps configuration in one place,
allows version-controlled per-project `.keys` files (for team environments),
and all values are also readable as environment variables for CI/CD pipelines.

**Alternatives considered:**

| Option | Reason rejected |
|---|---|
| CLI flags only (`--min-installs`, `--probe-limit`) | Verbose; easy to forget; can't persist across invocations without shell aliases |
| Separate `wendy/config.ini` or `wendy/probe.conf` | Another file to maintain; `.keys` already exists and uses the same KEY=VALUE format |
| Hardcoded defaults only (no user tuning) | Too rigid; a fast assessment needs different settings than a thorough audit |
| `argparse` with defaults from env | Would work, but endpoint_discovery.py is invoked as a library by wpscanner.py — not always from CLI |

**Tradeoff:** Module-level constants (`NORMAL_MODE_PROBE_LIMIT`, etc.) are
resolved at import time. Changing `.keys` requires restarting the process.
Acceptable for a CLI tool where each invocation is a fresh process.

---

### Decision: Wordfence Intelligence API upgrade v2 → v3 (API key required)
**Why:** Wordfence retired the unauthenticated v2 feed in favour of a v3 API
requiring a free account key. The free tier provides full access to the complete
vulnerability database with no meaningful rate limiting for weekly batch use.

**Alternatives considered:**

| Option | Reason rejected |
|---|---|
| Stay on v2 (unofficial mirrors / cached copies) | v2 returns stale data; using unofficial mirrors violates terms and creates dependency on third-party availability |
| Switch primary source to NVD NIST API v2 | Not WP-specific; requires complex heuristics to extract plugin slugs from CPE strings; coverage is worse for WP plugins |
| Switch to Patchstack free API | Free tier is limited; less complete than Wordfence for WP ecosystem |
| Keep embedded DB only (no live feed) | Already rejected in v0.3.0; coverage degrades to a few dozen curated entries |

**Impact on users:** First-time setup now requires one extra step — adding
`WORDFENCE_API_KEY` to `wendy/.keys`. A free key is obtained in under a minute
at wordfence.com/intelligence. The error message on missing key is explicit and
actionable.

**Tradeoff:** Introduces a required credential for database updates. Offline
/ no-account usage still works with the embedded DB as fallback. First-time
setup friction is the accepted cost for access to a complete, actively-maintained
feed.

---

## 2026-03 — v0.4.0 (post-release): WAF/CDN interception detection

### Problem: false positive bypass results behind Imperva / Cloudflare

Observed on `sorintsec.ai` (protected by Imperva Incapsula): every bypass
probe returned HTTP 200 — because Incapsula intercepts requests and serves
its own JavaScript challenge page with status 200 instead of forwarding the
request to the origin server. WENDY's bypass detection saw 200 and logged
it as a successful bypass, reporting dozens of false positives.

The same behaviour is documented for Cloudflare JS challenges, Sucuri block
pages, Akamai bot manager, and Wordfence block pages — all return 200 with a
self-contained HTML page rather than passing the request through.

**Root cause:** The existing false positive pipeline (`is_bypass_false_positive`,
`is_likely_false_positive`) was designed to detect soft 404s and homepage
clones. WAF challenge pages have completely different characteristics:
- Very short bodies (212 bytes for Incapsula JS challenge)
- No WordPress fingerprints in body
- No homepage title match
- No 404 error strings
- Pass all existing checks → incorrectly classified as valid bypasses

### Decision: dedicated `_is_waf_interception(response)` method

**Why a dedicated method and not extending `is_bypass_false_positive()`:**
WAF detection requires inspecting **response headers and cookies**, not just
body content. `is_bypass_false_positive()` only receives the body string (by
design — it was built before we needed headers). Extending its signature to
accept the full response object would require changing every call site and
break the separation of concerns.

A standalone `_is_waf_interception(response)` method:
- Takes the full `requests.Response` object
- Returns `(bool, str)` — (is_waf, vendor_name)
- Is called early, before any content analysis
- Has zero false positive risk on non-WAF sites (all checks are vendor-specific)

**Alternatives considered:**

| Option | Reason rejected |
|---|---|
| Add `response_headers` param to `is_bypass_false_positive()` | Breaks existing call signatures across test_403_bypasses; confuses the purpose of the function (FP detection vs WAF detection are different problems) |
| Detect WAF in `is_likely_false_positive()` | Same issue — content-only function; also called for non-bypass 200s where we have the response object, so a separate method is cleaner |
| Check body-only patterns (no headers) | Too fragile; Incapsula's 212-byte JS challenge body doesn't contain "blocked" or "firewall" strings — only `/_Incapsula_Resource`. Header detection (`x-iinfo`, `visid_incap_`) is far more reliable |
| Whitelist of known challenge page lengths | Brittle; Incapsula uses different lengths for different challenge types (212 for JS challenge, 842+ for bot fingerprint page) |

### Decision: three integration points for WAF detection

1. **`test_endpoint()` — 200 branch**: WAF check runs before `is_likely_false_positive()` and content pattern matching. If WAF detected: `interesting=False`, `waf_vendor` stored, `reason='WAF interception (vendor)'`. This prevents challenge pages from matching `interesting_patterns` (e.g. `'wordpress'` or `'wp-content'` appearing in Incapsula's `/_Incapsula_Resource` path).

2. **`test_403_bypasses()` — all four 200 checks**: The `and not self._is_waf_interception(r)[0]` guard is appended directly to each `if r.status_code == 200:` condition. Bypass entries are never added for WAF interceptions. This means the bypass count accurately reflects real bypasses and `[N BYPASSES]` is never inflated by WAF challenge pages.

3. **`run_full_scan()` Phase 8 banner**: One probe of the homepage runs `_is_waf_interception()` before the scan loop. If WAF is detected, a warning line informs the operator that challenge pages will be filtered. This is important context: the operator knows in advance that bypass results may be suppressed and that confirmed bypasses represent real WAF evasion.

**Why not abort the bypass scan entirely when WAF is detected?**
A WAF does not mean all paths are protected identically. Some paths may bypass
WAF rules (misconfiguration, path exceptions, IP allowlists triggered by
bypass headers). A real bypass through Imperva or Cloudflare is a CRITICAL
finding. Aborting would miss these. We filter noise (challenge pages) while
still looking for real bypasses.

### Decision: detection strategy — two tiers of signals

**Tier 1 — Vendor fingerprints (high confidence, vendor-specific):**
Each major WAF vendor leaves deterministic traces:
- **Imperva Incapsula**: `x-iinfo` header (present on ALL Incapsula responses),
  `visid_incap_<sid>` and `incap_ses_<port>_<sid>` cookies, `/_Incapsula_Resource`
  script in body
- **Cloudflare**: `cf-ray` header (present on ALL CF responses), `cf-mitigated`,
  `server: cloudflare`, `__cf_bm` / `cf_clearance` cookies, body phrases
  ("checking your browser", "ddos protection", "please enable cookies")
- **Sucuri**: `x-sucuri-id` / `x-sucuri-cache` headers, "sucuri website firewall"
  in body
- **Akamai**: `x-akamai-transformed`, `akamai-origin-hop`, `ak_bmsc` / `bm_sz`
  cookies (Bot Manager sensor cookies), "reference #" + "akamai" in body
- **Wordfence**: "your access to this site has been limited" or "generated by
  wordfence" in body (plugin-generated block page)
- **AWS WAF**: `x-amzn-requestid` / `x-amzn-trace-id` + "aws waf" in body;
  `x-amz-cf-id` + "the request could not be satisfied" (CloudFront error)
- **DDoS-Guard**: `server: ddos-guard`, `__ddg1_` / `__ddg2_` cookies
- **Barracuda**: any header starting with `x-barracuda`
- **F5 BIG-IP ASM**: `x-wa-info` header, `ts<hex>` cookies + "support id" body
- **Reblaze**: any header starting with `x-reblaze`
- **ModSecurity**: `mod_security` / `modsecurity` in Server header
- **Palo Alto**: any header starting with `x-pan-`
- **BunkerWeb**: `bunkerweb` in Server header
- **Fastly CDN**: `x-fastly-request-id` + "fastly error" in body

**Tier 2 — Generic block page phrases (lower confidence, last resort):**
Only triggered when no vendor-specific fingerprint matched. Phrases like
"your request has been blocked", "web application firewall", "you have been
blocked" appear across many vendors' generic templates. Risk of false positives
is low because legitimate WordPress pages don't contain these phrases.

**Why check `raw.headers.getlist('Set-Cookie')` instead of `response.cookies`?**
The `requests` library merges all `Set-Cookie` headers into a single `CookieJar`
by name. If two cookies have different names but the same prefix (`visid_incap_3269851`
and `visid_incap_8847312`), they are accessible individually. However, using
`.getlist('Set-Cookie')` on the raw urllib3 response object gives us the raw
header string including the full cookie name with the site ID suffix — which is
what we need for substring matching (`'visid_incap_' in set_cookie`).

**Tradeoff:** `_is_waf_interception()` is called for **every** 200 response in
bypass testing (up to ~30 bypass probes per 403 endpoint). The method does no
network I/O and only inspects already-loaded response data — CPU cost is
negligible. Memory: `response.text[:4000]` is always already buffered.

---

---

## 2026-03 — v0.4.0 (post-release): User enumeration — WAF diagnostic, fallback methods, RSS false positive fix

### Decision: WAF diagnostic verbosity in Method 1 (REST /wp-json/wp/v2/users)
**Why (bug fix + UX):** When the REST API returned a non-200 response, the
original code silently broke the loop with no indication of why. On sites
protected by a WAF (e.g. Incapsula/OpenResty), the operator had no way to
distinguish a WAF hard block from a WordPress restriction.

Added verbose diagnostic that distinguishes:
- No response at all (timeout/connection reset) → WAF hard block
- 401/403 with JSON body → WordPress restriction (`rest_user_cannot_view`)
- 401/403 with HTML body → WAF or proxy block (non-JSON = not WP)

**Tradeoff:** Diagnostic is printed only at `-v` (verbosity ≥ 1). Silent
in default mode to avoid noise on clean sites.

---

### Decision: REST fallback via `/?rest_route=` (Method 1b)
**Why:** Some WAFs apply path-based rules and block `/wp-json/` by URL prefix
while leaving `/?rest_route=` reachable (it is the pre-permalink-enabled
equivalent of the REST API path). This is a documented WAF misconfiguration.

Method 1b runs only when Method 1 failed (`_rest_ok = False`). It is
not a bypass of WP authentication — if WP itself restricts the endpoint,
the fallback also returns 401/403. It only helps when the WAF blocks by
URL pattern rather than by WordPress-level access control.

**Alternatives considered:**
| Option | Reason rejected |
|---|---|
| Always run both paths | Doubles requests on clean sites; Method 1 is authoritative when it works |
| Run 1b first | Method 1 is the canonical REST path; 1b is a fallback, not preferred |

---

### Decision: Method 7 (per-author RSS feed) — redirect-only slug extraction
**Why (bug fix):** Initial implementation extracted the username from
`<title>` of `/?feed=rss2&author=N` when no redirect occurred. WordPress
returns the main site feed (status 200, `<rss>` present) for non-existent
author IDs, making the title "Site Name" — which was being added as a
false username.

The only reliable signal is whether WordPress redirected the request to
`/author/<slug>/feed/`. If it did, `r.url` contains `/author/<slug>/` and
we extract the slug. If it didn't redirect, we skip — there is no safe
way to extract a username without risking a false positive.

**Accepted tradeoff:** Method 7 only fires on WP configurations that
redirect `/?feed=rss2&author=N` to the per-author feed URL. Configurations
that serve the per-author feed at the original URL without redirecting
are not covered. This is a minority case; Methods 1, 2, 3 handle those sites.

---

## 2026-03 — v0.4.0 (post-release): UI/output fixes

### Decision: Theme name shown inline in Phase 1 summary
**Why (bug fix):** Themes detected via HTML asset parsing were added to
`themes_from_html` and excluded from the probe loop. The probe loop prints
`+ slug v1.x` only for themes it discovers during probing. HTML-detected
themes never passed through the loop and therefore never appeared in output
beyond the bare count `N theme(s) detected`.

Fix: construct a comma-separated slug+version string from `themes_found`
and append it to the Phase 1 count line. Consistent with how plugin versions
are exposed during probing.

**Alternatives considered:**
| Option | Reason rejected |
|---|---|
| Print HTML-detected themes through the probe-loop print path | Loop is designed for probe results; mixing HTML detections would confuse progress display |
| Show names only at `-vv` | The count alone is useless without the name; the name should always be visible |

---

### Decision: Security header severity in Summary — HIGH for critical, LOW for optional
**Why (bug fix):** `check_security_headers` classifies each header as
`critical=True` (must-have: HSTS, X-Frame-Options, X-Content-Type-Options,
CSP) or `critical=False` (optional: Referrer-Policy, CORS headers, etc.).
Phase 3 output correctly reflects this with `[CRITICAL]` / `[OPTIONAL]`
labels. The Security Report Summary was hardcoding `'MEDIUM'` for all
missing critical headers and silently dropping missing optional ones.

Fix:
- `critical=True` + missing → `'HIGH'` in summary (not `'MEDIUM'`)
- `critical=False` + missing → `'LOW'` in summary (previously invisible)

`'HIGH'` is intentionally one level below `'CRITICAL'`: missing a security
header is a significant hardening gap but does not represent an immediately
exploitable vulnerability the way a CVSS 9+ CVE does.

**Tradeoff:** Optional headers now appear in the summary at `[LOW]`. This
increases the finding count. Accepted — the operator should be aware of
optional headers too, and `[LOW]` correctly signals their non-urgency.

---

## Future decision log template

```
## YYYY-MM — vX.Y.Z: <topic>

### Decision: <what was decided>
**Why:** <rationale and context>

**Alternatives considered:**
| Option | Reason rejected |
|---|---|
| Alternative A | Why it was dropped |
| Alternative B | Why it was dropped |

**Tradeoff:** <what was consciously accepted as a downside>
```
