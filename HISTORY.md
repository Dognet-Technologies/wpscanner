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
