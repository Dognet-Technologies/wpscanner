#!/usr/bin/env python3
"""
WENDY - WordPress ENDpoint discoverY v0.3.0
Dognet Technologies srl | info@dognet.tech
For authorized security testing only.

Usage: python endpoint_discovery.py <URL> [-v|-vv] [--aggressive]
"""

import json
import requests
import urllib.parse
import time
import random
import sys
import re
import datetime
import string
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
import warnings
warnings.filterwarnings('ignore')

# Load API keys and probe config — must happen before module-level constants below
try:
    from wendy.config import load_keys, load_probe_config
except ImportError:
    from config import load_keys, load_probe_config

load_keys()
_PROBE_CFG = load_probe_config()

# ─────────────────────────────────────────────────────────────────────────────
# ANSI COLOR HELPERS
# ─────────────────────────────────────────────────────────────────────────────

class C:
    """ANSI colors - auto-disabled when not a TTY"""
    _tty = sys.stdout.isatty()
    RED    = '\033[91m'  if _tty else ''
    GREEN  = '\033[92m'  if _tty else ''
    YELLOW = '\033[93m'  if _tty else ''
    BLUE   = '\033[94m'  if _tty else ''
    CYAN   = '\033[96m'  if _tty else ''
    BOLD   = '\033[1m'   if _tty else ''
    DIM    = '\033[2m'   if _tty else ''
    RESET  = '\033[0m'   if _tty else ''

def sev_color(severity):
    m = {'CRITICAL': C.RED+C.BOLD, 'HIGH': C.RED, 'MEDIUM': C.YELLOW, 'LOW': C.DIM, 'INFO': C.CYAN}
    return m.get(severity.upper(), '') + severity + C.RESET

# ─────────────────────────────────────────────────────────────────────────────
# EMBEDDED CVE DATABASE  (fallback when cve_db.json is absent)
# Format: { plugin_slug: [(max_vuln_version, cve_id, severity, cvss, desc)] }
# Only well-documented, publicly verified CVEs are included.
# Keep this as a minimal baseline; the live DB is populated by update_db.py.
# ─────────────────────────────────────────────────────────────────────────────

CVE_DATABASE = {
    'royal-elementor-addons': [
        ('1.3.78', 'CVE-2023-5360',  'CRITICAL', 10.0, 'Unauthenticated arbitrary file upload → RCE'),
    ],
    'wp-file-manager': [
        ('6.8',    'CVE-2020-25213', 'CRITICAL', 9.8,  'Unauthenticated RCE via elFinder API'),
    ],
    'duplicator': [
        ('1.3.26', 'CVE-2020-11738', 'HIGH',     7.5,  'Unauthenticated Path Traversal via installer.php'),
        ('1.4.6',  'CVE-2022-2551',  'HIGH',     7.5,  'Unauthenticated Path Traversal (installer bypass)'),
    ],
    'loginizer': [
        ('1.6.3',  'CVE-2020-27615', 'CRITICAL', 9.8,  'Unauthenticated SQL Injection on login page'),
    ],
    'wordfence': [
        ('5.2.3',  'CVE-2014-4664',  'MEDIUM',   5.3,  'WAF bypass via GET/POST parameter confusion'),
        ('7.9.1',  'CVE-2023-2499',  'HIGH',     8.8,  'Subscriber → Admin authentication bypass'),
    ],
    'wp01': [
        ('1.0.0',  'CVE-2025-30567', 'HIGH',     7.5,  'Unauthenticated Path Traversal → Arbitrary File Read'),
    ],
    'updraftplus': [
        ('1.22.3', 'CVE-2022-0633',  'MEDIUM',   6.5,  'Subscriber+ can download arbitrary backup files'),
        ('1.23.3', 'CVE-2023-32960', 'HIGH',     8.8,  'CSRF leading to Remote Code Execution'),
    ],
    'wp-fastest-cache': [
        ('1.2.1',  'CVE-2023-6063',  'CRITICAL', 9.8,  'Unauthenticated SQL Injection via cookie'),
    ],
    'litespeed-cache': [
        ('6.3.0.1','CVE-2024-28000', 'CRITICAL', 9.8,  'Unauthenticated Privilege Escalation via role simulation'),
        ('5.7',    'CVE-2023-40000', 'HIGH',     8.8,  'Stored XSS via plugin settings (admin+)'),
    ],
    'really-simple-ssl': [
        ('7.2.0',  'CVE-2023-5557',  'CRITICAL', 9.8,  'Two-Factor Authentication Bypass → Admin Account Takeover'),
    ],
    'advanced-custom-fields': [
        ('6.1.5',  'CVE-2023-30777', 'HIGH',     7.2,  'Admin+ Reflected XSS via field group name parameter'),
    ],
    'woocommerce-payments': [
        ('5.6.1',  'CVE-2023-28121', 'CRITICAL', 9.8,  'Unauthenticated Privilege Escalation to admin'),
    ],
    'ninja-forms': [
        ('3.6.10', 'CVE-2022-34867', 'CRITICAL', 9.8,  'Unauthenticated PHP Object Injection → RCE'),
    ],
    'contact-form-7': [
        ('5.3.1',  'CVE-2020-35489', 'CRITICAL', 9.8,  'Unrestricted file upload allows uploading PHP shells'),
        ('5.8.3',  'CVE-2023-6449',  'CRITICAL', 9.8,  'Unrestricted File Upload via uploaded file handling'),
    ],
    'revslider': [
        ('4.2',    'CVE-2014-9734',  'CRITICAL', 10.0, 'Arbitrary file upload + Local File Inclusion'),
    ],
    'w3-total-cache': [
        ('2.3.1',  'CVE-2023-40000', 'HIGH',     8.8,  'SSRF via New Relic API endpoint configuration'),
    ],
    'all-in-one-wp-migration': [
        ('7.66',   'CVE-2023-40004', 'HIGH',     8.8,  'Unauthenticated import → arbitrary PHP file write'),
    ],
    'the-events-calendar': [
        ('6.0.12', 'CVE-2023-32244', 'HIGH',     7.5,  'Unauthenticated SQL Injection via REST API endpoint'),
    ],
    'jetpack': [
        ('12.1.1', 'CVE-2023-2996',  'HIGH',     8.1,  'Contributor+ RCE via shortcode processing'),
    ],
    'elementor': [
        ('3.5.5',  'CVE-2022-1329',  'CRITICAL', 9.9,  'Contributor+ RCE via template import functionality'),
        ('3.12.1', 'CVE-2023-0329',  'CRITICAL', 9.8,  'Contributor+ arbitrary file upload → RCE'),
    ],
    'elementor-pro': [
        ('3.11.6', 'CVE-2023-0329',  'CRITICAL', 9.9,  'Unauthenticated Privilege Escalation to administrator'),
    ],
    'yoast-seo': [
        ('15.1.1', 'CVE-2021-25118', 'MEDIUM',   5.3,  'Unauthenticated information disclosure via REST API'),
    ],
    'wp-super-cache': [
        ('1.7.6',  'CVE-2021-24209', 'HIGH',     7.2,  'Admin RCE via malicious cache file injection'),
    ],
    'gravityforms': [
        ('2.7.3',  'CVE-2023-28782', 'HIGH',     8.8,  'PHP Object Injection via entry export feature'),
    ],
    'complianz-gdpr': [
        ('6.4.5',  'CVE-2023-3342',  'HIGH',     8.8,  'SQL Injection via cookie consent categories'),
    ],
    'wp-statistics': [
        ('13.2.8', 'CVE-2022-25148', 'HIGH',     8.8,  'SQL Injection via current_page_type parameter'),
    ],
    'broken-link-checker': [
        ('2.1.3',  'CVE-2023-4720',  'MEDIUM',   6.4,  'Stored XSS via checked link display in dashboard'),
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
# PROBE CONFIGURATION  (read from wendy/.keys / env, see .keys.example)
# ─────────────────────────────────────────────────────────────────────────────

NORMAL_MODE_PROBE_LIMIT  = _PROBE_CFG['probe_normal_limit']
NORMAL_MODE_THEME_LIMIT  = _PROBE_CFG['probe_theme_limit']
RECENT_CVE_YEARS         = _PROBE_CFG['cve_years']
MIN_ACTIVE_INSTALLS      = _PROBE_CFG['min_active_installs']

# ─────────────────────────────────────────────────────────────────────────────
# LIVE CVE DATABASE LOADER
# Loads wendy/cve_db.json (produced by update_db.py) and merges it with the
# embedded CVE_DATABASE above.  The JSON file is gitignored and generated
# locally; if absent the embedded DB is used as-is (works offline / first run).
# ─────────────────────────────────────────────────────────────────────────────

def _load_cve_db():
    """
    Load and merge plugin/theme CVE databases, installs index, and popular
    theme list from cve_db.json.

    Returns (db_plugins, db_themes, installs_index, popular_themes).
      db_plugins     – merged embedded CVE_DATABASE + JSON plugin entries
      db_themes      – theme CVE entries from JSON  (no embedded fallback)
      installs_index – {slug: active_installs} from WordPress.org (may be empty)
      popular_themes – [slug, ...] ordered by active_installs
    Falls back to (CVE_DATABASE, {}, {}, []) when the file is absent/corrupt.
    """
    json_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cve_db.json')
    if not os.path.exists(json_path):
        return CVE_DATABASE, {}, {}, []

    try:
        with open(json_path, encoding='utf-8') as fh:
            raw = json.load(fh)
    except Exception:
        return CVE_DATABASE, {}, {}, []

    meta           = raw.pop('_meta',   {})
    db_themes_raw  = raw.pop('_themes', {})
    installs_index = meta.get('installs_index', {})
    popular_themes = meta.get('popular_themes',  [])

    # Build plugin DB: embedded entries take priority
    db = {slug: list(entries) for slug, entries in CVE_DATABASE.items()}
    for slug, json_entries in raw.items():
        existing   = db.get(slug, [])
        known_cves = {e[1] for e in existing if e[1]}
        for entry in json_entries:
            if not isinstance(entry, list) or len(entry) < 5:
                continue
            cve_id = entry[1]
            if cve_id and cve_id in known_cves:
                continue
            known_cves.add(cve_id)
            db.setdefault(slug, []).append(tuple(entry))

    # Build theme DB
    db_themes = {
        slug: [tuple(e) for e in entries if isinstance(e, list) and len(e) >= 5]
        for slug, entries in db_themes_raw.items()
    }

    return db, db_themes, installs_index, popular_themes


EFFECTIVE_CVE_DB, EFFECTIVE_THEME_CVE_DB, INSTALLS_INDEX, POPULAR_THEMES = _load_cve_db()


# ─────────────────────────────────────────────────────────────────────────────
# INSTALLS SCORING  (graduated, mirrors WP.org active_installs bands)
# ─────────────────────────────────────────────────────────────────────────────

def _installs_score(n):
    """Return a popularity score (0–10) from a WordPress.org active_installs count."""
    if   n >= 1_000_000: return 10
    elif n >= 500_000:   return 9
    elif n >= 100_000:   return 7
    elif n >= 50_000:    return 6
    elif n >= 10_000:    return 5
    elif n >= 1_000:     return 3
    elif n >= 100:       return 1
    else:                return 0


# Pre-build a frozenset of CVE IDs whose year falls in RECENT_CVE_YEARS.
# Used in the scoring hot-loop to replace per-entry regex with an O(1) lookup.
_CVE_YEAR_RE  = re.compile(r'CVE-(\d{4})-')
RECENT_CVE_IDS: frozenset = frozenset(
    cve_id
    for entries in EFFECTIVE_CVE_DB.values()
    for entry   in entries
    for cve_id  in (entry[1] if len(entry) > 1 else '',)
    if  cve_id
    for m        in (_CVE_YEAR_RE.match(cve_id),)
    if  m and int(m.group(1)) in RECENT_CVE_YEARS
)


# ─────────────────────────────────────────────────────────────────────────────
# PRIORITY PROBE LIST BUILDER
# ─────────────────────────────────────────────────────────────────────────────

def _build_priority_probe_list(exclude_set, limit=None, min_installs=0):
    """Score and sort all CVE-DB plugin slugs for smart probing.

    Score per slug (cumulative across all its CVEs):
      0–10  _installs_score(n)  – graduated WordPress.org active_installs bands
      +3    per CVE in RECENT_CVE_IDS  (year in RECENT_CVE_YEARS)
      +2    per CRITICAL CVE
      +1    per HIGH CVE

    Filtering:
      If min_installs > 0 a slug is excluded UNLESS it has a recent CRITICAL CVE
      (those are always included regardless of install count — security priority).

    Returns slugs sorted by score descending, capped at `limit` (None = all).
    """
    scored = []

    for slug, entries in EFFECTIVE_CVE_DB.items():
        if slug in exclude_set:
            continue

        installs        = INSTALLS_INDEX.get(slug, 0)   # single lookup reused below
        score           = _installs_score(installs)
        has_recent_crit = False

        for entry in entries:
            cve_id   = entry[1] if len(entry) > 1 else ''
            severity = (entry[2] if len(entry) > 2 else '').upper()

            is_recent = cve_id in RECENT_CVE_IDS        # O(1) set lookup
            if is_recent:
                score += 3
                if severity == 'CRITICAL':
                    has_recent_crit = True

            if severity == 'CRITICAL':
                score += 2
            elif severity == 'HIGH':
                score += 1

        # Skip low-installs slugs in filtered mode unless they carry a
        # recent CRITICAL CVE (those are always probed — security priority).
        if min_installs > 0 and installs < min_installs and not has_recent_crit:
            continue

        scored.append((score, slug))

    scored.sort(key=lambda x: x[0], reverse=True)
    result = [slug for _, slug in scored]
    return result[:limit] if limit is not None else result

# ─────────────────────────────────────────────────────────────────────────────
# MAIN CLASS
# ─────────────────────────────────────────────────────────────────────────────

class EndpointDiscovery:

    def __init__(self, verbosity=0, aggressive=False):
        self.verbosity  = verbosity   # 0=normal, 1=-v, 2=-vv
        self.aggressive = aggressive  # expanded coverage
        self.valid_403s = True

        self.session = requests.Session()
        retry_strategy = Retry(
            total=3, backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://",  adapter)
        self.session.mount("https://", adapter)

        self.user_agents = [
            # Chrome – Windows
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
            # Chrome – macOS
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            # Chrome – Linux
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            # Firefox
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0',
            # Safari
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
            # Mobile
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
            # Edge
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0',
            # Crawlers (for detection evasion testing)
            'Googlebot/2.1 (+http://www.google.com/bot.html)',
            'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
            'Mozilla/5.0 (compatible; DuckDuckBot/1.0; +http://duckduckgo.com/duckduckbot.html)',
        ]

        self.bypass_headers_list = [
            # IP spoofing headers
            'X-Forwarded-For', 'X-Forwarded-Host', 'X-Remote-IP', 'X-Remote-Addr',
            'X-Client-IP', 'X-Real-IP', 'X-Originating-IP', 'X-Custom-IP-Authorization',
            # CDN / proxy headers
            'CF-Connecting-IP', 'True-Client-IP', 'X-Cluster-Client-IP',
            'X-Sucuri-Clientip', 'X-Akamai-Forwarded-For',
            'X-Azure-ClientIP', 'X-ProxyUser-Ip',
            # Misc bypass headers
            'X-Forwarded-Server', 'X-HTTP-Host-Override',
            'X-Original-Remote-Addr', 'X-Backend-Host',
        ]

        self.endpoint_categories = {
            'backup_files':       self.get_backup_endpoints,
            'config_files':       self.get_config_endpoints,
            'log_files':          self.get_log_endpoints,
            'directory_listings': self.get_directory_endpoints,
            'ajax_endpoints':     self.get_ajax_endpoints,
            'api_endpoints':      self.get_api_endpoints,
            'cache_files':        self.get_cache_endpoints,
            'debug_files':        self.get_debug_endpoints,
            'plugin_specific':    self.get_plugin_specific_endpoints,
            'sensitive_files':    self.get_sensitive_files_endpoints,
        }

    # ── UTILITIES ─────────────────────────────────────────────────────────────

    def vprint(self, msg, level=1):
        """Print only when verbosity >= level."""
        if self.verbosity >= level:
            print(msg)

    def _parse_ver(self, v):
        try:
            return tuple(int(x) for x in re.split(r'[.\-]', str(v).strip()) if x.isdigit())
        except Exception:
            return (0,)

    def _is_vulnerable(self, detected_ver, max_vuln_ver):
        d = self._parse_ver(detected_ver)
        m = self._parse_ver(max_vuln_ver)
        length = max(len(d), len(m))
        d = d + (0,) * (length - len(d))
        m = m + (0,) * (length - len(m))
        return d <= m

    def get_random_headers(self):
        headers = {
            'User-Agent':              random.choice(self.user_agents),
            'Accept':                  'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language':         'en-US,en;q=0.9',
            'Accept-Encoding':         'gzip, deflate, br',
            'Connection':              'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control':           'max-age=0',
        }
        bypass_header = random.choice(self.bypass_headers_list)
        random_ip = '.'.join(str(random.randint(1, 254)) for _ in range(4))
        headers[bypass_header] = random_ip
        return headers

    def generate_curl_command(self, url, method='GET', bypass_headers=None):
        cmd = f"curl -i -X {method} '{url}'"
        if bypass_headers:
            for k, v in bypass_headers.items():
                v_esc = str(v).replace("'", "'\\''")
                cmd += f" -H '{k}: {v_esc}'"
        return cmd

    def generate_download_command(self, url):
        return f"curl -i -O '{url}'"

    def _section(self, n, total, title):
        print(f"\n{C.BOLD}[{n}/{total}] {title.upper()}{C.RESET}")
        print("─" * 60)

    def _safe_get(self, url, timeout=10, **kwargs):
        try:
            return self.session.get(url, headers=self.get_random_headers(),
                                    timeout=timeout, verify=False,
                                    allow_redirects=True, **kwargs)
        except Exception:
            return None

    # ── FINGERPRINTING ────────────────────────────────────────────────────────

    def detect_wp_version(self, base_url):
        """
        Try to detect WordPress version from multiple sources.
        Returns (version_string, source) or (None, None).
        """
        sources = [
            # (path, regex_pattern)
            ('/',                     r'<meta[^>]+generator[^>]+WordPress\s+([\d.]+)'),
            ('/feed/',                r'<generator>[^<]*wordpress[^<]*/v=([\d.]+)</generator>'),
            # wp-login.php loads core assets with ver=X.X.X — match wp-includes URLs only
            ('/wp-login.php',         r'wp-includes/[^"]+[?&]ver=([\d.]+)'),
            ('/readme.html',          r'[Vv]ersion\s+(\d+\.\d+[\.\d]*)'),
            ('/wp-includes/version.php', r"\$wp_version\s*=\s*'([\d.]+)'"),
            # REST API index exposes "version" on some WP builds
            ('/wp-json/',             r'"version"\s*:\s*"([\d.]+)"'),
        ]
        if self.aggressive:
            sources += [
                ('/sitemap.xml',                         r'WordPress\s+([\d.]+)'),
                ('/wp-sitemap.xml',                      r'WordPress\s+([\d.]+)'),
                ('/wp-includes/css/dashicons.min.css',   r'[?&]ver=([\d.]+)'),
                ('/wp-admin/load-scripts.php',           r'[?&]ver=([\d.]+)'),
                ('/?p=1',                                r'<meta[^>]+generator[^>]+WordPress\s+([\d.]+)'),
                ('/wp-trackback.php',                    r'WordPress/([\d.]+)'),
                ('/wp-links-opml.php',                   r'generator="WordPress/([\d.]+)"'),
                ('/wp-app.php',                          r'WordPress/([\d.]+)'),
            ]

        for path, pattern in sources:
            r = self._safe_get(base_url.rstrip('/') + path)
            if r and r.status_code == 200:
                m = re.search(pattern, r.text, re.IGNORECASE)
                if m:
                    return m.group(1), path
            time.sleep(random.uniform(0.3, 0.8))
        return None, None

    def _get_plugin_version(self, base_url, slug):
        """
        Try to read version from plugin readme.txt or main plugin file.
        Returns version string or None.
        """
        readme_url = f"{base_url.rstrip('/')}/wp-content/plugins/{slug}/readme.txt"
        r = self._safe_get(readme_url, timeout=8)
        if r and r.status_code == 200 and 'text/html' not in r.headers.get('Content-Type',''):
            m = re.search(r'[Ss]table\s+tag:\s*([\d.]+)', r.text)
            if m:
                return m.group(1)
            m = re.search(r'[Vv]ersion:\s*([\d.]+)', r.text)
            if m:
                return m.group(1)

        # Try main plugin PHP header
        php_url = f"{base_url.rstrip('/')}/wp-content/plugins/{slug}/{slug}.php"
        r2 = self._safe_get(php_url, timeout=8)
        if r2 and r2.status_code == 200:
            m = re.search(r'Version:\s*([\d.]+)', r2.text)
            if m:
                return m.group(1)
        return None

    def enumerate_plugins_themes(self, base_url):
        """
        Detect installed plugins and themes.
        Strategy:
          1. Parse homepage HTML for /wp-content/plugins|themes/{slug}/ references
             (catches any plugin that loads frontend assets — very reliable)
          2. Probe a curated hardcoded list via readme.txt (catches backend-only
             plugins that load no frontend assets)
        Returns dict: {slug: version_or_None}
        """
        # ── STEP 1: HTML source discovery ─────────────────────────────────────
        print(f"    Parsing page source for asset references...", end=' ', flush=True)
        html_plugins: dict = {}
        html_themes:  dict = {}
        for path in ['/', '/?p=1', '/feed/']:
            r = self._safe_get(base_url.rstrip('/') + path, timeout=10)
            if not r or r.status_code != 200:
                continue
            for m in re.finditer(
                r'/wp-content/plugins/([a-z0-9_-]+)/', r.text, re.IGNORECASE
            ):
                slug = m.group(1).lower()
                if slug not in html_plugins:
                    html_plugins[slug] = None
            for m in re.finditer(
                r'/wp-content/themes/([a-z0-9_-]+)/', r.text, re.IGNORECASE
            ):
                slug = m.group(1).lower()
                if slug not in html_themes:
                    html_themes[slug] = None

        # Fetch versions for HTML-discovered plugins
        for slug in list(html_plugins.keys()):
            html_plugins[slug] = self._get_plugin_version(base_url, slug)
        print(f"found {len(html_plugins)} plugin(s), {len(html_themes)} theme(s)", flush=True)

        # ── STEP 2: Probe CVE-DB slugs — priority-scored ──────────────────────
        # Slugs are scored by:
        #   graduated active_installs (0–10) + recent CVE year (+3) + severity (+1/+2)
        # MIN_ACTIVE_INSTALLS filter: skip low-installs slugs in normal mode
        #   UNLESS they carry a recent CRITICAL CVE (always probed).
        # Normal mode:    top NORMAL_MODE_PROBE_LIMIT  + min_installs filter
        # Aggressive mode: all slugs, min_installs ignored (full coverage)
        exclude = set(html_plugins)
        if self.aggressive:
            probe_slugs = _build_priority_probe_list(
                exclude_set=exclude, min_installs=0
            )
        else:
            probe_slugs = _build_priority_probe_list(
                exclude_set=exclude,
                limit=NORMAL_MODE_PROBE_LIMIT,
                min_installs=MIN_ACTIVE_INSTALLS,
            )

        # Start with HTML-discovered plugins/themes as confirmed
        found = dict(html_plugins)
        themes_from_html = dict(html_themes)
        workers = 10 if self.aggressive else 5
        import uuid

        # Establish baseline: probe a random non-existent plugin to detect
        # servers that return 403 globally (global deny rules).
        _canary = f"_canary-{uuid.uuid4().hex[:12]}"
        print(f"    Detecting server baseline...", end=' ', flush=True)
        _canary_url = f"{base_url.rstrip('/')}/wp-content/plugins/{_canary}/readme.txt"
        _canary_r = self._safe_get(_canary_url, timeout=5)
        _baseline_status = _canary_r.status_code if _canary_r else 404
        print(f"done (baseline={_baseline_status})", flush=True)

        def _extract_version_from_readme(text):
            m = re.search(r'[Ss]table\s+tag:\s*([\d.]+)', text)
            if m:
                return m.group(1)
            m = re.search(r'[Vv]ersion:\s*([\d.]+)', text)
            if m:
                return m.group(1)
            return None

        def check_plugin(slug):
            # Use readme.txt as probe: present in every plugin, 200 only if installed.
            # Reuse the response to extract version (avoid double fetch).
            readme_url = f"{base_url.rstrip('/')}/wp-content/plugins/{slug}/readme.txt"
            r = self._safe_get(readme_url, timeout=6)
            if r and r.status_code == 200:
                content_type = r.headers.get('Content-Type', '')
                if 'text/html' not in content_type:
                    # Actual text file → plugin confirmed
                    ver = _extract_version_from_readme(r.text)
                    return slug, ver
                elif _baseline_status == 200:
                    # Soft-404 server: HTML readme.txt = page doesn't exist
                    return None, None
                else:
                    # Non-soft-404 server with HTML readme: unusual but possible,
                    # fall through to _get_plugin_version for further confirmation
                    ver = self._get_plugin_version(base_url, slug)
                    return slug, ver
            elif r and r.status_code != _baseline_status:
                # Status differs from baseline → real response (e.g. 403 while baseline=404)
                dir_url = f"{base_url.rstrip('/')}/wp-content/plugins/{slug}/"
                r2 = self._safe_get(dir_url, timeout=6)
                if r2 and r2.status_code == 200:
                    ver = self._get_plugin_version(base_url, slug)
                    return slug, ver
            return None, None

        total = len(probe_slugs)
        done  = 0
        if total > 0:
            db_total = len(EFFECTIVE_CVE_DB)
            if self.aggressive:
                mode_label = f"aggressive — all {total:,}/{db_total:,} slugs"
            else:
                in_index   = sum(1 for s in probe_slugs if s in INSTALLS_INDEX)
                filter_str = (f", min_installs≥{MIN_ACTIVE_INSTALLS:,}"
                              if MIN_ACTIVE_INSTALLS > 0 else "")
                mode_label = (f"normal — {total:,}/{db_total:,} priority-scored"
                              f" ({in_index:,} with installs data{filter_str})")
            self.vprint(f"    Probe mode: {mode_label}", level=1)
            print(f"    Probing [{done:{len(str(total))}}/{total}]", end='', flush=True)
            with ThreadPoolExecutor(max_workers=workers) as ex:
                futures = {ex.submit(check_plugin, s): s for s in probe_slugs}
                for fut in as_completed(futures):
                    done += 1
                    slug, ver = fut.result()
                    if slug:
                        found[slug] = ver
                        print(f"\r    Probing [{done:{len(str(total))}}/{total}]  + {slug}"
                              f"{'  v'+ver if ver else ''}", flush=True)
                    else:
                        print(f"\r    Probing [{done:{len(str(total))}}/{total}]", end='', flush=True)
            print(flush=True)

        # ── Theme detection ─────────────────────────────────────────────────
        # Priority: (1) theme CVE slugs from Wordfence, (2) popular from WP.org,
        # (3) hardcoded baseline fallback (always included as safety net).
        _baseline_themes = [
            # Default WP themes
            'twentytwentyfive','twentytwentyfour','twentytwentythree','twentytwentytwo',
            'twentytwentyone','twentytwenty','twentynineteen','twentyeighteen',
            'twentyseventeen','twentysixteen','twentyfifteen','twentyfourteen',
            'twentythirteen','twentytwelve','twentyeleven','twentyten',
            # Top commercial
            'divi','avada','flatsome','enfold','bridge','salient','betheme',
            'jupiter','woodmart','porto','electro','thrive-themes','newspaper',
            'jnews','soledad','newsmag','publisher','magazine-pro',
            # Top free/freemium
            'astra','hello-elementor','neve','generatepress','blocksy','kadence',
            'storefront','oceanwp','hestia','zakra','colibri-wp','botiga',
            'sydney','hueman','virtue','spacious','zerif-lite','layers',
            'customify','primer','gridlove','accesspress-basic','catch-base',
            # Page-builder specific
            'bricks','phlox','largo','llorix-one','allegiant',
            # WooCommerce-focused
            'shoptimizer','genesis','child-of-light',
        ]
        _theme_cve_slugs = list(EFFECTIVE_THEME_CVE_DB.keys())
        _theme_cve_set   = set(_theme_cve_slugs)
        _theme_popular   = [s for s in POPULAR_THEMES if s not in _theme_cve_set]
        _theme_pop_set   = set(_theme_popular)
        _theme_baseline  = [s for s in _baseline_themes
                            if s not in _theme_cve_set and s not in _theme_pop_set]

        if self.aggressive:
            theme_probe = _theme_cve_slugs + _theme_popular + _theme_baseline + [
                'divi-child','avada-child','newspaper-child','brooklyn','kalium',
                'impreza','the7','total','uncode','x','supreme','district',
                'movedo','sugar','stockholm','monstroid2','ivy','smart',
            ]
        else:
            # Fill up to NORMAL_MODE_THEME_LIMIT with CVE themes then popular themes,
            # then always append baseline fallbacks (they're few and always relevant).
            _priority   = _theme_cve_slugs + [s for s in _theme_popular
                                               if s not in _theme_cve_set]
            _capped     = _priority[:NORMAL_MODE_THEME_LIMIT]
            _capped_set = set(_capped)
            theme_probe = _capped + [s for s in _theme_baseline if s not in _capped_set]

        # Exclude already-found themes and deduplicate (preserving priority order)
        theme_probe = list(dict.fromkeys(s for s in theme_probe if s not in themes_from_html))

        # Baseline for themes
        _canary_theme_url = f"{base_url.rstrip('/')}/wp-content/themes/{_canary}/style.css"
        _canary_theme_r = self._safe_get(_canary_theme_url, timeout=5)
        _baseline_theme_status = _canary_theme_r.status_code if _canary_theme_r else 404

        themes_found = dict(themes_from_html)
        theme_total = len(theme_probe)
        if theme_total > 0:
            print(f"    Themes  [  0/{theme_total}]", end='', flush=True)
            for i, slug in enumerate(theme_probe, 1):
                style_url = f"{base_url.rstrip('/')}/wp-content/themes/{slug}/style.css"
                r = self._safe_get(style_url, timeout=5)
                if r and r.status_code == 200:
                    content_type = r.headers.get('Content-Type', '')
                    if 'text/html' not in content_type:
                        themes_found[slug] = None
                        print(f"\r    Themes  [{i:3}/{theme_total}]  + {slug}", flush=True)
                        continue
                    elif _baseline_theme_status != 200:
                        themes_found[slug] = None
                        print(f"\r    Themes  [{i:3}/{theme_total}]  + {slug}", flush=True)
                        continue
                print(f"\r    Themes  [{i:3}/{theme_total}]", end='', flush=True)
            print(flush=True)

        return found, themes_found

    # ── CVE ANALYSIS ──────────────────────────────────────────────────────────

    def check_cve_vulnerabilities(self, plugins_found):
        """
        Match detected plugins/versions against CVE_DATABASE.
        Returns list of finding dicts.
        """
        findings = []
        for slug, version in plugins_found.items():
            if slug not in EFFECTIVE_CVE_DB:
                continue
            for (max_vuln, cve_id, severity, cvss, desc) in EFFECTIVE_CVE_DB[slug]:
                if version is None:
                    # Version unknown - report as possible
                    findings.append({
                        'slug': slug, 'version': '?', 'cve': cve_id,
                        'severity': severity, 'cvss': cvss,
                        'desc': desc, 'certain': False,
                    })
                elif self._is_vulnerable(version, max_vuln):
                    findings.append({
                        'slug': slug, 'version': version, 'cve': cve_id,
                        'severity': severity, 'cvss': cvss,
                        'desc': desc, 'certain': True,
                    })
        # Sort by CVSS descending
        findings.sort(key=lambda x: x['cvss'], reverse=True)
        return findings

    def _cvss_score_to_severity(self, score):
        """Map a numeric CVSS score to a severity label."""
        try:
            s = float(score)
        except (TypeError, ValueError):
            return 'MEDIUM'
        if s >= 9.0:
            return 'CRITICAL'
        if s >= 7.0:
            return 'HIGH'
        if s >= 4.0:
            return 'MEDIUM'
        if s > 0.0:
            return 'LOW'
        return 'INFO'

    def _query_wpscan_api(self, slug, slug_type='plugin'):
        """
        Query WPScan API (https://wpscan.com/api/v3/) for a plugin/theme.
        Requires WPSCAN_API_TOKEN env var (free plan: 25 req/day).
        Returns the inner plugin/theme dict, or None on failure.

        Response structure:
          { "<slug>": { "friendly_name": "...", "vulnerabilities": [...] } }
        """
        token = os.environ.get('WPSCAN_API_TOKEN', '')
        if not token:
            return None
        try:
            url = f"https://wpscan.com/api/v3/{slug_type}s/{slug}"
            r = requests.get(url, headers={'Authorization': f'Token token={token}'},
                             timeout=15, verify=True)
            if r.status_code == 200:
                data = r.json()
                # Top-level key is the slug itself
                return data.get(slug)
            if r.status_code == 404:
                return None   # Plugin not in WPScan DB
            if r.status_code == 401:
                self.vprint(f"  {C.YELLOW}⚠ WPScan API: invalid token{C.RESET}", level=0)
            elif r.status_code == 429:
                self.vprint(f"  {C.YELLOW}⚠ WPScan API: rate limit reached (25 req/day on free plan){C.RESET}", level=0)
        except Exception:
            pass
        return None

    # ── SECURITY HEADERS ──────────────────────────────────────────────────────

    def check_security_headers(self, base_url):
        """
        Check HTTP security headers on the main page.
        Returns list of (header, status, value, risk_desc).
        """
        headers_spec = [
            ('Strict-Transport-Security',       True,  'HSTS missing - susceptible to protocol downgrade and MITM'),
            ('X-Frame-Options',                 True,  'Clickjacking protection absent'),
            ('X-Content-Type-Options',          True,  'MIME-type sniffing possible'),
            ('Content-Security-Policy',         True,  'No CSP - XSS mitigation severely weakened'),
            ('Referrer-Policy',                 False, 'Referrer information may leak to third parties'),
            ('Permissions-Policy',              False, 'Browser feature access unrestricted'),
            ('X-XSS-Protection',                False, 'Legacy header (deprecated but still informative)'),
            ('Cross-Origin-Opener-Policy',      False, 'Cross-origin window access unrestricted'),
            ('Cross-Origin-Embedder-Policy',    False, 'Cross-origin embedding unrestricted'),
            ('Cross-Origin-Resource-Policy',    False, 'Cross-origin resource sharing unrestricted'),
            ('Cache-Control',                   False, 'Response caching policy not set'),
            ('X-Permitted-Cross-Domain-Policies', False, 'Cross-domain policy not restricted (Flash/PDF)'),
        ]
        r = self._safe_get(base_url)
        if not r:
            return []
        results = []
        for (hdr, critical, risk) in headers_spec:
            val = r.headers.get(hdr)
            results.append({'header': hdr, 'present': bool(val),
                             'value': val, 'critical': critical, 'risk': risk})
        return results

    # ── USER ENUMERATION ──────────────────────────────────────────────────────

    def enumerate_users(self, base_url):
        """
        Attempt WordPress user enumeration via multiple methods.
        Returns list of discovered usernames.
        """
        users = {}   # id -> username

        # Method 1: REST API /wp-json/wp/v2/users
        r = self._safe_get(f"{base_url.rstrip('/')}/wp-json/wp/v2/users?per_page=100")
        if r and r.status_code == 200:
            try:
                data = r.json()
                if isinstance(data, list):
                    for u in data:
                        uid  = u.get('id', '?')
                        name = u.get('slug') or u.get('name') or u.get('link', '')
                        if name:
                            users[uid] = {'username': name, 'method': 'REST API', 'extra': u.get('name','')}
            except Exception:
                pass

        # Method 2: Author archives redirect /?author=N
        max_id = 20 if self.aggressive else 5
        for i in range(1, max_id + 1):
            url = f"{base_url.rstrip('/')}/?author={i}"
            try:
                r2 = self.session.get(url, headers=self.get_random_headers(),
                                      timeout=8, verify=False, allow_redirects=True)
                if r2 and r2.status_code == 200:
                    # Check for redirect to /author/<slug>/ in the final URL
                    redirected = r2.url.rstrip('/') != url.rstrip('/')
                    m = re.search(r'/author/([^/?#]+)', r2.url)
                    if m:
                        uname = m.group(1)
                        if i not in users:
                            users[i] = {'username': uname, 'method': 'Author archive', 'extra': ''}
                    elif redirected:
                        # Redirect happened but not to /author/ path - try page title
                        # (only when redirect occurred, to avoid capturing the site homepage title)
                        m2 = re.search(r'<title[^>]*>([^<]+)</title>', r2.text, re.IGNORECASE)
                        if m2 and i not in users:
                            title = m2.group(1).strip()
                            users[i] = {'username': title, 'method': 'Author page title', 'extra': ''}
            except Exception:
                pass
            time.sleep(random.uniform(0.3, 0.8))

        # Method 3: Feed author tags
        r3 = self._safe_get(f"{base_url.rstrip('/')}/feed/")
        if r3 and r3.status_code == 200:
            feed_authors = re.findall(r'<dc:creator[^>]*><!\[CDATA\[([^\]]+)\]\]></dc:creator>', r3.text)
            feed_authors += re.findall(r'<author><name>([^<]+)</name>', r3.text)
            for a in set(feed_authors):
                key = f'feed_{a}'
                if a not in [v['username'] for v in users.values()]:
                    users[key] = {'username': a, 'method': 'RSS Feed', 'extra': ''}

        # Method 4: Login page error differentiation (common usernames only in aggressive)
        if self.aggressive:
            test_users = [
                'admin', 'administrator', 'webmaster', 'editor', 'user', 'test',
                'wordpress', 'support', 'manager', 'author', 'demo', 'guest',
                'operator', 'info', 'contact', 'wp', 'service', 'backup',
                'dev', 'staging', 'root', 'superadmin', 'sysadmin',
            ]
            login_url  = f"{base_url.rstrip('/')}/wp-login.php"
            for uname in test_users:
                try:
                    r4 = self.session.post(
                        login_url,
                        data={'log': uname, 'pwd': 'wrong_password_WENDY_test_x9k2',
                              'wp-submit': 'Log+In', 'redirect_to': '/wp-admin/',
                              'testcookie': '1'},
                        headers={**self.get_random_headers(), 'Content-Type': 'application/x-www-form-urlencoded'},
                        timeout=10, verify=False, allow_redirects=True
                    )
                    if r4:
                        body = r4.text.lower()
                        # WP says "The password you entered for the username X is incorrect" when user exists
                        # vs "Invalid username" when user doesn't exist
                        if 'the password you entered' in body or 'incorrect password' in body:
                            if uname not in [v['username'] for v in users.values()]:
                                users[f'login_{uname}'] = {'username': uname,
                                                           'method': 'Login error differential', 'extra': ''}
                except Exception:
                    pass
                time.sleep(random.uniform(1.0, 2.0))

        return list(users.values())

    # ── XML-RPC ───────────────────────────────────────────────────────────────

    def test_xmlrpc(self, base_url):
        """
        Test XML-RPC endpoint for:
        - Accessibility
        - Exposed methods
        - Pingback (DDoS amplification)
        - Multicall (brute-force amplification)
        Returns list of finding dicts.
        """
        findings = []
        xmlrpc_url = f"{base_url.rstrip('/')}/xmlrpc.php"

        # Check if accessible
        r = self._safe_get(xmlrpc_url)
        if not r or r.status_code not in (200, 405):
            return findings   # Not accessible

        findings.append({'type': 'exposed', 'severity': 'MEDIUM',
                          'desc': 'xmlrpc.php is accessible (attack surface)',
                          'url': xmlrpc_url})

        # Probe system.listMethods
        payload_list = ('<?xml version="1.0" encoding="UTF-8"?>'
                         '<methodCall><methodName>system.listMethods</methodName>'
                         '<params/></methodCall>')
        try:
            r2 = self.session.post(xmlrpc_url, data=payload_list,
                                   headers={**self.get_random_headers(),
                                            'Content-Type': 'text/xml'},
                                   timeout=10, verify=False)
            if r2.status_code == 200 and 'methodResponse' in r2.text:
                methods_found = re.findall(r'<string>([^<]+)</string>', r2.text)
                has_pingback  = 'pingback.ping'   in methods_found
                has_multi     = 'system.multicall' in methods_found
                has_getUsersBlogs = 'wp.getUsersBlogs' in methods_found

                findings.append({'type': 'methods_exposed', 'severity': 'MEDIUM',
                                  'desc': f'system.listMethods returned {len(methods_found)} methods',
                                  'methods': methods_found[:10], 'url': xmlrpc_url})

                if has_pingback:
                    findings.append({'type': 'pingback', 'severity': 'HIGH',
                                      'desc': 'pingback.ping enabled → DDoS amplification / SSRF risk',
                                      'url': xmlrpc_url})
                if has_multi:
                    findings.append({'type': 'multicall', 'severity': 'HIGH',
                                      'desc': 'system.multicall enabled → brute-force amplification (1000 logins/req)',
                                      'url': xmlrpc_url})
                if has_getUsersBlogs:
                    findings.append({'type': 'getUsersBlogs', 'severity': 'MEDIUM',
                                      'desc': 'wp.getUsersBlogs enabled → username enumeration via brute force',
                                      'url': xmlrpc_url})
        except Exception:
            pass

        return findings

    # ── HARDENING CHECKS ──────────────────────────────────────────────────────

    def check_hardening(self, base_url):
        """
        Check common WordPress hardening issues.
        Returns list of finding dicts.
        """
        findings = []

        checks = [
            # (path, check_fn, severity, title, desc)
            ('/readme.html',
             lambda r: r.status_code == 200,
             'MEDIUM', 'readme.html exposed', 'WordPress version disclosed via readme.html'),
            ('/license.txt',
             lambda r: r.status_code == 200 and 'wordpress' in r.text.lower(),
             'INFO', 'license.txt exposed', 'WordPress license.txt discloses CMS identity'),
            # wp-cron: 200 with empty body is normal WP behaviour (cron fired with no output)
            ('/wp-cron.php',
             lambda r: r.status_code == 200 and len(r.text.strip()) > 0,
             'MEDIUM', 'wp-cron.php public', 'wp-cron.php accessible anonymously - DoS/amplification risk'),
            # install.php: only a real risk when WP is NOT already installed
            ('/wp-admin/install.php',
             lambda r: r.status_code == 200 and 'already installed' not in r.text.lower(),
             'HIGH', 'install.php accessible', 'WordPress install script accessible - may allow site reset'),
            # upgrade.php: only a risk when an actual upgrade is needed
            ('/wp-admin/upgrade.php',
             lambda r: r.status_code == 200 and 'no update' not in r.text.lower()
                       and 'già aggiornato' not in r.text.lower()
                       and 'already up to date' not in r.text.lower(),
             'MEDIUM', 'upgrade.php accessible', 'Database upgrade script publicly reachable'),
            ('/wp-content/debug.log',
             lambda r: r.status_code == 200 and len(r.text) > 10,
             'HIGH', 'debug.log exposed', 'WordPress debug log publicly accessible - potential data leak'),
            ('/wp-config.php',
             lambda r: r.status_code == 200 and 'DB_PASSWORD' in r.text,
             'CRITICAL', 'wp-config.php readable', 'wp-config.php is publicly readable - credentials exposed'),
            ('/wp-signup.php',
             lambda r: r.status_code == 200 and 'signup' in r.text.lower(),
             'LOW', 'Multisite signup open', 'WordPress multisite user signup is enabled'),
            ('/.git/HEAD',
             lambda r: r.status_code == 200 and 'ref:' in r.text,
             'HIGH', '.git directory exposed', '.git repository exposed - source code and secrets accessible'),
            ('/.git/config',
             lambda r: r.status_code == 200 and '[core]' in r.text,
             'HIGH', '.git/config exposed', '.git/config readable - remote URL and credentials may be exposed'),
            ('/.env',
             lambda r: r.status_code == 200 and len(r.text) > 5,
             'CRITICAL', '.env exposed', '.env file publicly readable - credentials/keys exposed'),
            ('/.htpasswd',
             lambda r: r.status_code == 200 and len(r.text) > 5,
             'CRITICAL', '.htpasswd exposed', '.htpasswd with password hashes publicly readable'),
            ('/wp-content/uploads/.htaccess',
             lambda r: r.status_code == 200 and len(r.text) > 5,
             'LOW', 'uploads .htaccess readable', '.htaccess in uploads directory is publicly readable'),
            ('/phpinfo.php',
             lambda r: r.status_code == 200 and 'phpinfo' in r.text.lower(),
             'HIGH', 'phpinfo.php exposed', 'phpinfo() page leaks PHP version, server config, and env variables'),
            ('/info.php',
             lambda r: r.status_code == 200 and 'phpinfo' in r.text.lower(),
             'HIGH', 'info.php exposed', 'phpinfo() page leaks PHP version, server config, and env variables'),
            ('/wp-admin/setup-config.php',
             lambda r: r.status_code == 200 and 'setup' in r.text.lower(),
             'HIGH', 'setup-config.php accessible', 'WordPress setup script accessible - DB config may be overwritten'),
            ('/.DS_Store',
             lambda r: r.status_code == 200 and len(r.content) > 5,
             'LOW', '.DS_Store exposed', '.DS_Store file leaks directory structure (macOS artifact)'),
            ('/server-status',
             lambda r: r.status_code == 200 and ('apache' in r.text.lower() or 'server status' in r.text.lower()),
             'MEDIUM', 'Apache server-status exposed', 'Apache mod_status leaks live request details and internal IPs'),
            ('/server-info',
             lambda r: r.status_code == 200 and 'apache' in r.text.lower(),
             'MEDIUM', 'Apache server-info exposed', 'Apache mod_info leaks server configuration details'),
            ('/crossdomain.xml',
             lambda r: r.status_code == 200 and 'allow-access-from' in r.text.lower(),
             'MEDIUM', 'crossdomain.xml permissive', 'Permissive crossdomain.xml allows cross-origin Flash/PDF access'),
            ('/wp-content/uploads/',
             lambda r: r.status_code == 200 and ('index of' in r.text.lower() or '<a href=' in r.text.lower()),
             'MEDIUM', 'Uploads directory listable', 'wp-content/uploads/ directory listing is enabled'),
            ('/wp-content/plugins/',
             lambda r: r.status_code == 200 and ('index of' in r.text.lower() or '<a href=' in r.text.lower()),
             'LOW', 'Plugins directory listable', 'wp-content/plugins/ directory listing is enabled'),
            ('/wp-includes/',
             lambda r: r.status_code == 200 and ('index of' in r.text.lower() or '<a href=' in r.text.lower()),
             'LOW', 'wp-includes directory listable', 'wp-includes/ directory listing is enabled'),
        ]

        # Check user registration
        r_reg = self._safe_get(f"{base_url.rstrip('/')}/wp-login.php?action=register")
        if r_reg and r_reg.status_code == 200 and not self._matches_homepage(r_reg, base_url):
            if 'registerform' in r_reg.text.lower() or 'user_login' in r_reg.text:
                findings.append({'severity': 'MEDIUM', 'title': 'User registration open',
                                  'desc': 'Anyone can register an account on this WordPress site'})

        # Check REST API exposes users unauthenticated
        r_rest = self._safe_get(f"{base_url.rstrip('/')}/wp-json/wp/v2/users")
        if r_rest and r_rest.status_code == 200 and not self._matches_homepage(r_rest, base_url):
            try:
                data = r_rest.json()
                if isinstance(data, list) and len(data) > 0:
                    findings.append({'severity': 'MEDIUM', 'title': 'REST API user list public',
                                      'desc': 'Unauthenticated REST API exposes user list at /wp-json/wp/v2/users'})
            except Exception:
                pass

        # Check HTTPS redirect
        if base_url.startswith('http://'):
            r_https = self._safe_get(base_url.replace('http://', 'https://'), timeout=8)
            if not r_https or r_https.status_code >= 400:
                findings.append({'severity': 'MEDIUM', 'title': 'No HTTPS redirect',
                                  'desc': 'Site does not redirect HTTP to HTTPS'})

        # Warm up homepage baseline before the loop (cached after first call)
        self.get_homepage_signature(base_url)

        for path, bad_cond, severity, title, desc in checks:
            r = self._safe_get(base_url.rstrip('/') + path)
            if r:
                try:
                    if bad_cond(r) and not self._matches_homepage(r, base_url):
                        findings.append({'severity': severity, 'title': title,
                                         'desc': desc, 'url': base_url.rstrip('/') + path})
                except Exception:
                    pass
            time.sleep(random.uniform(0.2, 0.5))

        return findings

    # ── FALSE POSITIVE DETECTION (EXISTING LOGIC) ─────────────────────────────

    def is_likely_false_positive(self, endpoint, content_type, content):
        non_html_extensions = [
            '.log','.txt','.sql','.zip','.tar','.gz','.bak','.old',
            '.conf','.cfg','.ini','.env','.json','.xml','.yml','.yaml',
            '.php','.py','.rb','.pl','.sh','.bash','.zsh','.fish',
            '.key','.pem','.crt','.cer','.pub','.ppk','.p12','.pfx','.jks',
            '.db','.sqlite','.sqlite3','.mdb','.csv','.tsv',
            '.7z','.rar','.tgz','.bz2','.xz','.lz','.lzma',
            '.dump','.dmp','.bson','.rdb',
            '.htpasswd','.htaccess',
            '.swp','.swo','.orig','.backup','.copy','.disabled',
            '.sample','.tmp','.temp','.cache',
            '.gpg','.asc','.sig',
            '.war','.jar','.class','.pyc','.pyo',
            '.DS_Store','.gitignore','.gitmodules',
        ]
        endpoint_lower = endpoint.lower()
        has_non_html_ext = any(endpoint_lower.endswith(ext) for ext in non_html_extensions)
        is_html = False
        if content_type:
            is_html = 'text/html' in content_type.lower()
        if not is_html and content:
            content_lower = content[:500].lower()
            is_html = any(m in content_lower for m in ['<!doctype html','<html','<head','<body'])
        return has_non_html_ext and is_html

    def get_homepage_signature(self, base_url):
        if hasattr(self, '_homepage_signature'):
            return self._homepage_signature
        try:
            r = self.session.get(base_url, headers=self.get_random_headers(),
                                 timeout=10, allow_redirects=True, verify=False)
            content = r.text[:2000]
            self._homepage_signature = {
                'length':        len(r.text),
                'title':         self._extract_title(content),
                'content_hash':  hash(content[:1000]),
                'final_url':     r.url.rstrip('/'),
            }
        except Exception:
            self._homepage_signature = None
        return self._homepage_signature

    def _matches_homepage(self, r, base_url):
        """
        Return True if the response appears to be the homepage served as a soft
        404/redirect — i.e., the path doesn't actually exist but the server
        returns the homepage content instead of a real resource.

        Uses three independent signals (any one is enough):
          1. Content hash of first 1 KB matches homepage
          2. Body length within 5 % of homepage length (and body is large enough
             to rule out trivially small real files)
          3. <title> tag identical to homepage title
        """
        if not r:
            return False
        sig = self.get_homepage_signature(base_url)
        if not sig:
            return False

        text = r.text

        # Signal 1 – identical content hash
        if hash(text[:1000]) == sig['content_hash']:
            return True

        # Signal 2 – body length within 5 % of homepage (only for large bodies)
        hp_len = sig['length']
        if hp_len > 1000:
            diff = abs(len(text) - hp_len) / hp_len
            if diff < 0.05:
                return True

        # Signal 3 – same page title
        page_title = self._extract_title(text[:2000])
        if page_title and sig['title'] and page_title == sig['title']:
            return True

        return False

    def _is_homepage_redirect(self, base_url, location):
        """
        Return True if a 301/302 Location header points to the site homepage,
        indicating a soft-404 redirect rather than a real resource redirect.
        """
        if not location:
            return False

        def _norm(u):
            """Strip scheme, trailing slash, and common index pages."""
            u = re.sub(r'^https?://', '', u).rstrip('/')
            u = re.sub(r'/index\.(php|html?)$', '', u)
            return u.lower()

        base_norm = _norm(base_url)
        loc_norm  = _norm(location)

        # Direct homepage match
        if loc_norm == base_norm:
            return True

        # Redirect to bare root path ("/", "")
        if location.strip('/') == '':
            return True

        # Redirect to homepage with query string (e.g. ?p=0)
        if loc_norm.startswith(base_norm + '?'):
            return True

        return False

    def _extract_title(self, html):
        m = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
        return m.group(1).strip() if m else ''

    def is_directory_listing(self, content):
        content_lower = content.lower()
        indicators = [
            'index of ', 'directory listing', 'parent directory',
            '[dir]', '[to parent directory]', 'last modified',
            'size  description', 'href=".."', 'href="../"',
            'apache/2', 'nginx/', 'lighttpd/', 'iis/',
            'folder listing', 'directory index',
            'file listing', 'ls -la',
        ]
        return sum(1 for i in indicators if i in content_lower) >= 2

    def is_bypass_false_positive(self, base_url, endpoint, bypass_content, bypass_url, content_length=None):
        if not bypass_content:
            return True, "Empty response", "high"
        content_lower  = bypass_content.lower()
        endpoint_parts = [p for p in endpoint.strip('/').split('/') if p]
        is_directory   = endpoint.endswith('/')
        actual_length  = content_length if content_length else len(bypass_content)

        if is_directory and self.is_directory_listing(bypass_content):
            if actual_length < 50000:
                return False, "Valid directory listing detected", "high"

        homepage_sig = self.get_homepage_signature(base_url)
        if homepage_sig:
            if hash(bypass_content[:1000]) == homepage_sig['content_hash']:
                return True, "Content identical to homepage", "high"
            bypass_title = self._extract_title(bypass_content)
            if bypass_title and homepage_sig['title']:
                if bypass_title == homepage_sig['title']:
                    if is_directory and 'index of' not in content_lower:
                        return True, f"Same title as homepage: '{bypass_title}'", "high"
                    elif endpoint_parts and not any(p.lower() in content_lower for p in endpoint_parts):
                        return True, f"Same title as homepage: '{bypass_title}'", "medium"
            if homepage_sig['length'] > 0:
                diff = abs(actual_length - homepage_sig['length']) / homepage_sig['length']
                if diff < 0.05:
                    if is_directory and 'index of' not in content_lower:
                        return True, f"Length matches homepage ({actual_length})", "high"
                    elif actual_length > 5000:
                        return True, f"Length matches homepage ({actual_length})", "medium"

        if is_directory:
            complexity = (bypass_content.lower().count('<div') +
                          bypass_content.lower().count('<script') * 2 +
                          bypass_content.lower().count('<nav') +
                          bypass_content.lower().count('<header') +
                          bypass_content.lower().count('<footer'))
            if complexity > 15 and 'index of' not in content_lower:
                return True, f"Complex HTML page (score {complexity})", "high"
            cms_ind = [
                'wordpress','wp-content','wp-includes','wp-json',
                'wp-login','wp-admin','wp-emoji','wp-block',
                'elementor','woocommerce','jetpack','yoast',
                'seo-by-rank-math','contact-form-7','akismet',
            ]
            if any(i in content_lower for i in cms_ind) and 'index of' not in content_lower:
                return True, "CMS/Framework content, not a directory listing", "high"

        error_patterns = [
            # High-confidence 404/error patterns
            ('page not found',       'high'),
            ('error 404',            'high'),
            ('404 not found',        'high'),
            ('file not found',       'high'),
            ('resource not found',   'high'),
            ('pagina non trovata',   'high'),
            ('página no encontrada', 'high'),
            ('seite nicht gefunden', 'high'),
            ('page introuvable',     'high'),
            ('404 error',            'high'),
            ('oops! that page',      'high'),
            # Medium-confidence patterns
            ('not found',            'medium'),
            ('does not exist',       'medium'),
            ('nothing found',        'medium'),
            ('no results found',     'medium'),
            ('sorry, we couldn',     'medium'),
            ('the page you',         'medium'),
            ('couldn\'t find',       'medium'),
            ('cannot be found',      'medium'),
        ]
        for pattern, confidence in error_patterns:
            if pattern in content_lower:
                if confidence == 'high':
                    return True, f"Soft 404 ('{pattern}')", "high"
                elif '<title' in content_lower or '<h1' in content_lower:
                    return True, f"Likely soft 404 ('{pattern}')", "medium"

        return False, "Appears valid", "low"

    def verify_403_validity(self, base_url):
        for _ in range(3):
            suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
            try:
                r = self.session.get(
                    f"{base_url.rstrip('/')}/this-does-not-exist-{suffix}",
                    headers=self.get_random_headers(), timeout=8,
                    allow_redirects=False, verify=False
                )
                if r.status_code == 403:
                    return False
                if r.status_code == 404:
                    return True
            except Exception:
                continue
        return True

    def verify_403_specific(self, base_url, endpoint):
        suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
        test_ep = (endpoint + suffix) if endpoint.endswith('/') else f"{endpoint}-{suffix}"
        try:
            r = self.session.get(
                f"{base_url.rstrip('/')}{test_ep}",
                headers=self.get_random_headers(), timeout=8,
                allow_redirects=False, verify=False
            )
            if r.status_code == 403:
                return False, f"False positive ({test_ep} also 403)"
            if r.status_code == 404:
                return True, f"Real 403 ({test_ep} correctly 404)"
            return True, f"Likely real 403 ({test_ep} → {r.status_code})"
        except Exception as e:
            return True, f"Cannot verify ({e})"

    # ── 403 BYPASS TESTING ────────────────────────────────────────────────────

    def test_403_bypasses(self, base_url, endpoint):
        bypasses = []

        # 1. HTTP methods
        for method in ['POST','PUT','PATCH','OPTIONS','HEAD','TRACE','CONNECT']:
            try:
                bypass_url = f"{base_url.rstrip('/')}{endpoint}"
                r = self.session.request(method, bypass_url, headers=self.get_random_headers(),
                                         timeout=10, allow_redirects=False, verify=False)
                if r.status_code == 200:
                    bypasses.append({'method': f'HTTP Method ({method})', 'http_method': method,
                                     'url': bypass_url, 'status': 200,
                                     'preview': r.text[:200], 'full_content': r.text[:2000],
                                     'content_length': len(r.text),
                                     'curl_command': self.generate_curl_command(bypass_url, method=method)})
            except Exception:
                pass

        # 2. Header-based bypasses
        header_payloads = [
            # URL override headers (rewrite server-side path)
            {'X-Original-URL': endpoint}, {'X-Rewrite-URL': endpoint},
            {'X-Forwarded-Path': endpoint}, {'X-Real-URL': endpoint},
            {'X-Override-URL': endpoint}, {'X-Custom-URL': endpoint},
            # IP spoofing – localhost
            {'X-Forwarded-For': '127.0.0.1'}, {'X-Forwarded-For': '::1'},
            {'X-Forwarded-For': '10.0.0.1'}, {'X-Forwarded-For': '192.168.1.1'},
            {'X-Real-IP': '127.0.0.1'}, {'X-Client-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'}, {'X-Remote-Addr': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'}, {'X-ProxyUser-Ip': '127.0.0.1'},
            {'X-Host': '127.0.0.1'}, {'X-Custom-IP-Authorization': '127.0.0.1'},
            {'X-Cluster-Client-IP': '127.0.0.1'},
            # Standard Forwarded header
            {'Forwarded': 'for=127.0.0.1;proto=http;host=localhost'},
            {'Forwarded': 'for=::1;proto=https;host=localhost'},
            # CDN headers
            {'CF-Connecting-IP': '127.0.0.1'}, {'True-Client-IP': '127.0.0.1'},
            {'X-Sucuri-Clientip': '127.0.0.1'}, {'X-Akamai-Forwarded-For': '127.0.0.1'},
            # Host/origin manipulation
            {'X-Forwarded-Host': '127.0.0.1'}, {'X-Original-Host': 'localhost'},
            {'X-Backend-Host': 'localhost'}, {'X-HTTP-Host-Override': 'localhost'},
        ]
        for payload in header_payloads:
            try:
                headers = {**self.get_random_headers(), **payload}
                rw_keys = {'X-Original-URL','X-Rewrite-URL','X-Forwarded-Path'}
                url = (f"{base_url.rstrip('/')}/" if any(k in payload for k in rw_keys)
                       else f"{base_url.rstrip('/')}{endpoint}")
                r = self.session.get(url, headers=headers, timeout=10,
                                     allow_redirects=False, verify=False)
                if r.status_code == 200:
                    header_name = list(payload.keys())[0]
                    bypasses.append({'method': f'Header ({header_name})', 'url': url,
                                     'bypass_headers': payload, 'status': 200,
                                     'preview': r.text[:200], 'full_content': r.text[:2000],
                                     'content_length': len(r.text),
                                     'curl_command': self.generate_curl_command(url, bypass_headers=payload)})
            except Exception:
                pass

        # 3. Path obfuscation
        variations = [
            # Trailing dot / slash tricks
            endpoint + '/.',
            endpoint + '//',
            endpoint + '//.',
            endpoint + '..;/',
            # Double-slash prefix
            '//' + endpoint.lstrip('/') + '//',
            # Dot traversal
            '/./' + endpoint.lstrip('/') + '/..',
            '/.' + endpoint,
            '/%2e' + endpoint,
            '/%2e/' + endpoint.lstrip('/'),
            # Semicolon bypass (Spring, Tomcat, etc.)
            '/;/' + endpoint.lstrip('/'),
            '/.;/' + endpoint.lstrip('/'),
            '//;//' + endpoint.lstrip('/'),
            endpoint + ';/',
            endpoint + ';param',
            # URL encoding
            endpoint + '%20',
            endpoint + '%09',
            endpoint + '%0a',
            endpoint + '%0d',
            endpoint + '%00',
            endpoint.rstrip('/') + '%2f',
            # Extension bypass
            endpoint + '.html',
            endpoint + '.php',
            endpoint + '.json',
            endpoint + '.xml',
            # Query string tricks
            endpoint + '?',
            endpoint + '?v=1',
            endpoint + '#',
            # Case variation (for case-insensitive servers)
            endpoint.upper(),
            endpoint.swapcase(),
        ]
        if self.aggressive:
            # Unicode normalization bypass
            unicode_map = {'a': 'ā', 'e': 'ē', 'i': 'ī', 'o': 'ō', 'u': 'ū'}
            uni_path = '/' + ''.join(unicode_map.get(c, c) for c in endpoint.strip('/'))
            variations += [
                uni_path,
                endpoint.rstrip('/') + '/..',
                '/' + endpoint.lstrip('/').replace('/', '%2f'),
                endpoint + '?%00',
                endpoint + '%23',        # encoded #
                endpoint + '%3f',        # encoded ?
                '/' + endpoint.lstrip('/').replace('/', '/./'),
                endpoint + '/.git/HEAD', # path confusion
            ]
        for variation in variations:
            try:
                bypass_url = f"{base_url.rstrip('/')}{variation}"
                r = self.session.get(bypass_url, headers=self.get_random_headers(),
                                     timeout=10, allow_redirects=False, verify=False)
                if r.status_code == 200:
                    bypasses.append({'method': f'Path ({variation})', 'url': bypass_url,
                                     'status': 200, 'preview': r.text[:200],
                                     'full_content': r.text[:2000], 'content_length': len(r.text),
                                     'curl_command': self.generate_curl_command(bypass_url)})
            except Exception:
                continue

        # 4. Case variation
        for variant in ['/' + endpoint.strip('/').upper(),
                        '/' + endpoint.strip('/').title()]:
            try:
                bypass_url = f"{base_url.rstrip('/')}{variant}"
                r = self.session.get(bypass_url, headers=self.get_random_headers(),
                                     timeout=10, allow_redirects=False, verify=False)
                if r.status_code == 200:
                    bypasses.append({'method': f'Case ({variant})', 'url': bypass_url,
                                     'status': 200, 'preview': r.text[:200],
                                     'full_content': r.text[:2000], 'content_length': len(r.text),
                                     'curl_command': self.generate_curl_command(bypass_url)})
            except Exception:
                pass

        # Filter false positives
        verified = []
        for bp in bypasses:
            content = bp.get('full_content', bp.get('preview', ''))
            is_fp, fp_reason, fp_conf = self.is_bypass_false_positive(
                base_url, endpoint, content, bp['url'], bp.get('content_length'))
            bp['is_false_positive'] = is_fp
            bp['fp_reason']         = fp_reason
            bp['fp_confidence']     = fp_conf
            if not is_fp:
                verified.append(bp)
            elif fp_conf == 'medium':
                bp['needs_verification'] = True
                verified.append(bp)
        return verified

    def _print_bypass_details(self, bypass, show_warning=False):
        method = bypass['method']
        url    = bypass['url']
        warn   = f" {C.YELLOW}⚠{C.RESET}" if show_warning else ""
        print(f"      ├─ {method}{warn}")
        if show_warning and bypass.get('fp_reason'):
            print(f"      │  {C.YELLOW}⚠  Warning: {bypass['fp_reason']}{C.RESET}")
        if bypass.get('bypass_headers'):
            for k, v in bypass['bypass_headers'].items():
                print(f"      │  Header: {k}: {v}")
        if self.verbosity >= 1:
            print(f"      │  Curl: {bypass['curl_command']}")
        if self.verbosity >= 2 and bypass.get('preview'):
            preview = bypass['preview'][:80].replace('\n',' ').strip()
            print(f"      │  Preview: {preview}...")
        print(f"      │")

    # ── ENDPOINT CATEGORIES (unchanged + minor additions) ─────────────────────

    def get_backup_endpoints(self, base_url):
        common = [
            # wp-config variants
            '/wp-config.php.bak','/wp-config.php~','/wp-config.php.save','/wp-config.php.old',
            '/wp-config.php.orig','/wp-config.php.backup','/wp-config.php.bkp',
            '/wp-config.php.copy','/wp-config.php.disabled','/wp-config.php.tmp',
            '/wp-config.php.txt','/wp-config.php.zip','/wp-config.php.tar.gz',
            '/wp-config.php.1','/wp-config.php.2',
            '/.wp-config.php.swp','/.wp-config.php.swo',
            '/wp-config.bak','/wp-config.bkp','/wp-config.old',
            '/wp-config-local.php','/wp-config-backup.php',
            # .htaccess variants
            '/.htaccess.bak','/.htaccess~','/.htaccess.old',
            '/.htaccess.save','/.htaccess.bkp','/.htaccess.orig',
            '/.htaccess.txt','/.htaccess.backup',
            # SQL dumps
            '/backup.sql','/database.sql','/db_backup.sql','/wp_backup.sql',
            '/backup-db.sql','/dump.sql','/mysql.sql','/db.sql',
            '/data.sql','/wordpress.sql','/wp-old.sql','/database_backup.sql',
            '/site.sql','/export.sql','/schema.sql','/tables.sql',
            '/wordpress.sql.gz','/database.sql.gz','/db.sql.gz','/dump.sql.gz',
            # ZIP/archive backups
            '/backup.zip','/backup.tar.gz','/backup.rar','/backup.7z',
            '/site_backup.zip','/site.zip','/site.tar.gz',
            '/wordpress_backup.zip','/wordpress.zip','/wordpress.tar.gz',
            '/website.zip','/website_backup.zip','/website.tar.gz',
            '/public_html.zip','/www.zip','/html.zip',
            '/all.zip','/archive.zip','/full.zip','/master.zip',
            '/old.zip','/monthly.zip','/weekly.zip','/daily.zip',
            '/db.zip','/db.tar.gz','/sql.zip',
            # wp-content backups
            '/wp-content/backup-db','/wp-content/backup-db/',
            '/wp-content/backups/','/wp-content/backup/',
            '/wp-content/uploads/backup.zip','/wp-content/uploads/backup.sql',
            '/wp-content/uploads/site.zip','/wp-content/uploads/database.sql',
            '/wp-content/debug.log.bak','/wp-content/debug.log.old',
            # Generic backup dirs
            '/backup/','/backups/','/bkp/','/bak/',
            '/_backup/','/_bkp/','/_old/','/old/',
        ]
        now = datetime.datetime.now()
        dates = [now.strftime("%Y"), now.strftime("%Y-%m"), now.strftime("%Y%m%d"),
                 (now - datetime.timedelta(days=1)).strftime("%Y%m%d"),
                 (now - datetime.timedelta(days=30)).strftime("%Y-%m")]
        fuzz = []
        for d in dates:
            fuzz += [f'/backup-{d}.zip',f'/backup-{d}.sql',f'/db-{d}.sql',
                     f'/{d}.zip',f'/{d}.sql']
        return list(set(common + fuzz))

    def get_config_endpoints(self, base_url):
        return [
            # WordPress core config
            '/wp-config.php','/wp-config-sample.php','/wp-config-local.php',
            '/wp-config.php~','/wp-config.php.bak','/wp-config.php.old',
            '/wp-config.inc.php','/wp-config.backup.php',
            # .env variants (commonly placed in WP web root by hosting panels)
            '/.env','/.env.local','/.env.production','/.env.dev','/.env.prod',
            '/.env.stage','/.env.staging','/.env.test','/.env.backup',
            '/.env.bak','/.env.old','/.env.example','/.env.sample',
            '/.env.template','/.env.default','/.env.php','/.env.dist',
            '/backup.env','/db.env','/app.env',
            # PHP config files (common WP/PHP patterns)
            '/config.php','/config.inc.php','/local-config.php','/local.php',
            '/settings.php','/settings.local.php','/configuration.php',
            '/database.php','/db.php','/connect.php','/connection.php',
            '/credentials.php','/secrets.php','/globals.php',
            # PHP dependency manager (WP uses Composer)
            '/composer.json','/composer.lock',
            '/config.json','/config.yml','/config.yaml',
            # Git metadata (exposed after git clone in web root)
            '/.git/config','/.git/HEAD','/.git/index','/.git/COMMIT_EDITMSG',
            '/.git/logs/HEAD','/.git/packed-refs','/.git/refs/heads/',
            '/.gitmodules','/.gitignore','/.git-credentials','/.gitattributes',
            # Web server configs
            '/web.config','/server.xml','/.htpasswd','/.htaccess',
            '/php.ini','/.user.ini','/nginx.conf','/nginx.conf.bak',
            '/apache.conf','/httpd.conf',
            # IDE/editor (left on server by devs)
            '/.vscode/settings.json','/.vscode/launch.json',
            '/.idea/workspace.xml','/.idea/dataSources.xml',
            # WP CLI config
            '/wp-cli.yml',
        ]

    def get_log_endpoints(self, base_url):
        return [
            # WordPress core logs
            '/wp-content/debug.log','/wp-content/error.log',
            '/wp-content/logs/','/wp-content/logs/debug.log',
            '/wp-content/logs/error.log','/wp-content/logs/access.log',
            '/wp-content/uploads/debug.log','/wp-content/uploads/error.log',
            '/wp-content/uploads/error_log','/wp-content/uploads/php_errors.log',
            '/wp-content/cache/debug.log',
            '/wp-content/wflogs/','/wp-content/wflogs/attack-data.php',
            '/wp-admin/error.log',
            # Plugin-specific logs
            '/wp-content/uploads/wc-logs/','/wp-content/uploads/wc-logs/error.log',
            '/wp-content/uploads/gravity_forms/',
            '/wp-content/uploads/ninja-forms/',
            '/wp-content/uploads/wp-mail-smtp/',
            '/wp-content/uploads/updraftplus/',
            '/wp-content/plugins/wordfence/tmp/',
            # Generic web server logs
            '/debug.log','/error.log','/access.log',
            '/error_log','/access_log',
            '/logs/','/logs/debug.log','/logs/error.log',
            '/logs/access.log','/logs/app.log',
            '/log/','/log/error.log','/log/access.log','/log/debug.log',
            # Generic PHP/web logs (can exist on any WP server)
            '/application.log','/app.log','/system.log',
            # PHP error logs
            '/php_errors.log','/php_error.log','/php.log',
            '/php-errors.log','/phperror.log',
        ]

    def get_directory_endpoints(self, base_url):
        return [
            # wp-content subdirs
            '/wp-content/','/wp-content/uploads/','/wp-content/themes/',
            '/wp-content/plugins/','/wp-content/mu-plugins/',
            '/wp-content/cache/','/wp-content/backups/','/wp-content/backup/',
            '/wp-content/upgrade/','/wp-content/temp/','/wp-content/tmp/',
            '/wp-content/logs/','/wp-content/languages/','/wp-content/fonts/',
            '/wp-content/wflogs/','/wp-content/et-cache/',
            '/wp-content/ngg/','/wp-content/gallery/',
            '/wp-content/uploads/backups/','/wp-content/uploads/tmp/',
            '/wp-content/uploads/logs/','/wp-content/uploads/cache/',
            '/wp-content/uploads/elementor/','/wp-content/uploads/revslider/',
            '/wp-content/uploads/gravity_forms/','/wp-content/uploads/ninja-forms/',
            '/wp-content/uploads/updraftplus/','/wp-content/uploads/wc-logs/',
            '/wp-content/uploads/wp-mail-smtp/','/wp-content/uploads/bbpress/',
            # WP core dirs
            '/wp-admin/','/wp-admin/css/','/wp-admin/js/','/wp-admin/images/',
            '/wp-admin/network/','/wp-admin/user/',
            '/wp-includes/','/wp-includes/js/','/wp-includes/css/',
            '/wp-includes/images/','/wp-includes/fonts/',
            # Common web dirs
            '/uploads/','/images/','/files/','/documents/','/assets/',
            '/media/','/downloads/','/static/','/public/',
            '/css/','/js/','/fonts/','/img/','/src/',
            # Sensitive/operational dirs
            '/backup/','/backups/','/bkp/','/bak/','/old/',
            '/temp/','/tmp/','/cache/','/logs/','/log/',
            '/private/','/secure/','/internal/','/admin/',
            '/staging/','/test/','/dev/','/development/','/prod/',
            # WP REST API root (separate from ajax, used for discovery)
            '/wp-json/',
            '/.well-known/',
        ]

    def get_ajax_endpoints(self, base_url):
        return [
            # Core admin-ajax
            '/wp-admin/admin-ajax.php',
            '/wp-admin/admin-ajax.php?action=heartbeat',
            '/wp-admin/admin-ajax.php?action=wp_compression_test',
            '/wp-admin/admin-ajax.php?action=fetch-list',
            '/wp-admin/admin-ajax.php?action=ajax-tag-search',
            '/wp-admin/admin-ajax.php?action=query-attachments',
            '/wp-admin/admin-ajax.php?action=save-attachment',
            '/wp-admin/admin-ajax.php?action=get-comments',
            '/wp-admin/admin-ajax.php?action=wp-remove-post-lock',
            # Plugin-specific AJAX
            '/wp-admin/admin-ajax.php?action=elementor_ajax',
            '/wp-admin/admin-ajax.php?action=nopriv_woocommerce_get_refreshed_fragments',
            '/wp-admin/admin-ajax.php?action=woocommerce_get_refreshed_fragments',
            '/wp-admin/admin-ajax.php?action=cf7_upload_file',
            '/wp-admin/admin-ajax.php?action=duplicator_package_scan',
            '/wp-admin/admin-ajax.php?action=revslider_ajax_action',
            '/wp-admin/admin-ajax.php?action=vc_get_vc_grid_data',
            # WooCommerce frontend ajax
            '/?wc-ajax=get_refreshed_fragments',
            '/?wc-ajax=apply_coupon',
            '/?wc-ajax=checkout',
            '/?wc-ajax=add_to_cart',
            '/?wc-ajax=remove_from_cart',
            # REST API - core
            '/wp-json/','/wp-json/wp/v2/',
            '/wp-json/wp/v2/users','/wp-json/wp/v2/posts',
            '/wp-json/wp/v2/pages','/wp-json/wp/v2/media',
            '/wp-json/wp/v2/comments','/wp-json/wp/v2/settings',
            '/wp-json/wp/v2/themes','/wp-json/wp/v2/plugins',
            '/wp-json/wp/v2/search','/wp-json/wp/v2/categories',
            '/wp-json/wp/v2/tags','/wp-json/wp/v2/taxonomies',
            '/wp-json/wp/v2/types','/wp-json/wp/v2/statuses',
            '/wp-json/wp/v2/block-types','/wp-json/wp/v2/templates',
            '/wp-json/wp/v2/blocks','/wp-json/wp/v2/global-styles/',
            '/wp-json/wp/v2/sidebars','/wp-json/wp/v2/widgets',
            '/wp-json/oembed/1.0/embed','/wp-json/oembed/1.0/',
            # REST API - plugins
            '/wp-json/contact-form-7/v1/',
            '/wp-json/woocommerce/v3/','/wp-json/woocommerce/v2/',
            '/wp-json/yoast/v1/','/wp-json/rank-math/v1/',
            '/wp-json/jetpack/v4/',
            '/wp-json/acf/v3/',
            # REST fallback routes
            '/?rest_route=/',
            '/?rest_route=/wp/v2/users',
            '/?rest_route=/wp/v2/posts',
            '/?rest_route=/wp/v2/pages',
        ]

    def get_api_endpoints(self, base_url):
        return [
            # Generic APIs
            '/api/','/api/v1/','/api/v2/','/api/v3/',
            '/graphql','/graphql/','/graphiql',
            '/rest/','/rest/v1/','/rest/v2/',
            # WordPress feeds
            '/feed/','/feed/rss/','/feed/rss2/','/feed/atom/',
            '/feed/rdf/','/comments/feed/',
            '/rss/','/rss.xml','/rss2.xml',
            '/atom/','/atom.xml',
            # Sitemaps
            '/sitemap.xml','/sitemap_index.xml','/wp-sitemap.xml',
            '/sitemap-1.xml','/sitemap-posts-post-1.xml',
            '/sitemap-pages-1.xml','/news-sitemap.xml',
            '/video-sitemap.xml','/image-sitemap.xml',
            # Discovery files
            '/robots.txt','/humans.txt','/ads.txt','/app-ads.txt',
            '/security.txt','/.well-known/security.txt',
            '/.well-known/change-password','/.well-known/',
            '/.well-known/openid-configuration',
            '/.well-known/oauth-authorization-server',
            # Browser/platform
            '/manifest.json','/manifest.webmanifest',
            '/browserconfig.xml','/crossdomain.xml',
            '/favicon.ico','/apple-touch-icon.png',
            # WordPress special endpoints
            '/wp-comments-post.php','/wp-trackback.php',
            '/wp-links-opml.php','/wp-app.php',
            '/xmlrpc.php',
            # Author enumeration via URL
            '/?author=1','/?author=2','/?author=3',
            # oEmbed
            '/wp-json/oembed/1.0/embed','/oembed/',
            '/?oembed=1',
        ]

    def get_cache_endpoints(self, base_url):
        return [
            # WP drop-in cache files
            '/wp-content/advanced-cache.php','/wp-content/object-cache.php',
            '/wp-content/wp-cache-config.php',
            # Cache plugin directories
            '/wp-content/cache/',
            '/wp-content/cache/supercache/',          # WP Super Cache
            '/wp-content/cache/wp-rocket/',           # WP Rocket
            '/wp-content/cache/wp-rocket/config/',
            '/wp-content/cache/min/',                 # WP Rocket / Autoptimize
            '/wp-content/cache/litespeed/',           # LiteSpeed Cache
            '/wp-content/cache/lscache/',
            '/wp-content/cache/autoptimize/',         # Autoptimize
            '/wp-content/cache/breeze/',              # Breeze (Cloudways)
            '/wp-content/cache/wpo/',                 # WP Optimize
            '/wp-content/cache/wp-fastest-cache/',    # WP Fastest Cache
            '/wp-content/cache/w3-total-cache/',      # W3 Total Cache
            '/wp-content/w3tc-config/',
            '/wp-content/cache/hummingbird/',         # Hummingbird
            '/wp-content/cache/sg-optimizer/',        # SG Optimizer
            '/wp-content/cache/comet-cache/',         # Comet Cache
            '/wp-content/cache/swift-performance/',   # Swift Performance
            '/wp-content/cache/cache-enabler/',       # Cache Enabler
            '/wp-content/cache/flying-press/',        # FlyingPress
            '/wp-content/cache/rapidload/',           # RapidLoad
            '/wp-content/et-cache/',                  # Divi ET cache
            '/wp-content/uploads/cache/',
            # Generic cache dirs
            '/cache/','/tmp/cache/','/.cache/',
            '/wp-content/plugins/wp-super-cache/',
        ]

    def get_debug_endpoints(self, base_url):
        return [
            # WordPress admin scripts
            '/wp-admin/install.php','/wp-admin/upgrade.php',
            '/wp-admin/setup-config.php','/wp-admin/maint/repair.php',
            '/wp-admin/admin-post.php','/wp-admin/async-upload.php',
            '/wp-login.php?action=lostpassword',
            # PHP info/debug pages
            '/phpinfo.php','/info.php','/php.php','/php_info.php',
            '/test.php','/debug.php','/status.php','/health.php',
            '/version.php','/env.php','/server.php','/check.php',
            '/ping.php','/pong.php','/alive.php','/ready.php','/ok.php',
            '/xdebug.php','/trace.php','/dump.php','/staging.php',
            '/dev.php','/local.php','/test.html',
            # WP debug logs
            '/wp-content/debug.log','/wp-content/logs/',
            '/wp-content/tmp/','/wp-content/test/',
            '/wp-content/uploads/debug.log','/wp-content/uploads/error.log',
            '/wp-content/uploads/error_log','/wp-content/uploads/php_errors.log',
            '/wp-content/uploads/logs/',
            # PHP error logs
            '/php_error.log','/php_errors.log','/error_log',
            # PHP profiler (Clockwork - generic PHP, sometimes on WP)
            '/__clockwork/','/__clockwork/latest','/clockwork/',
        ]

    def get_plugin_specific_endpoints(self, base_url):
        plugins = [
            # Page builders
            'elementor','elementor-pro','royal-elementor-addons',
            'js_composer','beaver-builder','beaver-builder-lite-version',
            'siteorigin-panels','kingcomposer','fusion-builder',
            'thrive-architect','oxygen','bricks','divi-builder',
            'visual-composer','wp-page-builder','brizy',
            # Elementor addons
            'essential-addons-for-elementor','happy-elementor-addons',
            'premium-addons-for-elementor','ultimate-addons-for-elementor',
            'envato-elements',
            # SEO
            'yoast-seo','all-in-one-seo-pack','seo-by-rank-math',
            'the-seo-framework','slim-seo','squirrly-seo',
            # WooCommerce core + extensions
            'woocommerce','woocommerce-payments','woocommerce-subscriptions',
            'woo-gutenberg-products-block','woocommerce-gateway-stripe',
            'woocommerce-paypal-payments','wc-order-export',
            'easy-digital-downloads','woo-stripe-payment',
            # Forms
            'contact-form-7','wpforms','wpforms-lite','gravityforms',
            'ninja-forms','formidable','caldera-forms','fluentform',
            'mailchimp-for-wp',
            # Security
            'wordfence','ithemes-security','sucuri-scanner',
            'all-in-one-wp-security-and-firewall','really-simple-ssl',
            'loginizer','two-factor','wp-cerber','shield-security',
            # Backup / Migration
            'updraftplus','duplicator','all-in-one-wp-migration',
            'backupbuddy','wp-migrate-db','backwpup',
            'wp-clone-by-wp-academy','xcloner-backup-and-restore',
            # Caching
            'wp-super-cache','w3-total-cache','wp-rocket','autoptimize',
            'litespeed-cache','wp-fastest-cache','sg-cachepress',
            'hummingbird-performance','comet-cache','cache-enabler',
            # Images / Media
            'ewww-image-optimizer','smush','imagify','shortpixel-image-optimiser',
            'regenerate-thumbnails','enable-media-replace',
            # ACF / Custom Fields
            'advanced-custom-fields','acf-pro','pods','toolset-types',
            'meta-box','codepress-admin-columns',
            # Multilingual
            'wpml','polylang','translatepress-multilingual',
            'weglot','gtranslate','loco-translate','wplingua',
            # Analytics / Tracking
            'google-analytics-for-wordpress','monsterinsights',
            'google-site-kit','wp-statistics','analytify',
            # Membership / LMS
            'paid-memberships-pro','restrict-content-pro','memberpress',
            'learnpress','learndash','tutor-lms','lifterlms',
            'user-role-editor','members',
            # Events / Booking
            'the-events-calendar','tribe-events-calendar-pro',
            'events-manager','bookly','amelia',
            # Social / Marketing
            'revslider','optinmonster','convert-pro','hustle','bloom',
            'instagram-feed','smash-balloon-social-photo-feed',
            # Utilities
            'wp-file-manager','classic-editor','classic-widgets',
            'redirection','broken-link-checker','tablepress',
            'query-monitor','wp-mail-smtp','post-smtp',
            'akismet','jetpack','complianz-gdpr','cookie-notice',
            'wp-crontrol','health-check','debug-bar',
            'user-switching','wp-reset','wp-rollback',
            'duplicate-page','duplicate-post',
            'simple-history','stream',
            # Infrastructure
            'mainwp','mainwp-child','envato-market',
            'tgm-plugin-activation','wp-cli-login-server',
            'wp-staging','wp-staging-pro',
            # Payments / eCommerce
            'give','give-donations','charitable',
            # File management
            'wp-file-manager','filester','file-manager-advanced',
        ]
        endpoints = []
        for plugin in plugins:
            endpoints += [
                f'/wp-content/plugins/{plugin}/',
                f'/wp-content/plugins/{plugin}/readme.txt',
                f'/wp-content/plugins/{plugin}/changelog.txt',
                f'/wp-content/plugins/{plugin}/LICENSE',
                f'/wp-content/plugins/{plugin}/config.php',
                f'/wp-content/plugins/{plugin}/settings.php',
                f'/wp-content/plugins/{plugin}/debug.log',
                f'/wp-content/plugins/{plugin}/error.log',
                f'/wp-content/plugins/{plugin}/readme.md',
                f'/wp-content/plugins/{plugin}/README.md',
            ]
        return endpoints

    def get_sensitive_files_endpoints(self, base_url):
        return [
            # Private keys accidentally placed in web root
            '/id_rsa','/id_rsa.pub','/id_dsa','/private_key',
            # TLS/SSL keys (sometimes in web root on cheap hosting)
            '/server.key','/server.crt','/server.pem','/server.p12',
            '/cert.pem','/cert.key','/private.key','/private.pem',
            '/ssl.key','/ssl.crt','/ssl.pem',
            # AWS credentials (misconfigured deployments / S3-backed WP)
            '/.aws/credentials','/.aws/config',
            '/.s3cfg','/.boto','/.passwd-s3fs',
            # Google API credentials (WP plugins: Site Kit, Google Analytics, etc.)
            '/google-credentials.json','/gcp-credentials.json',
            '/client_secret.json','/service_account.json',
            # Generic credential files (common on WP project repos)
            '/.netrc','/.git-credentials','/.gitconfig',
            '/.npmrc',
            '/auth.json','/credentials','/credentials.json',
            '/keys.json','/token.json','/tokens.json',
            '/access_token','/refresh_token',
            # Secrets files (sometimes in WP project root)
            '/.vault-token','/secrets.yml','/secrets.yaml',
            '/secrets.json','/secrets.env',
            # WP-specific system files
            '/.htpasswd',
            '/wp-cli.yml','/.wp-cli/config.yml',
            # Terraform state (sometimes in project root alongside WP)
            '/terraform.tfstate','/terraform.tfstate.backup',
            # Sensitive uploads (files mistakenly uploaded to WP media)
            '/wp-content/uploads/.env',
            '/wp-content/uploads/credentials.json',
            '/wp-content/uploads/config.php',
            '/wp-content/uploads/wp-config.php',
        ]

    # ── SINGLE ENDPOINT TEST ──────────────────────────────────────────────────

    def test_endpoint(self, base_url, endpoint):
        url = f"{base_url.rstrip('/')}{endpoint}"
        try:
            delay = random.uniform(0.3, 0.9) if self.aggressive else random.uniform(0.5, 1.5)
            time.sleep(delay)
            headers  = self.get_random_headers()
            response = self.session.get(url, headers=headers, timeout=10,
                                        allow_redirects=False, verify=False)
            is_directory = endpoint.endswith('/')
            content_type = response.headers.get('Content-Type','')

            result = {
                'url': url, 'endpoint': endpoint, 'status_code': response.status_code,
                'content_length': len(response.content), 'content_type': content_type,
                'server': response.headers.get('Server',''),
                'interesting': False, 'reason': '', 'preview': '',
                'bypasses': [], 'verification': '',
                'is_directory': is_directory, 'is_false_positive': False,
                'curl_command': self.generate_curl_command(url),
                'download_command': None if is_directory else self.generate_download_command(url),
            }

            if response.status_code == 200:
                content = response.text[:1000]
                result['preview'] = content[:200]
                if self.is_likely_false_positive(endpoint, content_type, content):
                    result['is_false_positive'] = True
                    result['reason'] = "Likely false positive (HTML for non-HTML file)"
                else:
                    interesting_patterns = [
                        # Credentials / secrets
                        'DB_PASSWORD','DB_USER','DB_NAME','DB_HOST','DB_PREFIX',
                        'AUTH_KEY','SECURE_AUTH_KEY','LOGGED_IN_KEY','NONCE_KEY',
                        'define(','API_KEY','API_SECRET','SECRET_KEY','SECRET',
                        'TOKEN','ACCESS_TOKEN','REFRESH_TOKEN','PRIVATE_KEY',
                        'password','passwd','pwd','credential','auth_token',
                        'client_secret','bearer ','basic ',
                        # Cloud/infra secrets
                        'aws_access_key','aws_secret','AKIA','s3.amazonaws.com',
                        'AIza',          # Google API key prefix
                        'GITHUB_TOKEN','GH_TOKEN',
                        # Error disclosure
                        'error','warning','exception','stack trace','debug',
                        'traceback','fatal error','syntax error',
                        'undefined variable','call to undefined',
                        'mysql_connect','pg_connect','mysqli',
                        # Directory listing
                        'Index of','Directory listing',
                        # Source code
                        '<?php','<?xml','<?=',
                        # SQL
                        'SQL','SELECT ','INSERT INTO','UPDATE ','DROP TABLE',
                        'UNION SELECT','information_schema',
                        # WP specific
                        'wp_','wordpress','wp-config','wp-content',
                        # Metadata / version info
                        'changelog','readme','version','license',
                        # DB connection strings
                        'mysql://','postgres://','mongodb://','redis://',
                        'mysql:','pgsql:','sqlite:',
                    ]
                    content_lower = content.lower()
                    for pat in interesting_patterns:
                        if pat.lower() in content_lower:
                            result['interesting'] = True
                            result['reason'] = f"Contains: {pat}"
                            break

            elif response.status_code == 403:
                is_real, verif_msg = self.verify_403_specific(base_url, endpoint)
                result['verification'] = verif_msg
                if is_real:
                    bypasses = self.test_403_bypasses(base_url, endpoint)
                    result['bypasses'] = bypasses
                    result['interesting'] = True
                    result['reason'] = (f"Real 403 + {len(bypasses)} bypasses" if bypasses
                                        else "Real 403 (protected)")
                else:
                    result['reason'] = "False positive 403"

            elif response.status_code in (301, 302):
                location = response.headers.get('Location', '')
                if self._is_homepage_redirect(base_url, location):
                    # Soft-404: server redirects everything to homepage
                    result['interesting'] = False
                    result['reason'] = f"Soft redirect to homepage"
                else:
                    result['interesting'] = True
                    result['reason'] = f"Redirect → {location}"

            return result

        except Exception as e:
            return {'url': url, 'endpoint': endpoint, 'status_code': 'Error',
                    'error': str(e), 'interesting': False}

    def scan_category(self, base_url, category_name):
        self.vprint(f"\n{C.CYAN}  Scanning {category_name.replace('_',' ').title()}...{C.RESET}", level=1)
        print(f"  {C.DIM}[{category_name.replace('_',' ').title()}]{C.RESET}", end=' ', flush=True)

        endpoints   = self.endpoint_categories[category_name](base_url)
        interesting = []
        workers     = 10 if self.aggressive else 5

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(self.test_endpoint, base_url, ep): ep for ep in endpoints}
            for future in as_completed(futures):
                result = future.result()
                if result['interesting']:
                    interesting.append(result)
                    status = result['status_code']
                    reason = result.get('reason','')
                    verif  = ''
                    if 'False positive' in result.get('verification',''):
                        verif = f" {C.YELLOW}[FP]{C.RESET}"
                    elif 'Real 403' in result.get('verification',''):
                        verif = f" {C.GREEN}[VERIFIED]{C.RESET}"
                    bp_info = ''
                    if result.get('bypasses'):
                        n = len(result['bypasses'])
                        bp_info = f" {C.RED}[{n} BYPASS{'ES' if n>1 else ''}]{C.RESET}"
                    self.vprint(f"\n   {C.GREEN}✓{C.RESET} {result['endpoint']} "
                                f"→ {status} {reason}{verif}{bp_info}", level=1)
                elif result.get('status_code') == 403 and 'False positive' in result.get('verification',''):
                    self.vprint(f"\n   {C.DIM}✗ {result['endpoint']} → 403 (FP){C.RESET}", level=2)

        count = len(interesting)
        color = C.RED if count > 0 else C.GREEN
        print(f"{color}{count} found{C.RESET}")
        return interesting

    # ── MASTER SCAN ───────────────────────────────────────────────────────────

    def run_full_scan(self, base_url):
        base_url = base_url.rstrip('/')
        TOTAL_PHASES = 8

        print(f"\n{C.BOLD}  Target :{C.RESET} {base_url}")
        print(f"{C.BOLD}  Mode   :{C.RESET} {'AGGRESSIVE' if self.aggressive else 'Normal'}"
              f"  Verbosity: {['quiet', 'verbose', 'debug'][self.verbosity]}")
        if self.aggressive and os.environ.get('WPSCAN_API_TOKEN'):
            print(f"{C.BOLD}  WPScan :{C.RESET} API token found - extended CVE lookup enabled")
        elif self.aggressive:
            print(f"{C.DIM}  Tip    : Set WPSCAN_API_TOKEN env var for extended CVE lookup{C.RESET}")

        # ── PHASE 1: FINGERPRINTING ───────────────────────────────────────────
        self._section(1, TOTAL_PHASES, "Fingerprinting")

        wp_version, wp_ver_source = self.detect_wp_version(base_url)
        if wp_version:
            print(f"  {C.GREEN}✓{C.RESET} WordPress version: {C.BOLD}{wp_version}{C.RESET}"
                  f"  {C.DIM}(via {wp_ver_source}){C.RESET}")
        else:
            print(f"  {C.DIM}✗ WordPress version: not detected{C.RESET}")

        print(f"  Enumerating plugins/themes ...")
        plugins_found, themes_found = self.enumerate_plugins_themes(base_url)
        print(f"  {C.GREEN}✓{C.RESET} {len(plugins_found)} plugin(s) detected"
              f"  {len(themes_found)} theme(s) detected")

        if self.verbosity >= 2:
            for slug, ver in sorted(plugins_found.items()):
                print(f"    {C.DIM}plugin: {slug}  {('v'+ver) if ver else '(ver unknown)'}{C.RESET}")
            for slug in sorted(themes_found.keys()):
                print(f"    {C.DIM}theme:  {slug}{C.RESET}")

        # ── PHASE 2: CVE ANALYSIS ────────────────────────────────────────────
        self._section(2, TOTAL_PHASES, "CVE Analysis")

        cve_findings = self.check_cve_vulnerabilities(plugins_found)

        # Optional WPScan API enrichment in aggressive mode
        if self.aggressive and os.environ.get('WPSCAN_API_TOKEN'):
            # Track CVE IDs already in embedded findings to avoid duplicates
            seen_cves = {f['cve'] for f in cve_findings}
            for slug in plugins_found:
                api_data = self._query_wpscan_api(slug, 'plugin')
                if not api_data:
                    continue
                for vuln in api_data.get('vulnerabilities', []):
                    if not vuln:
                        continue
                    cvss_score = float((vuln.get('cvss') or {}).get('score') or 0)
                    cve_list   = vuln.get('references', {}).get('cve') or []
                    cve_id     = f"CVE-{cve_list[0]}" if cve_list else vuln.get('title', '')
                    if cve_id in seen_cves:
                        continue   # Already reported from embedded DB
                    seen_cves.add(cve_id)
                    cve_findings.append({
                        'slug':     slug,
                        'version':  plugins_found[slug] or '?',
                        'cve':      cve_id,
                        'severity': self._cvss_score_to_severity(cvss_score),
                        'cvss':     cvss_score,
                        'desc':     vuln.get('title', ''),
                        'certain':  True,
                        'source':   'WPScan API',
                    })
            cve_findings.sort(key=lambda x: x['cvss'], reverse=True)

        confirmed = [f for f in cve_findings if f.get('certain', True)]
        possible  = [f for f in cve_findings if not f.get('certain', True)]

        if confirmed:
            for f in confirmed:
                src = f"  {C.DIM}[{f['source']}]{C.RESET}" if f.get('source') else ''
                sev = sev_color(f['severity'])
                print(f"  {C.RED}⚠{C.RESET} {sev} "
                      f"{C.BOLD}{f['slug']}{C.RESET} v{f['version']}{src}")
                print(f"     {f['cve']}  CVSS {f['cvss']}  {f['desc']}")
        else:
            print(f"  {C.GREEN}✓{C.RESET} No confirmed CVEs for detected plugins")
            self.vprint(f"  {C.DIM}(CVE database covers {len(EFFECTIVE_CVE_DB)} plugin families){C.RESET}", level=1)

        # "Possible" entries (version not readable): only show with --aggressive.
        # Showing unconfirmed CVEs as warnings is misleading without version proof.
        if possible:
            if self.aggressive:
                print(f"\n  {C.DIM}── Speculative findings (plugin detected, version unreadable) ──{C.RESET}")
                for f in possible:
                    sev = sev_color(f['severity'])
                    print(f"  {C.DIM}? {sev} {f['slug']}  {f['cve']}  CVSS {f['cvss']}  [UNCONFIRMED]{C.RESET}")
            else:
                print(f"  {C.DIM}ℹ  {len(possible)} speculative CVE match(es) suppressed"
                      f" (version unreadable) — rerun with --aggressive to show{C.RESET}")

        # ── PHASE 3: SECURITY HEADERS ────────────────────────────────────────
        self._section(3, TOTAL_PHASES, "Security Headers")

        header_findings = self.check_security_headers(base_url)
        if not header_findings:
            print(f"  {C.YELLOW}⚠{C.RESET} Could not fetch main page headers")
        else:
            for h in header_findings:
                if h['present']:
                    val_str = f"  {C.DIM}{h['value'][:60]}{C.RESET}" if self.verbosity >= 1 else ''
                    print(f"  {C.GREEN}✓{C.RESET} {h['header']:<35}{val_str}")
                else:
                    tag = f"{C.RED}[CRITICAL]{C.RESET}" if h['critical'] else f"{C.YELLOW}[OPTIONAL]{C.RESET}"
                    print(f"  {C.RED}✗{C.RESET} {h['header']:<35} {tag}  {C.DIM}{h['risk']}{C.RESET}")

        # ── PHASE 4: USER ENUMERATION ────────────────────────────────────────
        self._section(4, TOTAL_PHASES, "User Enumeration")

        users = self.enumerate_users(base_url)
        if users:
            print(f"  {C.RED}⚠{C.RESET} {C.BOLD}{len(users)} user(s) enumerated:{C.RESET}")
            for u in users:
                print(f"     {C.YELLOW}•{C.RESET} {u['username']}  {C.DIM}[{u['method']}]"
                      f"{(' - '+u['extra']) if u.get('extra') else ''}{C.RESET}")
        else:
            print(f"  {C.GREEN}✓{C.RESET} User enumeration blocked or no users exposed")

        # ── PHASE 5: XML-RPC ─────────────────────────────────────────────────
        self._section(5, TOTAL_PHASES, "XML-RPC")

        xmlrpc_findings = self.test_xmlrpc(base_url)
        if not xmlrpc_findings:
            print(f"  {C.GREEN}✓{C.RESET} xmlrpc.php not accessible")
        else:
            for f in xmlrpc_findings:
                sev = sev_color(f['severity'])
                print(f"  {C.YELLOW}⚠{C.RESET} {sev}  {f['desc']}")
                if self.verbosity >= 1 and f.get('methods'):
                    print(f"     {C.DIM}Methods (first 10): {', '.join(f['methods'])}{C.RESET}")

        # ── PHASE 6: HARDENING CHECKS ────────────────────────────────────────
        self._section(6, TOTAL_PHASES, "Hardening Checks")

        hardening_issues = self.check_hardening(base_url)
        if not hardening_issues:
            print(f"  {C.GREEN}✓{C.RESET} No obvious hardening issues detected")
        else:
            for issue in hardening_issues:
                sev = sev_color(issue['severity'])
                print(f"  {C.YELLOW}⚠{C.RESET} {sev}  {issue['title']}")
                self.vprint(f"     {C.DIM}{issue['desc']}{C.RESET}", level=1)
                if self.verbosity >= 1 and issue.get('url'):
                    print(f"     {C.DIM}URL: {issue['url']}{C.RESET}")

        # ── PHASE 7: ENDPOINT DISCOVERY ──────────────────────────────────────
        self._section(7, TOTAL_PHASES, "Endpoint Discovery")

        print(f"  Verifying 403 global validity...", end=' ', flush=True)
        self.valid_403s = self.verify_403_validity(base_url)
        status_403 = (f"{C.GREEN}valid (404 for nonexistent){C.RESET}" if self.valid_403s
                      else f"{C.YELLOW}suspicious (403 for nonexistent){C.RESET}")
        print(status_403)
        print()

        all_interesting = []
        for category in self.endpoint_categories:
            try:
                results = self.scan_category(base_url, category)
                all_interesting.extend(results)
                delay = random.uniform(1, 3) if self.aggressive else random.uniform(2, 5)
                time.sleep(delay)
            except KeyboardInterrupt:
                print(f"\n  {C.YELLOW}⚠  Scan interrupted by user{C.RESET}")
                break
            except Exception as e:
                self.vprint(f"  {C.RED}✗{C.RESET} Error in {category}: {e}", level=1)

        # Endpoint results detail
        if all_interesting:
            print(f"  Found {C.BOLD}{len(all_interesting)}{C.RESET} interesting endpoint(s)")
            by_status = {}
            bypass_results = []
            for r in all_interesting:
                s = r['status_code']
                by_status.setdefault(s, []).append(r)
                bypass_results.extend(r.get('bypasses', []))

            # Full per-endpoint detail only at verbosity >= 1
            if self.verbosity >= 1:
                for status, results in by_status.items():
                    print(f"\n  {'─'*56}")
                    print(f"  STATUS {status}  ({len(results)} endpoint{'s' if len(results)>1 else ''})")
                    print(f"  {'─'*56}")
                    for r in results:
                        icon = "📁" if r.get('is_directory') else "📄"
                        print(f"\n  {icon} {r['endpoint']}")
                        print(f"     └─ {r.get('reason','N/A')}")
                        if r.get('verification'):
                            print(f"     └─ Verification: {r['verification']}")
                        if r.get('preview') and not r.get('is_false_positive'):
                            prev = r['preview'][:100].replace('\n',' ').strip()
                            print(f"     └─ Preview: {prev}...")
                        # Actions: only for non-403 and non-redirect, at verbosity >= 1
                        if status not in (301, 302, 403):
                            if r.get('download_command') and not r.get('is_directory'):
                                print(f"     └─ Download: {r['download_command']}")
                            else:
                                print(f"     └─ Curl    : {r['curl_command']}")
                        if r.get('bypasses'):
                            verified_bp = [b for b in r['bypasses'] if not b.get('needs_verification')]
                            check_bp    = [b for b in r['bypasses'] if b.get('needs_verification')]
                            if verified_bp:
                                print(f"\n     {C.GREEN}✓ VERIFIED BYPASSES ({len(verified_bp)}):{C.RESET}")
                                for bp in verified_bp:
                                    self._print_bypass_details(bp)
                            if check_bp:
                                print(f"\n     {C.YELLOW}⚠ BYPASSES NEEDING VERIFICATION ({len(check_bp)}):{C.RESET}")
                                for bp in check_bp:
                                    self._print_bypass_details(bp, show_warning=True)

                if bypass_results:
                    print(f"\n  {'─'*56}")
                    print(f"  403 BYPASS SUMMARY  ({len(bypass_results)} techniques worked)")
                    print(f"  {'─'*56}")
                    by_method = {}
                    for bp in bypass_results:
                        m = bp['method'].split('(')[0].strip()
                        by_method[m] = by_method.get(m, 0) + 1
                    for m, cnt in sorted(by_method.items(), key=lambda x: -x[1]):
                        print(f"    • {m}: {cnt}")
            else:
                # Default verbosity: just a compact status summary
                for status, results in sorted(by_status.items()):
                    paths = ', '.join(r['endpoint'] for r in results[:5])
                    more  = f" +{len(results)-5} more" if len(results) > 5 else ""
                    print(f"    {C.DIM}[{status}] {paths}{more}{C.RESET}")
        else:
            print(f"  {C.GREEN}✓{C.RESET} No interesting endpoints found in scan")

        # ── PHASE 8: SUMMARY ─────────────────────────────────────────────────
        self._section(8, TOTAL_PHASES, "Security Report Summary")

        # Collect all findings for scoring + summary detail
        summary_findings = []  # (severity, label, detail)

        for f in cve_findings:
            summary_findings.append((
                f['severity'],
                f"{f['slug']} {f['cve']}",
                f"CVSS {f['cvss']}  {f['desc']}",
            ))
        for f in xmlrpc_findings:
            summary_findings.append((
                f.get('severity','MEDIUM'),
                f"XML-RPC: {f['desc']}",
                '',
            ))
        for f in hardening_issues:
            summary_findings.append((
                f.get('severity','LOW'),
                f['title'],
                f.get('desc',''),
            ))
        for h in (header_findings or []):
            if not h['present'] and h['critical']:
                summary_findings.append((
                    'MEDIUM',
                    f"Missing header: {h['header']}",
                    h.get('risk',''),
                ))

        all_sev = [s for s, _, _ in summary_findings]
        counts = {s: all_sev.count(s) for s in ['CRITICAL','HIGH','MEDIUM','LOW']}
        counts['INFO'] = len(all_interesting)

        print(f"  {'═'*56}")
        for sev, cnt in [('CRITICAL',counts['CRITICAL']),('HIGH',counts['HIGH']),
                         ('MEDIUM',counts['MEDIUM']),('LOW',counts['LOW']),
                         ('INFO',counts['INFO'])]:
            if cnt > 0:
                color = (C.RED+C.BOLD if sev=='CRITICAL' else
                         C.RED if sev=='HIGH' else
                         C.YELLOW if sev=='MEDIUM' else
                         C.DIM if sev=='LOW' else C.CYAN)
                bar = '█' * min(cnt, 20)
                print(f"  {color}{sev:<10}{C.RESET}  {cnt:>3}  {color}{bar}{C.RESET}")
        print(f"  {'═'*56}")

        # List vulnerabilities by severity (INFO only at verbosity >= 1)
        sev_order = ['CRITICAL','HIGH','MEDIUM','LOW']
        shown = [(s,l,d) for s,l,d in summary_findings if s in sev_order]
        shown.sort(key=lambda x: sev_order.index(x[0]))
        if shown:
            print()
            for sev, label, detail in shown:
                color = (C.RED+C.BOLD if sev=='CRITICAL' else
                         C.RED if sev=='HIGH' else
                         C.YELLOW if sev=='MEDIUM' else C.DIM)
                print(f"  {color}[{sev}]{C.RESET}  {label}")
                if detail:
                    print(f"    {C.DIM}{detail}{C.RESET}")
        if self.verbosity >= 1 and all_interesting:
            print()
            for r in all_interesting:
                print(f"  {C.CYAN}[INFO]{C.RESET}  {r['endpoint']}  {C.DIM}{r.get('reason','')}{C.RESET}")

        print()
        if counts['CRITICAL'] > 0 or counts['HIGH'] > 0:
            print(f"  {C.RED}{C.BOLD}⚠  High-severity issues found - immediate action recommended{C.RESET}")
        elif counts['MEDIUM'] > 0:
            print(f"  {C.YELLOW}⚠  Medium-severity issues found - review and remediate{C.RESET}")
        else:
            print(f"  {C.GREEN}✓  No critical/high severity issues found{C.RESET}")

        if self.aggressive and os.environ.get('WPSCAN_API_TOKEN'):
            print(f"  {C.DIM}(Extended CVE lookup performed via WPScan API){C.RESET}")

        print()
        return all_interesting


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def _do_self_update():
    """
    Pull latest code from the git remote.
    Returns (ok: bool, output: str).
    """
    import subprocess
    repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        result = subprocess.run(
            ['git', 'pull'],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            timeout=60,
        )
        out = (result.stdout + result.stderr).strip()
        return result.returncode == 0, out
    except FileNotFoundError:
        return False, "git not found in PATH"
    except subprocess.TimeoutExpired:
        return False, "git pull timed out"
    except Exception as e:
        return False, str(e)


def main():
    import argparse
    try:
        from wendy.update_db import auto_update_if_needed, run_db_update, DB_PATH
    except ImportError:
        from update_db import auto_update_if_needed, run_db_update, DB_PATH

    parser = argparse.ArgumentParser(
        prog='wendy',
        description='WENDY - WordPress ENDpoint discoverY v0.3.0\nDognet Technologies srl | info@dognet.tech\nFor authorized security testing only.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('url', nargs='?', default=None,
                        help='Target WordPress URL (e.g. https://example.com)')
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        help='-v: verbose output  -vv: full debug output')
    parser.add_argument('--aggressive', action='store_true',
                        help='Aggressive mode: wider coverage, more checks, more workers')
    parser.add_argument('-u', '--update', action='store_true',
                        help='Update WENDY (git pull) and the CVE database, then exit '
                             '(or continue scanning if URL is also given)')
    args = parser.parse_args()

    if not args.url and not args.update:
        parser.print_help()
        sys.exit(0)

    # ── Validate target URL (before banner / network calls) ───────────────────
    if args.url:
        raw_url = args.url.strip()
        _parsed = urllib.parse.urlparse(raw_url if '://' in raw_url else 'https://' + raw_url)
        _host   = _parsed.hostname or ''   # lowercase, strips port
        # Must be http/https, have a hostname, and look like "label.tld"
        # (at least one char before the dot, at least two after)
        _valid  = (
            _parsed.scheme in ('http', 'https')
            and bool(_host)
            and bool(re.match(r'^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?\.[a-z]{2,}$', _host))
        )
        if not _valid:
            print(f"\n  ✗  Invalid target: {raw_url!r}")
            print(f"     URL must start with http:// or https:// and include a valid domain.")
            print(f"     Example: https://example.com\n")
            sys.exit(1)

    verbosity = min(args.verbose, 2)

    # ── Banner ────────────────────────────────────────────────────────────────
    print("=" * 72)
    print()
    print("    :::       ::: :::::::::: ::::    ::: :::::::::  :::   :::")
    print("   :+:       :+: :+:        :+:+:   :+: :+:    :+: :+:   :+:")
    print("  +:+       +:+ +:+        :+:+:+  +:+ +:+    +:+  +:+ +:+")
    print(" +#+  +:+  +#+ +#++:++#   +#+ +:+ +#+ +#+    +:+   +#++:")
    print("+#+ +#+#+ +#+ +#+        +#+  +#+#+# +#+    +#+    +#+")
    print("#+#+# #+#+#  #+#        #+#   #+#+# #+#    #+#    #+#")
    print("###   ###   ########## ###    #### #########     ###")
    print()
    print("  WENDY - WordPress ENDpoint discoverY  v0.3.0")
    print("  Dognet Technologies srl | info@dognet.tech")
    print("  For Authorized Security Testing Only")
    print()
    print("=" * 72)

    # ── Explicit update (-u / --update) ──────────────────────────────────────
    if args.update:
        print(f"\n{C.BOLD}  [UPDATE] WENDY self-update{C.RESET}")
        print(f"  {'─'*56}")

        print(f"  Pulling latest code from git...", end=' ', flush=True)
        ok, out = _do_self_update()
        if ok:
            # Show only first meaningful line (e.g. "Already up to date." or "Updating abc..def")
            first_line = out.splitlines()[0] if out else 'done'
            print(f"{C.GREEN}{first_line}{C.RESET}")
        else:
            print(f"{C.YELLOW}warning: {out}{C.RESET}")

        print(f"\n  Updating CVE database from Wordfence Intelligence...")
        ok_db, msg_db = run_db_update(path=DB_PATH, verbose=False)
        if ok_db:
            print(f"  {C.GREEN}✓{C.RESET}  {msg_db}")
        else:
            print(f"  {C.YELLOW}⚠{C.RESET}  {msg_db}")

        print()
        if not args.url:
            sys.exit(0 if ok_db else 1)

    # ── Auto-update CVE DB silently if needed (weekly) ────────────────────────
    if not args.update:
        # Only auto-update when doing a normal scan (not already done above)
        auto_update_if_needed(path=DB_PATH, verbose=False)

    if not args.url:
        sys.exit(0)

    scanner = EndpointDiscovery(verbosity=verbosity, aggressive=args.aggressive)
    scanner.run_full_scan(args.url)


if __name__ == '__main__':
    main()
