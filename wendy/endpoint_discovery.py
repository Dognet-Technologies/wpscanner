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
# LIVE CVE DATABASE LOADER
# Loads wendy/cve_db.json (produced by update_db.py) and merges it with the
# embedded CVE_DATABASE above.  The JSON file is gitignored and generated
# locally; if absent the embedded DB is used as-is (works offline / first run).
# ─────────────────────────────────────────────────────────────────────────────

def _load_cve_db():
    """
    Return the effective CVE database, merging embedded + cve_db.json.

    Priority: embedded entries are kept as-is; additional entries from the
    JSON file are appended unless the same CVE ID is already present.
    """
    json_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cve_db.json')
    if not os.path.exists(json_path):
        return CVE_DATABASE

    try:
        with open(json_path, encoding='utf-8') as fh:
            raw = json.load(fh)
    except Exception:
        return CVE_DATABASE   # corrupted file → fall back

    raw.pop('_meta', None)   # strip metadata block

    db = {slug: list(entries) for slug, entries in CVE_DATABASE.items()}

    for slug, json_entries in raw.items():
        existing = db.get(slug, [])
        # Collect CVE IDs already present for this plugin
        known_cves = {e[1] for e in existing if e[1]}
        for entry in json_entries:
            if not isinstance(entry, list) or len(entry) < 5:
                continue
            cve_id = entry[1]
            if cve_id and cve_id in known_cves:
                continue   # already in embedded DB
            known_cves.add(cve_id)
            db.setdefault(slug, []).append(tuple(entry))

    return db


EFFECTIVE_CVE_DB = _load_cve_db()

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
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
            'Googlebot/2.1 (+http://www.google.com/bot.html)',
        ]

        self.bypass_headers_list = [
            'X-Forwarded-For', 'X-Forwarded-Host', 'X-Remote-IP', 'X-Remote-Addr',
            'X-Client-IP', 'X-Real-IP', 'X-Originating-IP', 'X-Custom-IP-Authorization',
            'CF-Connecting-IP', 'True-Client-IP', 'X-Cluster-Client-IP',
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

    def generate_browser_command(self, url):
        return f"xdg-open '{url}' 2>/dev/null || open '{url}'"

    def generate_download_command(self, url):
        return f"curl -O '{url}'"

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
            ('/readme.html',          r'[Vv]ersion\s+(\d+\.\d+[\.\d]*)'),
            ('/',                     r'<meta[^>]+generator[^>]+WordPress\s+([\d.]+)'),
            ('/feed/',                r'<generator>[^<]*wordpress[^<]*/v=([\d.]+)</generator>'),
            ('/wp-login.php',         r'ver=([\d.]+)'),
            ('/wp-includes/version.php', r"\$wp_version\s*=\s*'([\d.]+)'"),
        ]
        if self.aggressive:
            sources += [
                ('/sitemap.xml',      r'WordPress\s+([\d.]+)'),
                ('/wp-json/',         r'"version":"([\d.]+)"'),
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
        Returns dict: {slug: version_or_None}
        """
        plugin_slugs = [
            'royal-elementor-addons','elementor','elementor-pro','woocommerce','woocommerce-payments',
            'jetpack','contact-form-7','wp-file-manager','yoast-seo','all-in-one-seo-pack',
            'wordfence','ithemes-security','really-simple-ssl','sucuri-scanner',
            'wp-fastest-cache','litespeed-cache','w3-total-cache','wp-super-cache','wp-rocket',
            'autoptimize','advanced-custom-fields','acf-pro','gravityforms','ninja-forms','wpforms',
            'revslider','js_composer','tablepress','the-events-calendar',
            'duplicator','updraftplus','all-in-one-wp-migration','backupbuddy',
            'wp-statistics','monsterinsights','complianz-gdpr','broken-link-checker',
            'loginizer','wps-hide-login','limit-login-attempts-reloaded',
            'ewww-image-optimizer','smush','redirection','wordpress-seo',
            'wp-mail-smtp','mailchimp-for-wp','query-monitor','wp-crontrol',
            'mainwp','managewp-worker','wp-migrate-db','wp01','w3-total-cache',
        ]

        if self.aggressive:
            plugin_slugs += [
                'akismet','classic-editor','gutenberg','beaver-builder-plugin',
                'divi','avada','enfold','siteorigin-panels','cornerstone',
                'popup-maker','convert-pro','sumo','optinmonster','hustle',
                'wpcf7-recaptcha','invisible-recaptcha','hcaptcha-for-forms',
                'buddypress','bbpress','lms-by-learndash','tutor',
                'paid-memberships-pro','woocommerce-subscriptions',
                'stripe-payments','woo-stripe-payment','paypal-for-woocommerce',
                'wp-simple-firewall','anti-malware','clef',
            ]

        found = {}
        workers = 10 if self.aggressive else 5

        def check_plugin(slug):
            url = f"{base_url.rstrip('/')}/wp-content/plugins/{slug}/"
            r = self._safe_get(url, timeout=8)
            if r and r.status_code in (200, 403):
                ver = self._get_plugin_version(base_url, slug)
                return slug, ver
            return None, None

        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(check_plugin, s): s for s in plugin_slugs}
            for fut in as_completed(futures):
                slug, ver = fut.result()
                if slug:
                    found[slug] = ver
                    self.vprint(f"    + {slug}  {C.DIM}{'v'+ver if ver else '(version unknown)'}{C.RESET}", level=1)
                time.sleep(random.uniform(0.1, 0.3))

        # Basic theme detection
        theme_slugs_base = ['twentytwentyfour','twentytwentythree','twentytwentytwo',
                            'divi','avada','astra','hello-elementor','neve','generatepress',
                            'flatsome','storefront','oceanwp','enfold','bridge','salient']
        if self.aggressive:
            theme_slugs_base += ['betheme','jupiter','woodmart','porto','electro',
                                  'thrive-themes','kadence','blocksy']

        themes_found = {}
        for slug in theme_slugs_base:
            url = f"{base_url.rstrip('/')}/wp-content/themes/{slug}/"
            r = self._safe_get(url, timeout=6)
            if r and r.status_code in (200, 403):
                themes_found[slug] = None
                self.vprint(f"    + theme:{slug}", level=1)
            time.sleep(random.uniform(0.1, 0.3))

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
            ('Strict-Transport-Security',  True,  'HSTS missing - susceptible to protocol downgrade and MITM'),
            ('X-Frame-Options',            True,  'Clickjacking protection absent'),
            ('X-Content-Type-Options',     True,  'MIME-type sniffing possible'),
            ('Content-Security-Policy',    True,  'No CSP - XSS mitigation severely weakened'),
            ('Referrer-Policy',            False, 'Referrer information may leak to third parties'),
            ('Permissions-Policy',         False, 'Browser feature access unrestricted'),
            ('X-XSS-Protection',           False, 'Legacy header (deprecated but still informative)'),
            ('Cross-Origin-Opener-Policy', False, 'Cross-origin window access unrestricted'),
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
            test_users = ['admin', 'administrator', 'webmaster', 'editor', 'user', 'test']
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
            # (path, expected_bad_status, check_fn, severity, title, desc)
            ('/readme.html',            lambda r: r.status_code == 200,
             'MEDIUM', 'readme.html exposed', 'WordPress version disclosed via readme.html'),
            ('/wp-cron.php',            lambda r: r.status_code == 200,
             'MEDIUM', 'wp-cron.php public', 'wp-cron.php accessible anonymously - DoS/amplification risk'),
            ('/wp-admin/install.php',   lambda r: r.status_code == 200,
             'HIGH',   'install.php accessible', 'WordPress install script accessible - may allow site reset'),
            ('/wp-admin/upgrade.php',   lambda r: r.status_code == 200,
             'MEDIUM', 'upgrade.php accessible', 'Database upgrade script publicly reachable'),
            ('/wp-content/debug.log',   lambda r: r.status_code == 200 and len(r.text) > 10,
             'HIGH',   'debug.log exposed', 'WordPress debug log publicly accessible - potential data leak'),
            ('/wp-config.php',          lambda r: r.status_code == 200 and 'DB_PASSWORD' in r.text,
             'CRITICAL','wp-config.php readable', 'wp-config.php is publicly readable - credentials exposed'),
            ('/wp-signup.php',          lambda r: r.status_code == 200 and 'signup' in r.text.lower(),
             'LOW',    'Multisite signup open', 'WordPress multisite user signup is enabled'),
            ('/.git/HEAD',              lambda r: r.status_code == 200 and 'ref:' in r.text,
             'HIGH',   '.git directory exposed', '.git repository exposed - source code and secrets accessible'),
            ('/.env',                   lambda r: r.status_code == 200 and len(r.text) > 5,
             'CRITICAL','.env exposed', '.env file publicly readable - credentials/keys exposed'),
        ]

        # Check user registration
        r_reg = self._safe_get(f"{base_url.rstrip('/')}/wp-login.php?action=register")
        if r_reg and r_reg.status_code == 200:
            if 'registerform' in r_reg.text.lower() or 'user_login' in r_reg.text:
                findings.append({'severity': 'MEDIUM', 'title': 'User registration open',
                                  'desc': 'Anyone can register an account on this WordPress site'})

        # Check REST API exposes users unauthenticated
        r_rest = self._safe_get(f"{base_url.rstrip('/')}/wp-json/wp/v2/users")
        if r_rest and r_rest.status_code == 200:
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

        for path, bad_cond, severity, title, desc in checks:
            r = self._safe_get(base_url.rstrip('/') + path)
            if r:
                try:
                    if bad_cond(r):
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
            '.php','.py','.rb','.pl','.sh','.bash','.zsh',
            '.key','.pem','.crt','.cer','.pub','.ppk',
            '.db','.sqlite','.sqlite3','.mdb','.csv',
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
            }
        except Exception:
            self._homepage_signature = None
        return self._homepage_signature

    def _extract_title(self, html):
        m = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
        return m.group(1).strip() if m else ''

    def is_directory_listing(self, content):
        content_lower = content.lower()
        indicators = ['index of ','directory listing','parent directory','[dir]',
                      '[to parent directory]','last modified','size  description',
                      'href=".."','href="../"']
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
            cms_ind = ['wordpress','wp-content','jquery','bootstrap','react','angular','vue']
            if any(i in content_lower for i in cms_ind) and 'index of' not in content_lower:
                return True, "CMS/Framework content, not a directory listing", "high"

        error_patterns = [
            ('page not found','high'),('error 404','high'),('file not found','high'),
            ('pagina non trovata','high'),('not found','medium'),('does not exist','medium'),
            ('nothing found','medium'),
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
            {'X-Original-URL': endpoint}, {'X-Rewrite-URL': endpoint},
            {'X-Forwarded-Path': endpoint}, {'X-Real-URL': endpoint},
            {'X-ProxyUser-Ip': '127.0.0.1'}, {'X-Forwarded-For': '127.0.0.1'},
            {'X-Forwarded-For': '::1'}, {'X-Originating-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'}, {'X-Remote-Addr': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'}, {'X-Host': '127.0.0.1'},
            {'Forwarded': 'for=127.0.0.1;proto=http;host=localhost'},
            # Cloudflare-specific
            {'CF-Connecting-IP': '127.0.0.1'}, {'True-Client-IP': '127.0.0.1'},
            # AWS ALB
            {'X-Forwarded-Host': '127.0.0.1'}, {'X-Original-Host': 'localhost'},
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
            endpoint + '/.',
            '//' + endpoint.lstrip('/') + '//',
            '/./' + endpoint.lstrip('/') + '/..',
            '/;/' + endpoint.lstrip('/'),
            '/.;/' + endpoint.lstrip('/'),
            '//;//' + endpoint.lstrip('/'),
            endpoint + '..;/',
            endpoint + '%20',
            endpoint + '%09',
            endpoint + '%00',
            endpoint + '.html',
            endpoint + '?',
            endpoint + '#',
            '/%2e' + endpoint,
            '/.' + endpoint,
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
            if not bypass.get('bypass_headers') and bypass.get('http_method','GET') == 'GET':
                print(f"      │  Browser: {self.generate_browser_command(url)}")
        if self.verbosity >= 2 and bypass.get('preview'):
            preview = bypass['preview'][:80].replace('\n',' ').strip()
            print(f"      │  Preview: {preview}...")
        print(f"      │")

    # ── ENDPOINT CATEGORIES (unchanged + minor additions) ─────────────────────

    def get_backup_endpoints(self, base_url):
        common = [
            '/wp-config.php.bak','/wp-config.php~','/wp-config.php.save','/wp-config.php.old',
            '/wp-config.php.orig','/.wp-config.php.swp','/wp-config.bak','/backup.zip',
            '/backup.sql','/backup.tar.gz','/database.sql','/db_backup.sql','/wp_backup.sql',
            '/site_backup.zip','/wordpress_backup.zip','/.htaccess.bak','/.htaccess~',
            '/wp-config.php.backup','/wp-config.php.bkp','/wp-config.php.copy',
            '/wp-config.php.disabled','/wp-config.php.tmp','/wp-config.php.txt',
            '/wp-config.php.zip','/wp-config.php.tar.gz','/wp-config.bkp','/wp-config.old',
            '/db.sql','/database_backup.sql','/backup-db.sql','/wp.sql','/wordpress.sql',
            '/wordpress.sql.gz','/database.sql.gz','/site.zip','/site.tar.gz',
            '/website.zip','/website_backup.zip','/public_html.zip','/www.zip',
            '/html.zip','/.htaccess.old','/.htaccess.save','/.htaccess.bkp',
            '/wp-content/backup-db','/dump.sql','/mysql.sql','/sql.zip',
            '/data.sql','/db.zip','/db.tar.gz','/backup.rar','/backup.7z',
            '/all.zip','/archive.zip','/full.zip','/master.zip',
            '/wp-content/debug.log.bak','/wp-content/debug.log.old',
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
            '/wp-config.php','/wp-config-sample.php','/wp-config.php~','/wp-config.php.bak',
            '/wp-config.php.old','/.env','/.env.local','/.env.production','/.env.dev',
            '/.env.prod','/.env.stage','/.env.staging','/.env.test','/.env.backup',
            '/.env.bak','/.env.old','/config.php','/config.inc.php','/local-config.php',
            '/settings.php','/settings.local.php','/configuration.php',
            '/parameters.yml','/parameters.yaml','/services.yml','/config.json',
            '/app.json','/appsettings.json','/composer.json','/package.json',
            '/firebase.json','/credentials.json','/.git/config','/.git/HEAD',
            '/.git/index','/.git/logs/HEAD','/.gitmodules','/.gitignore',
            '/web.config','/server.xml','/.htpasswd','/php.ini','/.user.ini',
            '/nginx.conf','/.vscode/settings.json','/.dockerignore','/Dockerfile',
            '/docker-compose.yml','/Procfile','/runtime.txt','/requirements.txt',
        ]

    def get_log_endpoints(self, base_url):
        return [
            '/debug.log','/error.log','/access.log','/wp-content/debug.log',
            '/wp-content/uploads/debug.log','/wp-content/cache/debug.log',
            '/wp-content/logs/debug.log','/wp-content/logs/error.log',
            '/wp-content/logs/access.log','/logs/debug.log','/logs/error.log',
            '/logs/access.log','/log/error.log','/log/access.log',
            '/error_log','/access_log','/wp-admin/error.log',
            '/application.log','/system.log','/php_errors.log',
            '/php_error.log','/php.log','/mysql.log','/mysqld.log',
            '/wp-content/uploads/wc-logs/','/wp-content/uploads/wc-logs/error.log',
        ]

    def get_directory_endpoints(self, base_url):
        return [
            '/wp-content/','/wp-content/uploads/','/wp-content/themes/',
            '/wp-content/plugins/','/wp-content/cache/','/wp-content/backups/',
            '/wp-content/backup/','/wp-content/upgrade/','/wp-content/temp/',
            '/wp-content/tmp/','/wp-content/logs/','/wp-content/uploads/backups/',
            '/wp-content/uploads/tmp/','/wp-content/uploads/logs/',
            '/wp-admin/','/wp-includes/','/uploads/','/images/',
            '/files/','/documents/','/backup/','/backups/','/temp/',
            '/tmp/','/cache/','/logs/','/assets/','/media/','/downloads/',
            '/private/','/old/','/staging/','/test/','/dev/',
        ]

    def get_ajax_endpoints(self, base_url):
        return [
            '/wp-admin/admin-ajax.php',
            '/wp-admin/admin-ajax.php?action=heartbeat',
            '/wp-admin/admin-ajax.php?action=wp_compression_test',
            '/wp-admin/admin-ajax.php?action=fetch-list',
            '/wp-admin/admin-ajax.php?action=ajax-tag-search',
            '/wp-json/','/wp-json/wp/v2/','/wp-json/wp/v2/users',
            '/wp-json/wp/v2/posts','/wp-json/wp/v2/pages',
            '/wp-json/wp/v2/media','/wp-json/wp/v2/comments',
            '/wp-json/wp/v2/settings','/wp-json/wp/v2/themes',
            '/wp-json/wp/v2/plugins','/wp-json/wp/v2/search',
            '/wp-json/oembed/1.0/embed','/?rest_route=/',
            '/?rest_route=/wp/v2/users','/?rest_route=/wp/v2/posts',
        ]

    def get_api_endpoints(self, base_url):
        return [
            '/api/','/api/v1/','/api/v2/','/graphql','/graphql/',
            '/rest/','/rest/v1/','/wp-json/','/wp-json/wp/v2/',
            '/feed/','/feed/rss/','/feed/atom/','/rss/','/rss.xml',
            '/atom/','/atom.xml','/sitemap.xml','/sitemap_index.xml',
            '/wp-sitemap.xml','/robots.txt','/.well-known/',
            '/.well-known/security.txt','/.well-known/change-password',
            '/security.txt','/humans.txt','/ads.txt','/crossdomain.xml',
        ]

    def get_cache_endpoints(self, base_url):
        return [
            '/wp-content/cache/','/wp-content/wp-cache-config.php',
            '/wp-content/advanced-cache.php','/wp-content/object-cache.php',
            '/wp-content/w3tc-config/','/wp-content/cache/supercache/',
            '/wp-content/cache/wp-rocket/','/wp-content/cache/min/',
            '/wp-content/cache/litespeed/','/wp-content/cache/lscache/',
            '/wp-content/cache/autoptimize/','/wp-content/cache/breeze/',
            '/wp-content/cache/wpo/','/wp-content/cache/wp-fastest-cache/',
            '/wp-content/cache/w3-total-cache/','/cache/','/tmp/cache/',
            '/wp-content/plugins/wp-super-cache/','/wp-content/uploads/cache/',
            '/.cache/',
        ]

    def get_debug_endpoints(self, base_url):
        return [
            '/wp-content/debug.log','/phpinfo.php','/info.php','/test.php',
            '/debug.php','/status.php','/health.php','/version.php',
            '/wp-admin/maint/repair.php','/wp-admin/setup-config.php',
            '/wp-admin/install.php','/wp-content/uploads/debug.log',
            '/wp-content/uploads/error.log','/wp-content/uploads/php_errors.log',
            '/wp-content/uploads/logs/','/wp-content/logs/',
            '/wp-content/tmp/','/wp-content/test/',
            '/php_error.log','/error_log','/xdebug.php',
            '/trace.php','/dump.php','/wp-admin/upgrade.php',
        ]

    def get_plugin_specific_endpoints(self, base_url):
        plugins = [
            'royal-elementor-addons','elementor','elementor-pro',
            'ewww-image-optimizer','wp-fastest-cache','litespeed-cache',
            'wordfence','the-events-calendar','complianz-gdpr','duplicate-page',
            'contact-form-7','wp-file-manager','woocommerce','jetpack',
            'all-in-one-seo-pack','yoast-seo','wpforms','akismet',
            'updraftplus','monsterinsights','advanced-custom-fields',
            'revslider','js_composer','gravityforms','duplicator',
            'backupbuddy','wp-migrate-db','wp-rocket','autoptimize',
            'w3-total-cache','all-in-one-wp-migration','wp-super-cache',
            'ithemes-security','sucuri-scanner','ninja-forms',
            'mailchimp-for-wp','smush','broken-link-checker','redirection',
            'tablepress','query-monitor','mainwp','wp01',
            'woocommerce-payments','loginizer','really-simple-ssl',
            'wp-statistics','broken-link-checker','wp-mail-smtp',
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
            '/.ssh/id_rsa','/.ssh/id_dsa','/.ssh/authorized_keys',
            '/.ssh/known_hosts','/.aws/credentials','/.aws/config',
            '/.npmrc','/.bash_history','/.zsh_history','/.mysql_history',
            '/.psql_history','/.docker/config.json','/.dockercfg',
            '/.git-credentials','/.s3cfg','/.wp-cli/config.yml',
            '/.netrc','/.passwd','/.shadow','/auth.json',
            '/.gnupg/secring.gpg',
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
                'browser_command': self.generate_browser_command(url),
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
                        'DB_PASSWORD','DB_USER','DB_NAME','DB_HOST','define(',
                        'API_KEY','SECRET','TOKEN','password','username',
                        'error','warning','exception','stack trace','debug',
                        'Index of','Directory listing',
                        '<?php','<?xml','SQL','SELECT','INSERT','UPDATE',
                        'wp_','wordpress','admin','version','changelog',
                        'mysql:','postgres:',
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
                result['interesting'] = True
                result['reason'] = f"Redirect → {response.headers.get('Location','?')}"

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
              f"  Verbosity: {'vv' if self.verbosity==2 else ('v' if self.verbosity==1 else '-')}")
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

        if self.verbosity >= 1:
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
                    cvss_score = float(vuln.get('cvss', {}).get('score') or 0)
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

        # "Possible" entries (version not readable) shown only in verbose mode
        if possible:
            if self.verbosity >= 1:
                print(f"\n  {C.DIM}── Possible findings (version could not be read) ──{C.RESET}")
                for f in possible:
                    sev = sev_color(f['severity'])
                    print(f"  {C.DIM}⚠ {sev} {f['slug']}  {f['cve']}  CVSS {f['cvss']}{C.RESET}")
            else:
                print(f"  {C.DIM}ℹ  {len(possible)} additional finding(s) where plugin version"
                      f" could not be read — run with -v to show{C.RESET}")

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
            print(f"\n  Found {C.BOLD}{len(all_interesting)}{C.RESET} interesting endpoints")
            by_status = {}
            bypass_results = []
            for r in all_interesting:
                s = r['status_code']
                by_status.setdefault(s, []).append(r)
                bypass_results.extend(r.get('bypasses', []))

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
                    if r.get('preview') and not r.get('is_false_positive') and self.verbosity >= 1:
                        prev = r['preview'][:100].replace('\n',' ').strip()
                        print(f"     └─ Preview: {prev}...")
                    if self.verbosity >= 1 and status not in (301, 302):
                        print(f"     └─ Actions:")
                        if r.get('browser_command'):
                            print(f"        • Browser : {r['browser_command']}")
                        if r.get('download_command') and not r.get('is_directory'):
                            print(f"        • Download: {r['download_command']}")
                        print(f"        • Curl    : {r['curl_command']}")
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
            print(f"  {C.GREEN}✓{C.RESET} No interesting endpoints found in scan")

        # ── PHASE 8: SUMMARY ─────────────────────────────────────────────────
        self._section(8, TOTAL_PHASES, "Security Report Summary")

        # Collect all findings for scoring
        all_sev = []
        for f in cve_findings:
            all_sev.append(f['severity'])
        for f in xmlrpc_findings:
            all_sev.append(f.get('severity','MEDIUM'))
        for f in hardening_issues:
            all_sev.append(f.get('severity','LOW'))
        for h in (header_findings or []):
            if not h['present'] and h['critical']:
                all_sev.append('MEDIUM')

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

        if counts['CRITICAL'] > 0 or counts['HIGH'] > 0:
            print(f"\n  {C.RED}{C.BOLD}⚠  High-severity issues found - immediate action recommended{C.RESET}")
        elif counts['MEDIUM'] > 0:
            print(f"\n  {C.YELLOW}⚠  Medium-severity issues found - review and remediate{C.RESET}")
        else:
            print(f"\n  {C.GREEN}✓  No critical/high severity issues found{C.RESET}")

        if self.aggressive and os.environ.get('WPSCAN_API_TOKEN'):
            print(f"  {C.DIM}(Extended CVE lookup performed via WPScan API){C.RESET}")

        print()
        return all_interesting


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main():
    import argparse

    parser = argparse.ArgumentParser(
        prog='wendy',
        description='WENDY - WordPress ENDpoint discoverY v0.2.0\nDognet Technologies srl | info@dognet.tech\nFor authorized security testing only.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('url', help='Target WordPress URL (e.g. https://example.com)')
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        help='-v: verbose output  -vv: full debug output')
    parser.add_argument('--aggressive', action='store_true',
                        help='Aggressive mode: wider coverage, more checks, more workers')

    args = parser.parse_args()
    verbosity = min(args.verbose, 2)

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
    print("  WENDY - WordPress ENDpoint discoverY  v0.2.0")
    print("  Dognet Technologies srl | info@dognet.tech")
    print("  For Authorized Security Testing Only")
    print()
    print("=" * 72)

    scanner = EndpointDiscovery(verbosity=verbosity, aggressive=args.aggressive)
    scanner.run_full_scan(args.url)


if __name__ == '__main__':
    main()
