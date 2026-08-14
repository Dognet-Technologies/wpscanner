"""
WENDY API Key & Probe Config Loader

Reads wendy/.keys (KEY=VALUE format) and injects values into os.environ.
Environment variables already set take precedence over the file.

Supported keys:
    WORDFENCE_API_KEY       — Wordfence Intelligence v3 feed (required for -u)
    WPSCAN_API_TOKEN        — WPScan API (required for --aggressive CVE lookup)

Probe tuning (all optional, see .keys.example for defaults):
    MIN_ACTIVE_INSTALLS     — skip plugins below this install count in normal mode
    PROBE_NORMAL_LIMIT      — max plugins probed in normal mode
    PROBE_THEME_LIMIT       — max themes probed in normal mode
    INSTALLS_INDEX_LIMIT    — how many plugins to index from WordPress.org
    CVE_YEARS               — comma-separated years considered "recent" for scoring
"""

import os

# Single source of truth for the WENDY version — imported by endpoint_discovery.py
# and update_db.py so it can never drift out of sync between the two entry points.
# Bump per SemVer: PATCH for fixes only, MINOR for a backward-compatible feature
# add/remove, MAJOR for a breaking change (core engine rewrite, dropped feature,
# incompatible CLI/config format).
__version__ = "0.5.0"

_KEYS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.keys')

# Defaults for all probe tuning parameters
PROBE_DEFAULTS = {
    'MIN_ACTIVE_INSTALLS':   0,              # 0 = no filter
    'PROBE_NORMAL_LIMIT':    3000,
    'PROBE_THEME_LIMIT':     100,
    'INSTALLS_INDEX_LIMIT':  10000,
    'CVE_YEARS':             '2024,2025,2026',
}


def load_keys(path=None):
    """
    Load API keys and probe tuning from the .keys file into os.environ.

    Lines starting with # are treated as comments and ignored.
    Blank lines are ignored.
    Each valid line must be in KEY=VALUE format.
    Environment variables already set take precedence.
    """
    keys_path = path or _KEYS_FILE
    if not os.path.isfile(keys_path):
        return

    with open(keys_path, encoding='utf-8') as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' not in line:
                continue
            key, _, value = line.partition('=')
            key   = key.strip()
            value = value.strip()
            if key and value and key not in os.environ:
                os.environ[key] = value


def load_probe_config():
    """
    Read probe tuning parameters from os.environ (populated by load_keys).

    Returns a dict with typed values:
        min_active_installs  (int)  – skip plugins below this installs count
        probe_normal_limit   (int)  – max plugins in normal mode probe list
        probe_theme_limit    (int)  – max themes in normal mode probe list
        installs_index_limit (int)  – how many plugins to index from WP.org
        cve_years            (set)  – set of recent CVE years (ints)
    """
    def _int(key):
        try:
            return int(os.environ.get(key, PROBE_DEFAULTS[key]))
        except (ValueError, TypeError):
            return int(PROBE_DEFAULTS[key])

    def _str(key):
        return os.environ.get(key, PROBE_DEFAULTS[key])

    raw_years = _str('CVE_YEARS')
    cve_years = set()
    for y in raw_years.split(','):
        y = y.strip()
        if y.isdigit():
            cve_years.add(int(y))

    return {
        'min_active_installs':   _int('MIN_ACTIVE_INSTALLS'),
        'probe_normal_limit':    _int('PROBE_NORMAL_LIMIT'),
        'probe_theme_limit':     _int('PROBE_THEME_LIMIT'),
        'installs_index_limit':  _int('INSTALLS_INDEX_LIMIT'),
        'cve_years':             cve_years or {2024, 2025, 2026},
    }
