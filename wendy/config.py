"""
WENDY API Key Loader

Reads wendy/.keys (KEY=VALUE format) and injects values into os.environ.
Environment variables already set take precedence over the file.

Supported keys:
    WORDFENCE_API_KEY   — Wordfence Intelligence v3 feed (required for CVE DB update)
    WPSCAN_API_TOKEN    — WPScan API (required for --aggressive CVE lookup)
"""

import os

_KEYS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.keys')


def load_keys(path=None):
    """
    Load API keys from the .keys file into os.environ (if not already set).

    Lines starting with # are treated as comments and ignored.
    Blank lines are ignored.
    Each valid line must be in KEY=VALUE format.
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
