#!/usr/bin/env python3
"""
WENDY CVE Database Updater v0.3.0
Dognet Technologies srl | info@dognet.tech

Fetches WordPress plugin vulnerability data from Wordfence Intelligence v3
(token-based authentication required) and saves to wendy/cve_db.json.

Source: https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production/
License for data: https://www.wordfence.com/wordfence-intelligence-terms-and-conditions/

Authentication:
    Set the WORDFENCE_API_KEY environment variable to your Wordfence Intelligence
    API key before running. Obtain a free key from your Wordfence.com account
    under Account → Integrations.

Usage:
    WORDFENCE_API_KEY=your_key python -m wendy.update_db
    WORDFENCE_API_KEY=your_key python wendy/update_db.py   # full update
    WORDFENCE_API_KEY=your_key python wendy/update_db.py --dry-run

Intended to run weekly (cron or CI). The generated cve_db.json is gitignored
and must be regenerated locally after each clone.
"""

import json
import os
import re
import sys
import datetime
import argparse
import requests
from concurrent.futures import ThreadPoolExecutor as _TPE

# Load API keys from wendy/.keys before anything else reads os.environ
try:
    from wendy.config import load_keys, load_probe_config
except ImportError:
    from config import load_keys, load_probe_config
load_keys()
_PROBE_CFG = load_probe_config()

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────

FEED_URL = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production/"
DB_PATH  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cve_db.json")

# Only include CVEs at or above this CVSS score (0.0 = include all)
MIN_CVSS = 0.0

# WordPress.org public API (no auth required)
WP_ORG_PLUGIN_API            = "https://api.wordpress.org/plugins/info/1.2/"
WP_ORG_THEME_API             = "https://api.wordpress.org/themes/info/1.2/"
# Plugins indexed for installs data + scoring — configurable via INSTALLS_INDEX_LIMIT
# in wendy/.keys (see config.py); falls back to the same 10000 default.
WP_ORG_POPULAR_PLUGINS_LIMIT = _PROBE_CFG['installs_index_limit']
WP_ORG_POPULAR_THEMES_LIMIT  = 500     # themes cached for smart theme probing

_USER_AGENT = 'WENDY-Updater/0.3 (github.com/Dognet-Technologies/wpscanner)'

# ─────────────────────────────────────────────────────────────────────────────
# VERSION COMPARISON (mirrors EndpointDiscovery._parse_ver logic)
# ─────────────────────────────────────────────────────────────────────────────

def _parse_ver(v):
    """Parse a version string into a comparable tuple of ints."""
    parts = []
    for segment in re.split(r'[.\-_]', str(v)):
        m = re.match(r'(\d+)', segment)
        if m:
            parts.append(int(m.group(1)))
    return tuple(parts) or (0,)


def _max_version(versions):
    """Return the lexicographically max version from a list of version strings."""
    if not versions:
        return None
    result = versions[0]
    for v in versions[1:]:
        a = _parse_ver(result)
        b = _parse_ver(v)
        length = max(len(a), len(b))
        a = a + (0,) * (length - len(a))
        b = b + (0,) * (length - len(b))
        if b > a:
            result = v
    return result


# ─────────────────────────────────────────────────────────────────────────────
# WORDPRESS.ORG POPULAR LIST  (no auth – public API)
# ─────────────────────────────────────────────────────────────────────────────

def fetch_popular_wp_org(kind='plugin', limit=10000, timeout=30):
    """Fetch top N popular plugins or themes from WordPress.org (no auth required).

    kind  : 'plugin' or 'theme'
    limit : maximum number of entries to return
    Returns a dict  { slug: active_installs }  ordered by active_installs desc.
    On any network error returns an empty dict rather than raising.

    The dict preserves insertion order (Python 3.7+), so iteration is always
    highest → lowest installs.
    """
    api_url  = WP_ORG_PLUGIN_API if kind == 'plugin' else WP_ORG_THEME_API
    action   = 'query_plugins'   if kind == 'plugin' else 'query_themes'
    item_key = 'plugins'         if kind == 'plugin' else 'themes'
    per_page = 100
    result   = {}   # {slug: active_installs}
    page     = 1

    while len(result) < limit:
        params = {
            'action':                            action,
            'request[per_page]':                 per_page,
            'request[page]':                     page,
            'request[browse]':                   'popular',
            'request[fields][active_installs]':  1,
            'request[fields][versions]':         0,
            'request[fields][banners]':          0,
            'request[fields][screenshots]':      0,
        }
        try:
            r = requests.get(
                api_url, params=params, timeout=timeout,
                headers={'User-Agent': _USER_AGENT},
            )
            r.raise_for_status()
            data = r.json()
        except Exception:
            break

        items = data.get(item_key, [])
        if not items:
            break

        for item in items:
            slug = item.get('slug', '').strip()
            if slug and slug not in result:
                try:
                    installs = int(item.get('active_installs') or 0)
                except (ValueError, TypeError):
                    installs = 0
                result[slug] = installs
                if len(result) >= limit:
                    break

        info        = data.get('info', {})
        total_pages = int(info.get('pages', 1))
        if page >= total_pages or len(result) >= limit:
            break
        page += 1

    return result


# ─────────────────────────────────────────────────────────────────────────────
# FEED FETCH
# ─────────────────────────────────────────────────────────────────────────────

def fetch_feed(timeout=90):
    """Fetch the full Wordfence Intelligence v3 vulnerability feed.

    Requires WORDFENCE_API_KEY to be set in os.environ (loaded from wendy/.keys
    or the environment before calling this function).
    """
    key = os.environ.get('WORDFENCE_API_KEY', '').strip()
    if not key:
        raise RuntimeError(
            "Wordfence API key required for v3 feed.\n"
            "  Add WORDFENCE_API_KEY=<your_key> to wendy/.keys\n"
            "  (copy wendy/.keys.example as a template).\n"
            "  Obtain a free key at: https://www.wordfence.com (Account → Integrations)"
        )

    print(f"  Fetching: {FEED_URL}")
    r = requests.get(
        FEED_URL,
        timeout=timeout,
        headers={
            'User-Agent':     'WENDY-Updater/0.3 (github.com/Dognet-Technologies/wpscanner)',
            'Accept':         'application/json',
            'Authorization':  f'Bearer {key}',
        }
    )
    if r.status_code == 401:
        raise RuntimeError(
            "HTTP 401 Unauthorized — API key is missing or invalid.\n"
            "  Check your WORDFENCE_API_KEY environment variable."
        )
    if r.status_code == 403:
        raise RuntimeError(
            "HTTP 403 Forbidden — API key does not have access to this feed."
        )
    if r.status_code == 429:
        raise RuntimeError(
            "HTTP 429 Too Many Requests — rate limit reached.\n"
            "  Wait before retrying, or contact wfi-support@wordfence.com for a higher limit."
        )
    if r.status_code == 410:
        raise RuntimeError(
            f"Feed returned HTTP 410 Gone — the Wordfence Intelligence endpoint\n"
            f"  has moved or been retired. Update FEED_URL in wendy/update_db.py.\n"
            f"  Current URL: {FEED_URL}"
        )
    r.raise_for_status()
    return r.json()


# ─────────────────────────────────────────────────────────────────────────────
# PARSING
# ─────────────────────────────────────────────────────────────────────────────

def parse_feed(data):
    """
    Parse Wordfence Intelligence feed into WENDY CVE_DATABASE format.

    Input structure per entry:
      {
        "id": "uuid",
        "title": "Plugin/Theme <= X.Y.Z - Vuln type",
        "software": [
          {
            "type": "plugin" | "theme",
            "slug": "slug",
            "affected_versions": {
              "* - 1.2.3": {
                "from_version": "*", "from_inclusive": true,
                "to_version":   "1.2.3", "to_inclusive": true
              }
            }
          }
        ],
        "cve":  "CVE-2024-XXXXX",   # may be null
        "cvss": {"score": 9.8, "rating": "critical", ...},
        "title": "...",
      }

    Output: (db_plugins, db_themes, skipped)
      db_plugins / db_themes : { slug: [[max_vuln, cve_id, severity, cvss_score, desc], ...] }
    """
    db_plugins = {}
    db_themes  = {}
    skipped    = 0

    for uid, vuln in data.items():
        if not isinstance(vuln, dict):
            continue

        software_list = vuln.get('software') or []
        for sw in software_list:
            if not isinstance(sw, dict):
                continue

            sw_type = sw.get('type', '')
            if sw_type not in ('plugin', 'theme'):
                continue

            slug = (sw.get('slug') or '').strip()
            if not slug:
                continue

            # ── Find max vulnerable version ───────────────────────────────
            concrete_to_versions = []

            for rng in (sw.get('affected_versions') or {}).values():
                to_ver = (rng.get('to_version') or '').strip()
                if not to_ver or to_ver == '*':
                    pass  # wildcard – no concrete upper bound
                else:
                    concrete_to_versions.append(to_ver)

            if not concrete_to_versions:
                # All versions affected / no concrete cap → skip (can't compare)
                skipped += 1
                continue

            max_vuln = _max_version(concrete_to_versions)

            # ── CVE / severity ────────────────────────────────────────────
            cve_id    = (vuln.get('cve') or '').strip()
            cvss_data = vuln.get('cvss')

            if isinstance(cvss_data, dict):
                severity = (cvss_data.get('rating') or 'medium').upper()
            else:
                severity = 'MEDIUM'
            if severity == 'NONE':
                severity = 'INFO'

            cvss_score = 0.0
            if isinstance(cvss_data, dict):
                try:
                    cvss_score = float(cvss_data.get('score') or 0)
                except (ValueError, TypeError):
                    cvss_score = 0.0

            if cvss_score < MIN_CVSS:
                skipped += 1
                continue

            desc  = (vuln.get('title') or '')[:150].strip()
            entry = [max_vuln, cve_id, severity, cvss_score, desc]

            if sw_type == 'theme':
                db_themes.setdefault(slug, []).append(entry)
            else:
                db_plugins.setdefault(slug, []).append(entry)

    return db_plugins, db_themes, skipped


# ─────────────────────────────────────────────────────────────────────────────
# AUTO-UPDATE HELPERS
# ─────────────────────────────────────────────────────────────────────────────

UPDATE_INTERVAL_DAYS = 7


def db_age_days(path=DB_PATH):
    """
    Return how many days ago the DB was last updated, or None if unknown.
    Reads the _meta.updated field from cve_db.json without loading the whole file.
    """
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding='utf-8') as f:
            raw = json.load(f)
        updated_str = raw.get('_meta', {}).get('updated', '')
        if not updated_str:
            return None
        updated_dt = datetime.datetime.strptime(updated_str, '%Y-%m-%dT%H:%M:%SZ')
        delta = datetime.datetime.utcnow() - updated_dt
        return delta.days
    except Exception:
        return None


def needs_update(path=DB_PATH, max_age_days=UPDATE_INTERVAL_DAYS):
    """Return True if the DB is absent or older than max_age_days."""
    if not os.path.exists(path):
        return True
    age = db_age_days(path)
    if age is None:
        return True
    return age >= max_age_days


def run_db_update(path=DB_PATH, verbose=True):
    """
    Fetch the Wordfence feed + WordPress.org popular lists and save to path.
    Returns (ok: bool, message: str).
    """
    # Fetch Wordfence CVE feed
    try:
        data = fetch_feed(timeout=90)
    except Exception as e:
        return False, f"Fetch failed: {e}"

    # Fetch WordPress.org installs index in parallel with theme list (best-effort;
    # fetch_popular_wp_org swallows network errors and returns {} on failure).
    if verbose:
        print("  Fetching installs index from WordPress.org...", end=' ', flush=True)
    with _TPE(max_workers=2) as ex:
        f_plugins = ex.submit(fetch_popular_wp_org, 'plugin', WP_ORG_POPULAR_PLUGINS_LIMIT)
        f_themes  = ex.submit(fetch_popular_wp_org, 'theme',  WP_ORG_POPULAR_THEMES_LIMIT)
        installs_index = f_plugins.result()
        themes_dict    = f_themes.result()
    popular_themes = list(themes_dict.keys())
    if verbose:
        print(f"done ({len(installs_index):,} plugins, {len(popular_themes):,} themes)", flush=True)

    try:
        db_plugins, db_themes, _ = parse_feed(data)
        meta = save_db(db_plugins, db_themes=db_themes, path=path,
                       installs_index=installs_index, popular_themes=popular_themes)
    except Exception as e:
        return False, f"Parse/save failed: {e}"

    total   = meta['entries']
    plugins = meta['plugins']
    themes  = meta.get('themes', 0)
    return True, (f"{plugins:,} plugins + {themes:,} themes, {total:,} CVE entries; "
                  f"{len(installs_index):,} plugins in installs index")


def auto_update_if_needed(path=DB_PATH, max_age_days=UPDATE_INTERVAL_DAYS, verbose=True):
    """
    Check if the CVE DB needs updating and do so automatically.

    verbose=True  → print status line(s) to stdout
    verbose=False → completely silent

    Returns (updated: bool, message: str).
    """
    if not needs_update(path, max_age_days):
        age = db_age_days(path)
        msg = f"CVE DB up to date (updated {age}d ago)"
        if verbose:
            print(f"  {msg}")
        return False, msg

    age = db_age_days(path)
    if age is None:
        reason = "not found" if not os.path.exists(path) else "timestamp unreadable"
    else:
        reason = f"last update {age}d ago"

    if verbose:
        print(f"  [CVE DB] Auto-updating ({reason})...", end=' ', flush=True)

    ok, msg = run_db_update(path=path, verbose=False)

    if verbose:
        if ok:
            print(f"done  ({msg})")
        else:
            print(f"FAILED  ({msg})")

    return ok, msg


# ─────────────────────────────────────────────────────────────────────────────
# SAVE / LOAD
# ─────────────────────────────────────────────────────────────────────────────

def save_db(db_plugins, db_themes=None, path=DB_PATH, source_url=FEED_URL,
            installs_index=None, popular_themes=None):
    """Serialize plugin/theme CVE databases and popularity data to JSON.

    Layout of cve_db.json:
      {
        "_meta": {
            source, updated, plugins, entries, themes, theme_entries,
            installs_index,    # {slug: active_installs} for top-N plugins
            popular_themes,    # [slug, ...] ordered by active_installs
            popular_updated
        },
        "_themes": { slug: [[max_vuln, cve_id, severity, cvss, desc], ...] },
        "<plugin-slug>": [ ... ],
        ...
      }

    installs_index : dict {slug: active_installs} from WordPress.org
    popular_themes : list of theme slugs ordered by active_installs
    """
    db_themes = db_themes or {}
    total_plugin_entries = sum(len(v) for v in db_plugins.values())
    total_theme_entries  = sum(len(v) for v in db_themes.values())
    now = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

    meta = {
        'source':        source_url,
        'updated':       now,
        'plugins':       len(db_plugins),
        'entries':       total_plugin_entries,
        'themes':        len(db_themes),
        'theme_entries': total_theme_entries,
    }
    if installs_index:   # only persist when WP.org fetch actually returned data
        meta['installs_index']  = installs_index    # {slug: N}
        meta['popular_themes']  = popular_themes or []
        meta['popular_updated'] = now

    payload = {'_meta': meta}
    if db_themes:
        payload['_themes'] = db_themes
    payload.update(db_plugins)

    with open(path, 'w', encoding='utf-8') as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    return meta


def load_db(path=DB_PATH):
    """Load cve_db.json and return (meta, db_plugins, db_themes)."""
    with open(path, encoding='utf-8') as f:
        raw = json.load(f)
    meta      = raw.pop('_meta',   {})
    db_themes = raw.pop('_themes', {})
    return meta, raw, db_themes


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Update WENDY CVE database from Wordfence Intelligence v3 feed'
    )
    parser.add_argument('--dry-run', action='store_true',
                        help='Fetch and parse but do not write cve_db.json')
    parser.add_argument('--output', default=DB_PATH, metavar='PATH',
                        help=f'Output path (default: {DB_PATH})')
    args = parser.parse_args()

    key_present = bool(os.environ.get('WORDFENCE_API_KEY', '').strip())

    print("WENDY CVE Database Updater")
    print(f"Source : {FEED_URL}")
    print(f"Output : {args.output}")
    print(f"Auth   : {'key loaded' if key_present else 'NO KEY — add WORDFENCE_API_KEY to wendy/.keys'}")
    print()

    # Fetch
    try:
        data = fetch_feed()
    except requests.exceptions.Timeout:
        print("ERROR: Request timed out. Retry or check connectivity.", file=sys.stderr)
        sys.exit(1)
    except requests.exceptions.HTTPError as e:
        print(f"ERROR: HTTP {e.response.status_code} from feed.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"ERROR fetching feed: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"  Received {len(data):,} entries")

    # Parse
    db_plugins, db_themes, skipped = parse_feed(data)
    total_p = sum(len(v) for v in db_plugins.values())
    total_t = sum(len(v) for v in db_themes.values())
    print(f"  Parsed  {total_p:,} CVE entries for {len(db_plugins):,} plugins "
          f"+ {total_t:,} entries for {len(db_themes):,} themes "
          f"({skipped:,} skipped - no concrete version cap)")

    if args.dry_run:
        print("\nDry-run mode: skipping save and popular fetch.")
        return

    # Fetch WordPress.org installs index + theme list in parallel (best-effort)
    print()
    print("  Fetching installs index from WordPress.org...", end=' ', flush=True)
    with _TPE(max_workers=2) as ex:
        f_plugins = ex.submit(fetch_popular_wp_org, 'plugin', WP_ORG_POPULAR_PLUGINS_LIMIT)
        f_themes  = ex.submit(fetch_popular_wp_org, 'theme',  WP_ORG_POPULAR_THEMES_LIMIT)
        installs_index = f_plugins.result()
        themes_dict    = f_themes.result()
    popular_themes = list(themes_dict.keys())
    print(f"done ({len(installs_index):,} plugins, {len(popular_themes):,} themes)")
    print()

    # Save
    meta = save_db(db_plugins, db_themes=db_themes, path=args.output,
                   installs_index=installs_index, popular_themes=popular_themes)
    print(f"Saved to: {args.output}")
    print(f"Updated : {meta['updated']}")
    print(f"Plugins : {meta['plugins']:,} slugs, {meta['entries']:,} CVE entries")
    print(f"Themes  : {meta['themes']:,} slugs, {meta['theme_entries']:,} CVE entries")
    print(f"Index   : {len(installs_index):,} plugins with installs data, "
          f"{len(popular_themes):,} themes cached")
    print()
    print("Run WENDY normally - it will automatically load the updated database.")


if __name__ == '__main__':
    main()
