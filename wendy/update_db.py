#!/usr/bin/env python3
"""
WENDY CVE Database Updater v0.3.0
Dognet Technologies srl | info@dognet.tech

Fetches WordPress plugin vulnerability data from Wordfence Intelligence
(public feed, no authentication required) and saves to wendy/cve_db.json.

Source: https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production/
License for data: https://www.wordfence.com/wordfence-intelligence-terms-and-conditions/

Usage:
    python -m wendy.update_db
    python wendy/update_db.py              # full update
    python wendy/update_db.py --dry-run    # fetch only, don't save

Intended to run weekly (cron or CI). The generated cve_db.json is gitignored
and must be regenerated locally after each clone.
"""

import json
import os
import sys
import datetime
import argparse
import requests

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────

FEED_URL = "https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production/"
DB_PATH  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cve_db.json")

# Only include CVEs at or above this CVSS score (0.0 = include all)
MIN_CVSS = 0.0

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
# FEED FETCH
# ─────────────────────────────────────────────────────────────────────────────

def fetch_feed(timeout=90):
    """Fetch the full Wordfence Intelligence vulnerability feed."""
    print(f"  Fetching: {FEED_URL}")
    r = requests.get(
        FEED_URL,
        timeout=timeout,
        headers={
            'User-Agent':  'WENDY-Updater/0.3 (github.com/Dognet-Technologies/wpscanner)',
            'Accept':      'application/json',
        }
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
        "title": "Plugin <= X.Y.Z - Vuln type",
        "software": [
          {
            "type": "plugin",
            "slug": "plugin-slug",
            "affected_versions": {
              "* - 1.2.3": {
                "from_version": "*", "from_inclusive": true,
                "to_version":   "1.2.3", "to_inclusive": true
              }
            }
          }
        ],
        "cve":         "CVE-2023-XXXXX",   # may be null
        "cvss_rating": "critical",          # critical/high/medium/low/none
        "cvss":        {"score": 9.8, ...},
        "title":       "...",
      }

    Output: { slug: [[max_vuln, cve_id, severity, cvss_score, desc], ...] }
    """
    import re as _re

    db      = {}
    skipped = 0

    for uid, vuln in data.items():
        if not isinstance(vuln, dict):
            continue

        software_list = vuln.get('software') or []
        for sw in software_list:
            if not isinstance(sw, dict):
                continue
            if sw.get('type') != 'plugin':
                continue

            slug = (sw.get('slug') or '').strip()
            if not slug:
                continue

            # ── Find max vulnerable version ───────────────────────────────
            concrete_to_versions = []
            has_wildcard = False

            for rng in (sw.get('affected_versions') or {}).values():
                to_ver       = (rng.get('to_version') or '').strip()
                to_inclusive = rng.get('to_inclusive', True)
                if not to_ver or to_ver == '*':
                    has_wildcard = True
                else:
                    concrete_to_versions.append(to_ver)

            if not concrete_to_versions:
                # All versions affected / no concrete cap → skip (can't compare)
                skipped += 1
                continue

            max_vuln = _max_version(concrete_to_versions)

            # ── CVE / severity ────────────────────────────────────────────
            cve_id   = (vuln.get('cve') or '').strip()
            severity = (vuln.get('cvss_rating') or 'medium').upper()
            if severity == 'NONE':
                severity = 'INFO'

            cvss_score = 0.0
            cvss_data  = vuln.get('cvss')
            if isinstance(cvss_data, dict):
                try:
                    cvss_score = float(cvss_data.get('score') or 0)
                except (ValueError, TypeError):
                    cvss_score = 0.0

            if cvss_score < MIN_CVSS:
                skipped += 1
                continue

            desc = (vuln.get('title') or '')[:150].strip()

            entry = [max_vuln, cve_id, severity, cvss_score, desc]
            db.setdefault(slug, []).append(entry)

    return db, skipped


# ─────────────────────────────────────────────────────────────────────────────
# SAVE / LOAD
# ─────────────────────────────────────────────────────────────────────────────

def save_db(db, path=DB_PATH, source_url=FEED_URL):
    """Serialize db to JSON, adding a _meta block."""
    total_entries = sum(len(v) for v in db.values())
    payload = {
        '_meta': {
            'source':  source_url,
            'updated': datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
            'plugins': len(db),
            'entries': total_entries,
        }
    }
    payload.update(db)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    return payload['_meta']


def load_db(path=DB_PATH):
    """Load cve_db.json and return (meta, db_dict)."""
    with open(path, encoding='utf-8') as f:
        raw = json.load(f)
    meta = raw.pop('_meta', {})
    return meta, raw


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main():
    import re  # needed by _parse_ver inside parse_feed closure

    # Re-import re at module level for parse_feed
    global re
    import re

    parser = argparse.ArgumentParser(
        description='Update WENDY CVE database from Wordfence Intelligence public feed'
    )
    parser.add_argument('--dry-run', action='store_true',
                        help='Fetch and parse but do not write cve_db.json')
    parser.add_argument('--output', default=DB_PATH, metavar='PATH',
                        help=f'Output path (default: {DB_PATH})')
    args = parser.parse_args()

    print("WENDY CVE Database Updater")
    print(f"Source : {FEED_URL}")
    print(f"Output : {args.output}")
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
    db, skipped = parse_feed(data)
    total = sum(len(v) for v in db.values())
    print(f"  Parsed  {total:,} CVE entries for {len(db):,} plugins "
          f"({skipped:,} skipped - no concrete version cap)")
    print()

    if args.dry_run:
        print("Dry-run mode: skipping save.")
        return

    # Save
    meta = save_db(db, path=args.output)
    print(f"Saved to: {args.output}")
    print(f"Updated : {meta['updated']}")
    print(f"Coverage: {meta['plugins']:,} plugins, {meta['entries']:,} CVE entries")
    print()
    print("Run WENDY normally - it will automatically load the updated database.")


if __name__ == '__main__':
    import re
    main()
