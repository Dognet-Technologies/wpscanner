#!/usr/bin/env python3
"""
WordPress Hidden Endpoint Discovery
For authorized security testing only.

Usage: python endpoint_discovery.py https://example.com
"""

import requests
import urllib.parse
import time
import random
import sys
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

class EndpointDiscovery:
    def __init__(self):
        self.session = requests.Session()
        
        # Retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Comprehensive User-Agent list for rotation
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1'
        ]

        # Common WAF bypass headers
        self.bypass_headers_list = [
            'X-Forwarded-For',
            'X-Forwarded-Host',
            'X-Remote-IP',
            'X-Remote-Addr',
            'X-Client-IP',
            'X-Real-IP',
            'X-Originating-IP',
            'X-Custom-IP-Authorization',
            'CF-Connecting-IP',
            'True-Client-IP',
            'X-Cluster-Client-IP'
        ]
        
        # Categories of endpoints to test
        self.endpoint_categories = {
            'backup_files': self.get_backup_endpoints,
            'config_files': self.get_config_endpoints,
            'log_files': self.get_log_endpoints,
            'directory_listings': self.get_directory_endpoints,
            'ajax_endpoints': self.get_ajax_endpoints,
            'api_endpoints': self.get_api_endpoints,
            'cache_files': self.get_cache_endpoints,
            'debug_files': self.get_debug_endpoints,
            'plugin_specific': self.get_plugin_specific_endpoints,
            'sensitive_files': self.get_sensitive_files_endpoints
        }

    def get_random_headers(self):
        """Generate a randomized header set for each request"""
        headers = {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0'
        }
        
        # Add a random bypass header with a random IP
        bypass_header = random.choice(self.bypass_headers_list)
        random_ip = f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        headers[bypass_header] = random_ip
        
        return headers

    def get_backup_endpoints(self, base_url):
        """Common backup file locations"""
        common_backups = [
            '/wp-config.php.bak', '/wp-config.php~', '/wp-config.php.save', '/wp-config.php.old',
            '/wp-config.php.orig', '/.wp-config.php.swp', '/wp-config.bak', '/backup.zip',
            '/backup.sql', '/backup.tar.gz', '/database.sql', '/db_backup.sql', '/wp_backup.sql',
            '/site_backup.zip', '/wordpress_backup.zip', '/.htaccess.bak', '/.htaccess~',
            '/wp-config.php.backup', '/wp-config.php.bkp', '/wp-config.php.copy', '/wp-config.php.disabled',
            '/wp-config.php.tmp', '/wp-config.php.txt', '/wp-config.php.zip', '/wp-config.php.tar.gz',
            '/wp-config.bkp', '/wp-config.old', '/wp-config.php.bak.php', '/db.sql',
            '/database_backup.sql', '/backup-db.sql', '/wp.sql', '/wordpress.sql', '/wordpress.sql.gz',
            '/database.sql.gz', '/db_backup.sql.gz', '/site.zip', '/site.tar.gz', '/website.zip',
            '/website_backup.zip', '/public_html.zip', '/www.zip', '/html.zip', '/.htaccess.old',
            '/.htaccess.save', '/.htaccess.bkp', '/.htaccess.disabled', '/wp-content/backup-db',
            '/wp-config.php#', '/wp-config.php.swo', '/wp-config.php.swn', '/.htaccess.orig',
            '/dump.sql', '/mysql.sql', '/sql.zip', '/sql.tar.gz', '/data.sql', '/db.zip', '/db.tar.gz',
            '/backup.rar', '/backup.7z', '/all.zip', '/archive.zip', '/full.zip', '/master.zip',
            '/wp-content/debug.log.bak', '/wp-content/debug.log.old'
        ]
        
        # Add some date-based fuzzed backups
        import datetime
        now = datetime.datetime.now()
        dates = [
            now.strftime("%Y"), now.strftime("%Y-%m"), now.strftime("%Y%m%d"),
            (now - datetime.timedelta(days=1)).strftime("%Y%m%d"),
            (now - datetime.timedelta(days=30)).strftime("%Y-%m")
        ]
        
        fuzzed = []
        for d in dates:
            fuzzed.extend([f'/backup-{d}.zip', f'/backup-{d}.sql', f'/db-{d}.sql', f'/{d}.zip', f'/{d}.sql'])
            
        return list(set(common_backups + fuzzed))

    def get_config_endpoints(self, base_url):
        """Configuration and sensitive files"""
        return [
            '/wp-config.php', '/wp-config-sample.php', '/wp-config.php~', '/wp-config.php.bak',
            '/wp-config.php.old', '/wp-config.php.save', '/wp-config.php.orig', '/.env',
            '/.env.local', '/.env.production', '/.env.dev', '/.env.prod', '/.env.stage',
            '/.env.staging', '/.env.test', '/.env.backup', '/.env.bak', '/.env.old',
            '/config.php', '/config.inc.php', '/local-config.php', '/settings.php',
            '/settings.local.php', '/configuration.php', '/parameters.yml', '/parameters.yaml',
            '/services.yml', '/services.yaml', '/config.json', '/app.json', '/appsettings.json',
            '/appsettings.Production.json', '/composer.json', '/package.json', '/firebase.json',
            '/credentials.json', '/.git/config', '/.git/HEAD', '/.git/index', '/.git/logs/HEAD',
            '/.gitmodules', '/.gitignore', '/web.config', '/server.xml', '/.htpasswd',
            '/passwd', '/etc/passwd', '/php.ini', '/.user.ini', '/web.config.bak', '/nginx.conf',
            '/.vscode/settings.json', '/.idea/workspace.xml', '/.dockerignore', '/Dockerfile',
            '/docker-compose.yml', '/Procfile', '/runtime.txt', '/requirements.txt', '/Gemfile'
        ]

    def get_log_endpoints(self, base_url):
        """Log files that might contain sensitive info"""
        return [
            '/debug.log', '/error.log', '/access.log', '/wp-content/debug.log',
            '/wp-content/uploads/debug.log', '/wp-content/cache/debug.log', '/wp-content/logs/debug.log',
            '/wp-content/logs/error.log', '/wp-content/logs/access.log', '/logs/debug.log',
            '/logs/error.log', '/logs/access.log', '/log/error.log', '/log/access.log',
            '/var/log/apache2/error.log', '/var/log/apache2/access.log', '/var/log/nginx/error.log',
            '/var/log/nginx/access.log', '/error_log', '/access_log', '/wp-admin/error.log',
            '/wp-includes/error.log', '/application.log', '/system.log', '/php_errors.log',
            '/php_error.log', '/php.log', '/mysql.log', '/mysqld.log', '/sql.log', '/db.log',
            '/wp-content/uploads/wc-logs/', '/wp-content/uploads/wc-logs/error.log'
        ]


    def get_directory_endpoints(self, base_url):
        """Directory listings that might be exposed"""
        return [
            '/wp-content/',
            '/wp-content/uploads/',
            '/wp-content/themes/',
            '/wp-content/plugins/',
            '/wp-content/cache/',
            '/wp-content/backups/',
            '/wp-content/backup/',
            '/wp-content/upgrade/',
            '/wp-content/temp/',
            '/wp-content/tmp/',
            '/wp-content/logs/',
            '/wp-content/uploads/backups/',
            '/wp-content/uploads/tmp/',
            '/wp-content/uploads/logs/',
            '/wp-admin/',
            '/wp-includes/',
            '/uploads/',
            '/images/',
            '/files/',
            '/documents/',
            '/backup/',
            '/backups/',
            '/temp/',
            '/tmp/',
            '/cache/',
            '/logs/',
            '/assets/',
            '/media/',
            '/downloads/',
            '/private/',
            '/old/',
            '/staging/',
            '/test/',
            '/dev/'
        ]


    def get_ajax_endpoints(self, base_url):
        """AJAX endpoints that might not be protected"""
        return [
            '/wp-admin/admin-ajax.php',
            '/wp-admin/admin-ajax.php?action=heartbeat',
            '/wp-admin/admin-ajax.php?action=wp_compression_test',
            '/wp-admin/admin-ajax.php?action=fetch-list',
            '/wp-admin/admin-ajax.php?action=ajax-tag-search',
            '/wp-admin/admin-ajax.php?action=logged-in',
            '/wp-admin/admin-ajax.php?action=check_ajax_referer',
            '/wp-admin/admin-ajax.php?action=wp_ajax_nopriv',
            '/wp-json/',
            '/wp-json/wp/v2/',
            '/wp-json/wp/v2/users',
            '/wp-json/wp/v2/posts',
            '/wp-json/wp/v2/pages',
            '/wp-json/wp/v2/media',
            '/wp-json/wp/v2/comments',
            '/wp-json/wp/v2/taxonomies',
            '/wp-json/wp/v2/statuses',
            '/wp-json/wp/v2/types',
            '/wp-json/wp/v2/settings',
            '/wp-json/wp/v2/themes',
            '/wp-json/wp/v2/plugins',
            '/wp-json/wp/v2/search',
            '/wp-json/oembed/1.0/embed',
            '/wp-json/oembed/1.0/proxy',
            '/?rest_route=/',
            '/?rest_route=/wp/v2/users',
            '/?rest_route=/wp/v2/posts',
            '/?rest_route=/wp/v2/media'
        ]


    def get_api_endpoints(self, base_url):
        """API endpoints that might expose data"""
        return [
            '/api/',
            '/api/v1/',
            '/api/v2/',
            '/api/v3/',
            '/api/public/',
            '/api/private/',
            '/rest/',
            '/rest/v1/',
            '/rest/v2/',
            '/graphql',
            '/graphql/',
            '/wp-json/',
            '/wp-json/wp/v2/',
            '/wp-json/wp/v2/users',
            '/wp-json/wp/v2/posts',
            '/wp-json/wp/v2/pages',
            '/feed/',
            '/feed/rss/',
            '/feed/atom/',
            '/rss/',
            '/rss.xml',
            '/atom/',
            '/atom.xml',
            '/sitemap.xml',
            '/sitemap_index.xml',
            '/wp-sitemap.xml',
            '/wp-sitemap-posts-post-1.xml',
            '/robots.txt',
            '/.well-known/',
            '/.well-known/security.txt',
            '/.well-known/change-password',
            '/security.txt',
            '/humans.txt',
            '/ads.txt',
            '/favicon.ico',
            '/crossdomain.xml',
            '/clientaccesspolicy.xml'
        ]


    def get_cache_endpoints(self, base_url):
        """Cache files and directories"""
        return [
            '/wp-content/cache/',
            '/wp-content/wp-cache-config.php',
            '/wp-content/advanced-cache.php',
            '/wp-content/object-cache.php',
            '/wp-content/w3tc-config/',
            '/wp-content/cache/supercache/',
            '/wp-content/cache/wp-rocket/',
            '/wp-content/cache/min/',
            '/wp-content/cache/critical-css/',
            '/wp-content/cache/background-css/',
            '/cache/',
            '/tmp/cache/',
            '/wp-content/cache/litespeed/',
            '/wp-content/cache/lscache/',
            '/wp-content/cache/autoptimize/',
            '/wp-content/cache/breeze/',
            '/wp-content/cache/wpo/',
            '/wp-content/cache/wp-fastest-cache/',
            '/wp-content/cache/w3-total-cache/',
            '/wp-content/cache/cloudflare/',
            '/wp-content/plugins/wp-super-cache/',
            '/wp-content/uploads/cache/',
            '/.cache/'
        ]

    def get_debug_endpoints(self, base_url):
        """Debug and development files"""
        return [
            '/wp-content/debug.log',
            '/wp-content/uploads/wc-logs/',
            '/wp-content/ewww/',
            '/wp-content/et-cache/',
            '/wp-admin/includes/file.php',
            '/phpinfo.php',
            '/info.php',
            '/test.php',
            '/debug.php',
            '/status.php',
            '/health.php',
            '/version.php',
            '/wp-admin/maint/repair.php',
            '/wp-admin/setup-config.php',
            '/wp-admin/install.php',
            '/wp-content/uploads/debug.log',
            '/wp-content/uploads/error.log',
            '/wp-content/uploads/php_errors.log',
            '/wp-content/uploads/logs/',
            '/wp-content/logs/',
            '/wp-content/tmp/',
            '/wp-content/test/',
            '/wp-content/staging/',
            '/php_error.log',
            '/error_log',
            '/xdebug.php',
            '/trace.php',
            '/dump.php',
            '/wp-admin/upgrade.php'
        ]

    def get_plugin_specific_endpoints(self, base_url):
        """Plugin-specific endpoints based on common WordPress plugins and vulnerabilities"""
        plugins = [
            'royal-elementor-addons', 'elementor', 'ewww-image-optimizer', 'wp-fastest-cache',
            'wordfence', 'the-events-calendar', 'complianz-gdpr', 'duplicate-page',
            'events-widgets-for-elementor-and-the-events-calendar', 'contact-form-7',
            'wp-file-manager', 'woocommerce', 'jetpack', 'all-in-one-seo-pack', 'yoast-seo',
            'wp-forms', 'akismet', 'updraftplus', 'monsterinsights', 'advanced-custom-fields',
            'revslider', 'js_composer', 'wp-bakery', 'gravityforms', 'duplicator',
            'backupbuddy', 'wp-migrate-db', 'wp-rocket', 'autoptimize', 'w3-total-cache',
            'all-in-one-wp-migration', 'wp-super-cache', 'ithemes-security', 'sucuri-scanner',
            'ninja-forms', 'mailchimp-for-wp', 'smush', 'broken-link-checker', 'redirection',
            'tablepress', 'query-monitor', 'better-wp-security', 'mainwp'
        ]
        
        endpoints = []
        for plugin in plugins:
            endpoints.extend([
                f'/wp-content/plugins/{plugin}/',
                f'/wp-content/plugins/{plugin}/readme.txt',
                f'/wp-content/plugins/{plugin}/changelog.txt',
                f'/wp-content/plugins/{plugin}/LICENSE',
                f'/wp-content/plugins/{plugin}/composer.json',
                f'/wp-content/plugins/{plugin}/package.json',
                f'/wp-content/plugins/{plugin}/config.php',
                f'/wp-content/plugins/{plugin}/settings.php',
                f'/wp-content/plugins/{plugin}/debug.log',
                f'/wp-content/plugins/{plugin}/error.log',
                f'/wp-content/plugins/{plugin}/cache/',
                f'/wp-content/plugins/{plugin}/uploads/',
                f'/wp-content/plugins/{plugin}/temp/',
                f'/wp-content/plugins/{plugin}/backup/',
                f'/wp-content/plugins/{plugin}/logs/',
                f'/wp-content/plugins/{plugin}/admin/config.php',
                f'/wp-content/plugins/{plugin}/readme.md',
                f'/wp-content/plugins/{plugin}/README.md',
                f'/wp-content/plugins/{plugin}/readme.html',
                f'/wp-content/plugins/{plugin}/uninstall.php',
                f'/wp-content/plugins/{plugin}/vendor/',
                f'/wp-content/plugins/{plugin}/vendor/autoload.php',
                f'/wp-content/plugins/{plugin}/tests/',
                f'/wp-content/plugins/{plugin}/includes/config.php'
            ])
        
        return endpoints

    def get_sensitive_files_endpoints(self, base_url):
        """Generic sensitive files often found on web servers"""
        return [
            '/.ssh/id_rsa',
            '/.ssh/id_dsa',
            '/.ssh/authorized_keys',
            '/.ssh/known_hosts',
            '/.aws/credentials',
            '/.aws/config',
            '/.npmrc',
            '/.bash_history',
            '/.zsh_history',
            '/.mysql_history',
            '/.psql_history',
            '/.docker/config.json',
            '/.dockercfg',
            '/.vimrc',
            '/.ssh/id_rsa.pub',
            '/.ssh/id_rsa.bak',
            '/.ssh/id_rsa~',
            '/.git-credentials',
            '/.gnupg/secring.gpg',
            '/.gnupg/pubring.gpg',
            '/auth.json',
            '/.s3cfg',
            '/.wp-cli/config.yml',
            '/.netrc',
            '/.passwd',
            '/.shadow'
        ]

    def generate_curl_command(self, url, method='GET', headers=None, bypass_headers=None):
        """Generate a simplified curl command for manual testing"""
        cmd = f"curl -i -X {method} '{url}'"

        # Only include essential headers for bypass, not all browser headers
        if bypass_headers:
            for k, v in bypass_headers.items():
                v_escaped = str(v).replace("'", "'\\''")
                cmd += f" -H '{k}: {v_escaped}'"

        return cmd

    def generate_browser_command(self, url):
        """Generate command to open URL in browser"""
        # xdg-open works on Linux, open works on macOS
        return f"xdg-open '{url}' 2>/dev/null || open '{url}'"

    def _print_bypass_details(self, bypass, show_warning=False):
        """Print formatted bypass details"""
        method = bypass['method']
        url = bypass['url']
        has_custom_headers = bypass.get('bypass_headers')
        http_method = bypass.get('http_method', 'GET')

        # Show warning indicator if needed
        warning = " ⚠️" if show_warning else ""
        print(f"      ├─ {method}{warning}")

        if show_warning and bypass.get('fp_reason'):
            print(f"      │  ⚠️  Warning: {bypass['fp_reason']}")

        if has_custom_headers:
            for k, v in has_custom_headers.items():
                print(f"      │  Header: {k}: {v}")

        print(f"      │  Curl: {bypass['curl_command']}")

        # Browser can only open GET requests without custom headers
        if not has_custom_headers and http_method == 'GET':
            print(f"      │  Browser: {self.generate_browser_command(url)}")

        if bypass.get('preview'):
            bp_preview = bypass['preview'][:60].replace('\n', ' ').strip()
            print(f"      │  Preview: {bp_preview}...")

        print(f"      │")

    def generate_download_command(self, url):
        """Generate command to download a file"""
        return f"curl -O '{url}'"

    def is_likely_false_positive(self, endpoint, content_type, content):
        """Check if a 200 response is likely a false positive (HTML returned for non-HTML file)"""
        # List of extensions that should NOT return HTML
        non_html_extensions = [
            '.log', '.txt', '.sql', '.zip', '.tar', '.gz', '.bak', '.old',
            '.conf', '.cfg', '.ini', '.env', '.json', '.xml', '.yml', '.yaml',
            '.php', '.py', '.rb', '.pl', '.sh', '.bash', '.zsh',
            '.key', '.pem', '.crt', '.cer', '.pub', '.ppk',
            '.db', '.sqlite', '.sqlite3', '.mdb',
            '.csv', '.tsv', '.xls', '.xlsx'
        ]

        # Check if endpoint has a non-HTML extension
        endpoint_lower = endpoint.lower()
        has_non_html_ext = any(endpoint_lower.endswith(ext) for ext in non_html_extensions)

        # Check if response is HTML
        is_html = False
        if content_type:
            is_html = 'text/html' in content_type.lower()
        if not is_html and content:
            # Check content for HTML markers
            content_lower = content[:500].lower()
            is_html = any(marker in content_lower for marker in ['<!doctype html', '<html', '<head', '<body'])

        return has_non_html_ext and is_html

    def get_homepage_signature(self, base_url):
        """Fetch homepage content to use as reference for false positive detection"""
        if hasattr(self, '_homepage_signature'):
            return self._homepage_signature

        try:
            response = self.session.get(base_url, headers=self.get_random_headers(), timeout=10, allow_redirects=True)
            content = response.text[:2000]
            # Create a signature: length + hash of key elements
            self._homepage_signature = {
                'length': len(response.text),
                'title': self._extract_title(content),
                'content_sample': content[:500],
                'content_hash': hash(content[:1000])
            }
        except Exception:
            self._homepage_signature = None

        return self._homepage_signature

    def _extract_title(self, html_content):
        """Extract title from HTML content"""
        import re
        match = re.search(r'<title[^>]*>([^<]+)</title>', html_content, re.IGNORECASE)
        return match.group(1).strip() if match else ''

    def is_directory_listing(self, content):
        """Check if content looks like a directory listing"""
        content_lower = content.lower()
        # Common directory listing indicators
        indicators = [
            'index of',
            'directory listing',
            'parent directory',
            '[dir]',
            '[to parent directory]',
            '<pre>',  # Apache default listing uses <pre>
            'last modified',
            'size  description',
            'name</a>',
            'href=".."',
            'href="../"'
        ]
        matches = sum(1 for ind in indicators if ind in content_lower)
        return matches >= 2  # At least 2 indicators

    def is_bypass_false_positive(self, base_url, endpoint, bypass_content, bypass_url):
        """
        Verify if a bypass result is a false positive.
        Returns (is_false_positive: bool, reason: str, confidence: str)
        """
        if not bypass_content:
            return True, "Empty response", "high"

        content_lower = bypass_content.lower()
        endpoint_parts = [p for p in endpoint.strip('/').split('/') if p]
        is_directory = endpoint.endswith('/')

        # Check 1: Is it a real directory listing?
        if is_directory and self.is_directory_listing(bypass_content):
            # Verify the listing mentions files/dirs we'd expect
            return False, "Valid directory listing detected", "high"

        # Check 2: Compare with homepage
        homepage_sig = self.get_homepage_signature(base_url)
        if homepage_sig:
            # Check if content is very similar to homepage
            bypass_hash = hash(bypass_content[:1000])
            if bypass_hash == homepage_sig['content_hash']:
                return True, "Content identical to homepage", "high"

            # Check if title matches homepage (common false positive)
            bypass_title = self._extract_title(bypass_content)
            if bypass_title and homepage_sig['title']:
                if bypass_title == homepage_sig['title']:
                    # Same title as homepage - likely false positive
                    # Unless endpoint name is in content
                    if endpoint_parts and not any(part.lower() in content_lower for part in endpoint_parts):
                        return True, f"Same title as homepage: '{bypass_title}'", "medium"

            # Check content length similarity (within 5%)
            length_diff = abs(len(bypass_content) - homepage_sig['length']) / max(homepage_sig['length'], 1)
            if length_diff < 0.05 and len(bypass_content) > 1000:
                return True, "Content length matches homepage", "medium"

        # Check 3: For directories, verify endpoint reference in content
        if is_directory and endpoint_parts:
            last_dir = endpoint_parts[-1].lower()
            # A real directory listing should mention the directory name or its contents
            if last_dir not in content_lower and 'index of' not in content_lower:
                # Check if it's a complex HTML page (not a listing)
                if content_lower.count('<div') > 10 or content_lower.count('<script') > 3:
                    return True, "Complex HTML page, not a directory listing", "medium"

        # Check 4: Common error page patterns that return 200
        error_patterns = [
            'page not found',
            'not found',
            '404',
            'does not exist',
            'error 404',
            'file not found',
            'nothing found',
            'pagina non trovata',
            'non trovato'
        ]
        if any(pattern in content_lower for pattern in error_patterns):
            # But make sure it's not just mentioning 404 in another context
            if 'page not found' in content_lower or 'error 404' in content_lower:
                return True, "Soft 404 error page", "high"

        # Check 5: For header bypasses (X-Original-URL etc), verify we're not just getting homepage
        if '/' in bypass_url and bypass_url.rstrip('/').endswith(base_url.rstrip('/')):
            # We requested the base URL with bypass header - verify content changed
            if homepage_sig and len(bypass_content) > 500:
                # If content is similar length and same title, it's the homepage
                if abs(len(bypass_content) - homepage_sig['length']) < 100:
                    return True, "Response is the homepage (bypass header ignored)", "high"

        return False, "Appears valid", "low"

    def verify_403_validity(self, base_url):
        """Verify if 403 responses are real or false positives"""
        # Test a clearly non-existent endpoint
        fake_endpoints = [
            f'/this-definitely-does-not-exist-{random.randint(10000, 99999)}',
            f'/fake-dir-test-{random.randint(10000, 99999)}/', 
            f'/nonexistent-file-{random.randint(10000, 99999)}.txt'
        ]
        
        for fake_endpoint in fake_endpoints:
            try:
                url = f"{base_url.rstrip('/')}{fake_endpoint}"
                response = self.session.get(url, headers=self.get_random_headers(), timeout=10, allow_redirects=False)
                
                if response.status_code == 403:
                    return False  # Server returns 403 for non-existent files = false positive
                elif response.status_code == 404:
                    return True   # Server properly returns 404 = 403s are likely real
                    
            except Exception:
                continue
                
        return True  # Default to assuming 403s are valid

    def test_403_bypasses(self, base_url, endpoint):
        """Test various bypass techniques for 403 forbidden endpoints"""
        bypasses = []
        
        # 1. HTTP Methods Bypass
        methods = ['POST', 'PUT', 'PATCH', 'OPTIONS', 'HEAD', 'TRACE', 'CONNECT']
        for method in methods:
            try:
                headers = self.get_random_headers()
                bypass_url = f"{base_url.rstrip('/')}{endpoint}"
                response = self.session.request(method, bypass_url, headers=headers, timeout=10, allow_redirects=False)
                if response.status_code == 200:
                    bypasses.append({
                        'method': f'HTTP Method ({method})',
                        'http_method': method,
                        'url': bypass_url,
                        'status': response.status_code,
                        'preview': response.text[:200],
                        'curl_command': self.generate_curl_command(bypass_url, method=method)
                    })
            except Exception:
                pass

        # 2. Header-based bypasses
        header_payloads = [
            {'X-Original-URL': endpoint},
            {'X-Rewrite-URL': endpoint},
            {'X-Forwarded-Path': endpoint},
            {'X-Real-URL': endpoint},
            {'X-ProxyUser-Ip': '127.0.0.1'},
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Forwarded-For': '::1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Remote-Addr': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Host': '127.0.0.1'},
            {'Forwarded': 'for=127.0.0.1;proto=http;host=localhost'},
        ]

        for payload in header_payloads:
            try:
                headers = self.get_random_headers()
                headers.update(payload)
                # For URL rewrite headers, we often need to request a "safe" path
                url = f"{base_url.rstrip('/')}/" if any(k in payload for k in ['X-Original-URL', 'X-Rewrite-URL', 'X-Forwarded-Path']) else f"{base_url.rstrip('/')}{endpoint}"
                response = self.session.get(url, headers=headers, timeout=10, allow_redirects=False)
                if response.status_code == 200:
                    header_name = list(payload.keys())[0]
                    bypasses.append({
                        'method': f'Header ({header_name})',
                        'url': url,
                        'bypass_headers': payload,
                        'status': response.status_code,
                        'preview': response.text[:200],
                        'curl_command': self.generate_curl_command(url, method='GET', bypass_headers=payload)
                    })
            except Exception:
                pass

        # 3. Path Obfuscation variations
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
            endpoint + '??',
            endpoint + '#',
            '/%2e' + endpoint,
            '/.' + endpoint,
            './' + endpoint.lstrip('/'),
            '/./' + endpoint.lstrip('/')
        ]
        
        for variation in variations:
            try:
                bypass_url = f"{base_url.rstrip('/')}{variation}"
                headers = self.get_random_headers()
                response = self.session.get(bypass_url, headers=headers, timeout=10, allow_redirects=False)
                if response.status_code == 200:
                    bypasses.append({
                        'method': f'Path ({variation})',
                        'url': bypass_url,
                        'status': response.status_code,
                        'preview': response.text[:200],
                        'curl_command': self.generate_curl_command(bypass_url)
                    })
            except Exception:
                continue

        # 4. Case variation bypass
        try:
            case_variations = []
            original_path = endpoint.strip('/')
            if original_path:
                case_variations.append('/' + ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in original_path))
                case_variations.append('/' + original_path.upper())
                case_variations.append('/' + original_path.title())

            for variation in case_variations:
                bypass_url = f"{base_url.rstrip('/')}{variation}"
                headers = self.get_random_headers()
                response = self.session.get(bypass_url, headers=headers, timeout=10, allow_redirects=False)
                if response.status_code == 200:
                    bypasses.append({
                        'method': f'Case ({variation})',
                        'url': bypass_url,
                        'status': response.status_code,
                        'preview': response.text[:200],
                        'curl_command': self.generate_curl_command(bypass_url)
                    })
        except Exception:
            pass

        # Verify each bypass for false positives
        verified_bypasses = []
        for bypass in bypasses:
            content = bypass.get('preview', '')
            # Get more content for verification if available
            is_fp, fp_reason, fp_confidence = self.is_bypass_false_positive(
                base_url, endpoint, content, bypass['url']
            )

            bypass['is_false_positive'] = is_fp
            bypass['fp_reason'] = fp_reason
            bypass['fp_confidence'] = fp_confidence

            if not is_fp:
                verified_bypasses.append(bypass)
            elif fp_confidence == 'medium':
                # Include medium confidence false positives but mark them
                bypass['needs_verification'] = True
                verified_bypasses.append(bypass)
            # High confidence false positives are excluded

        return verified_bypasses

    def verify_403_specific(self, base_url, endpoint):
        """Verify if a specific 403 response is real by testing with random extension"""
        import string
        random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
        
        if endpoint.endswith('/'):
            test_endpoint = endpoint + random_suffix
        else:
            test_endpoint = f"{endpoint}-{random_suffix}"
        
        try:
            test_url = f"{base_url.rstrip('/')}{test_endpoint}"
            response = self.session.get(test_url, headers=self.get_random_headers(), timeout=10, allow_redirects=False)
            
            if response.status_code == 403:
                return False, f"False positive (test endpoint {test_endpoint} also returns 403)"
            elif response.status_code == 404:
                return True, f"Real 403 (test endpoint {test_endpoint} correctly returns 404)"
            else:
                return True, f"Likely real 403 (test endpoint returns {response.status_code})"
                
        except Exception as e:
            return True, f"Cannot verify (test failed: {str(e)})"

    def test_endpoint(self, base_url, endpoint):
        """Test a single endpoint with enhanced 403 handling"""
        url = f"{base_url.rstrip('/')}{endpoint}"
        
        try:
            # Random delay to avoid rate limiting
            time.sleep(random.uniform(0.5, 1.5))
            
            headers = self.get_random_headers()
            response = self.session.get(url, headers=headers, timeout=10, allow_redirects=False)
            
            # Determine if this is a directory or file
            is_directory = endpoint.endswith('/')
            content_type = response.headers.get('Content-Type', '')

            result = {
                'url': url,
                'endpoint': endpoint,
                'status_code': response.status_code,
                'content_length': len(response.content),
                'content_type': content_type,
                'server': response.headers.get('Server', ''),
                'interesting': False,
                'reason': '',
                'preview': '',
                'bypasses': [],
                'verification': '',
                'is_directory': is_directory,
                'is_false_positive': False,
                'curl_command': self.generate_curl_command(url),
                'browser_command': self.generate_browser_command(url),
                'download_command': None if is_directory else self.generate_download_command(url)
            }

            # Determine if endpoint is interesting
            if response.status_code == 200:
                content = response.text[:1000]  # First 1000 chars
                result['preview'] = content[:200]

                # Check for false positive (HTML response for non-HTML file)
                if self.is_likely_false_positive(endpoint, content_type, content):
                    result['is_false_positive'] = True
                    result['interesting'] = False
                    result['reason'] = "Likely false positive (HTML returned for non-HTML file)"
                else:
                    # Check for interesting content
                    interesting_patterns = [
                        'DB_PASSWORD', 'DB_USER', 'DB_NAME', 'DB_HOST',
                        'define(', 'mysql:', 'postgres:',
                        'API_KEY', 'SECRET', 'TOKEN',
                        'password', 'username', 'admin',
                        'error', 'warning', 'exception',
                        'stack trace', 'debug',
                        'Index of', 'Directory listing',
                        '<?php', '<?xml', '{', '[',
                        'SQL', 'SELECT', 'INSERT', 'UPDATE',
                        'wp_', 'wordpress', 'admin',
                        'version', 'changelog'
                    ]

                    content_lower = content.lower()
                    for pattern in interesting_patterns:
                        if pattern.lower() in content_lower:
                            result['interesting'] = True
                            result['reason'] = f"Contains: {pattern}"
                            break
                
            elif response.status_code == 403:
                # FIRST: Verify if the 403 is real using the random suffix method
                is_real_403, verification_msg = self.verify_403_specific(base_url, endpoint)
                result['verification'] = verification_msg
                
                if is_real_403:
                    # It's a real 403, test bypasses
                    bypasses = self.test_403_bypasses(base_url, endpoint)
                    result['bypasses'] = bypasses
                    
                    if bypasses:
                        result['interesting'] = True
                        result['reason'] = f"Real 403 + Bypass Found ({len(bypasses)} methods work)"
                    else:
                        result['interesting'] = True
                        result['reason'] = "Real 403 (file exists but protected)"
                else:
                    # It's a false positive, not interesting
                    result['interesting'] = False
                    result['reason'] = "False positive 403 (endpoint likely doesn't exist)"
                
            elif response.status_code == 301 or response.status_code == 302:
                result['interesting'] = True
                result['reason'] = f"Redirect to: {response.headers.get('Location', 'Unknown')}"
                
            return result
            
        except Exception as e:
            return {
                'url': url,
                'endpoint': endpoint,
                'status_code': 'Error',
                'error': str(e),
                'interesting': False
            }

    def scan_category(self, base_url, category_name):
        """Scan a specific category of endpoints"""
        print(f"\n🔍 Scanning {category_name.replace('_', ' ').title()}...")
        
        endpoints = self.endpoint_categories[category_name](base_url)
        interesting_results = []
        
        # Use ThreadPoolExecutor for concurrent requests
        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_endpoint = {
                executor.submit(self.test_endpoint, base_url, endpoint): endpoint 
                for endpoint in endpoints
            }
            
            for future in as_completed(future_to_endpoint):
                result = future.result()
                
                if result['interesting']:
                    interesting_results.append(result)
                    status = result['status_code']
                    reason = result.get('reason', '')
                    
                    # Show verification info in real-time for 403s
                    verification_info = ""
                    if result.get('verification') and 'False positive' in result.get('verification', ''):
                        verification_info = " [⚠️ FALSE POSITIVE]"
                    elif result.get('verification') and 'Real 403' in result.get('verification', ''):
                        verification_info = " [✓ VERIFIED]"
                    
                    # Show bypass info in real-time if found
                    bypass_info = ""
                    if result.get('bypasses'):
                        bypass_count = len(result['bypasses'])
                        bypass_methods = [b['method'] for b in result['bypasses']]
                        bypass_info = f" [🚨 {bypass_count} BYPASSES: {', '.join(bypass_methods[:2])}{'...' if len(bypass_methods) > 2 else ''}]"
                    
                    print(f"   ✅ {result['endpoint']} - Status: {status} - {reason}{verification_info}{bypass_info}")
                
                # Show progress for non-interesting results, including false positive 403s
                elif result['status_code'] == 200:
                    print(f"   ℹ️  {result['endpoint']} - Status: {result['status_code']}")
                elif result['status_code'] == 403 and 'False positive' in result.get('verification', ''):
                    print(f"   ⚠️  {result['endpoint']} - Status: 403 (False positive - skipped)")
        
        return interesting_results

    def run_full_scan(self, base_url):
        """Run complete endpoint discovery scan"""
        print(f"🎯 Starting endpoint discovery for: {base_url}")
        print("🔍 Testing categories: backup files, configs, logs, directories, AJAX, APIs, cache, debug, plugins")
        print("=" * 80)
        
        # First, verify if 403 responses are valid (global test)
        print("🔍 Verifying 403 response validity (global test)...")
        self.valid_403s = self.verify_403_validity(base_url)
        if self.valid_403s:
            print("   ✅ 403 responses appear to be valid globally (server returns 404 for non-existent files)")
        else:
            print("   ⚠️  403 responses may be false positives globally (server returns 403 for non-existent files)")
        print("   💡 Each 403 will be individually verified with random suffix method")
        print()
        
        all_interesting = []
        
        # Scan each category
        for category in self.endpoint_categories.keys():
            try:
                results = self.scan_category(base_url, category)
                all_interesting.extend(results)
                time.sleep(random.uniform(2, 5))  # Delay between categories
            except KeyboardInterrupt:
                print("\n⚠️  Scan interrupted by user")
                break
            except Exception as e:
                print(f"   ❌ Error scanning {category}: {e}")
                continue
        
        # Summary
        print("\n" + "=" * 80)
        print("📊 DISCOVERY SUMMARY")
        print("=" * 80)
        
        if all_interesting:
            print(f"✅ Found {len(all_interesting)} interesting endpoints:")
            
            # Group by status code
            by_status = {}
            bypass_results = []
            
            for result in all_interesting:
                status = result['status_code']
                if status not in by_status:
                    by_status[status] = []
                by_status[status].append(result)
                
                # Collect bypass results
                if result.get('bypasses'):
                    bypass_results.extend(result['bypasses'])
            
            for status, results in by_status.items():
                print(f"\n{'─' * 60}")
                print(f"  STATUS {status} ({len(results)} endpoints)")
                print(f"{'─' * 60}")

                for result in results:
                    endpoint = result['endpoint']
                    reason = result.get('reason', 'N/A')
                    is_dir = result.get('is_directory', endpoint.endswith('/'))

                    # Print endpoint header
                    icon = "📁" if is_dir else "📄"
                    print(f"\n{icon} {endpoint}")
                    print(f"   └─ {reason}")

                    # Skip manual test commands for redirects
                    if result['status_code'] in (301, 302):
                        continue

                    # Show verification for 403s
                    if result.get('verification'):
                        print(f"   └─ Verification: {result['verification']}")

                    # Show preview if available (and not a false positive warning)
                    if result.get('preview') and not result.get('is_false_positive'):
                        preview = result['preview'][:80].replace('\n', ' ').strip()
                        print(f"   └─ Preview: {preview}...")

                    # Show quick actions
                    print(f"   └─ Actions:")
                    if result.get('browser_command'):
                        print(f"      • Open in browser: {result['browser_command']}")
                    if result.get('download_command') and not is_dir:
                        print(f"      • Download: {result['download_command']}")
                    if result.get('curl_command'):
                        print(f"      • Curl: {result['curl_command']}")

                    # Show bypasses if found (for 403s)
                    if result.get('bypasses'):
                        # Count verified vs needs-verification bypasses
                        verified = [b for b in result['bypasses'] if not b.get('needs_verification')]
                        needs_check = [b for b in result['bypasses'] if b.get('needs_verification')]

                        if verified:
                            print(f"\n   ✅ VERIFIED BYPASSES ({len(verified)}):")
                            for bypass in verified:
                                self._print_bypass_details(bypass)

                        if needs_check:
                            print(f"\n   ⚠️  BYPASSES NEEDING VERIFICATION ({len(needs_check)}):")
                            for bypass in needs_check:
                                self._print_bypass_details(bypass, show_warning=True)

            # Summary of bypasses
            if bypass_results:
                print(f"\n{'=' * 60}")
                print("  403 BYPASS SUMMARY")
                print(f"{'=' * 60}")
                print(f"  Found {len(bypass_results)} successful bypass techniques\n")

                # Group bypasses by method type
                bypass_methods = {}
                for bypass in bypass_results:
                    method = bypass['method']
                    if method not in bypass_methods:
                        bypass_methods[method] = 0
                    bypass_methods[method] += 1

                print("  Techniques that worked:")
                for method, count in sorted(bypass_methods.items(), key=lambda x: -x[1]):
                    print(f"    • {method}: {count} endpoint(s)")
        
        else:
            print("❌ No interesting endpoints found")
            print("💡 Consider:")
            print("   - Target may have strong security configuration")
            print("   - Try different timing or user agents")
            print("   - Focus on specific plugin vulnerabilities")
        
        return all_interesting

def main():
    if len(sys.argv) != 2:
        print("Usage: python endpoint_discovery.py <BASE_URL>")
        print("Example: python endpoint_discovery.py https://example.com")
        sys.exit(1)
    
    base_url = sys.argv[1]
    
    scanner = EndpointDiscovery()
    interesting_endpoints = scanner.run_full_scan(base_url)
    
    if interesting_endpoints:
        print(f"\n🎉 Discovery complete! Found {len(interesting_endpoints)} interesting endpoints")
        print("🔬 Recommended next steps:")
        print("   1. Manually inspect high-value endpoints (configs, logs)")
        print("   2. Look for version information in accessible files")
        print("   3. Test AJAX endpoints for parameter injection")
        print("   4. Check directory listings for sensitive files")
    else:
        print("\n💭 No immediate findings, but this is normal")
        print("🔄 Consider running focused tests on specific vulnerabilities")

if __name__ == "__main__":
    print("=" * 80)
    print()
    print("    :::       ::: :::::::::: ::::    ::: :::::::::  :::   :::") 
    print("   :+:       :+: :+:        :+:+:   :+: :+:    :+: :+:   :+:")  
    print("  +:+       +:+ +:+        :+:+:+  +:+ +:+    +:+  +:+ +:+")    
    print(" +#+  +:+  +#+ +#++:++#   +#+ +:+ +#+ +#+    +:+   +#++:")      
    print("+#+ +#+#+ +#+ +#+        +#+  +#+#+# +#+    +#+    +#+")        
    print("#+#+# #+#+#  #+#        #+#   #+#+# #+#    #+#    #+#")         
    print("###   ###   ########## ###    #### #########     ###")          
    print("=" * 80)
    print()
    print("🔍 WENDY - Wordpress ENDpoint discoverY")
    print("📚 For Authorized Security Testing Only")
    print("Dognet Technologies srl | info@dognet.tech")
    print()
    print("=" * 80)
    main()