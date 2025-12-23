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
            total=2,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Low-profile headers to avoid WAF detection
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
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
            'plugin_specific': self.get_plugin_specific_endpoints
        }

    def get_backup_endpoints(self, base_url):
        """Common backup file locations"""
        return [
            '/wp-config.php.bak',
            '/wp-config.php~',
            '/wp-config.php.save',
            '/wp-config.php.old',
            '/wp-config.php.orig',
            '/.wp-config.php.swp',
            '/wp-config.bak',
            '/backup.zip',
            '/backup.sql',
            '/backup.tar.gz',
            '/database.sql',
            '/db_backup.sql',
            '/wp_backup.sql',
            '/site_backup.zip',
            '/wordpress_backup.zip',
            '/.htaccess.bak',
            '/.htaccess~',
            '/wp-config.php.backup',
            '/wp-config.php.bkp',
            '/wp-config.php.copy',
            '/wp-config.php.disabled',
            '/wp-config.php.tmp',
            '/wp-config.php.txt',
            '/wp-config.php.zip',
            '/wp-config.php.tar.gz',
            '/wp-config.bkp',
            '/wp-config.old',
            '/wp-config.php.bak.php',
            '/db.sql',
            '/database_backup.sql',
            '/backup-db.sql',
            '/wp.sql',
            '/wordpress.sql',
            '/wordpress.sql.gz',
            '/database.sql.gz',
            '/db_backup.sql.gz',
            '/site.zip',
            '/site.tar.gz',
            '/website.zip',
            '/website_backup.zip',
            '/public_html.zip',
            '/www.zip',
            '/html.zip',
            '/.htaccess.old',
            '/.htaccess.save',
            '/.htaccess.bkp',
            '/.htaccess.disabled',
            '/wp-content/backup-db',
            '/wp-config.php#',
            '/wp-config.php.swo',
            '/wp-config.php.swn',
            '/.htaccess.orig'
        ]

    def get_config_endpoints(self, base_url):
        """Configuration and sensitive files"""
        return [
            '/wp-config.php',
            '/wp-config-sample.php',
            '/wp-config.php~',
            '/wp-config.php.bak',
            '/wp-config.php.old',
            '/wp-config.php.save',
            '/wp-config.php.orig',
            '/.env',
            '/.env.local',
            '/.env.production',
            '/.env.dev',
            '/.env.prod',
            '/.env.stage',
            '/.env.staging',
            '/.env.test',
            '/.env.backup',
            '/.env.bak',
            '/.env.old',
            '/config.php',
            '/config.inc.php',
            '/local-config.php',
            '/settings.php',
            '/settings.local.php',
            '/configuration.php',
            '/parameters.yml',
            '/parameters.yaml',
            '/services.yml',
            '/services.yaml',
            '/config.json',
            '/app.json',
            '/appsettings.json',
            '/appsettings.Production.json',
            '/composer.json',
            '/package.json',
            '/firebase.json',
            '/credentials.json',
            '/.git/config',
            '/.git/HEAD',
            '/.git/index',
            '/.git/logs/HEAD',
            '/.gitmodules',
            '/.gitignore',
            '/web.config',
            '/server.xml',
            '/.htpasswd',
            '/passwd',
            '/etc/passwd'
        ]

    def get_log_endpoints(self, base_url):
        """Log files that might contain sensitive info"""
        return [
            '/debug.log',
            '/error.log',
            '/access.log',
            '/wp-content/debug.log',
            '/wp-content/uploads/debug.log',
            '/wp-content/cache/debug.log',
            '/wp-content/logs/debug.log',
            '/wp-content/logs/error.log',
            '/wp-content/logs/access.log',
            '/logs/debug.log',
            '/logs/error.log',
            '/logs/access.log',
            '/log/error.log',
            '/log/access.log',
            '/var/log/apache2/error.log',
            '/var/log/apache2/access.log',
            '/var/log/nginx/error.log',
            '/var/log/nginx/access.log',
            '/error_log',
            '/access_log',
            '/wp-admin/error.log',
            '/wp-includes/error.log',
            '/application.log',
            '/system.log',
            '/php_errors.log',
            '/php_error.log',
            '/php.log',
            '/mysql.log',
            '/mysqld.log'
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
        """Plugin-specific endpoints based on WPScan results"""
        plugins = [
            'royal-elementor-addons',
            'elementor', 
            'ewww-image-optimizer',
            'wp-fastest-cache',
            'wordfence',
            'the-events-calendar',
            'complianz-gdpr',
            'duplicate-page',
            'events-widgets-for-elementor-and-the-events-calendar'
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

    def verify_403_validity(self, base_url):
        """Verify if 403 responses are real or false positives"""
        # Test a clearly non-existent endpoint
        fake_endpoints = [
            '/this-definitely-does-not-exist-12345',
            '/fake-dir-test-999/', 
            '/nonexistent-file-xyz.txt'
        ]
        
        for fake_endpoint in fake_endpoints:
            try:
                url = f"{base_url.rstrip('/')}{fake_endpoint}"
                response = self.session.get(url, headers=self.headers, timeout=10, allow_redirects=False)
                
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
        original_url = f"{base_url.rstrip('/')}{endpoint}"
        
        # 1. X-Original-URL header bypass
        try:
            headers = self.headers.copy()
            headers['X-Original-URL'] = endpoint
            fake_url = f"{base_url.rstrip('/')}/anything"
            response = self.session.get(fake_url, headers=headers, timeout=10, allow_redirects=False)
            if response.status_code == 200:
                bypasses.append({
                    'method': 'X-Original-URL Header',
                    'url': fake_url,
                    'headers': 'X-Original-URL: ' + endpoint,
                    'status': response.status_code,
                    'preview': response.text[:200]
                })
        except Exception:
            pass

        # 2. %2e after first slash
        try:
            if endpoint.startswith('/'):
                bypass_url = f"{base_url.rstrip('/')}/%2e{endpoint}"
                response = self.session.get(bypass_url, headers=self.headers, timeout=10, allow_redirects=False)
                if response.status_code == 200:
                    bypasses.append({
                        'method': '%2e Encoding',
                        'url': bypass_url,
                        'status': response.status_code,
                        'preview': response.text[:200]
                    })
        except Exception:
            pass

        # 3. Dot, slash, semicolon variations
        variations = [
            endpoint + '/.',
            '//' + endpoint.lstrip('/') + '//',
            '/./' + endpoint.lstrip('/') + '/..',
            '/;/' + endpoint.lstrip('/'),
            '/.;/' + endpoint.lstrip('/'),
            '//;//' + endpoint.lstrip('/')
        ]
        
        for variation in variations:
            try:
                bypass_url = f"{base_url.rstrip('/')}{variation}"
                response = self.session.get(bypass_url, headers=self.headers, timeout=10, allow_redirects=False)
                if response.status_code == 200:
                    bypasses.append({
                        'method': f'Path Variation ({variation})',
                        'url': bypass_url,
                        'status': response.status_code,
                        'preview': response.text[:200]
                    })
            except Exception:
                continue

        # 4. ..;/ bypass
        try:
            if '/' in endpoint.strip('/'):
                parts = endpoint.strip('/').split('/')
                if len(parts) > 0:
                    modified_endpoint = '/' + '/'.join(parts[:-1]) + '/' + parts[-1] + '..;/'
                    bypass_url = f"{base_url.rstrip('/')}{modified_endpoint}"
                    response = self.session.get(bypass_url, headers=self.headers, timeout=10, allow_redirects=False)
                    if response.status_code == 200:
                        bypasses.append({
                            'method': '..;/ Directory Bypass',
                            'url': bypass_url,
                            'status': response.status_code,
                            'preview': response.text[:200]
                        })
        except Exception:
            pass

        # 5. Case variation bypass
        try:
            # Create case variations
            case_variations = []
            original_path = endpoint.strip('/')
            if original_path:
                # Random case mixing
                varied_path = ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in original_path)
                case_variations.append('/' + varied_path)
                
                # All uppercase
                case_variations.append('/' + original_path.upper())
                
                # Title case
                case_variations.append('/' + original_path.title())

            for variation in case_variations:
                bypass_url = f"{base_url.rstrip('/')}{variation}"
                response = self.session.get(bypass_url, headers=self.headers, timeout=10, allow_redirects=False)
                if response.status_code == 200:
                    bypasses.append({
                        'method': f'Case Variation ({variation})',
                        'url': bypass_url,
                        'status': response.status_code,
                        'preview': response.text[:200]
                    })
        except Exception:
            pass

        # 6. Web Cache Poisoning with X-Original-URL (alternative headers)
        cache_headers = ['X-Rewrite-URL', 'X-Forwarded-Path', 'X-Real-URL']
        for header_name in cache_headers:
            try:
                headers = self.headers.copy()
                headers[header_name] = endpoint
                fake_url = f"{base_url.rstrip('/')}/cache-test"
                response = self.session.get(fake_url, headers=headers, timeout=10, allow_redirects=False)
                if response.status_code == 200:
                    bypasses.append({
                        'method': f'Cache Poisoning ({header_name})',
                        'url': fake_url,
                        'headers': f'{header_name}: {endpoint}',
                        'status': response.status_code,
                        'preview': response.text[:200]
                    })
            except Exception:
                continue

        return bypasses

    def verify_403_specific(self, base_url, endpoint):
        """Verify if a specific 403 response is real by testing with random extension"""
        import string
        
        # Generate random string
        random_suffix = ''.join(random.choices(string.ascii_lowercase, k=8))
        
        # Create test endpoint with random suffix
        if endpoint.endswith('/'):
            test_endpoint = endpoint + random_suffix
        else:
            test_endpoint = endpoint + '-' + random_suffix
        
        try:
            test_url = f"{base_url.rstrip('/')}{test_endpoint}"
            response = self.session.get(test_url, headers=self.headers, timeout=10, allow_redirects=False)
            
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
            time.sleep(random.uniform(0.5, 2.0))
            
            response = self.session.get(url, headers=self.headers, timeout=10, allow_redirects=False)
            
            result = {
                'url': url,
                'endpoint': endpoint,
                'status_code': response.status_code,
                'content_length': len(response.content),
                'content_type': response.headers.get('Content-Type', ''),
                'server': response.headers.get('Server', ''),
                'interesting': False,
                'reason': '',
                'preview': '',
                'bypasses': [],
                'verification': ''
            }
            
            # Determine if endpoint is interesting
            if response.status_code == 200:
                content = response.text[:1000]  # First 1000 chars
                result['preview'] = content[:200]
                
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
                print(f"\n📋 Status {status} ({len(results)} endpoints):")
                for result in results:
                    print(f"   • {result['endpoint']}")
                    print(f"     Reason: {result.get('reason', 'N/A')}")
                    
                    # Show verification info for 403s
                    if result.get('verification'):
                        print(f"     Verification: {result['verification']}")
                    
                    if result.get('preview'):
                        preview = result['preview'][:100].replace('\n', ' ')
                        print(f"     Preview: {preview}...")
                    
                    # Show bypasses if found
                    if result.get('bypasses'):
                        print(f"     🚨 BYPASSES FOUND ({len(result['bypasses'])}):")
                        for bypass in result['bypasses']:
                            print(f"       - {bypass['method']}: {bypass['status']}")
                            if 'headers' in bypass:
                                print(f"         Headers: {bypass['headers']}")
                            if bypass.get('preview'):
                                bp_preview = bypass['preview'][:80].replace('\n', ' ')
                                print(f"         Preview: {bp_preview}...")
                    print()
            
            # Summary of bypasses
            if bypass_results:
                print("\n🚨 403 BYPASS SUMMARY")
                print("=" * 50)
                print(f"✅ Found {len(bypass_results)} successful bypasses!")
                
                # Group bypasses by method
                bypass_methods = {}
                for bypass in bypass_results:
                    method = bypass['method']
                    if method not in bypass_methods:
                        bypass_methods[method] = 0
                    bypass_methods[method] += 1
                
                print("📊 Bypass techniques that worked:")
                for method, count in bypass_methods.items():
                    print(f"   - {method}: {count} endpoint(s)")
                
                print("\n🔧 Recommended actions:")
                print("   1. Test bypassed endpoints manually for sensitive data")
                print("   2. Use successful bypass techniques on other targets")
                print("   3. Document bypass methods for reporting")
        
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
    print("🔍 WORDPRESS ENDPOINT DISCOVERY")
    print("📚 For Authorized Security Testing Only")
    print("=" * 80)
    main()