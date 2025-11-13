import requests
import re
import os
from typing import Optional, Dict, List
from urllib.parse import urljoin
import json
from concurrent.futures import ThreadPoolExecutor
from distutils.version import LooseVersion

class WordPressScanner:
    
    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36'
        }) # this part to make the script not look like a bot
        
    
    def is_wordpress(self) -> Dict[str, any]:
        indicators = {
            'is_wordpress': False,
            'confidence': 0,
            'detected_by': [],
            'wp_version': None,
            'url': self.target_url
        }
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, allow_redirects=True)
            self.target_url = response.url.rstrip('/')
            html = response.text
            if '/wp-content/' in html or '/wp-includes/' in html:
                indicators['detected_by'].append('wp-content/wp-includes paths')
                indicators['confidence'] += 30
            generator_match = re.search(r'<meta name="generator" content="WordPress ([0-9.]+)"', html, re.IGNORECASE)
            if generator_match:
                indicators['detected_by'].append('meta generator tag')
                indicators['wp_version'] = generator_match.group(1)
                indicators['confidence'] += 40
            try:
                api_url = urljoin(self.target_url, '/wp-json/')
                api_response = self.session.get(api_url, timeout=self.timeout)
                if api_response.status_code == 200 and 'namespaces' in api_response.text:
                    indicators['detected_by'].append('REST API endpoint')
                    indicators['confidence'] += 30
            except:
                pass
            if indicators['confidence'] >= 30:
                indicators['is_wordpress'] = True
        except requests.RequestException as e:
            indicators['error'] = str(e)
        return indicators
    
    def check_plugin(self, plugin_slug: str) -> Dict[str, any]:
        result = {
            'plugin_slug': plugin_slug,
            'is_installed': False,
            'version': None,
            'detected_by': None,
            'plugin_url': None
        }
        plugin_base_url = f'{self.target_url}/wp-content/plugins/{plugin_slug}/'
        readme_url = urljoin(plugin_base_url, 'readme.txt')
        try:
            readme_response = self.session.get(readme_url, timeout=self.timeout)
            if readme_response.status_code == 200:
                result['is_installed'] = True
                result['detected_by'] = 'readme.txt'
                result['plugin_url'] = readme_url
                version_match = re.search(r'Stable tag:\s*([0-9.]+)', readme_response.text, re.IGNORECASE)
                if version_match:
                    result['version'] = version_match.group(1)
                return result
        except requests.RequestException:
            pass
        try:
            css_url = urljoin(plugin_base_url, f'assets/css/{plugin_slug}.css') 
            file_response = self.session.head(css_url, timeout=self.timeout)
            if file_response.status_code == 200:
                result['is_installed'] = True
                result['detected_by'] = 'asset file'
                result['plugin_url'] = css_url
        except requests.RequestException:
            pass
        return result

    def get_plugin_cves(self, plugin_slug: str, version: Optional[str] = None) -> Dict[str, any]:
        """
        Task 003: Get CVE info.
        NEW LOGIC: Checks free API first. Only uses paid API if plugin is outdated.
        """
        result = {
            'plugin_slug': plugin_slug,
            'version': version,
            'vulnerabilities': [],
            'is_outdated': False,
            'latest_version': None,
            'source': 'N/A'
        }
        api_token = os.environ.get('WPSCAN_API_TOKEN') 

        # --- Step 1: Check free API first to see if plugin is outdated ---
        result['source'] = 'WordPress.org API'
        try:
            wp_api_url = f'https://api.wordpress.org/plugins/info/1.0/{plugin_slug}.json'
            wp_response = self.session.get(wp_api_url, timeout=self.timeout)
            
            if wp_response.status_code == 200:
                plugin_data = wp_response.json()
                result['latest_version'] = plugin_data.get('version')
                if version and result['latest_version']:
                    result['is_outdated'] = LooseVersion(version) < LooseVersion(result['latest_version'])
            else:
                # If this API fails, we must assume it's outdated to be safe too
                result['is_outdated'] = True 
        except Exception:
            # any error assume it's outdated to trigger the CVE scan
            result['is_outdated'] = True
            pass 

        # --- Step 2: If it's outdated (or we couldn't check) AND we have a token, get CVEs ---
        # the (not result['latest_version'] and version) part handles plugins not on wordpress.org
        is_unknown = (not result['latest_version'] and version)
        
        if (result['is_outdated'] or is_unknown) and api_token:
            result['source'] = 'WPScan API (Outdated)'
            api_url = f'https://wpscan.com/api/v3/plugins/{plugin_slug}'
            headers = {'Authorization': f'Token token={api_token}'}
            try:
                api_response = self.session.get(api_url, headers=headers, timeout=self.timeout)
                if api_response.status_code == 200:
                    data = api_response.json()
                    plugin_data = data.get(plugin_slug, {})
                    
                    # We trust the WPScan latest_version more, so update it..
                    if plugin_data.get('latest_version'):
                        result['latest_version'] = plugin_data.get('latest_version')
                        if version and result['latest_version']:
                            result['is_outdated'] = LooseVersion(version) < LooseVersion(result['latest_version'])

                    # --- IMPROVEMENT: Only show relevant CVEs ---
                    for vuln in plugin_data.get('vulnerabilities', []):
                        fixed_in_version = vuln.get('fixed_in')
                        
                        if not fixed_in_version:
                            # Vulnerability is not fixed, so it's relevant
                            result['vulnerabilities'].append({
                                'title': vuln.get('title'),
                                'cve': vuln.get('cve'),
                                'fixed_in': 'Not fixed'
                            })
                        elif version:
                            try:
                                # show only if less than fixed version
                                if LooseVersion(version) < LooseVersion(fixed_in_version):
                                    result['vulnerabilities'].append({
                                        'title': vuln.get('title'),
                                        'cve': vuln.get('cve'),
                                        'fixed_in': fixed_in_version
                                    })
                            except:

                                result['vulnerabilities'].append({
                                        'title': vuln.get('title'),
                                        'cve': vuln.get('cve'),
                                        'fixed_in': fixed_in_version
                                    })
            except Exception as e:
                result['error'] = f"WPScan API error: {str(e)}"
        
        # the plugin was up-to-date AND we have a token, we skipped the CVE scan.
        if not result['is_outdated'] and api_token:
            result['source'] = 'WordPress.org API (Up to date)'

        return result
    
    
    def load_common_plugins(self, filename="plugin_list.txt", scan_level: int = 1000) -> List[str]:
        """Loads the plugin list from a file and slices it to scan_level."""
    # i used simple list first, in case the file is missing
        default_list = [
            'akismet', 'contact-form-7', 'wordpress-seo', 'jetpack',
            'wordfence', 'elementor', 'woocommerce'
        ]
        
        if not os.path.exists(filename):
            print(f"Warning: {filename} not found. Using small default list.")
            return default_list
        
        try:
            with open(filename, 'r') as f:
                plugins = [line.strip() for line in f if line.strip()]
            if scan_level == -1:
                # User selected "Full List"
                print(f"--- Loaded {len(plugins)} (All) plugins from {filename} ---")
                return plugins
            else:
                # Slice the list to the selected amount
                limited_plugins = plugins[:scan_level]
                print(f"--- Loaded {len(limited_plugins)} (Top {scan_level}) plugins from {filename} ---")
                return limited_plugins

            
        except Exception as e:
            print(f"Error reading {filename}: {e}. Using small default list.")
            return default_list



    def enumerate_plugins(self, scan_level: int = 1000) -> Dict[str, any]:
        """Task 004: Enumerate all installed WordPress plugins."""
        
        result = {
            'plugins': [],
            'total_found': 0,
            'detection_methods': []
        }
        found_slugs = set()
        
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            html = response.text
            plugin_pattern = r'/wp-content/plugins/([^/\'"]+)'
            slugs_from_html = set(re.findall(plugin_pattern, html))
            
            if slugs_from_html:
                result['detection_methods'].append('HTML parsing')
                for slug in slugs_from_html:
                    if slug not in found_slugs:
                        plugin_info = self.check_plugin(slug)
                        if plugin_info['is_installed']:
                            result['plugins'].append(plugin_info)
                            found_slugs.add(slug)
        except:
            pass
        
        # --- 3. PASS THE VALUE HERE ---
        common_plugins = self.load_common_plugins(scan_level=scan_level)
        
        result['detection_methods'].append('common plugin checking (concurrent)')
        
        plugins_to_check = [slug for slug in common_plugins if slug not in found_slugs]
        
        with ThreadPoolExecutor(max_workers=20) as executor: 
            futures = [executor.submit(self.check_plugin, slug) for slug in plugins_to_check]
            for future in futures:
                plugin_info = future.result()
                if plugin_info['is_installed']:
                    result['plugins'].append(plugin_info)
                    found_slugs.add(plugin_info['plugin_slug'])
                    
        result['total_found'] = len(result['plugins'])
        return result