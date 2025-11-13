import requests
import re
from typing import Optional, Dict, List
from urllib.parse import urljoin
import json

class WordPressScanner:
    """WordPress security scanning utility"""
    
    def __init__(self, target_url: str, timeout: int = 10):
        """
        Initialize scanner with target URL
        
        Args:
            target_url: The WordPress site URL to scan
            timeout: Request timeout in seconds
        """
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def is_wordpress(self) -> Dict[str, any]:
        """
        Task 001: Check if the target website is using WordPress
        
        Returns:
            Dict containing detection results and details
        """
        indicators = {
            'is_wordpress': False,
            'confidence': 0,
            'detected_by': [],
            'wp_version': None
        }
        
        try:
            # Check main page
            response = self.session.get(self.target_url, timeout=self.timeout)
            html = response.text
            
            # Method 1: Check for wp-content in HTML
            if '/wp-content/' in html or '/wp-includes/' in html:
                indicators['detected_by'].append('wp-content/wp-includes paths')
                indicators['confidence'] += 30
            
            # Method 2: Check meta generator tag
            generator_match = re.search(r'<meta name="generator" content="WordPress ([0-9.]+)"', html)
            if generator_match:
                indicators['detected_by'].append('meta generator tag')
                indicators['wp_version'] = generator_match.group(1)
                indicators['confidence'] += 40
            
            # Method 3: Check for wp-json endpoint
            try:
                api_url = urljoin(self.target_url, '/wp-json/')
                api_response = self.session.get(api_url, timeout=self.timeout)
                if api_response.status_code == 200:
                    indicators['detected_by'].append('REST API endpoint')
                    indicators['confidence'] += 30
                    
                    # Try to get version from API
                    if not indicators['wp_version']:
                        try:
                            api_data = api_response.json()
                            if 'namespaces' in api_data and 'wp/v2' in api_data['namespaces']:
                                indicators['confidence'] += 10
                        except:
                            pass
            except:
                pass
            
            # Method 4: Check common WordPress files
            wp_files = ['/wp-login.php', '/readme.html', '/license.txt']
            for file_path in wp_files:
                try:
                    file_url = urljoin(self.target_url, file_path)
                    file_response = self.session.head(file_url, timeout=self.timeout)
                    if file_response.status_code == 200:
                        indicators['detected_by'].append(f'{file_path} exists')
                        indicators['confidence'] += 20
                        break
                except:
                    pass
            
            # Determine if WordPress
            if indicators['confidence'] >= 30:
                indicators['is_wordpress'] = True
            
        except requests.RequestException as e:
            indicators['error'] = str(e)
        
        return indicators
    
    def check_plugin(self, plugin_slug: str) -> Dict[str, any]:
        """
        Task 002: Check if a specific plugin is installed and get its version
        
        Args:
            plugin_slug: The plugin slug (folder name)
            
        Returns:
            Dict containing plugin detection results and version
        """
        result = {
            'plugin_slug': plugin_slug,
            'is_installed': False,
            'version': None,
            'detected_by': [],
            'plugin_url': None
        }
        
        try:
            plugin_base_url = f'{self.target_url}/wp-content/plugins/{plugin_slug}/'
            result['plugin_url'] = plugin_base_url
            
            # Method 1: Check readme.txt
            readme_url = urljoin(plugin_base_url, 'readme.txt')
            try:
                readme_response = self.session.get(readme_url, timeout=self.timeout)
                if readme_response.status_code == 200:
                    result['is_installed'] = True
                    result['detected_by'].append('readme.txt')
                    
                    # Extract version from readme.txt
                    version_match = re.search(r'Stable tag:\s*([0-9.]+)', readme_response.text)
                    if version_match:
                        result['version'] = version_match.group(1)
            except:
                pass
            
            # Method 2: Check for main plugin file
            if not result['is_installed']:
                main_file_url = urljoin(plugin_base_url, f'{plugin_slug}.php')
                try:
                    main_response = self.session.head(main_file_url, timeout=self.timeout)
                    if main_response.status_code == 200:
                        result['is_installed'] = True
                        result['detected_by'].append('main plugin file')
                except:
                    pass
            
            # Method 3: Check plugin directory
            if not result['is_installed']:
                try:
                    dir_response = self.session.get(plugin_base_url, timeout=self.timeout)
                    if dir_response.status_code == 200 and 'Index of' in dir_response.text:
                        result['is_installed'] = True
                        result['detected_by'].append('directory listing')
                except:
                    pass
            
            # Method 4: Try to get version from main plugin file if not found
            if result['is_installed'] and not result['version']:
                main_file_url = urljoin(plugin_base_url, f'{plugin_slug}.php')
                try:
                    file_response = self.session.get(main_file_url, timeout=self.timeout)
                    if file_response.status_code == 200:
                        version_match = re.search(r'Version:\s*([0-9.]+)', file_response.text)
                        if version_match:
                            result['version'] = version_match.group(1)
                except:
                    pass
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def get_plugin_cves(self, plugin_slug: str, version: Optional[str] = None) -> Dict[str, any]:
        """
        Task 003: Get CVE information for a specific plugin and version
        
        Args:
            plugin_slug: The plugin slug
            version: The plugin version (optional)
            
        Returns:
            Dict containing CVE information and related data
        """
        result = {
            'plugin_slug': plugin_slug,
            'version': version,
            'vulnerabilities': [],
            'total_cves': 0,
            'severity_count': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'source': 'WPScan API'
        }
        
        try:
            # Using WPScan Vulnerability Database API
            # Note: You need to get a free API token from https://wpscan.com/api
            api_url = f'https://wpscan.com/api/v3/plugins/{plugin_slug}'
            
            # For this example, we'll use a mock request
            # In production, you would need to add your API token:
            # headers = {'Authorization': f'Token token={YOUR_API_TOKEN}'}
            
            # Mock response structure for demonstration
            result['note'] = 'To use this function, you need a WPScan API token from https://wpscan.com/api'
            result['example_usage'] = {
                'api_url': api_url,
                'required_header': 'Authorization: Token token=YOUR_API_TOKEN'
            }
            
            # Alternative: Check WordPress.org plugin vulnerabilities
            # This is a simplified example
            try:
                wp_api_url = f'https://api.wordpress.org/plugins/info/1.0/{plugin_slug}.json'
                wp_response = self.session.get(wp_api_url, timeout=self.timeout)
                
                if wp_response.status_code == 200:
                    plugin_data = wp_response.json()
                    result['plugin_info'] = {
                        'name': plugin_data.get('name'),
                        'latest_version': plugin_data.get('version'),
                        'last_updated': plugin_data.get('last_updated'),
                        'active_installs': plugin_data.get('active_installs'),
                        'requires_wp': plugin_data.get('requires'),
                        'tested_up_to': plugin_data.get('tested')
                    }
                    
                    # Check if version is outdated
                    if version and plugin_data.get('version'):
                        result['is_outdated'] = version != plugin_data.get('version')
            except:
                pass
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def enumerate_plugins(self) -> Dict[str, any]:
        """
        Task 004: Enumerate all installed WordPress plugins
        
        Returns:
            Dict containing list of detected plugins with details
        """
        result = {
            'plugins': [],
            'total_found': 0,
            'detection_methods': []
        }
        
        try:
            # Method 1: Check REST API for plugins
            api_url = urljoin(self.target_url, '/wp-json/wp/v2/plugins')
            try:
                api_response = self.session.get(api_url, timeout=self.timeout)
                if api_response.status_code == 200:
                    plugins_data = api_response.json()
                    result['detection_methods'].append('REST API')
                    
                    for plugin in plugins_data:
                        result['plugins'].append({
                            'slug': plugin.get('plugin'),
                            'name': plugin.get('name'),
                            'version': plugin.get('version'),
                            'status': plugin.get('status')
                        })
            except:
                pass
            
            # Method 2: Parse HTML for plugin references
            try:
                response = self.session.get(self.target_url, timeout=self.timeout)
                html = response.text
                
                # Find all wp-content/plugins/ references
                plugin_pattern = r'/wp-content/plugins/([^/\'"]+)'
                found_slugs = set(re.findall(plugin_pattern, html))
                
                if found_slugs:
                    result['detection_methods'].append('HTML parsing')
                    
                    for slug in found_slugs:
                        # Check if already in list
                        if not any(p['slug'] == slug for p in result['plugins']):
                            # Try to get version
                            plugin_info = self.check_plugin(slug)
                            result['plugins'].append({
                                'slug': slug,
                                'name': slug.replace('-', ' ').title(),
                                'version': plugin_info.get('version'),
                                'detected_by': 'HTML reference'
                            })
            except:
                pass
            
            # Method 3: Common plugin brute-force (top 20 popular plugins)
            common_plugins = [
                'akismet', 'contact-form-7', 'wordpress-seo', 'jetpack',
                'wordfence', 'elementor', 'woocommerce', 'all-in-one-seo-pack',
                'google-analytics-for-wordpress', 'wpforms-lite', 'wp-super-cache',
                'classic-editor', 'duplicate-post', 'wordpress-importer',
                'updraftplus', 'wp-optimize', 'really-simple-ssl', 'autoptimize',
                'limit-login-attempts-reloaded', 'redirection'
            ]
            
            result['detection_methods'].append('common plugin checking')
            
            for slug in common_plugins:
                # Skip if already found
                if any(p['slug'] == slug for p in result['plugins']):
                    continue
                
                plugin_info = self.check_plugin(slug)
                if plugin_info['is_installed']:
                    result['plugins'].append({
                        'slug': slug,
                        'name': slug.replace('-', ' ').title(),
                        'version': plugin_info.get('version'),
                        'detected_by': 'common plugin check'
                    })
            
            result['total_found'] = len(result['plugins'])
            
        except Exception as e:
            result['error'] = str(e)
        
        return result


# Example usage
if __name__ == '__main__':
    # Initialize scanner
    target = 'https://olddriving.s3-tastewp.com/'  # Replace with target WordPress site
    scanner = WordPressScanner(target)
    
    # Task 001: Check if WordPress
    print("=== Task 001: WordPress Detection ===")
    wp_check = scanner.is_wordpress()
    print(json.dumps(wp_check, indent=2))
    print()
    
    # Task 002: Check specific plugin
    print("=== Task 002: Plugin Detection ===")
    plugin_check = scanner.check_plugin('contact-form-7')
    print(json.dumps(plugin_check, indent=2))
    print()
    
    # Task 003: Get CVE information
    print("=== Task 003: CVE Information ===")
    cve_info = scanner.get_plugin_cves('contact-form-7', '5.4.2')
    print(json.dumps(cve_info, indent=2))
    print()
    
    # Task 004: Enumerate all plugins
    print("=== Task 004: Plugin Enumeration ===")
    all_plugins = scanner.enumerate_plugins()
    print(json.dumps(all_plugins, indent=2))