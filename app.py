import threading
import os
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, render_template, request, jsonify
from scanner import WordPressScanner
from plugin_builder import build_list
from urllib.parse import urlparse, urlunparse 

app = Flask(__name__)

@app.route('/')
def index():
    """Serves the main HTML page."""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def start_scan():
    """Runs the scanner and returns JSON results."""
    data = request.json
    url = data.get('target_url')
    
    scan_level = data.get('scan_level', 1000)
    
    if not url:
        return jsonify({'error': 'No target URL provided'}), 400
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        parsed_url = urlparse(url)
        sanitized_url = urlunparse((
            parsed_url.scheme, 
            parsed_url.netloc, 
            '', '', '', ''
        ))
    except:
        sanitized_url = url
    
    try:
        scanner = WordPressScanner(sanitized_url) 
        results = {}
        
        results['wp_check'] = scanner.is_wordpress()
        
        if results['wp_check']['is_wordpress']:
            
            plugin_data = scanner.enumerate_plugins(scan_level=scan_level)
            
            results['plugins'] = plugin_data
            
            cve_results = []
            with ThreadPoolExecutor(max_workers=10) as executor: 
                futures = {
                    executor.submit(scanner.get_plugin_cves, p['plugin_slug'], p.get('version')): p 
                    for p in plugin_data['plugins']
                }
                for future in futures:
                    cve_results.append(future.result())
                    
            results['vulnerabilities'] = cve_results
        
        return jsonify(results)

    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

@app.route('/builder')
def builder_page():
    """Serves the new plugin builder HTML page."""
    return render_template('builder.html')

@app.route('/run-builder', methods=['POST'])
def run_builder():
    """Runs the plugin builder script in the background."""
    try:
        data = request.json
        sort_by = data.get('sort_by', 'popular')
        total_plugins = data.get('total_plugins', 1000)
        
        print("Starting background thread for plugin build...")
        thread = threading.Thread(
            target=build_list, 
            args=(sort_by, total_plugins)
        )
        thread.start()
        
        return jsonify({
            'message': 'Plugin list build started! Check your terminal console for progress.'
        }), 202

    except Exception as e:
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500


if __name__ == '__main__':
    app.run(debug=True)