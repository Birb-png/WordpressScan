import requests
import json
import math

PLUGIN_LIST_FILE = 'plugin_list.txt'
PER_PAGE = 100 # API max is 100

def build_list(sort_by: str = "popular", total_plugins: int = 1000):
    """
    Fetches the top plugins from the WordPress.org API
    and saves their slugs to a file.
    """
    
    pages_to_fetch = math.ceil(total_plugins / PER_PAGE)
    
    print("--- PLUGIN LIST BUILD STARTED ---")
    print(f"Mode: {sort_by}, Total Plugins: {total_plugins}")
    
    all_plugin_slugs = []
    
    for page in range(1, pages_to_fetch + 1):
        try:
            api_url = (
                f'https://api.wordpress.org/plugins/info/1.2/?'
                f'action=query_plugins&request[page]={page}&'
                f'request[per_page]={PER_PAGE}&request[browse]={sort_by}'
            )
            
            response = requests.get(api_url, timeout=10)
            if response.status_code != 200:
                print(f"Error fetching page {page}, status code: {response.status_code}")
                continue
                
            data = response.json()
            plugins = data.get('plugins', [])
            if not plugins:
                print(f"No more plugins found at page {page}.")
                break
                
            for plugin in plugins:
                all_plugin_slugs.append(plugin['slug'])
                
            print(f"Fetched page {page}/{pages_to_fetch}... found {len(all_plugin_slugs)} total slugs.")
            
            # Stop if we have enough plugins
            if len(all_plugin_slugs) >= total_plugins:
                break

        except Exception as e:
            print(f"An error occurred: {e}")
            
    try:
        final_list = all_plugin_slugs[:total_plugins]
        with open(PLUGIN_LIST_FILE, 'w') as f:
            for slug in final_list:
                f.write(f"{slug}\n")
        print(f"\nSUCCESS: Saved {len(final_list)} plugin slugs to {PLUGIN_LIST_FILE}")
        
    except Exception as e:
        print(f"Error writing to file: {e}")
        
    print("--- PLUGIN LIST BUILD FINISHED ---")