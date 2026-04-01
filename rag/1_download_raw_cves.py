import os
import time
import requests
import json

# ==========================================
# CONFIGURATION
# ==========================================
RAW_DATA_DIR = "./raw_knowledgebase"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000

# NVD allows 50 requests/30s with a key, and 5 requests/30s without one.
API_KEY = os.getenv("NVD_API_KEY")
SLEEP_TIME = 1 if API_KEY else 6 

def get_latest_start_index():
    """Checks the raw directory to find where we left off."""
    if not os.path.exists(RAW_DATA_DIR):
        os.makedirs(RAW_DATA_DIR)
        return 0
        
    files = [f for f in os.listdir(RAW_DATA_DIR) if f.startswith("cve_batch_") and f.endswith(".json")]
    if not files:
        return 0
        
    # Extract the starting index from the filenames (e.g., "cve_batch_4000.json" -> 4000)
    indices = [int(f.split("_")[2].split(".")[0]) for f in files]
    # If the highest file is 4000, the next batch should start at 4000 + 2000
    return max(indices) + RESULTS_PER_PAGE

def download_all_cves():
    print(f"📁 Initializing raw download to {RAW_DATA_DIR}...")
    
    start_index = get_latest_start_index()
    total_results = None 
    
    headers = {"apiKey": API_KEY} if API_KEY else {}
    
    while True:
        if total_results and start_index >= total_results:
            print("\n✅ Successfully downloaded the entire NVD database!")
            break
            
        print(f"📥 Fetching records {start_index} to {start_index + RESULTS_PER_PAGE}...")
        params = {"startIndex": start_index, "resultsPerPage": RESULTS_PER_PAGE}
        
        try:
            response = requests.get(NVD_API_URL, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()
            
            # On the first successful request, grab the total number of records
            if total_results is None:
                total_results = data.get("totalResults", 0)
                print(f"📊 Total CVEs in NVD: {total_results}")

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                print("No vulnerabilities returned. Ending download.")
                break
                
            # Save the raw batch to disk
            batch_filename = os.path.join(RAW_DATA_DIR, f"cve_batch_{start_index}.json")
            with open(batch_filename, 'w', encoding='utf-8') as f:
                json.dump(vulnerabilities, f)
                
            start_index += RESULTS_PER_PAGE
            
            # Respect API limits
            time.sleep(SLEEP_TIME)
            
        except requests.exceptions.HTTPError as e:
            print(f"❌ HTTP Error (Likely rate limited). Sleeping for 30s before retrying... {e}")
            time.sleep(30)
            # Notice we do NOT increment start_index here, so it retries the same batch
        except Exception as e:
            print(f"❌ Critical Error: {e}")
            break

if __name__ == "__main__":
    download_all_cves()