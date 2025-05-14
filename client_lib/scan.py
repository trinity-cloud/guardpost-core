import requests
import time
from . import config as client_config # Import config module directly
# from .config import SESSION, ACCESS_TOKEN, BASE_URL, TEST_AWS_ACCOUNT_ID # Old import

def start_scan(services: list = None, regions: list = None):
    """Start a new scan using the stored token from client_lib.config."""
    if not client_config.ACCESS_TOKEN:
        print("Cannot start scan: Not logged in (no access token in client_lib.config).")
        return None
        
    if client_config.TEST_AWS_ACCOUNT_ID == "YOUR_AWS_ACCOUNT_ID":
         print("\n*** WARNING: Please set GUARDPOST_TEST_ACCOUNT_ID environment variable or update TEST_AWS_ACCOUNT_ID in client_lib/config.py ***\n")
         return None

    print(f"--- [Client Lib] Starting GuardPost Core scan for AWS Account: {client_config.TEST_AWS_ACCOUNT_ID} ---")
    url = f"{client_config.BASE_URL}/scans/"
    payload = {
        "aws_account_id": client_config.TEST_AWS_ACCOUNT_ID,
        "scan_type": "standard", 
    }
    if services:
        payload["services"] = services
        print(f"    Target Services: {services}")
    if regions:
         payload["regions"] = regions
         print(f"    Target Regions: {regions}")
    else:
        print("    (Using default services/regions defined in backend)")
         
    try:
        response = client_config.SESSION.post(url, json=payload)
        if response.status_code == 200:
            scan_data = response.json()
            scan_id = scan_data.get("id")
            print(f"Scan request accepted. Scan ID: {scan_id}")
            print("(Scan runs asynchronously in the background. Polling for status...)")
            return scan_id
        else:
            print(f"Failed to start scan: {response.status_code} - {response.text}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Start scan request failed: {e}")
        return None

def poll_scan_status(scan_id):
    """Poll the scan status until completed or failed using token from client_lib.config."""
    if not client_config.ACCESS_TOKEN:
        print("Cannot poll scan status: Not logged in (no access token in client_lib.config).")
        return None
    if not scan_id:
        print("Cannot poll scan status: Invalid scan_id.")
        return None

    print(f"--- [Client Lib] Polling status for Scan ID: {scan_id} ---")
    url = f"{client_config.BASE_URL}/scans/{scan_id}"
    start_time = time.time()
    timeout_seconds = 600 # 10 minutes timeout

    while time.time() - start_time < timeout_seconds:
        try:
            response = client_config.SESSION.get(url)
            if response.status_code == 200:
                scan_data = response.json()
                status = scan_data.get("status")
                progress = scan_data.get("progress_percentage", 0)
                task_info = scan_data.get("current_task") or "-"
                print(f"    Status: {status}, Progress: {progress}%, Current Task: {task_info}", end='\r')

                if status == "completed":
                    print("\nScan completed. Resource data and relationships stored in Neo4j.") 
                    return "completed"
                elif status == "failed":
                    error_msg = scan_data.get("error_message", "Unknown error")
                    print(f"\nScan failed: {error_msg}") 
                    return "failed"
                
            elif response.status_code == 404:
                 print(f"\nScan ID {scan_id} not found (404).")
                 return "not_found"
            else:
                print(f"\nError getting scan status: {response.status_code} - {response.text}. Retrying...")
                time.sleep(5) 

        except requests.exceptions.RequestException as e:
            print(f"\nPolling request failed: {e}. Retrying...")
        
        time.sleep(10) 

    print("\nPolling timed out after 10 minutes.") 
    return "timeout" 