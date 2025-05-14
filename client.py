import time
import argparse

# Import functions from the new client_lib package
from client_lib import auth, scan, findings, display
from client_lib import config as client_config # Import the config module directly to check ACCESS_TOKEN

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GuardPost Core API Client Example.")
    parser.add_argument("--get-token", action="store_true", help="Register/Login and print the access token, then exit.")
    parser.add_argument("--s3-only", action="store_true", help="Only scan S3 resources")
    # Add arguments for other services if desired, e.g., --iam-only, --ec2-only
    # For now, the default will be all services unless --s3-only is specified.
    parser.add_argument("--show-all-remediations", action="store_true", help="Show remediation guidance for all findings")
    parser.add_argument("--max-remediations", type=int, default=3, help="Maximum number of remediations to display (default: 3, ignored if --show-all-remediations is set)")
    args = parser.parse_args()

    if args.get_token:
        print("Attempting to get auth token...")
        # Try registration, if it returns True (meaning user exists or was created), then try login.
        if auth.register_user(): 
            auth.login_user()
        # If register_user returned False (hard failure), still attempt login as a fallback.
        else:
            auth.login_user()
        
        if client_config.ACCESS_TOKEN: # Check token from client_lib.config
            print("\n--- ACCESS TOKEN ---")
            print(client_config.ACCESS_TOKEN)
            print("--- END TOKEN --- \n(Use 'export GUARDPOST_TOKEN=...' for other tools or copy/paste)")
        else:
            print("\nFailed to retrieve access token after login attempt.")
        exit() 

    print("Starting GuardPost Core API Client Example Flow...")

    # 1. Register / Login
    # Attempt registration. auth.register_user() returns True if user exists or registration is successful.
    # If True, then attempt login. auth.login_user() sets ACCESS_TOKEN in client_config.
    if auth.register_user():
        auth.login_user() 
    else:
        # If registration outright failed (not just user exists), then try login as a last resort.
        auth.login_user()

    # After all attempts, check if ACCESS_TOKEN in client_config is set.
    if not client_config.ACCESS_TOKEN:
         print("\nExiting - failed to obtain access token after registration/login attempts.")
         exit()
         
    print(f"Auth successful. Token: {client_config.ACCESS_TOKEN[:20]}...") # Print a snippet for confirmation
    time.sleep(1)

    # Determine services to scan
    scan_services_to_run = [] # Default to empty list (scan all services as per backend default)
    if args.s3_only:
        scan_services_to_run = ["s3"]
    # Add more conditions here if other service-specific flags are introduced
    # e.g., elif args.ec2_only: scan_services_to_run = ["ec2"]
    
    # If no specific service flag is set, scan_services_to_run remains [], 
    # which the backend should interpret as "all services".
    # If you want an explicit "all" to be sent, you might need to fetch available services first
    # or have a convention with the backend for an empty list meaning all.

    scan_id = scan.start_scan(services=scan_services_to_run if scan_services_to_run else None)
    # Passing None if scan_services_to_run is empty to rely on backend default for "all"
    # Or, if backend expects an empty list for all, pass scan_services_to_run directly.
    # Based on current client_lib/scan.py, passing None will trigger "Using default services/regions"

    if not scan_id:
        print("\nExiting due to scan start failure.")
        exit()
        
    time.sleep(1)

    # 3. Poll Scan Status
    final_status = scan.poll_scan_status(scan_id)

    # 4. Process Results if Scan Completed
    if final_status == "completed":
        print("\n--- Scan Complete - Retrieving Results ---")
        
        scan_findings_results = findings.get_scan_findings(scan_id=scan_id, limit=100)
        print("-" * 20)
        time.sleep(1)

        if not scan_findings_results or len(scan_findings_results) == 0:
            print("\nNo findings to display remediation guidance for.")
        else:
            print("\n--- Demonstrating Remediation Guidance --- ")
            
            if args.show_all_remediations:
                for i, finding_data in enumerate(scan_findings_results):
                    finding_id = finding_data.get('id')
                    finding_title = finding_data.get('title')
                    finding_severity = finding_data.get('severity', '').upper()
                    
                    print(f"\n[{finding_severity}] Finding: {finding_title}")
                    findings.get_finding_remediation(finding_id)
                    time.sleep(0.5)
            else:
                high_prio_findings = []
                for finding_data in scan_findings_results:
                    severity = finding_data.get('severity', '').lower()
                    if severity in ['critical', 'high']:
                        high_prio_findings.append(finding_data)
                
                if high_prio_findings:
                    count = 0
                    for finding_data in high_prio_findings:
                        if count >= args.max_remediations:
                            print(f"\nShowing only first {args.max_remediations} high priority remediations. Use --max-remediations to adjust or --show-all-remediations to see all.")
                            break
                        
                        finding_id = finding_data.get('id')
                        finding_title = finding_data.get('title')
                        finding_severity = finding_data.get('severity', '').upper()
                        
                        print(f"\n[{finding_severity}] Finding: {finding_title}")
                        findings.get_finding_remediation(finding_id)
                        count += 1
                        time.sleep(0.5)
                else:
                    print("\nNo CRITICAL or HIGH severity findings found in this scan.")
                    if scan_findings_results: # Show at least one if no high prio
                        finding_data = scan_findings_results[0]
                        finding_id = finding_data.get('id')
                        finding_title = finding_data.get('title')
                        finding_severity = finding_data.get('severity', '').upper()
                        print(f"\nShowing remediation for a [{finding_severity}] finding instead: {finding_title}")
                        findings.get_finding_remediation(finding_id)
            
            print("-" * 20) 

        display.show_graph_info()
            
    else:
        print(f"\nScan did not complete successfully (Status: {final_status}). Cannot show findings or graph examples.")

    print("\nGuardPost Core API Client Example Finished.") 