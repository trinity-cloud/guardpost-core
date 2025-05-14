import requests
import json # For pretty printing JSON
from . import config as client_config # Import config module directly
# from .config import SESSION, ACCESS_TOKEN, BASE_URL # Old import

def get_scan_findings(scan_id: str, limit: int = 100):
    """Get findings for a specific completed scan using token from client_lib.config."""
    if not client_config.ACCESS_TOKEN:
        print("Cannot get findings: Not logged in (no access token in client_lib.config).")
        return None

    print(f"--- [Client Lib] Fetching findings for completed Scan ID: {scan_id} (Limit: {limit}) ---")
    url = f"{client_config.BASE_URL}/findings/"
    params = {"scan_id": scan_id, "limit": limit}
    
    try:
        response = client_config.SESSION.get(url, params=params)
        if response.status_code == 200:
            findings = response.json()
            print(f"Found {len(findings)} findings for this scan (showing up to {limit}):")
            if findings:
                for i, finding_item in enumerate(findings):
                    print(f"  {i+1}. [{finding_item.get('severity', 'N/A').upper()}] {finding_item.get('title', 'No Title')} ({finding_item.get('resource_type', 'N/A')}: {finding_item.get('resource_id', 'N/A')}) ID: {finding_item.get('id')}")
            else:
                 print("  No findings generated for this scan.")
            return findings
        else:
            print(f"Failed to get findings: {response.status_code} - {response.text}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Get findings request failed: {e}")
        return None

def get_finding_remediation(finding_id: str):
    """Gets the remediation guidance for a finding and handles different response structures."""
    if not client_config.ACCESS_TOKEN:
        print("Cannot get remediation: Not logged in.")
        return None
    if not finding_id:
        print("Cannot get remediation: Invalid finding_id.")
        return None

    print(f"--- [Client Lib] Fetching remediation for Finding ID: {finding_id} ---")
    url = f"{client_config.BASE_URL}/findings/{finding_id}/remediation"
    try:
        response = client_config.SESSION.get(url)
        if response.status_code == 200:
            api_response_data = response.json()
            print("Remediation Details:")

            # Check for V2 schema version directly from the response data
            if api_response_data and api_response_data.get('schema_version') == '2.0':
                is_llm_enhanced = api_response_data.get('is_llm_enhanced', False) # Check our new flag
                enhancement_type = "LLM Enhanced" if is_llm_enhanced else "Rule-Based"
                print(f"\n  Remediation Details (V2 - {enhancement_type}):")

                # Issue Summary
                if api_response_data.get('issue_summary'):
                    print(f"\n  Issue Summary:")
                    print(f"    {api_response_data.get('issue_summary')}")
                
                # Technical Details
                if api_response_data.get('technical_details'):
                    print(f"\n  Technical Details:")
                    print(f"    {api_response_data.get('technical_details')}")
                
                # Risk Score
                risk_score = api_response_data.get('risk_score')
                if risk_score:
                    print(f"\n  Risk Score: {risk_score.get('score', 'N/A')}/100 (Confidence: {risk_score.get('confidence', 'N/A')})")
                
                # Impact Analysis
                impact = api_response_data.get('impact_analysis')
                if impact:
                    print(f"\n  Impact Analysis:")
                    print(f"    Affected Resource Count: {impact.get('affected_resource_count', 'N/A')}")
                    print(f"    Blast Radius Score: {impact.get('blast_radius_score', 'N/A')}")
                    if impact.get('critical_affected_resources'):
                        print(f"    Critical Affected Resources:")
                        for res in impact.get('critical_affected_resources')[:5]:  # Limit to first 5
                            print(f"      - {res}")
                
                # Manual Steps
                manual_steps = api_response_data.get('manual_steps', [])
                if manual_steps:
                    print(f"\n  Manual Remediation Steps:")
                    for i, step in enumerate(manual_steps, 1):
                        print(f"    {i}. {step}")
                
                # IaC Remediation
                iac_remediation_data = api_response_data.get('iac_remediation')
                if iac_remediation_data:
                    print(f"\n  Infrastructure as Code ({iac_remediation_data.get('tool', 'Terraform').upper()}):")
                    code = iac_remediation_data.get('code_snippet', '')
                    if code:
                        formatted_code = code.replace('\n', '\n      ')
                        print(f"      {formatted_code}")
                    if iac_remediation_data.get('apply_instructions'):
                        print(f"\n    Apply Instructions: {iac_remediation_data.get('apply_instructions')}")
                elif api_response_data.get('iac_applicable') is False: # Handle cases where IaC is explicitly not applicable
                    print("\n  Infrastructure as Code: Not Applicable")
                    if api_response_data.get('reason'): # If a reason is provided for not being applicable
                         print(f"    Reason: {api_response_data.get('reason')}")

                # Compliance Standards
                if api_response_data.get('compliance_standards'):
                    print(f"\n  Compliance Standards:")
                    for std in api_response_data.get('compliance_standards', []):
                        print(f"    - {std}")

                # Reference Links
                if api_response_data.get('reference_links'):
                    print(f"\n  Reference Links:")
                    for ref in api_response_data.get('reference_links', []):
                        print(f"    - {ref}")
            
            # Fallback for older/unexpected formats or if no V2 schema detected
            else:
                legacy_steps = api_response_data.get('steps', [])
                guidance_content = api_response_data.get('guidance', {}) # Check for old nested structure

                if not legacy_steps and not guidance_content: # If truly nothing
                    print("  No remediation guidance or steps provided by the API, or format is unrecognized.")
                else:
                    print("\n  Displaying basic or legacy remediation details:")
                    if legacy_steps:
                        print(f"\n  Basic Remediation Steps (from finding model):")
                        for i, step in enumerate(legacy_steps, 1):
                            print(f"    {i}. {step}")
                    if guidance_content: # If old nested 'guidance' key exists
                        print(f"\n  Additional Raw Guidance Content (Legacy Format):")
                        # Basic display of some known old fields if they exist
                        if guidance_content.get('finding_title'): print(f"    Title: {guidance_content.get('finding_title')}")
                        if guidance_content.get('guidance_notes'): print(f"    Notes: {guidance_content.get('guidance_notes')}")
                        if guidance_content.get('required_change'): print(f"    Required Change: {json.dumps(guidance_content.get('required_change'), indent=2)}")
                        if 'reason' in guidance_content: print(f"    Reason (if IaC not applicable): {guidance_content.get('reason')}")

            print("\n" + "-" * 40)
            return api_response_data
        
        elif response.status_code == 404:
            print(f"Finding ID {finding_id} not found (for remediation).")
            return None
        else:
            print(f"Failed to get remediation: {response.status_code} - {response.text}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Get remediation request failed: {e}")
        return None 