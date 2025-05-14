from typing import List, Dict, Any
from loguru import logger

def format_tags(tags_list: List[Dict[str, str]]) -> Dict[str, str]:
    """Converts the AWS tag list format to a simple key-value dictionary."""
    if not tags_list:
        return {}
    return {tag['Key']: tag['Value'] for tag in tags_list if 'Key' in tag and 'Value' in tag}

# --- Helper function to parse S3/Lambda Policy Principals ---
def _parse_s3_policy_principals(principal_block: Any) -> Dict[str, Any]:
    """Parses Principal block from S3/Lambda policy. Returns dict with categorized lists."""
    parsed = {
        "aws_principals": [],
        "service_principals": [],
        "canonical_user_principals": [],
        "federated_principals": [], # SAML or OIDC
        "is_wildcard_principal": False,
        "original_principal_block": principal_block # For auditing/debugging
    }
    if not principal_block:
        return parsed

    if principal_block == "*":
        parsed["is_wildcard_principal"] = True
        parsed["aws_principals"].append("*") 
        return parsed

    if isinstance(principal_block, dict):
        for principal_type, identifiers in principal_block.items():
            current_list = []
            if isinstance(identifiers, str):
                current_list = [identifiers]
            elif isinstance(identifiers, list):
                current_list = identifiers
            else:
                logger.warning(f"Policy Principal Parser: Unexpected identifier format for {principal_type}: {identifiers}")
                continue

            # Normalize keys for comparison
            pt_lower = principal_type.lower()
            if pt_lower == "aws":
                parsed["aws_principals"].extend(current_list)
                if "*" in current_list:
                    parsed["is_wildcard_principal"] = True
            elif pt_lower == "service":
                parsed["service_principals"].extend(current_list)
            elif pt_lower == "canonicaluser":
                parsed["canonical_user_principals"].extend(current_list)
            elif pt_lower == "federated": # Covers SAML, OIDC
                parsed["federated_principals"].extend(current_list)
            else:
                logger.warning(f"Policy Principal Parser: Unknown principal type '{principal_type}'. Storing identifier under aws_principals as fallback.")
                parsed["aws_principals"].extend(current_list) 
    else:
        logger.warning(f"Policy Principal Parser: Unexpected principal_block format: {principal_block}. Treating as potential AWS principal.")
        if isinstance(principal_block, str):
            parsed["aws_principals"].append(principal_block)

    # Deduplicate and final wildcard check
    for key in ["aws_principals", "service_principals", "canonical_user_principals", "federated_principals"]:
        parsed[key] = list(set(parsed[key]))
        if "*" in parsed["aws_principals"]: # Check list after deduplication
            parsed["is_wildcard_principal"] = True

    return parsed
# --- End Helper ---

# Add other common scanner utilities here as needed 