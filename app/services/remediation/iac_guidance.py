from typing import Optional, Dict, Any, Callable, Union

# Assuming schemas and models are accessible via absolute import paths
# from app.api.v1.schemas import FindingSeverity, FindingCategory, Finding # Not directly needed here anymore
from app.db import models # DB Model for Finding type hint

# Import the V2 remediation guidance schema
from .schemas import RemediationOutputV2

# Import service-specific maps
from .s3_guidance import S3_GUIDANCE_MAP
from .ec2_guidance import EC2_GUIDANCE_MAP
from .iam_guidance import IAM_GUIDANCE_MAP
from .lambda_guidance import LAMBDA_GUIDANCE_MAP
from .rds_guidance import RDS_GUIDANCE_MAP

# --- Consolidate Guidance Maps ---
# All mapped functions should now aim to return RemediationOutputV2 or None (if error/not applicable)
FINDING_GUIDANCE_MAP: Dict[tuple[str, str], Callable[[models.Finding], Optional[RemediationOutputV2]]] = {
    **S3_GUIDANCE_MAP,
    **EC2_GUIDANCE_MAP,
    **IAM_GUIDANCE_MAP,
    **LAMBDA_GUIDANCE_MAP,
    **RDS_GUIDANCE_MAP,
    # Add other maps here if new services are added
}


# Main dispatcher function
def get_remediation_guidance(finding: models.Finding) -> Optional[RemediationOutputV2]:
    """
    Provides structured V2 remediation guidance for a given finding.

    Args:
        finding: The database Finding object (expected to have a .details attribute).

    Returns:
        A RemediationOutputV2 Pydantic model containing V2 guidance,
        or None if no specific guidance function is matched or an error occurs.
    """
    resource_type = finding.resource_type
    # Normalize title for keyword matching - be careful with overly aggressive lowercasing if map keys are case-sensitive.
    # It might be better to ensure map keys are consistently cased (e.g., all lowercase).
    title_for_match = finding.title.lower() 
    
    guidance_func_to_call: Optional[Callable[[models.Finding], Optional[RemediationOutputV2]]] = None

    # Exact match first (most specific)
    if (resource_type, title_for_match) in FINDING_GUIDANCE_MAP:
        guidance_func_to_call = FINDING_GUIDANCE_MAP[(resource_type, title_for_match)]
    else:
        # Fallback to keyword-based matching (less specific)
        for (map_resource_type, title_keyword), guidance_func in FINDING_GUIDANCE_MAP.items():
            if resource_type == map_resource_type and title_keyword.lower() in title_for_match:
                guidance_func_to_call = guidance_func
                break
    
    if guidance_func_to_call:
        try:
            # Ensure the called function returns RemediationOutputV2 or None
            guidance_result = guidance_func_to_call(finding)
            if guidance_result is not None and not isinstance(guidance_result, RemediationOutputV2):
                # This case should ideally not happen if all guidance functions are correctly refactored.
                print(f"Warning: Guidance function {guidance_func_to_call.__name__} for finding {finding.id} did not return RemediationOutputV2 or None.")
                return None # Or attempt to convert/wrap if a defined fallback exists
            return guidance_result
        except Exception as e:
            print(f"Error generating V2 guidance for finding {finding.id} ({resource_type} - {title_for_match}) with {guidance_func_to_call.__name__}: {e}")
            import traceback
            traceback.print_exc() # Print full traceback for debugging
            return None

    print(f"No specific V2 guidance function found for finding {finding.id} ({resource_type} - '{title_for_match}')")
    return None
