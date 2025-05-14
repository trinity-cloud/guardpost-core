import os
import anthropic
import json
from typing import Dict, Any, Optional, List
from loguru import logger
from app.db import models
from .schemas import RemediationOutputV2, ImpactAnalysis, IacRemediation, RiskScore, IacTool

# Initialize Anthropic client
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "claude-3-7-sonnet-latest")
MAX_TOKENS = int(os.getenv("CLAUDE_MAX_TOKENS", "2000"))


def initialize_claude_client():
    """Initialize and return the Anthropic client if the API key is available."""
    if not ANTHROPIC_API_KEY:
        return None
    return anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

def generate_llm_remediation(
    finding: models.Finding,
    base_guidance: Dict[str, Any],
    impact_data: Optional[ImpactAnalysis] = None,
    risk_score: Optional[RiskScore] = None,
    resource_details: Optional[Dict[str, Any]] = None
) -> RemediationOutputV2:
    """
    Enhances remediation guidance using Claude to generate more detailed,
    context-aware remediation steps and explanations.
    
    Args:
        finding: The security finding object
        base_guidance: Rule-based remediation guidance dictionary
        impact_data: Optional impact analysis data from graph
        risk_score: Optional risk score data
        resource_details: Optional detailed properties of the resource
        
    Returns:
        RemediationOutputV2: Enhanced remediation guidance
    """
    claude_client = initialize_claude_client()
    if not claude_client:
        return create_fallback_remediation(finding, base_guidance)
    
    # Create system prompt
    system_prompt = """
    You are GuardPost AI, an expert AWS cloud security advisor specializing in remediation guidance.
    Given information about a security finding, you'll generate detailed, accurate remediation guidance.
    
    Your response MUST be in valid JSON format with the following structure:
    {
        "issue_summary": "Clear and concise explanation of the security issue",
        "technical_details": "Detailed technical information about why this is a security concern",
        "manual_steps": ["Step 1", "Step 2", "Step 3"],
        "iac_remediation": {
            "tool": "terraform or cloudformation",
            "code_snippet": "Infrastructure as Code snippet",
            "apply_instructions": "Instructions on how to apply the IaC"
        },
        "reference_links": ["URL1", "URL2"]
    }
    
    Focus on:
    1. Factual, accurate information that aligns with AWS best practices
    2. Precise, actionable remediation steps
    3. Infrastructure as Code (IaC) examples tailored to the specific finding
    4. Valid JSON structure - this is critical for automated processing
    """
    
    # Prepare user message with finding details
    finding_details_str = json.dumps(finding.details, indent=2) if finding.details else "Not available"

    # Ensure base_guidance is a serializable dictionary
    base_guidance_for_json = {}
    if isinstance(base_guidance, dict):
        # Recursively convert Pydantic models in dict values to dicts
        temp_dict = {}
        for k, v in base_guidance.items():
            if hasattr(v, 'model_dump'):
                temp_dict[k] = v.model_dump()
            else:
                temp_dict[k] = v
        base_guidance_for_json = temp_dict
    elif hasattr(base_guidance, 'model_dump'): # Check if base_guidance itself is a Pydantic model
        base_guidance_for_json = base_guidance.model_dump()
    # If it's some other non-dict, non-Pydantic type, it will likely remain problematic for json.dumps
    # but the common case from security_analyzer should be dict or Pydantic model.

    # More detailed debug log for base_guidance_for_json
    logger.info(f"[LLM DEBUG] Type of base_guidance_for_json before dumps: {type(base_guidance_for_json)}")
    if isinstance(base_guidance_for_json, dict):
        logger.info(f"[LLM DEBUG] Keys in base_guidance_for_json: {list(base_guidance_for_json.keys())}")
    else:
        logger.info(f"[LLM DEBUG] base_guidance_for_json is not a dict, it is: {str(base_guidance_for_json)[:200]}") # Log first 200 chars if not dict

    user_message = f"""
    AWS Security Finding:
    - Title: {finding.title}
    - Resource Type: {finding.resource_type}
    - Resource ID: {finding.resource_id}
    - Severity: {finding.severity}
    - Description: {finding.description}
    - Specific Finding Details: 
    {finding_details_str}
    
    Base Remediation Guidance (from rule-based system):
    {json.dumps(base_guidance_for_json, indent=2)}
    """
    
    # Add impact context if available
    if impact_data:
        user_message += f"""
        
        Impact Context:
        - Affected Resource Count: {impact_data.affected_resource_count}
        - Blast Radius Score: {impact_data.blast_radius_score}
        - Critical Affected Resources: {', '.join(impact_data.critical_affected_resources[:5]) if impact_data.critical_affected_resources else 'None'}
        """
    
    # Add resource details if available
    if resource_details:
        user_message += f"""
        
        Resource Details:
        {json.dumps(resource_details, indent=2)}
        """
    
    user_message += """
    
    Please generate a JSON response with:
    1. A concise summary of this security issue in the "issue_summary" field
    2. Technical details explaining why this is a security concern in the "technical_details" field
    3. Step-by-step remediation instructions as an array of strings in the "manual_steps" field
    4. Infrastructure as Code (IaC) details in the "iac_remediation" object, including:
       - "tool": The IaC tool (e.g., "terraform", "cloudformation")
       - "code_snippet": The actual IaC code
       - "apply_instructions": Instructions for applying the IaC
    5. Relevant reference links as an array of strings in the "reference_links" field
    
    Your entire response must be valid JSON that can be parsed with json.loads().
    """
    
    # Call Claude API
    try:
        response = claude_client.messages.create(
            model=CLAUDE_MODEL,
            system=system_prompt,
            max_tokens=MAX_TOKENS,
            messages=[
                {"role": "user", "content": user_message}
            ]
        )
        
        # Parse Claude's JSON response
        llm_content = response.content[0].text
        
        # Extract just the JSON part if there's any surrounding text
        json_start = llm_content.find('{')
        json_end = llm_content.rfind('}') + 1
        if json_start >= 0 and json_end > json_start:
            llm_content = llm_content[json_start:json_end]
        
        try:
            parsed_response = json.loads(llm_content)
            
            # Extract IaC remediation information if available
            iac_remediation = None
            if parsed_response.get("iac_remediation"):
                iac_data = parsed_response["iac_remediation"]
                iac_tool_str = iac_data.get("tool", "terraform").lower()
                iac_tool = IacTool.TERRAFORM
                if iac_tool_str == "cloudformation":
                    iac_tool = IacTool.CLOUDFORMATION
                
                iac_remediation = IacRemediation(
                    tool=iac_tool,
                    code_snippet=iac_data.get("code_snippet", ""),
                    apply_instructions=iac_data.get("apply_instructions", "")
                )
            
            # Create enhanced remediation output
            return RemediationOutputV2(
                schema_version="2.0",
                finding_id=str(finding.id),
                issue_summary=parsed_response.get("issue_summary", ""),
                technical_details=parsed_response.get("technical_details", ""),
                impact_analysis=impact_data,
                iac_remediation=iac_remediation,
                manual_steps=parsed_response.get("manual_steps", []),
                risk_score=risk_score,
                compliance_standards=determine_compliance_standards(finding),
                reference_links=parsed_response.get("reference_links", []),
                is_llm_enhanced=True
            )
            
        except json.JSONDecodeError:
            # If JSON parsing fails, fall back to basic text parsing
            return parse_unstructured_response(llm_content, finding, base_guidance, impact_data, risk_score)
        
    except Exception as e:
        # Fallback to base guidance if LLM fails
        print(f"LLM remediation generation failed: {e}")
        return create_fallback_remediation(finding, base_guidance)

def parse_unstructured_response(
    content: str, 
    finding: models.Finding,
    base_guidance: Dict[str, Any],
    impact_data: Optional[ImpactAnalysis] = None,
    risk_score: Optional[RiskScore] = None
) -> RemediationOutputV2:
    """
    Fallback parser for when Claude doesn't return valid JSON.
    Attempts to extract structured sections from free text response.
    """
    # Initialize with empty values
    issue_summary = ""
    technical_details = ""
    manual_steps = []
    iac_snippet = ""
    iac_tool = IacTool.TERRAFORM
    apply_instructions = ""
    references = []
    
    # Simplistic section parsing based on common headings
    lines = content.split('\n')
    current_section = None
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        line_lower = line.lower()
        
        # Check for section headers
        if "summary" in line_lower and len(line) < 50:
            current_section = "summary"
            continue
        elif "technical" in line_lower and "detail" in line_lower and len(line) < 50:
            current_section = "technical"
            continue
        elif "steps" in line_lower and len(line) < 50:
            current_section = "steps"
            continue
        elif "terraform" in line_lower and len(line) < 50:
            current_section = "terraform"
            iac_tool = IacTool.TERRAFORM
            continue
        elif "cloudformation" in line_lower and len(line) < 50:
            current_section = "cloudformation"
            iac_tool = IacTool.CLOUDFORMATION
            continue
        elif "instructions" in line_lower and "apply" in line_lower and len(line) < 50:
            current_section = "apply"
            continue
        elif "reference" in line_lower and len(line) < 50:
            current_section = "references"
            continue
        
        # Process content based on current section
        if current_section == "summary":
            if not issue_summary:
                issue_summary = line
            else:
                issue_summary += " " + line
        elif current_section == "technical":
            if not technical_details:
                technical_details = line
            else:
                technical_details += " " + line
        elif current_section == "steps":
            # Check if line starts with a number or bullet point
            if line[0].isdigit() or line[0] in ['-', '*', '•']:
                manual_steps.append(line.lstrip('0123456789.-*• '))
            elif manual_steps:
                manual_steps[-1] += " " + line
        elif current_section in ["terraform", "cloudformation"]:
            if not iac_snippet:
                iac_snippet = line
            else:
                iac_snippet += "\n" + line
        elif current_section == "apply":
            if not apply_instructions:
                apply_instructions = line
            else:
                apply_instructions += " " + line
        elif current_section == "references":
            if line.startswith("http") or "aws.amazon.com" in line:
                references.append(line)
    
    # Create IaC remediation if we have a snippet
    iac_remediation = None
    if iac_snippet:
        iac_remediation = IacRemediation(
            tool=iac_tool,
            code_snippet=iac_snippet,
            apply_instructions=apply_instructions
        )
    
    # Return the structured output
    return RemediationOutputV2(
        schema_version="2.0",
        finding_id=str(finding.id),
        issue_summary=issue_summary if issue_summary else "See technical details.",
        technical_details=technical_details,
        impact_analysis=impact_data,
        iac_remediation=iac_remediation,
        manual_steps=manual_steps,
        risk_score=risk_score,
        compliance_standards=determine_compliance_standards(finding),
        reference_links=references,
        is_llm_enhanced=True
    )

def create_fallback_remediation(
    finding: models.Finding, 
    base_guidance: Dict[str, Any],
    impact_data: Optional[ImpactAnalysis] = None,
    risk_score: Optional[RiskScore] = None
) -> RemediationOutputV2:
    """
    Creates a fallback remediation output using the base guidance when LLM fails.
    """
    # If base_guidance is already in RemediationOutputV2 format, use it with some additions
    if isinstance(base_guidance, dict) and base_guidance.get("schema_version") == "2.0":
        # Update with finding ID and additional data
        base_guidance["finding_id"] = str(finding.id)
        
        # If these fields are available in base_guidance, use them, otherwise initialize
        if impact_data:
            base_guidance["impact_analysis"] = impact_data.dict() if hasattr(impact_data, "dict") else impact_data
        if risk_score:
            base_guidance["risk_score"] = risk_score.dict() if hasattr(risk_score, "dict") else risk_score
        
        # Convert the dict to a RemediationOutputV2 object (assuming Pydantic model)
        base_guidance['is_llm_enhanced'] = False
        return RemediationOutputV2(**base_guidance)
    
    # If we don't have proper base guidance, create a minimal response
    return RemediationOutputV2(
        schema_version="2.0",
        finding_id=str(finding.id),
        issue_summary=f"Security issue in {finding.resource_type}: {finding.title}",
        technical_details=finding.description,
        impact_analysis=impact_data,
        iac_remediation=None,
        manual_steps=[
            f"Review the finding details for {finding.resource_type} {finding.resource_id}",
            "Consult AWS documentation for remediation steps",
            "Apply the appropriate security controls based on AWS best practices"
        ],
        risk_score=risk_score,
        compliance_standards=determine_compliance_standards(finding),
        reference_links=["https://docs.aws.amazon.com/security/"],
        is_llm_enhanced=False
    )

def determine_compliance_standards(finding: models.Finding) -> List[str]:
    """
    Determines applicable compliance standards based on the finding.
    """
    standards = []
    
    # Extract from finding if available
    if hasattr(finding, "compliance_standards") and finding.compliance_standards:
        return finding.compliance_standards
    
    # Basic heuristic mapping based on finding title/description
    title_lower = finding.title.lower() if finding.title else ""
    description_lower = finding.description.lower() if finding.description else ""
    
    mappings = [
        (["encryption", "kms", "encrypt"], ["PCI DSS", "HIPAA", "FedRAMP"]),
        (["public", "exposed", "internet"], ["CIS AWS Foundations", "AWS Foundational Security Best Practices"]),
        (["iam", "permission", "policy", "role", "access"], ["CIS AWS Foundations", "AWS Foundational Security Best Practices"]),
        (["logging", "cloudtrail"], ["CIS AWS Foundations", "NIST 800-53", "AWS Foundational Security Best Practices"]),
        (["password", "credential", "secret"], ["PCI DSS", "CIS AWS Foundations", "NIST 800-53"]),
        (["network", "security group", "firewall"], ["CIS AWS Foundations", "AWS Foundational Security Best Practices"]),
        (["s3", "bucket"], ["CIS AWS Foundations", "AWS Foundational Security Best Practices"]),
        (["rds", "database"], ["PCI DSS", "HIPAA"]),
    ]
    
    for keywords, potential_standards in mappings:
        if any(keyword in title_lower or keyword in description_lower for keyword in keywords):
            for standard in potential_standards:
                if standard not in standards:
                    standards.append(standard)
    
    return standards
