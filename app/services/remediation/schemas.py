from typing import Dict, Any, List, Optional, Literal, Union
from pydantic import BaseModel, Field
from enum import Enum

# Based on planning/sprint_2_detailed.md

class StructuredGuidance(BaseModel):
    """Structure for remediation guidance when IaC is applicable."""
    iac_applicable: Literal[True] = True
    finding_title: str = Field(..., description="The title of the finding being addressed.")
    resource_type: str = Field(..., description="The AWS resource type (e.g., AWS::S3::Bucket).")
    resource_id: str = Field(..., description="The specific identifier of the resource.")
    change_description: str = Field(..., description="Human-readable summary of the required change.")
    required_change: Dict[str, Any] = Field(..., description="Structured representation of the property/attribute and target value(s).")
    guidance_notes: List[str] = Field(default_factory=list, description="Contextual notes, warnings, or links for the agent interpreting this guidance.")
    # example_structure_hint: Optional[str] = Field(None, description="Optional minimal skeleton hinting at the location of the change.") # Decided against for now

class IacNotApplicableGuidance(BaseModel):
    """Structure for remediation guidance when IaC is not applicable."""
    iac_applicable: Literal[False] = False
    reason: str = Field(..., description="Explanation why IaC is not applicable (e.g., requires manual console action).")

# Union type for use in other modules
Guidance = Union[StructuredGuidance, IacNotApplicableGuidance] 

# --- V1 Guidance Schemas (Retained for reference/transition) --- 

class StructuredGuidanceV1(BaseModel):
    """Structure for remediation guidance when IaC is applicable."""
    model_config = {"extra": "allow"} # Allow extra fields during transition if needed
    iac_applicable: Literal[True] = True
    finding_title: str = Field(..., description="The title of the finding being addressed.")
    resource_type: str = Field(..., description="The AWS resource type (e.g., AWS::S3::Bucket).")
    resource_id: str = Field(..., description="The specific identifier of the resource.")
    change_description: str = Field(..., description="Human-readable summary of the required change.")
    required_change: Dict[str, Any] = Field(..., description="Structured representation of the property/attribute and target value(s).")
    guidance_notes: List[str] = Field(default_factory=list, description="Contextual notes, warnings, or links for the agent interpreting this guidance.")

class IacNotApplicableGuidanceV1(BaseModel):
    """Structure for remediation guidance when IaC is not applicable."""
    iac_applicable: Literal[False] = False
    reason: str = Field(..., description="Explanation why IaC is not applicable (e.g., requires manual console action).")

GuidanceV1 = Union[StructuredGuidanceV1, IacNotApplicableGuidanceV1] 

# --- V2 Remediation Output Schema (Sprint 3 Goal) --- 

class IacTool(str, Enum):
    TERRAFORM = "terraform"
    CLOUDFORMATION = "cloudformation"
    AWS_CLI = "aws-cli"
    # Add others like Pulumi, Ansible if needed

class ImpactAnalysis(BaseModel):
    """Details about the potential impact of the finding or remediation."""
    affected_resource_count: int = Field(..., description="Estimated number of resources directly or indirectly affected by this finding (based on blast radius calculation).")
    critical_affected_resources: List[str] = Field(default_factory=list, description="List of identifiers (e.g., ARNs) for the top N most critical affected resources.")
    blast_radius_score: Optional[float] = Field(None, description="Numerical score representing the calculated blast radius impact (0-1000 scale). Populated by Task 3.1.2.")
    service_dependencies: List[str] = Field(default_factory=list, description="List of potential services or applications that might depend on the affected resource.")

class IacRemediation(BaseModel):
    """Infrastructure-as-Code snippet for remediation."""
    tool: IacTool = Field(..., description="The IaC tool the snippet is written for.")
    code_snippet: str = Field(..., description="The actual IaC code snippet.")
    provider_version: Optional[str] = Field(None, description="Recommended provider version, if applicable (e.g., for Terraform).")
    apply_instructions: str = Field(..., description="Brief instructions on how to apply this snippet.")

class RiskScore(BaseModel):
    """Calculated risk score for the finding."""
    score: float = Field(..., ge=0, le=100, description="Overall calculated risk score (0-100). Higher is more severe.")
    severity_base: float = Field(..., description="Base score derived from the finding's inherent severity.")
    exposure_factor: float = Field(..., description="Multiplier based on the resource's exposure (e.g., public vs. private).")
    impact_factor: float = Field(..., description="Multiplier based on the potential blast radius or business impact.")
    confidence: float = Field(..., ge=0, le=1, description="Confidence level in the calculated score (0-1).")

class RemediationOutputV2(BaseModel):
    """Comprehensive remediation details including context, risk, and IaC."""
    schema_version: Literal["2.0"] = "2.0"
    finding_id: str = Field(..., description="The UUID of the finding being addressed.")
    issue_summary: str = Field(..., description="Concise summary of the security issue found.")
    technical_details: str = Field(..., description="Detailed explanation of why this is a security concern.")
    impact_analysis: Optional[ImpactAnalysis] = Field(None, description="Analysis of the potential impact of this finding. Populated by Task 3.1.3 using data from Task 3.1.2.")
    iac_remediation: Optional[IacRemediation] = Field(None, description="IaC snippet for remediation, if applicable and generated (Task 3.1.4).")
    manual_steps: List[str] = Field(default_factory=list, description="Human-readable steps for manual remediation (can supplement or replace IaC).")
    risk_score: Optional[RiskScore] = Field(None, description="Calculated risk score for prioritization. Populated by Task 2.4 logic.")
    compliance_standards: List[str] = Field(default_factory=list, description="Relevant compliance standards (e.g., CIS, PCI-DSS). Inherited from Finding.")
    reference_links: List[str] = Field(default_factory=list, description="URLs to relevant documentation or best practices.")
    is_llm_enhanced: Optional[bool] = Field(default=False, description="Indicates if the remediation guidance was enhanced by an LLM.")

# --- Type Alias for Current Usage --- 
# During transition, get_remediation might return V2 or fallback info
RemediationResponseData = Union[RemediationOutputV2, Dict[str, Any]] # Allow plain dict for potential errors/fallbacks 