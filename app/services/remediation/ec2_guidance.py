from typing import Dict, Any, Callable, Union
from app.db import models # Assuming models are accessible
# Import the new schema models
from .schemas import (
    RemediationOutputV2, 
    IacRemediation, 
    IacTool,
    # ImpactAnalysis, # Not used yet
    # RiskScore       # Not used yet
)
import json

# Helper to sanitize resource names for Terraform
def sanitize_for_terraform_resource_name(resource_name: str) -> str:
    sanitized = '_'.join(filter(None, resource_name.split(':')))
    sanitized = ''.join(c if c.isalnum() or c == '_' else '_' for c in sanitized)
    if not sanitized or not (sanitized[0].isalpha() or sanitized[0] == '_'):
        sanitized = "tf_" + sanitized
    return sanitized.lower()

if hasattr(models, 'Finding') and not hasattr(models.Finding, 'resource_id_sanitized'):
    # For SG findings, resource_id is sg_id. For Instance findings, it's instance_arn.
    # The sanitizer should be robust enough, but guidance functions will need to get the correct ID for TF names.
    setattr(models.Finding, 'resource_id_sanitized', property(lambda self: sanitize_for_terraform_resource_name(self.resource_id.split('/')[-1])))

# --- EC2 Guidance Functions ---

def get_sg_unrestricted_ssh_guidance(finding: models.Finding) -> RemediationOutputV2:
    # For this function, the finding could be for an Instance or an SG itself.
    # Prioritize details provided by the analyzer.
    sg_id = finding.details.get("security_group_id")
    if not sg_id and finding.resource_type == "AWS::EC2::SecurityGroup":
        sg_id = finding.resource_id # Fallback if it's an SG finding without details.sg_id
    elif not sg_id: # Should not happen if analyzer provides details for instance findings
        return RemediationOutputV2(finding_id=str(finding.id), issue_summary="Missing security group ID in finding details for SSH rule.", technical_details="Cannot provide guidance without SG ID.", manual_steps=["Investigate finding details - SG ID is missing."])
        
    sg_name = finding.details.get("security_group_name", sg_id) 
    port = finding.details.get("port_opened", 22) # Changed from "port" to "port_opened" to match analyzer
    service_name = finding.details.get("service_name", "SSH")
    instance_id_ctx = f" for instance '{finding.details.get('instance_id')}'" if finding.resource_type == "AWS::EC2::Instance" else ""
    
    issue_summary = f"Security group '{sg_name}' ({sg_id}) allows unrestricted SSH access{instance_id_ctx}."
    technical_details = (
        f"Leaving SSH (port {port}) open to 0.0.0.0/0 or ::/0 significantly increases the risk of brute-force attacks and unauthorized access attempts. "
        "Access should be restricted to known, trusted IP addresses or security groups."
    )
    manual_steps = [
        f"Navigate to the EC2 console -> Security Groups -> Select '{sg_name}' ({sg_id}).",
        "Select the 'Inbound rules' tab and click 'Edit inbound rules'.",
        f"Find the rule allowing traffic to port {port} ({service_name}) from source '0.0.0.0/0' or '::/0'.",
        "Modify the 'Source' of this rule:",
        "  - Choose 'My IP' to restrict to your current IP address (for temporary individual access).",
        "  - Choose 'Custom' and enter specific CIDR blocks (e.g., your company VPN range, bastion host IP).",
        "  - Alternatively, specify a source Security Group ID if access is needed from other EC2 instances.",
        "Remove the overly permissive 0.0.0.0/0 or ::/0 entry for this rule.",
        "Save rules.",
        "Consider using EC2 Instance Connect or Systems Manager Session Manager as more secure alternatives to direct SSH exposure."
    ]

    tf_sg_resource_name_suffix = sanitize_for_terraform_resource_name(sg_id)
    
    terraform_snippet = f"""
# Ensure security group '{sg_name}' ({sg_id}) is managed by Terraform.
# The following example shows how to define a restrictive SSH rule.
# You will need to integrate this into your existing `aws_security_group` resource for '{sg_name}'
# or create a new `aws_security_group_rule` resource and remove the offending public rule.

resource "aws_security_group_rule" "restrict_ssh_for_{tf_sg_resource_name_suffix}" {{
  type              = "ingress"
  security_group_id = "{sg_id}"
  protocol          = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_blocks       = ["YOUR_TRUSTED_CIDR_HERE/32"] 
  description       = "Allow SSH from trusted source for {sg_name}"
}}

# IMPORTANT: You must also ensure the rule allowing 0.0.0.0/0 for SSH is REMOVED from security group '{sg_name}'.
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions=f"Update the Terraform configuration for security group '{sg_name}' ({sg_id}). Replace 'YOUR_TRUSTED_CIDR_HERE/32' with the appropriate source. Ensure the overly permissive 0.0.0.0/0 rule for SSH is removed or modified."
    )

    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or ["CIS AWS Benchmark 4.1"],
        reference_links=["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html"]
    )

def get_sg_unrestricted_rdp_guidance(finding: models.Finding) -> RemediationOutputV2:
    sg_id = finding.details.get("security_group_id")
    if not sg_id and finding.resource_type == "AWS::EC2::SecurityGroup":
        sg_id = finding.resource_id 
    elif not sg_id:
        return RemediationOutputV2(finding_id=str(finding.id), issue_summary="Missing security group ID in finding details for RDP rule.", technical_details="Cannot provide guidance without SG ID.", manual_steps=["Investigate finding details - SG ID is missing."])

    sg_name = finding.details.get("security_group_name", sg_id)
    port = finding.details.get("port_opened", 3389) # Changed from "port" to "port_opened"
    service_name = finding.details.get("service_name", "RDP")
    instance_id_ctx = f" for instance '{finding.details.get('instance_id')}'" if finding.resource_type == "AWS::EC2::Instance" else ""

    issue_summary = f"Security group '{sg_name}' ({sg_id}) allows unrestricted RDP access{instance_id_ctx}."
    technical_details = (
        f"Leaving RDP (port {port}) open to 0.0.0.0/0 or ::/0 significantly increases the risk of unauthorized access and attacks targeting Windows instances. "
        "Access should be strictly limited to known, trusted IP addresses."
    )
    manual_steps = [
        f"Navigate to the EC2 console -> Security Groups -> Select '{sg_name}' ({sg_id}).",
        "Select the 'Inbound rules' tab and click 'Edit inbound rules'.",
        f"Find the rule allowing traffic to port {port} ({service_name}) from source '0.0.0.0/0' or '::/0'.",
        "Modify the 'Source' to specific, trusted CIDR blocks.",
        "Remove the overly permissive 0.0.0.0/0 or ::/0 entry for this rule.",
        "Save rules.",
        "Consider using AWS Systems Manager Session Manager or an RD Gateway for more secure access to Windows instances without direct RDP exposure."
    ]

    tf_sg_resource_name_suffix = sanitize_for_terraform_resource_name(sg_id)
    terraform_snippet = f"""
resource "aws_security_group_rule" "restrict_rdp_for_{tf_sg_resource_name_suffix}" {{
  type              = "ingress"
  security_group_id = "{sg_id}"
  protocol          = "tcp"
  from_port         = 3389
  to_port           = 3389
  cidr_blocks       = ["YOUR_TRUSTED_CIDR_HERE/32"] 
  description       = "Allow RDP from trusted source for {sg_name}"
}}

# IMPORTANT: Ensure the rule allowing 0.0.0.0/0 for RDP is REMOVED from the security group '{sg_name}'.
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions=f"Update the Terraform configuration for security group '{sg_name}' ({sg_id}). Replace 'YOUR_TRUSTED_CIDR_HERE/32' with the appropriate source for RDP access. Ensure the overly permissive 0.0.0.0/0 rule for RDP is removed."
    )

    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or ["CIS AWS Benchmark 4.2"],
        reference_links=["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/security-group-rules-reference.html"]
    )

def get_sg_unrestricted_egress_guidance(finding: models.Finding) -> RemediationOutputV2:
    sg_id = finding.resource_id
    sg_name = finding.details.get("security_group_name", sg_id)
    rule_details_str = json.dumps(finding.details.get("rule_details", {}), indent=2)

    issue_summary = f"Security group '{sg_name}' ({sg_id}) has an overly permissive egress rule."
    technical_details = (
        "Allowing unrestricted egress (e.g., all protocols, all ports to 0.0.0.0/0) increases the risk of data exfiltration "
        "and allows instances to connect to potentially malicious endpoints. Egress traffic should be restricted to only necessary destinations and ports."
        f"\nProblematic rule details: {rule_details_str}"
    )
    manual_steps = [
        f"Navigate to the EC2 console -> Security Groups -> Select '{sg_name}' ({sg_id}).",
        "Select the 'Outbound rules' tab and click 'Edit outbound rules'.",
        "Identify the overly permissive rule (typically destination 0.0.0.0/0 or ::/0 with 'All traffic' or wide port ranges).",
        "Modify this rule to restrict the 'Protocol', 'Port range', and 'Destination' to only what is absolutely necessary for the resources using this security group.",
        "Alternatively, delete the unrestricted rule and add new, more specific egress rules as needed.",
        "Save rules.",
        "Consider using VPC Endpoints for accessing AWS services within your VPC without needing broad internet egress."
    ]

    tf_sg_resource_name_suffix = finding.resource_id_sanitized 
    terraform_snippet = f"""
# Review the egress rules for security group '{sg_name}' ({sg_id}).
# The following is a conceptual example of a more restrictive egress rule.
# You need to replace this with rules specific to your application's needs.

# Example: Allow HTTPS outbound to any destination
# resource "aws_security_group_rule" "restricted_egress_https_{tf_sg_resource_name_suffix}" {{
#   type              = "egress"
#   security_group_id = "{sg_id}"
#   protocol          = "tcp"
#   from_port         = 443
#   to_port           = 443
#   cidr_blocks       = ["0.0.0.0/0"] 
#   description       = "Allow outbound HTTPS"
# }}

# IMPORTANT: Ensure the overly permissive egress rule (e.g., All traffic to 0.0.0.0/0) is REMOVED or MODIFIED.
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions=f"Modify the egress rules for security group '{sg_name}' ({sg_id}) in your Terraform configuration. Remove or replace the unrestricted rule with specific, least-privilege rules based on application requirements."
    )

    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or ["CIS AWS Benchmark 4.4"],
        reference_links=["https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html#security-group-egress-rules"]
    )

def get_sg_default_insecure_guidance(finding: models.Finding) -> RemediationOutputV2:
    sg_id = finding.resource_id
    sg_name = finding.details.get("security_group_name", "default")
    
    issue_summary = f"Default security group '{sg_name}' ({sg_id}) has custom rules or is in use."
    technical_details = (
        "The default security group should generally not be used for resources and should not have custom rules. "
        "It typically allows all outbound traffic and all traffic between instances assigned to it by default. "
        "Modifying it or using it can lead to overly permissive access."
    )
    manual_steps = [
        f"Identify all resources currently using the default security group '{sg_name}' ({sg_id}).",
        "Create new, custom security groups with least-privilege rules tailored for those resources.",
        f"Migrate the identified resources from the default security group to the new custom security groups.",
        f"Once no resources are using the default security group '{sg_name}', review its rules:",
        "  - Navigate to EC2 console -> Security Groups -> Select the default group.",
        "  - Remove ALL custom inbound rules (it should have no inbound rules by default).",
        "  - Ensure the outbound rules only contain the default 'All traffic | All | All | 0.0.0.0/0' rule. Remove any other custom outbound rules."
    ]
    
    tf_sg_resource_name_suffix = finding.resource_id_sanitized 
    terraform_snippet = f"""
# It is NOT recommended to manage the rules of the DEFAULT security group via Terraform directly,
# as its existence is managed by AWS and it behaves differently.
# The primary remediation is to NOT USE the default security group.

# 1. Create specific, least-privilege security groups for your resources.
# resource "aws_security_group" "my_custom_app_sg" {{
#   name        = "my-custom-app-sg"
#   description = "Allow specific traffic for my application"
#   vpc_id      = "YOUR_VPC_ID"
#   ingress = [ 
#     {{ from_port = 80, to_port = 80, protocol = "tcp", cidr_blocks = ["0.0.0.0/0"] }}
#   ]
#   egress = [ 
#     {{ from_port = 0, to_port = 0, protocol = "-1", cidr_blocks = ["0.0.0.0/0"] }}
#   ]
# }}

# 2. Associate your EC2 instances and other resources with these custom security groups
#    instead of the default security group '{sg_id}'.

# 3. Manually ensure the default security group '{sg_id}' has no custom INBOUND rules 
#    and only the standard default OUTBOUND rule (Allow All to 0.0.0.0/0).
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions=f"The primary action is to migrate resources off the default security group '{sg_name}' ({sg_id}) to custom, least-privilege security groups. Then, manually reset the default SG rules via AWS Console if modified."
    )

    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or ["CIS AWS Benchmark 4.3"],
        reference_links=["https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html#default-security-group"]
    )

def get_ec2_ebs_encryption_default_guidance(finding: models.Finding) -> RemediationOutputV2:
    region = finding.region 
    kms_key_id = finding.details.get("kms_key_id", "aws/ebs (AWS managed key)")

    issue_summary = f"EBS encryption by default is not enabled in region '{region}'."
    technical_details = (
        "Enabling EBS encryption by default ensures that all newly created EBS volumes in the region are automatically encrypted, "
        "enhancing data protection and simplifying compliance. This setting does not encrypt existing volumes."
    )
    manual_steps = [
        f"Navigate to the EC2 console.",
        f"In the top right, ensure the correct region ('{region}') is selected.",
        "Under 'Account Attributes' in the left navigation pane (or search for 'EBS encryption by default'), select 'EBS encryption'.",
        "Click 'Manage'.",
        "Enable 'Always encrypt new EBS volumes'.",
        f"Optionally, specify a default KMS key. If not specified, the AWS managed key '{kms_key_id}' will be used.",
        "Click 'Update EBS encryption'."
    ]

    terraform_snippet = f"""
resource "aws_ebs_encryption_by_default" "default_ebs_encryption_{sanitize_for_terraform_resource_name(region)}" {{
  enabled = true
  
  # Optionally, specify a default KMS key ARN. 
  # kms_key_arn = "YOUR_CMK_ARN_FOR_EBS_IN_{region.upper().replace('-','_')}" 
}}
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions=f"Apply this Terraform configuration to enable EBS encryption by default in region '{region}'. If you want to use a specific Customer Managed Key (CMK), uncomment and set the `kms_key_arn`."
    )

    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or ["CIS AWS Benchmark 4.5"],
        reference_links=["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encryption-by-default"]
    )

def get_ec2_ebs_volume_unencrypted_guidance(finding: models.Finding) -> RemediationOutputV2:
    volume_id = finding.resource_id
    
    issue_summary = f"EBS volume '{volume_id}' is not encrypted."
    technical_details = (
        "EBS volumes, especially those containing sensitive data, should be encrypted at rest to protect against unauthorized data access. "
        "Encrypting an existing, unencrypted EBS volume is a manual process involving snapshot creation, copying the snapshot with encryption, "
        "and then creating a new volume from the encrypted snapshot. This process typically involves downtime for instances using the volume."
    )
    manual_steps = [
        f"Identify the EC2 instance(s) using volume '{volume_id}' (if any). Plan for downtime if the volume is in use.",
        f"If the volume is attached, stop the associated EC2 instance(s).",
        f"In the EC2 console, navigate to 'Elastic Block Store' -> 'Volumes' and select volume '{volume_id}'.",
        "Choose 'Actions' -> 'Create snapshot'. Provide a description and create the snapshot.",
        "Navigate to 'Elastic Block Store' -> 'Snapshots'. Select the newly created snapshot.",
        "Choose 'Actions' -> 'Copy snapshot'.",
        "In the 'Copy snapshot' dialog, ensure you are in the correct destination region.",
        "Check the 'Encrypt this snapshot' box.",
        "Select a KMS key for encryption (either an AWS managed key like `aws/ebs` or a Customer Managed Key).",
        "Click 'Copy snapshot'.",
        "Once the copied snapshot status is 'completed', select it.",
        "Choose 'Actions' -> 'Create volume from snapshot'. Ensure the Availability Zone matches your instance(s). Specify size and type as needed.",
        "Ensure the new volume is created as encrypted.",
        f"Once the new encrypted volume is available, detach the original unencrypted volume '{volume_id}' from your instance(s) (if it was attached).",
        "Attach the new encrypted volume to your instance(s), ensuring the correct device name.",
        "Start your EC2 instance(s) and verify data access and application functionality.",
        f"After confirming everything works, you can delete the original unencrypted volume '{volume_id}' and its non-encrypted snapshot to avoid further charges."
    ]
    
    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=None, 
        compliance_standards=finding.compliance_standards or ["CIS AWS Benchmark 4.6"],
        reference_links=["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html#encrypt-unencrypted-volume"]
    )

def get_ec2_instance_imdsv2_guidance(finding: models.Finding) -> RemediationOutputV2:
    instance_id = finding.details.get("instance_id", finding.resource_id.split('/')[-1])
    http_tokens_status = finding.details.get("http_tokens", "optional")

    issue_summary = f"EC2 instance '{instance_id}' does not require IMDSv2 (Instance Metadata Service v2)."
    technical_details = (
        f"The instance metadata service (IMDS) for '{instance_id}' is currently configured with HttpTokens='{http_tokens_status}'. "
        "IMDSv2 (which requires HttpTokens='required') uses session-oriented requests, mitigating several types of SSRF vulnerabilities compared to IMDSv1. "
        "It is strongly recommended to enforce IMDSv2 for enhanced security."
    )
    manual_steps = [
        f"Navigate to the EC2 console -> Instances -> Select instance '{instance_id}'.",
        "Select Actions -> Instance settings -> Modify instance metadata options.",
        "In the 'Modify instance metadata options' dialog:",
        "  - Set 'IMDSv2' to 'Enabled'.",
        "  - Set 'IMDSv1' to 'Disabled' (or ensure HttpTokens is set to 'required'). Alternatively, during transition, you might set HttpTokens to 'optional' while applications are updated, then switch to 'required'.",
        "  - (Recommended) Set 'Metadata response hop limit' to 1 to restrict metadata access from within the instance.",
        "Click 'Save'.",
        "CRITICAL: Ensure all applications and SDKs running on the instance are compatible with IMDSv2 before enforcing it (setting HttpTokens to 'required' or disabling IMDSv1). Most modern AWS SDKs and tools support IMDSv2."
    ]

    tf_instance_id_sanitized = sanitize_for_terraform_resource_name(instance_id)
    terraform_snippet = f"""
resource "aws_instance" "{tf_instance_id_sanitized}" {{
  # Assuming this instance is managed by Terraform, or you are modifying an existing definition.
  # ami           = "ami-xxxxxxxxxxxxxxxxx" 
  # instance_type = "t2.micro"             

  metadata_options {{
    http_tokens              = "required" 
    http_put_response_hop_limit = 1        
    http_endpoint            = "enabled"  
  }}
}}
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions=f"Update the Terraform configuration for instance '{instance_id}'. Add or modify the `metadata_options` block as shown to enforce IMDSv2. Ensure application compatibility before applying."
    )

    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or ["CIS AWS Benchmark 4.8"],
        reference_links=["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-options.html"]
    )


# --- EC2 Guidance Map ---
EC2_GUIDANCE_MAP: Dict[tuple[str, str], Callable[[models.Finding], RemediationOutputV2]] = {
    # EC2 Security Group
    ("AWS::EC2::SecurityGroup", "allows unrestricted ssh access"): get_sg_unrestricted_ssh_guidance,
    ("AWS::EC2::SecurityGroup", "allows unrestricted rdp access"): get_sg_unrestricted_rdp_guidance,
    ("AWS::EC2::SecurityGroup", "allows unrestricted egress traffic"): get_sg_unrestricted_egress_guidance,
    ("AWS::EC2::SecurityGroup", "default security group"): get_sg_default_insecure_guidance,
    # Instance findings that relate to Security Group rules (new mappings)
    ("AWS::EC2::Instance", "sensitive port ssh exposed"): get_sg_unrestricted_ssh_guidance,
    ("AWS::EC2::Instance", "sensitive port rdp exposed"): get_sg_unrestricted_rdp_guidance,
    # EC2 Regional / EBS / Instance
    ("AWS::EC2::RegionalSettings", "ebs encryption by default is not enabled"): get_ec2_ebs_encryption_default_guidance,
    ("AWS::EC2::Volume", "is not encrypted"): get_ec2_ebs_volume_unencrypted_guidance,
    ("AWS::EC2::Instance", "does not require imdsv2"): get_ec2_instance_imdsv2_guidance,
} 