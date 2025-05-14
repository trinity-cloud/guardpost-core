from typing import Dict, Any, Callable, Union
from app.db import models
from .schemas import (
    RemediationOutputV2, 
    IacRemediation, 
    IacTool, 
    ImpactAnalysis, # Will be None for now
    RiskScore       # Will be None for now
)
import json

# Helper to sanitize resource names for Terraform
def sanitize_for_terraform_resource_name(resource_name: str) -> str:
    sanitized = '_'.join(filter(None, resource_name.split(':')))
    sanitized = ''.join(c if c.isalnum() or c == '_' else '_' for c in sanitized)
    if not sanitized or not (sanitized[0].isalpha() or sanitized[0] == '_'):
        sanitized = "tf_" + sanitized
    return sanitized.lower()

# Monkey patch the model for this purpose (not ideal for production but ok for this context)
# Ensure this is defined or handled appropriately if models.Finding might not always be loaded when this module is.
if hasattr(models, 'Finding') and not hasattr(models.Finding, 'resource_id_sanitized'):
    setattr(models.Finding, 'resource_id_sanitized', property(lambda self: sanitize_for_terraform_resource_name(self.resource_id)))


def get_s3_encryption_guidance(finding: models.Finding) -> RemediationOutputV2:
    encryption_config = finding.details.get("encryption_config", "Not Set")
    
    issue_summary = f"S3 bucket '{finding.resource_id}' does not have default server-side encryption enabled."
    technical_details = (
        f"Default server-side encryption ensures all new objects are automatically encrypted at rest. "
        f"Current configuration reported: {encryption_config}. This setting does not encrypt existing objects; "
        "they must be re-uploaded or copied with new encryption settings. SSE-S3 (AES256) is the simplest option, "
        "while SSE-KMS offers more control via AWS Key Management Service."
    )
    manual_steps = [
        "Navigate to the S3 console -> Buckets -> Select your bucket.",
        "Go to the 'Properties' tab.",
        "Under 'Default encryption', click 'Edit'.",
        "Choose an encryption type (e.g., 'SSE-S3' for AES256 or 'SSE-KMS' and specify a KMS key).",
        "Save changes.",
        "Note: To encrypt existing objects, you may need to copy them in place (e.g., `aws s3 cp s3://bucket/ s3://bucket/ --recursive --metadata-directive REPLACE --server-side-encryption AES256`)."
    ]
    
    terraform_snippet = f"""
resource "aws_s3_bucket_server_side_encryption_configuration" "bucket_encryption_{finding.resource_id_sanitized}" {{
  bucket = "{finding.resource_id}"

  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm     = "AES256" # For SSE-S3
      # Or for SSE-KMS:
      # sse_algorithm     = "aws:kms"
      # kms_master_key_id = "YOUR_KMS_KEY_ARN" 
    }}
    # bucket_key_enabled = true # Recommended for SSE-KMS to reduce costs & request rates
  }}
}}
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions="Adapt and apply this Terraform configuration. If using SSE-KMS, uncomment and provide your KMS key ARN. Consider enabling bucket_key_enabled for SSE-KMS."
    )

    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or ["CIS AWS Foundations Benchmark 2.1.1"],
        reference_links=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html"]
    )

def get_s3_public_access_block_guidance(finding: models.Finding) -> RemediationOutputV2:
    issue_summary = f"S3 bucket '{finding.resource_id}' does not have all Public Access Block settings enabled."
    technical_details = (
        "S3 Public Access Block is a critical security control to prevent accidental public exposure of data. "
        "It overrides conflicting ACLs and bucket policies. All four settings (BlockPublicAcls, IgnorePublicAcls, "
        "BlockPublicPolicy, RestrictPublicBuckets) should typically be enabled."
    )
    manual_steps = [
        "Navigate to the S3 console -> Buckets -> Select your bucket.",
        "Go to the 'Permissions' tab.",
        "Under 'Block public access (bucket settings)', click 'Edit'.",
        "Check all four boxes: 'Block public ACLs', 'Ignore public ACLs', 'Block public policy', and 'Restrict public buckets'.",
        "Save changes and confirm.",
        "Ensure applications relying on public access (if any, which is discouraged) are updated or use alternative methods (e.g., pre-signed URLs, CloudFront OAI)."
    ]
    terraform_snippet = f"""
resource "aws_s3_bucket_public_access_block" "pab_{finding.resource_id_sanitized}" {{
  bucket = "{finding.resource_id}"

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}}
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions="Adapt and apply this Terraform configuration to enable all Public Access Block settings for the bucket."
    )
    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or ["CIS AWS Foundations Benchmark 1.1.1"],
        reference_links=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"]
    )

def get_s3_logging_guidance(finding: models.Finding) -> RemediationOutputV2:
    issue_summary = f"Server access logging is disabled for S3 bucket '{finding.resource_id}'."
    technical_details = (
        "Server access logging provides detailed records for requests made to an S3 bucket, which is essential for "
        "security auditing, monitoring access patterns, and troubleshooting. Logs should be stored in a separate target bucket."
    )
    manual_steps = [
        "Choose or create a target S3 bucket (in the same region, cannot be the source bucket) to store the logs. This target bucket should ideally be in a separate, dedicated logging account.",
        "Ensure the S3 Log Delivery group (`http://acs.amazonaws.com/groups/s3/LogDelivery`) has Write and Read ACP permissions on the target bucket's ACL.",
        "Navigate to the source S3 bucket: S3 console -> Buckets -> Select your bucket -> Properties tab.",
        "Under 'Server access logging', click 'Edit'.",
        "Select 'Enable'.",
        "For 'Target bucket', browse S3 and select your designated logging bucket.",
        "Specify a 'Target prefix' (e.g., `logs/{finding.resource_id}/`) to organize logs within the target bucket.",
        "Save changes."
    ]
    terraform_snippet = f"""
resource "aws_s3_bucket_logging" "logging_{finding.resource_id_sanitized}" {{
  bucket = "{finding.resource_id}"

  target_bucket = "YOUR_LOG_BUCKET_NAME"  # Replace with your actual log bucket name
  target_prefix = "logs/{finding.resource_id}/" 
}}

# Note: Ensure the target_bucket exists and has appropriate permissions
# for the S3 log delivery service principal (logging.s3.amazonaws.com)
# to write objects to it. This might involve configuring the target bucket's policy.
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions="Replace 'YOUR_LOG_BUCKET_NAME' with the actual name of your S3 log bucket. Ensure the target bucket is correctly permissioned for S3 log delivery."
    )
    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or ["CIS AWS Foundations Benchmark 2.6.1"],
        reference_links=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-server-access-logging.html"]
    )

def get_s3_versioning_guidance(finding: models.Finding) -> RemediationOutputV2:
    versioning_status = finding.details.get("versioning_status", "Unknown/Disabled")
    issue_summary = f"S3 bucket '{finding.resource_id}' versioning is {versioning_status}."
    technical_details = (
        "Versioning keeps multiple variants of an object in the same bucket, protecting against accidental overwrites "
        "and deletions, and enabling recovery of previous object versions. It's also a prerequisite for S3 Object Lock."
    )
    manual_steps = [
        "Navigate to the S3 console -> Buckets -> Select your bucket.",
        "Go to the 'Properties' tab.",
        "Under 'Bucket Versioning', click 'Edit'.",
        "Select 'Enable' and save changes.",
        "Consider lifecycle policies to manage storage costs associated with older versions (e.g., transition to Glacier, expire)."
    ]
    terraform_snippet = f"""
resource "aws_s3_bucket_versioning" "versioning_{finding.resource_id_sanitized}" {{
  bucket = "{finding.resource_id}"
  versioning_configuration {{
    status = "Enabled"
  }}
}}
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions="Apply this Terraform configuration to enable versioning for the bucket."
    )
    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or ["CIS AWS Foundations Benchmark 2.2.1"],
        reference_links=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html"]
    )

def get_s3_public_acl_guidance(finding: models.Finding) -> RemediationOutputV2:
    grantee_uri_full = finding.details.get("grantee_uri", "Unknown grantee")
    grantee = grantee_uri_full.split('/')[-1] if grantee_uri_full else 'Unknown'
    permission = finding.details.get("permission", "Unknown permission")
    
    risk_level = "high"
    if permission and ("WRITE" in permission.upper() or "FULL_CONTROL" in permission.upper()):
        risk_level = "critical"

    issue_summary = f"S3 bucket '{finding.resource_id}' allows public access via ACL ({permission} to {grantee})."
    technical_details = (
        f"Granting '{permission}' permission to '{grantee}' (URI: {grantee_uri_full}) via an Access Control List (ACL) "
        f"makes this bucket publicly accessible. This is a {risk_level}-risk configuration. Public ACLs often bypass bucket policies "
        "and are a common source of data exposure. Using S3 Block Public Access is the strongly recommended primary fix."
    )
    manual_steps = [
        "STRONGLY RECOMMENDED: Enable S3 Block Public Access for this bucket.",
        "  - Navigate to S3 console -> Buckets -> Select bucket -> Permissions tab.",
        "  - Edit 'Block public access (bucket settings)' and enable all four settings.",
        "If Block Public Access cannot be immediately enabled:",
        "  - Navigate to S3 console -> Buckets -> Select bucket -> Permissions tab.",
        "  - Under 'Access control list (ACL)', click 'Edit'.",
        f"  - Remove the grant that gives '{grantee}' the '{permission}' permission.",
        "  - Save changes."
    ]
    terraform_snippet = f"""
# Strongly Recommended: Enable S3 Block Public Access
resource "aws_s3_bucket_public_access_block" "pab_{finding.resource_id_sanitized}" {{
  bucket = "{finding.resource_id}"
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}}

# Secondary: Set bucket ACL to private (if Block Public Access cannot be used directly)
resource "aws_s3_bucket_acl" "acl_{finding.resource_id_sanitized}" {{
  bucket = "{finding.resource_id}"
  acl    = "private" # This removes all public grants including the problematic one
  depends_on = [aws_s3_bucket_public_access_block.pab_{finding.resource_id_sanitized}]
}}
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions="It is strongly recommended to apply the `aws_s3_bucket_public_access_block` resource. The `aws_s3_bucket_acl` resource with `acl = \"private\"` can be used as an additional or alternative measure."
    )
    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or ["CIS AWS Foundations Benchmark 1.1.2"],
        reference_links=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html"]
    )

def get_s3_public_all_users_acl_guidance(finding: models.Finding) -> RemediationOutputV2:
    # This can reuse or slightly specialize the generic public ACL guidance
    # For now, let's make it specific and emphasize the risk
    permission = finding.details.get("permission", "Unknown permission")
    issue_summary = f"S3 bucket '{finding.resource_id}' grants '{permission}' to 'AllUsers' via ACL."
    technical_details = (
        f"Granting '{permission}' to 'AllUsers' (anyone on the internet) via ACL is a CRITICAL security risk, "
        "as it allows anonymous access. S3 Block Public Access should be enabled immediately to mitigate this."
    )
    # Manual steps and IaC would be very similar to get_s3_public_acl_guidance, focusing on Block Public Access
    # and setting ACL to private. We can call the generic one or tailor.
    # For brevity and to avoid too much repetition, we could reference the generic one or create more specific text.
    # Let's create specific text here to be explicit.
    manual_steps = [
        "CRITICAL: Enable S3 Block Public Access immediately for this bucket.",
        "  - Navigate to S3 console -> Buckets -> Select bucket -> Permissions tab.",
        "  - Edit 'Block public access (bucket settings)' and enable all four settings (BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets).",
        "  - Save changes.",
        "After enabling Block Public Access, or if it cannot be enabled immediately:",
        "  - Under 'Access control list (ACL)', click 'Edit'.",
        "  - Remove the grant for 'Everyone (public access)' that allows this permission.",
        "  - Save changes.",
        "If public read access is absolutely required, use pre-signed URLs or CloudFront with Origin Access Identity instead of public ACLs."
    ]
    terraform_snippet = f"""
# CRITICAL: Enable S3 Block Public Access
resource "aws_s3_bucket_public_access_block" "pab_{finding.resource_id_sanitized}" {{
  bucket = "{finding.resource_id}"
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}}

# Set bucket ACL to private
resource "aws_s3_bucket_acl" "acl_{finding.resource_id_sanitized}" {{
  bucket = "{finding.resource_id}"
  acl    = "private"
  depends_on = [aws_s3_bucket_public_access_block.pab_{finding.resource_id_sanitized}]
}}
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions="Apply `aws_s3_bucket_public_access_block` immediately. The `aws_s3_bucket_acl` resource ensures the ACL is private."
    )

    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or ["CIS AWS Foundations Benchmark 1.1.2"],
        reference_links=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"]
    )

def get_s3_public_authenticated_users_acl_guidance(finding: models.Finding) -> RemediationOutputV2:
    permission = finding.details.get("permission", "Unknown permission")
    issue_summary = f"S3 bucket '{finding.resource_id}' grants '{permission}' to 'AuthenticatedUsers' via ACL."
    technical_details = (
        f"Granting '{permission}' to 'AuthenticatedUsers' (any AWS account holder) via ACL is a HIGH security risk, "
        "potentially exposing data to millions of AWS users. S3 Block Public Access should be enabled."
    )
    manual_steps = [
        "HIGH RISK: Enable S3 Block Public Access for this bucket.",
        "  - Navigate to S3 console -> Buckets -> Select bucket -> Permissions tab.",
        "  - Edit 'Block public access (bucket settings)' and enable all four settings.",
        "  - Save changes.",
        "After enabling Block Public Access, or if it cannot be enabled immediately:",
        "  - Under 'Access control list (ACL)', click 'Edit'.",
        "  - Remove the grant for 'Authenticated users group (any AWS account)' that allows this permission.",
        "  - Save changes.",
        "If cross-account access is required, use bucket policies with specific AWS Account ARNs or IAM Role ARNs, not 'AuthenticatedUsers' ACL grants."
    ]
    terraform_snippet = f"""
# HIGH RISK: Enable S3 Block Public Access
resource "aws_s3_bucket_public_access_block" "pab_{finding.resource_id_sanitized}" {{
  bucket = "{finding.resource_id}"
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}}

# Set bucket ACL to private
resource "aws_s3_bucket_acl" "acl_{finding.resource_id_sanitized}" {{
  bucket = "{finding.resource_id}"
  acl    = "private"
  depends_on = [aws_s3_bucket_public_access_block.pab_{finding.resource_id_sanitized}]
}}
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions="Apply `aws_s3_bucket_public_access_block`. The `aws_s3_bucket_acl` resource ensures the ACL is private."
    )
    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or ["CIS AWS Foundations Benchmark 1.1.2"],
        reference_links=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"]
    )

def get_s3_public_policy_guidance(finding: models.Finding) -> RemediationOutputV2:
    statement_sid = finding.details.get("statement_sid", "Unknown")
    statement_actions_list = finding.details.get("statement_actions", ["*"])
    statement_actions = ', '.join(statement_actions_list) if isinstance(statement_actions_list, list) else str(statement_actions_list)
    statement_principal_str = str(finding.details.get("statement_principal_json", '{"AWS": "*"}'))
    statement_conditions = str(finding.details.get("statement_conditions", "None"))
    
    risk_level = "high"
    if any(keyword in statement_actions.upper() for keyword in ["PUT", "DELETE", ":*", "*"]):
        risk_level = "critical"

    issue_summary = f"S3 bucket '{finding.resource_id}' has a public policy statement (SID: {statement_sid})."
    technical_details = (
        f"Bucket policy statement (SID: '{statement_sid}') allows public access for actions: [{statement_actions}] "
        f"(Principal: {statement_principal_str}). This is a {risk_level}-risk configuration. "
        f"Conditions found: {statement_conditions}. Verify conditions correctly and effectively restrict access, as misconfigured conditions are a common source of breaches. "
        "STRONGLY recommended: Enable S3 Block Public Access (`BlockPublicPolicy`, `RestrictPublicBuckets`) to prevent public policies."
    )
    manual_steps = [
        "STRONGLY RECOMMENDED: Enable S3 Block Public Access settings for this bucket, specifically 'Block public policy' and 'Restrict public buckets'.",
        "  - Navigate to S3 console -> Buckets -> Select bucket -> Permissions tab.",
        "  - Edit 'Block public access (bucket settings)' and ensure these are enabled.",
        "If Block Public Access cannot be fully enabled, or for further review:",
        "  - Navigate to S3 console -> Buckets -> Select bucket -> Permissions tab -> Bucket policy -> Edit.",
        f"  - Identify and remove or significantly restrict the statement SID '{statement_sid}' that allows public access.",
        "  - If restricting, change the Principal from a wildcard or broad public identifier to specific, known AWS Account ARNs or IAM Role/User ARNs.",
        "  - Carefully review any `Condition` elements to ensure they adequately limit access as intended."
    ]
    
    # Sanitized finding.resource_id for Terraform resource naming
    tf_bucket_name_sanitized = finding.resource_id_sanitized

    terraform_snippet = f"""
# Strongly Recommended: Enable S3 Block Public Access for policies
resource "aws_s3_bucket_public_access_block" "pab_{tf_bucket_name_sanitized}" {{
  bucket = "{finding.resource_id}"
  
  block_public_acls       = true # Also block/ignore public ACLs
  ignore_public_acls      = true
  block_public_policy     = true # PRIMARY FIX for public policies
  restrict_public_buckets = true # Restrict new public bucket policies
}}

# If a bucket policy is still required after blocking public access,
# ensure it does NOT contain public principals or overly permissive statements.
# The following is an EXAMPLE of removing a public statement or creating a restrictive policy.
# You MUST adapt it to your specific needs.
# Option 1: Remove the entire policy if BlockPublicPolicy is True and no other statements are needed.
# resource "aws_s3_bucket_policy" "policy_{tf_bucket_name_sanitized}" {{
#   bucket = "{finding.resource_id}"
#   # policy = "" # To remove policy, or construct policy without the public statement.
#   # Ensure depends_on if creating this after block public access.
#   depends_on = [aws_s3_bucket_public_access_block.pab_{tf_bucket_name_sanitized}]
# }}

# Option 2: Example of a policy with a specific, non-public statement
# (assuming the public statement SID '{statement_sid}' is removed or modified)
# data "aws_iam_policy_document" "secure_s3_policy_{tf_bucket_name_sanitized}" {{
#   statement {{
#     sid    = "AllowSpecificRole"
#     effect = "Allow"
#     principals {{
#       type        = "AWS"
#       identifiers = ["arn:aws:iam::YOUR_ACCOUNT_ID:role/YOUR_SPECIFIC_ROLE"]
#     }}
#     actions   = ["s3:GetObject"]
#     resources = ["arn:aws:s3:::{finding.resource_id}/*"]
#   }}
#   # Add other necessary, non-public statements here
# }}

# resource "aws_s3_bucket_policy" "policy_{tf_bucket_name_sanitized}" {{
#   bucket = "{finding.resource_id}"
#   policy = data.aws_iam_policy_document.secure_s3_policy_{tf_bucket_name_sanitized}.json
#   depends_on = [aws_s3_bucket_public_access_block.pab_{tf_bucket_name_sanitized}]
# }}
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions=(
            "First, apply the `aws_s3_bucket_public_access_block` resource. "
            "Then, if a bucket policy is still necessary, remove the public statement (SID: "
            f"{statement_sid}) or replace it with a more restrictive one. The example shows how to structure a restrictive policy. "
            "Managing bucket policies with IaC requires defining the entire policy document."
        )
    )

    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or ["CIS AWS Foundations Benchmark 1.1.3"],
        reference_links=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html"]
    )

def get_s3_mfa_delete_guidance(finding: models.Finding) -> RemediationOutputV2:
    mfa_status = finding.details.get("mfa_delete_status", "Disabled")
    versioning_status = finding.details.get("versioning_status", "Unknown")

    issue_summary = f"MFA Delete is {mfa_status} for S3 bucket '{finding.resource_id}' (Versioning: {versioning_status})."
    technical_details = (
        "MFA Delete requires additional authentication (from the root account's MFA device) for changing bucket "
        "versioning state or permanently deleting object versions. It provides strong protection against accidental/malicious deletions."
    )
    manual_steps = [
        "Prerequisites: Bucket versioning MUST be 'Enabled'. The AWS account root user MUST have an MFA device configured.",
        "Action: This setting can ONLY be enabled/modified by the AWS account ROOT USER using their MFA credentials.",
        "Console: Log in as the root user. Navigate to S3 -> Buckets -> Select bucket -> Properties tab -> Bucket Versioning -> Edit -> Enable MFA Delete.",
        "CLI (as root user with MFA): `aws s3api put-bucket-versioning --bucket YOUR_BUCKET_NAME --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa \"arn:aws:iam::ROOT_ACCOUNT_ID:mfa/ROOT_MFA_DEVICE_NAME MFA_CODE\"` (Replace placeholders)."
    ]
    
    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=None, # IaC is not applicable
        compliance_standards=finding.compliance_standards or [],
        reference_links=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/MultiFactorAuthenticationDelete.html"],
        # Explicitly add a note about IaC non-applicability in a structured way if desired,
        # but the absence of iac_remediation and manual_steps implies it.
        # Could add to technical_details: "Due to the root user and interactive MFA requirement, this is NOT typically managed via standard IAM-role-based IaC."
    )


def get_s3_secure_transport_guidance(finding: models.Finding) -> RemediationOutputV2:
    issue_summary = f"S3 bucket '{finding.resource_id}' does not enforce secure transport (HTTPS)."
    technical_details = (
        "Enforcing HTTPS for all requests to an S3 bucket protects data in transit from eavesdropping or modification. "
        "This is implemented via a bucket policy statement that denies requests where `aws:SecureTransport` is 'false'."
    )
    manual_steps = [
        "Navigate to the S3 console -> Buckets -> Select your bucket -> Permissions tab -> Bucket policy -> Edit.",
        "Add or merge the following policy statement into your existing bucket policy. Be careful not to overwrite existing non-public statements:",
        json.dumps({
            "Sid": "EnforceSSLOnlyAccess",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [
                f"arn:aws:s3:::{finding.resource_id}",
                f"arn:aws:s3:::{finding.resource_id}/*"
            ],
            "Condition": {
                "Bool": {"aws:SecureTransport": "false"}
            }
        }, indent=2),
        "Save changes.",
        "Ensure all clients and applications accessing the bucket support and use HTTPS."
    ]
    
    # Sanitized resource_id for Terraform
    tf_bucket_name_sanitized = finding.resource_id_sanitized
    
    terraform_snippet = f"""
# Enforce secure transport (HTTPS) via bucket policy for bucket {finding.resource_id}
# IMPORTANT: This Terraform code defines the entire policy. 
# You MUST merge this statement with any other existing policy statements your bucket requires.

data "aws_iam_policy_document" "existing_policy_statements_{tf_bucket_name_sanitized}" {{
  # If you have other statements to preserve, define them here. For example:
  # statement {{
  #   sid    = "AllowAppAccess"
  #   effect = "Allow" 
  #   # ... other fields
  # }}
}}

data "aws_iam_policy_document" "ssl_only_statement_{tf_bucket_name_sanitized}" {{
  statement {{
    sid       = "EnforceSSLOnlyAccess"
    effect    = "Deny"
    principals {{
      type        = "*"
      identifiers = ["*"]
    }}
    actions   = ["s3:*"]
    resources = [
      "arn:aws:s3:::{finding.resource_id}",
      "arn:aws:s3:::{finding.resource_id}/*",
    ]
    condition {{
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }}
  }}
}}

resource "aws_s3_bucket_policy" "policy_{tf_bucket_name_sanitized}" {{
  bucket = "{finding.resource_id}"
  policy = jsonencode({{
    Version   = "2012-10-17"
    Statement = concat(
      data.aws_iam_policy_document.existing_policy_statements_{tf_bucket_name_sanitized}.statement,
      data.aws_iam_policy_document.ssl_only_statement_{tf_bucket_name_sanitized}.statement
    )
  }})
}}
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions="Adapt this Terraform configuration. You must merge the 'EnforceSSLOnlyAccess' statement with any existing statements in your bucket policy. Managing S3 bucket policies with IaC involves defining the entire policy document."
    )

    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or ["NIST CSF PR.DS-2"], # Example standard
        reference_links=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html#transit"]
    )

# --- S3 Guidance Map ---
S3_GUIDANCE_MAP: Dict[tuple[str, str], Callable[[models.Finding], RemediationOutputV2]] = {
    ("AWS::S3::Bucket", "public access block is not enabled"): get_s3_public_access_block_guidance,
    ("AWS::S3::Bucket", "versioning is not enabled"): get_s3_versioning_guidance, # Title from analyzer: "S3 bucket '{bucket_name}' versioning is not enabled (Status: {status})"
    ("AWS::S3::Bucket", "server access logging is disabled"): get_s3_logging_guidance,
    ("AWS::S3::Bucket", "default encryption is not enabled"): get_s3_encryption_guidance,
    ("AWS::S3::Bucket", "mfa delete is disabled"): get_s3_mfa_delete_guidance, # Title from analyzer: "S3 bucket '{bucket_name}' does not have MFA Delete enabled (Status: {status})"
    ("AWS::S3::Bucket", "does not enforce secure transport"): get_s3_secure_transport_guidance, # Assuming a generic title match
    
    # More specific titles from the S3 analyzer:
    ("AWS::S3::Bucket", "allows public access via ACL"): get_s3_public_acl_guidance, # Generic handler for titles like "S3 bucket '{bucket_name}' allows public access via ACL ({permission} to {grantee})"
    ("AWS::S3::Bucket", "public acl grant to AllUsers"): get_s3_public_all_users_acl_guidance, # Match specific findings if analyzer creates them with this exact title part
    ("AWS::S3::Bucket", "public acl grant to AuthenticatedUsers"): get_s3_public_authenticated_users_acl_guidance, # Same as above
    ("AWS::S3::Bucket", "has a public policy statement"): get_s3_public_policy_guidance, # For titles like "S3 bucket '{bucket_name}' has a public policy statement (SID: {stmt_sid})"
} 