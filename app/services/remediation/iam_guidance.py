from typing import Dict, Any, Callable, Union
from app.db import models # Assuming models are accessible
from .schemas import (
    RemediationOutputV2,
    IacRemediation,
    IacTool,
    # ImpactAnalysis, # Will be None for now, can import later if used
    # RiskScore       # Will be None for now, can import later if used
) 
import json # For pretty printing policy documents in notes

# Helper to sanitize resource names for Terraform
# (Could be in a shared util if used by many guidance modules)
def sanitize_for_terraform_resource_name(resource_name: str) -> str:
    # Basic sanitization: replace non-alphanumeric with underscores
    # Terraform names usually start with a letter or underscore.
    sanitized = '_'.join(filter(None, resource_name.split(':')))
    sanitized = ''.join(c if c.isalnum() or c == '_' else '_' for c in sanitized)
    if not sanitized or not (sanitized[0].isalpha() or sanitized[0] == '_'):
        sanitized = "tf_" + sanitized
    return sanitized.lower()

# Monkey patch the model for this purpose (not ideal for production but ok for this context)
# Ensure this is defined or handled appropriately if models.Finding might not always be loaded when this module is.
if hasattr(models, 'Finding') and not hasattr(models.Finding, 'resource_id_sanitized'):
    setattr(models.Finding, 'resource_id_sanitized', property(lambda self: sanitize_for_terraform_resource_name(self.resource_id)))


# --- IAM & Account Guidance Functions ---

def get_iam_password_policy_guidance(finding: models.Finding) -> RemediationOutputV2:
    issue_summary = "IAM password policy is not configured or is not sufficiently strong."
    technical_details = (
        "A strong IAM password policy enforces complexity requirements and regular rotation, reducing the risk of unauthorized access via weak or compromised passwords. "
        "This policy applies to IAM users, not the AWS account root user password."
    )
    
    desired_policy_settings_desc = [
        "MinimumPasswordLength: 14 or greater",
        "RequireSymbols: True",
        "RequireNumbers: True",
        "RequireUppercaseCharacters: True",
        "RequireLowercaseCharacters: True",
        "AllowUsersToChangePassword: True (generally recommended)",
        "MaxPasswordAge: 90 days or less (or as per compliance)",
        "PasswordReusePrevention: 24 or higher (or as per compliance)",
        "HardExpiry: False (user-friendly) or True (stricter, requires admin for reset after expiry)"
    ]
    manual_steps = [
        "Navigate to the IAM console -> Account settings.",
        "In the 'Password policy' section, click 'Edit'.",
        "Configure the policy settings according to your organization's security requirements. Recommended strong settings include:",
    ] + [f"  - {s}" for s in desired_policy_settings_desc] + [
        "Save changes."
    ]

    # Terraform for aws_iam_account_password_policy
    terraform_snippet = f"""
resource "aws_iam_account_password_policy" "default" {{
  minimum_password_length        = 14
  require_lowercase_characters = true
  require_numbers                = true
  require_symbols                = true
  require_uppercase_characters = true
  allow_users_to_change_password = true
  max_password_age             = 90
  password_reuse_prevention    = 24
  # hard_expiry                  = false
}}
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions="Adapt and apply this Terraform configuration to set a strong account password policy. Adjust parameters like max_password_age based on compliance."
    )

    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or ["CIS AWS Foundations Benchmark 1.5-1.11"],
        reference_links=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"]
    )

def get_iam_root_mfa_guidance(finding: models.Finding) -> RemediationOutputV2:
    issue_summary = "Multi-Factor Authentication (MFA) is not enabled for the AWS account root user."
    technical_details = (
        "MFA for the root account is the single most important security measure for your AWS account. It provides an additional layer of security against unauthorized access, "
        "even if the root password is compromised. This action MUST be performed manually by logging in as the root user."
    )
    manual_steps = [
        "Log in to the AWS Management Console as the root user.",
        "Navigate to 'My Security Credentials' (usually under your account name in the top right).",
        "Expand the 'Multi-factor authentication (MFA)' section.",
        "Click 'Activate MFA'.",
        "Follow the prompts to set up an MFA device (virtual authenticator app or hardware MFA key).",
        "Ensure you securely store any backup codes provided."
    ]

    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=None, # Not applicable for root MFA setup via typical IaC roles
        compliance_standards=finding.compliance_standards or ["CIS AWS Foundations Benchmark 1.1"],
        reference_links=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#root-user-mfa"]
    )

# --- Remaining IAM Guidance Functions (To be updated in subsequent steps) ---
# ... (get_iam_user_console_mfa_guidance, etc. will be updated next)

def get_iam_user_console_mfa_guidance(finding: models.Finding) -> RemediationOutputV2:
    user_name = finding.resource_id.split('/')[-1]
    issue_summary = f"IAM user '{user_name}' with console access does not have MFA enabled."
    technical_details = (
        "Multi-Factor Authentication (MFA) adds a crucial second layer of security to user logins. If an IAM user has console access, "
        "MFA should be enabled to protect against unauthorized access if their password is compromised. Managing MFA for individual users via IaC "
        "is complex due to the need for user interaction (e.g., QR code scanning for virtual MFA)."
    )
    manual_steps = [
        f"Log in to the AWS Management Console as an administrator or as the user '{user_name}' (if permissions allow).",
        f"Navigate to IAM -> Users -> Select user '{user_name}'.",
        "Go to the 'Security credentials' tab.",
        "Under 'Multi-factor authentication (MFA)', click 'Manage' (or 'Assign MFA device').",
        "Follow the prompts to assign and activate an MFA device (virtual or hardware).",
        "Consider creating an IAM policy to enforce MFA for console users (e.g., by denying actions if `aws:MultiFactorAuthPresent` is false for critical operations)."
    ]
    
    # Terraform for aws_iam_user_mfa_device is more for registering an existing device ARN with a user.
    # The initial creation of the virtual MFA device (`aws_iam_virtual_mfa_device`) and user interaction is hard to fully automate in IaC.
    terraform_snippet = f"""
# Note: Managing user-specific MFA setup via Terraform can be complex due to user interaction requirements.
# This example shows associating a pre-existing virtual MFA device with a user.
# The virtual MFA device itself would need to be created and its ARN obtained first.

# resource "aws_iam_virtual_mfa_device" "mfa_{user_name}" {{
#   virtual_mfa_device_name = "mfa_{user_name}"
#   # Output: base_32_string_seed, qr_code_png (user needs these for setup)
# }}

# resource "aws_iam_user_mfa_device" "user_mfa_{user_name}" {{
#   username            = "{user_name}"
#   virtual_mfa_device_arn = aws_iam_virtual_mfa_device.mfa_{user_name}.arn # Or an existing device ARN
#   # Requires two consecutive authentication codes after user registers device
#   authentication_code1 = "FIRST_MFA_CODE"
#   authentication_code2 = "SECOND_MFA_CODE"
# }}

# A more common IaC approach is to enforce MFA via policy:
resource "aws_iam_user_policy" "enforce_mfa_{sanitize_for_terraform_resource_name(user_name)}" {{
  name = "EnforceMFAFor-{user_name}"
  user = "{user_name}"

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Sid      = "AllowAllActionsWithMFA"
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
        Condition = {{
          BoolIfExists = {{ "aws:MultiFactorAuthPresent" = "true" }}
        }}
      }},
      {{
        Sid      = "DenyAllActionsWithoutMFA"
        Effect   = "Deny"
        Action   = "*"
        Resource = "*"
        Condition = {{
          BoolIfExists = {{ "aws:MultiFactorAuthPresent" = "false" }}
        }}
      }}
    ]
  }})
}}
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions="Enforcing MFA via IAM policy (as shown) is a robust IaC method. Direct user MFA device assignment in Terraform is complex and may require manual steps for initial device registration and code input."
    )

    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or ["CIS AWS Foundations Benchmark 1.2"],
        reference_links=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"]
    )

def get_iam_user_unused_password_guidance(finding: models.Finding) -> RemediationOutputV2:
    user_name = finding.resource_id.split('/')[-1]
    password_last_used_str = finding.details.get("password_last_used", "Not available")
    
    issue_summary = f"Console password for IAM user '{user_name}' has not been used recently."
    technical_details = (
        f"The console password for IAM user '{user_name}' was last used on {password_last_used_str}. "
        "Long-unused passwords increase the attack surface if the account is dormant but credentials remain active. "
        "Consider if console access is still necessary for this user."
    )
    manual_steps = [
        f"Verify with the user '{user_name}' or their manager if AWS Management Console access is still required.",
        "If console access is not needed, delete the user's login profile:",
        f"  - Navigate to IAM -> Users -> Select user '{user_name}'.",
        "  - Go to the 'Security credentials' tab.",
        "  - Under 'Console password', click 'Manage' or 'Remove password'.",
        "If console access is still needed but infrequent, ensure the password meets complexity requirements and consider reminding the user to log in or rotate their password if it's very old."
    ]
    
    terraform_snippet = f"""
# To remove/disable a login profile for user '{user_name}' in Terraform:
# Option 1: Remove the aws_iam_user_login_profile resource entirely if it was managed by Terraform.

# Option 2: If managing the user and wanting to ensure no password (or force reset):
resource "aws_iam_user" "user_{sanitize_for_terraform_resource_name(user_name)}" {{
  name = "{user_name}"
  # ... other user attributes
  # To disable login profile, omit password_length, password_reset_required, etc.
  # Or, to force reset without providing a password:
  # password_reset_required = true 
}}

# Ensure no aws_iam_user_login_profile resource exists for this user if password should be removed.
# If you have one, for example:
# resource "aws_iam_user_login_profile" "lp_{sanitize_for_terraform_resource_name(user_name)}" {{
#   user = aws_iam_user.user_{sanitize_for_terraform_resource_name(user_name)}.name
#   # To remove, either delete this resource block or set count = 0
#   # count = 0 
# }}
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions=f"To remove console password for user '{user_name}', ensure no `aws_iam_user_login_profile` resource is defined for them, or remove/comment it out. Alternatively, within an `aws_iam_user` resource, omitting password-related arguments or setting `password_reset_required = true` can effectively disable direct login until reset."
    )

    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or [],
        reference_links=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_manage-user.html#id_credentials_passwords_disable-user"]
    )

# --- Remaining IAM Guidance Functions (To be updated in subsequent steps) ---
# ... (get_iam_key_unused_guidance, etc. will be updated next)

def get_iam_key_unused_guidance(finding: models.Finding) -> RemediationOutputV2:
    parts = finding.resource_id.split('/')
    key_id = parts[-1] if len(parts) > 0 else "UnknownKey"
    user_name = parts[-3] if len(parts) > 2 else "UnknownUser"
    status = finding.details.get("key_status", "Unknown") 
    last_used_date = finding.details.get("key_last_used_date", "Never or N/A")
    create_date = finding.details.get("key_create_date", "Unknown") # For "never used" keys

    if last_used_date == "Never or N/A" and create_date != "Unknown":
        issue_summary = f"IAM access key '{key_id}' for user '{user_name}' has never been used (created: {create_date})."
        technical_details = (
            f"Access key '{key_id}' for user '{user_name}' was created on {create_date} but has never been used. "
            "Unused credentials, even if never active, pose a potential risk if their existence is forgotten or if the user's account is compromised."
        )
    else:
        issue_summary = f"IAM access key '{key_id}' for user '{user_name}' (Status: {status}) has not been used recently."
        technical_details = (
            f"Access key '{key_id}' for user '{user_name}' (Status: {status}) was last used on {last_used_date}. "
            "Long-unused active keys or keys that remain inactive represent an unnecessary security risk if compromised."
        )
    
    manual_steps = [
        f"Verify if access key '{key_id}' for user '{user_name}' is still required by any application or script.",
        "If the key is active and possibly in use, the recommended best practice is to first deactivate it:",
        f"  - Console: IAM -> Users -> {user_name} -> Security credentials tab -> Access keys -> Select key '{key_id}' -> Actions -> Make inactive.",
        "  - Monitor applications/scripts for any failures for a period (e.g., 7-30 days).",
        "If the key is confirmed to be unused (or after the deactivation monitoring period):",
        f"  - Delete the key: Console -> IAM -> Users -> {user_name} -> Security credentials tab -> Access keys -> Select key '{key_id}' -> Actions -> Delete."
    ]
    
    sanitized_user_name = sanitize_for_terraform_resource_name(user_name)
    # Terraform can manage the status or presence of an access key.
    terraform_snippet = f"""
# To manage access key '{key_id}' for user '{user_name}'
# If the key was created by Terraform, modify its status or remove the resource.
# If created manually, it might need to be imported or managed manually first.

resource "aws_iam_access_key" "key_{sanitized_user_name}_{sanitize_for_terraform_resource_name(key_id)}" {{
  user   = "{user_name}"
  # To deactivate an existing key managed by Terraform:
  status = "Inactive"
  # To delete a key managed by Terraform, remove this resource block.
  # Note: Deleting the resource will delete the key from AWS.
}}
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions=f"To deactivate key '{key_id}' for user '{user_name}', set its status to 'Inactive' in your Terraform configuration. To delete, remove the resource block. Always verify key usage before deletion."
    )

    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or ["CIS AWS Foundations Benchmark 1.3"],
        reference_links=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_RotateAccessKey"]
    )

def get_iam_key_rotation_guidance(finding: models.Finding) -> RemediationOutputV2:
    parts = finding.resource_id.split('/')
    key_id = parts[-1] if len(parts) > 0 else "UnknownKey"
    user_name = parts[-3] if len(parts) > 2 else "UnknownUser"
    create_date = finding.details.get("key_create_date", "Unknown")
    key_age_days = finding.details.get("key_age_days", "over 90") # Default text if not precise

    issue_summary = f"Active IAM access key '{key_id}' for user '{user_name}' is old and needs rotation."
    technical_details = (
        f"The active access key '{key_id}' for user '{user_name}' was created on {create_date} (approx. {key_age_days} days old). "
        "Regular rotation of access keys (e.g., every 90 days) is a security best practice to limit the time window an attacker can use a compromised key."
    )
    manual_steps = [
        f"Plan the rotation for key '{key_id}' of user '{user_name}'.",
        "1. Create a new access key for the IAM user:",
        f"   - Console: IAM -> Users -> {user_name} -> Security credentials -> Access keys -> Create access key.",
        "   - Securely store the new key ID and secret access key.",
        "2. Update all applications, scripts, and services currently using the old key '{key_id}' to use the new key credentials.",
        "3. Thoroughly test all updated applications/scripts to ensure they function correctly with the new key.",
        f"4. Deactivate the old key '{key_id}':",
        f"   - Console: IAM -> Users -> {user_name} -> Security credentials -> Access keys -> Select old key '{key_id}' -> Actions -> Make inactive.",
        "5. Monitor applications and systems for a period (e.g., 1-7 days) to ensure no residual use of the old key and that everything works with the new key.",
        f"6. Delete the old, inactive key '{key_id}':",
        f"   - Console: IAM -> Users -> {user_name} -> Security credentials -> Access keys -> Select inactive key '{key_id}' -> Actions -> Delete."
    ]
    
    # IaC can create a new key and delete/deactivate an old one, but cannot update applications.
    sanitized_user_name = sanitize_for_terraform_resource_name(user_name)
    terraform_snippet = f"""
# Step 1: Create a new access key (if not already done manually)
# resource "aws_iam_access_key" "new_key_{sanitized_user_name}" {{
#   user = "{user_name}"
#   # The secret will be available in `aws_iam_access_key.new_key_{sanitized_user_name}.secret`
#   # Store it securely and update your applications.
# }}

# Step 4 & 6: To deactivate and then delete an old key managed by Terraform
# (assuming '{key_id}' refers to a key previously defined in Terraform, e.g., "old_key_resource_name")
# resource "aws_iam_access_key" "old_key_resource_name" {{
#   user   = "{user_name}"
#   # To deactivate:
#   # status = "Inactive"
#   # To delete: Remove this entire resource block after applications are updated.
# }}
"""

    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=IacRemediation(
            tool=IacTool.TERRAFORM,
            code_snippet=terraform_snippet.strip(), # Shows conceptual IaC steps for key management
            apply_instructions="Key rotation is a multi-step process. IaC can manage key creation and deletion/deactivation. The critical step of updating applications with the new key credentials is manual or requires separate automation outside of this direct IaC snippet."
        ),
        compliance_standards=finding.compliance_standards or ["CIS AWS Foundations Benchmark 1.3"],
        reference_links=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#rotating_access_keys"]
    )

# --- Remaining IAM Guidance Functions (To be updated in subsequent steps) ---
# ... (get_iam_policy_admin_guidance, etc. will be updated next)

def get_iam_policy_admin_guidance(finding: models.Finding) -> RemediationOutputV2:
    policy_name = finding.details.get("policy_name", finding.resource_id.split('/')[-1])
    principal_name = finding.details.get("principal_name", "Unknown Principal")
    resource_type_simple = finding.resource_type.split("::")[-1]

    issue_summary = f"IAM policy '{policy_name}' grants excessive administrative privileges."
    technical_details = (
        f"The IAM policy '{policy_name}' (resource ARN: {finding.resource_id}, possibly associated with {principal_name} of type {resource_type_simple}) "
        "grants overly broad administrative privileges (e.g., `Allow Action='*' on Resource='*'`). This violates the principle of least privilege "
        "and significantly increases the potential blast radius if the associated principal's credentials are compromised."
    )
    manual_steps = [
        "Identify the minimum set of permissions absolutely required by the principal or service using this policy.",
        "Create a new, fine-grained IAM policy that grants only those necessary permissions.",
        "Use tools like IAM Access Analyzer to help generate least-privilege policies based on actual CloudTrail activity.",
        f"Detach the overly permissive policy '{policy_name}' from all principals (users, roles, groups).",
        "Attach the new, more restrictive policy to the principals.",
        "Thoroughly test to ensure applications and users can still perform their required tasks.",
        "Consider using permission boundaries as an additional layer of defense to restrict the maximum permissions an entity can ever have."
    ]
    
    sanitized_principal_name = sanitize_for_terraform_resource_name(principal_name if principal_name != "Unknown Principal" else policy_name + "_principal")
    sanitized_new_policy_name = sanitize_for_terraform_resource_name(policy_name + "_restricted")
    
    terraform_snippet = f"""
# 1. Define a new, more restrictive IAM policy (example - customize actions/resources)
resource "aws_iam_policy" "{sanitized_new_policy_name}" {{
  name        = "{policy_name}-Restricted"
  description = "Least-privilege replacement for policy {policy_name}"
  policy      = jsonencode({{
    Version   = "2012-10-17"
    Statement = [
      {{
        Effect   = "Allow"
        Action   = [
          "s3:ListBucket",
          "s3:GetObject"
          # Add only necessary permissions here
        ]
        Resource = [
          "arn:aws:s3:::your-specific-bucket",
          "arn:aws:s3:::your-specific-bucket/*"
          # Define specific resources
        ]
      }}
      # Add other statements as needed for fine-grained access
    ]
  }})
}}

# 2. Example of attaching the new policy to a user 
# (similar for roles `aws_iam_role_policy_attachment` or groups `aws_iam_group_policy_attachment`)
# You would also need to ensure the old, overly permissive policy is detached.
resource "aws_iam_user_policy_attachment" "attach_restricted_{sanitized_principal_name}" {{
  user       = "{principal_name if principal_name != 'Unknown Principal' else 'YOUR_USER_NAME'}" # Replace if principal_name was Unknown
  policy_arn = aws_iam_policy.{sanitized_new_policy_name}.arn
}}

# To detach the old policy (if it was a managed policy attached directly):
# (Ensure you know the exact ARN of the old policy: {finding.resource_id})
# Consider using `terraform import` if the attachment wasn't managed by Terraform previously, or remove manually first.
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions="Create a new IAM policy with least-privilege permissions based on the example. Detach the old overly permissive policy and attach the new one to the relevant principals (users, roles, groups). Update placeholders like 'YOUR_USER_NAME' or resource ARNs."
    )

    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or ["CIS AWS Foundations Benchmark 1.16"],
        reference_links=["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"]
    )

def get_iam_role_broad_trust_guidance(finding: models.Finding) -> RemediationOutputV2:
    role_name = finding.details.get("role_name", finding.resource_id.split('/')[-1])
    trust_details_str = str(finding.details.get("trust_details", "Details not available in finding.")) 
    conditions = str(finding.details.get("conditions", "None specified in finding."))

    issue_summary = f"IAM role '{role_name}' has an overly permissive trust policy."
    technical_details = (
        f"The trust policy for IAM role '{role_name}' (ARN: {finding.resource_id}) allows broad entities to assume it, increasing the risk of unauthorized access and privilege escalation. "
        f"Current trust principal information suggests: {trust_details_str}. Conditions applied: {conditions}. "
        "Trust policies should be scoped to the minimum necessary principals and further restricted with conditions where possible."
    )
    manual_steps = [
        f"Navigate to IAM -> Roles -> Select role '{role_name}'.",
        "Go to the 'Trust relationships' tab and click 'Edit trust policy'.",
        "Review the JSON policy document.",
        "Modify the `Principal` element. Replace wildcard principals (e.g., `\"AWS\": \"*\"`) with specific service principals (e.g., `\"Service\": \"ec2.amazonaws.com\"`), specific AWS account ARNs (e.g., `\"AWS\": \"arn:aws:iam::ACCOUNT_ID:root\"`), or specific IAM user/role ARNs.",
        "If cross-account or federated access is granted, add or strengthen `Condition` elements (e.g., using `sts:ExternalId`, `aws:SourceArn`, or `aws:SourceAccount`) to restrict when the role can be assumed.",
        "Validate the policy changes and save."
    ]

    sanitized_role_name = finding.resource_id_sanitized # Use the sanitized version
    terraform_snippet = f"""
resource "aws_iam_role" "{sanitized_role_name}" {{
  name = "{role_name}"
  
  # Example: Restrict trust to a specific AWS service and an external account with an ExternalId
  assume_role_policy = jsonencode({{
    Version   = "2012-10-17",
    Statement = [
      {{
        Effect    = "Allow",
        Principal = {{ "Service" = "ec2.amazonaws.com" }},
        Action    = "sts:AssumeRole"
      }},
      {{
        Effect    = "Allow",
        Principal = {{ "AWS" = "arn:aws:iam::YOUR_TRUSTED_ACCOUNT_ID:root" }},
        Action    = "sts:AssumeRole",
        Condition = {{
          StringEquals = {{ "sts:ExternalId" = "YOUR_UNIQUE_EXTERNAL_ID" }}
        }}
      }}
      # Add other specific trusted principals as needed
    ]
  }})
  
  # Ensure other configurations for this role (permissions policies, description, etc.) are also defined here
  # For example, to attach a managed policy:
  # managed_policy_arns = ["arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"]
}}
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions="Modify the `assume_role_policy` in your Terraform configuration for this role. Replace placeholders like 'YOUR_TRUSTED_ACCOUNT_ID' and 'YOUR_UNIQUE_EXTERNAL_ID' with actual values. Ensure only necessary principals are trusted."
    )

    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or [],
        reference_links=["https://docs.aws.amazon.com/IAM/latest/UserGuide/roles-trust-policies.html"]
    )

def get_iam_support_role_missing_guidance(finding: models.Finding) -> RemediationOutputV2:
    expected_role_name = finding.details.get("expected_role_name", "SecurityAuditRole")
    issue_summary = f"Dedicated IAM role for incident investigation (e.g., '{expected_role_name}') is missing."
    technical_details = (
        "A dedicated IAM role with specific, read-only permissions (e.g., SecurityAudit, ReadOnlyAccess) is recommended for security incident investigation. "
        "This allows for audited, controlled access during security events without granting broad standing permissions to individuals."
    )
    manual_steps = [
        f"Navigate to IAM -> Roles -> Create role.",
        "Select 'AWS account' or 'Custom trust policy' depending on who needs to assume this role (e.g., users in your account, a federated identity, or another AWS account for centralized security).",
        "If using a custom trust policy, define the trusted principals carefully.",
        "Attach managed policies like `SecurityAudit` and `ReadOnlyAccess` (or more specific custom policies as needed for investigation).",
        f"Name the role (e.g., '{expected_role_name}') and add a description.",
        "Create the role.",
        "Grant permissions to authorized security personnel or incident responders to assume this role."
    ]
    
    sanitized_role_name = sanitize_for_terraform_resource_name(expected_role_name)
    terraform_snippet = f"""
resource "aws_iam_role" "{sanitized_role_name}" {{
  name = "{expected_role_name}"
  assume_role_policy = jsonencode({{
    Version   = "2012-10-17"
    Statement = [
      {{
        Effect    = "Allow"
        Principal = {{
          # IMPORTANT: Define who can assume this role. 
          # Example: Allow users in the current account. Restrict further if possible.
          AWS = "arn:aws:iam::${{data.aws_caller_identity.current.account_id}}:root"
        }}
        Action    = "sts:AssumeRole"
      }}
    ]
  }})
  description = "Role for security incident investigation and response."
}}

data "aws_caller_identity" "current" {{}}

resource "aws_iam_role_policy_attachment" "{sanitized_role_name}_security_audit" {{
  role       = aws_iam_role.{sanitized_role_name}.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}}

resource "aws_iam_role_policy_attachment" "{sanitized_role_name}_readonly_access" {{
  role       = aws_iam_role.{sanitized_role_name}.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}}
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions=f"Adapt and apply this Terraform configuration to create the '{expected_role_name}'. Ensure the `assume_role_policy` correctly defines trusted principals. You may need to adjust the `Principal` based on your identity setup."
    )

    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or ["CIS AWS Foundations Benchmark 1.15"],
        reference_links=["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#create-iam-roles"]
    )

def get_iam_server_cert_expired_guidance(finding: models.Finding) -> RemediationOutputV2:
    cert_name = finding.details.get("certificate_name", finding.resource_id.split('/')[-1])
    expiration_date = finding.details.get("expiration_date", "Unknown")

    issue_summary = f"IAM server certificate '{cert_name}' has expired."
    technical_details = (
        f"The server certificate '{cert_name}' (ARN: {finding.resource_id}) stored in IAM expired on {expiration_date}. "
        "Expired SSL/TLS certificates can cause service disruptions for applications relying on them (e.g., ELB listeners, CloudFront custom SSL)."
    )
    manual_steps = [
        f"Identify all services or endpoints currently configured to use the expired certificate '{cert_name}'.",
        "Obtain or generate a new, valid SSL/TLS certificate.",
        "Upload the new certificate to IAM or AWS Certificate Manager (ACM). ACM is generally preferred for easier management and auto-renewal capabilities for supported services.",
        "Update the configurations of affected services (e.g., ELB listeners, CloudFront distributions, API Gateway custom domains) to use the new certificate.",
        "Thoroughly test affected services to ensure they are working correctly with the new certificate.",
        f"After successful migration and testing, delete the expired certificate '{cert_name}' from IAM."
    ]
    
    # IaC for certificate replacement is complex as it involves out-of-band cert acquisition and service updates.
    # Terraform can manage aws_iam_server_certificate or aws_acm_certificate.
    sanitized_cert_name = sanitize_for_terraform_resource_name(cert_name + "_new")
    terraform_snippet = f"""
# Example: Uploading a new certificate to IAM (replace with your actual cert body/key)
# resource "aws_iam_server_certificate" "{sanitized_cert_name}" {{
#   name             = "{cert_name}-new"
#   certificate_body = file("path/to/your/new_certificate.pem")
#   private_key      = file("path/to/your/new_private_key.key")
#   # certificate_chain = file("path/to/your/certificate_chain.pem") # Optional
# }}

# OR Using ACM (Recommended for supported services)
# resource "aws_acm_certificate" "cert" {{
#   # ... configuration for importing or requesting a certificate ...
# }}

# After uploading/creating new cert, update relevant resources (e.g., ELB Listener, CloudFront) to use its ARN.
# Finally, the old IAM certificate can be deleted (manually or via IaC if imported).
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions="Replacing an expired certificate involves obtaining a new certificate, uploading it (to IAM or ACM), updating service configurations, and then deleting the old one. The Terraform snippet shows conceptual steps for IAM/ACM. Actual implementation depends on how your services are configured."
    )

    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or [],
        reference_links=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_server-certs.html",
            "https://aws.amazon.com/certificate-manager/"
        ]
    )

def get_iam_server_cert_expires_soon_guidance(finding: models.Finding) -> RemediationOutputV2:
    cert_name = finding.details.get("certificate_name", finding.resource_id.split('/')[-1])
    expiration_date = finding.details.get("expiration_date", "Unknown")

    issue_summary = f"IAM server certificate '{cert_name}' is expiring soon."
    technical_details = (
        f"The server certificate '{cert_name}' (ARN: {finding.resource_id}) stored in IAM is expiring soon (on {expiration_date}). "
        "Proactive renewal or replacement is crucial to prevent service disruptions."
    )
    manual_steps = [
        f"Identify all services using certificate '{cert_name}'.",
        "Plan the renewal process: obtain/generate a new certificate.",
        "Upload the new certificate to IAM or, preferably, AWS Certificate Manager (ACM).",
        "Schedule a maintenance window to update all dependent services to use the new certificate.",
        "After successful migration and testing, the old certificate can be scheduled for deletion from IAM after it expires or is no longer needed.",
        "Refer to the guidance for 'Expired Server Certificate' for more detailed steps on replacement."
    ]
    
    # Terraform snippet would be similar to expired cert - focusing on creating/uploading new one.
    sanitized_cert_name = sanitize_for_terraform_resource_name(cert_name + "_replacement")
    terraform_snippet = f"""
# Plan to replace certificate '{cert_name}'.
# Example: Uploading a new certificate to IAM (replace with your actual cert body/key)
# resource "aws_iam_server_certificate" "{sanitized_cert_name}" {{
#   name             = "{cert_name}-replacement"
#   certificate_body = file("path/to/your/replacement_certificate.pem")
# }}

# OR Using ACM (Recommended)
# resource "aws_acm_certificate" "cert_replacement" {{
#   # ... configuration for importing or requesting a certificate ...
# }}

# Remember to update services to use the new certificate ARN before the old one expires.
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions="Proactively obtain and upload a new certificate to IAM or ACM. Update service configurations to use the new certificate ARN before the current one expires. The snippet provides a conceptual Terraform resource for a new IAM certificate."
    )

    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or [],
        reference_links=[
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_server-certs.html", 
            "https://aws.amazon.com/certificate-manager/"
        ]
    )

# --- IAM & Account Guidance Map ---
IAM_GUIDANCE_MAP: Dict[tuple[str, str], Callable[[models.Finding], RemediationOutputV2]] = {
    # Account Level
    ("AWS::IAM::Account", "password policy not configured"): get_iam_password_policy_guidance,
    ("AWS::IAM::RootAccount", "root account mfa not enabled"): get_iam_root_mfa_guidance,
    ("AWS::IAM::Account", "incident investigation not found"): get_iam_support_role_missing_guidance,

    # User Level
    ("AWS::IAM::User", "console access has no mfa"): get_iam_user_console_mfa_guidance,
    ("AWS::IAM::User", "password not used recently"): get_iam_user_unused_password_guidance,
    
    ("AWS::IAM::AccessKey", "not used recently"): get_iam_key_unused_guidance,
    ("AWS::IAM::AccessKey", "never used"): get_iam_key_unused_guidance, 
    ("AWS::IAM::AccessKey", "inactive access key"): get_iam_key_unused_guidance,
    ("AWS::IAM::AccessKey", "active access key older than"): get_iam_key_rotation_guidance,

    ("AWS::IAM::Policy", "grants full admin access"): get_iam_policy_admin_guidance,
    ("AWS::IAM::InlinePolicy", "grants full admin access"): get_iam_policy_admin_guidance, 

    ("AWS::IAM::Role", "overly permissive trust policy"): get_iam_role_broad_trust_guidance,

    ("AWS::IAM::ServerCertificate", "expired server certificate"): get_iam_server_cert_expired_guidance,
    ("AWS::IAM::ServerCertificate", "server certificate expires soon"): get_iam_server_cert_expires_soon_guidance,
} 