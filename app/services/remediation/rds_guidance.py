from typing import Dict, Any, Callable, Union
from app.db import models
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
    # Further sanitize common problematic characters in ARNs or IDs for TF names
    sanitized = sanitized.replace("-", "_").replace(".", "_").replace("/", "_")
    sanitized = ''.join(c if c.isalnum() or c == '_' else '_' for c in sanitized)
    if not sanitized or not (sanitized[0].isalpha() or sanitized[0] == '_'):
        sanitized = "tf_" + sanitized
    return sanitized.lower()

if hasattr(models, 'Finding') and not hasattr(models.Finding, 'resource_id_sanitized'):
    setattr(models.Finding, 'resource_id_sanitized', property(lambda self: sanitize_for_terraform_resource_name(self.resource_id.split('/')[-1])))


# --- RDS Guidance Functions ---

def get_rds_storage_encryption_guidance(finding: models.Finding) -> RemediationOutputV2:
    instance_id = finding.details.get("RdsInstanceId", finding.resource_id.split('/')[-1])
    engine = finding.details.get("RdsEngine", "Unknown Engine")

    issue_summary = f"RDS instance '{instance_id}' storage is not encrypted."
    technical_details = (
        f"The storage for RDS instance '{instance_id}' (Engine: {engine}) is not encrypted. Encrypting data at rest is crucial for protecting sensitive information. "
        "For RDS, storage encryption must typically be enabled at the time of instance creation or via a more involved process of snapshotting an unencrypted instance, copying the snapshot with encryption enabled, and then restoring a new instance from that encrypted snapshot."
    )
    manual_steps = [
        "Note: Enabling encryption for an existing unencrypted RDS instance usually requires downtime and a restore process.",
        f"1. Create a snapshot of the unencrypted DB instance '{instance_id}'.",
        "2. Copy the snapshot. In the copy options, enable encryption and select an appropriate KMS key (AWS managed `aws/rds` or a Customer Managed Key).",
        "3. Restore a new DB instance from this encrypted snapshot.",
        "4. Update your application(s) to use the endpoint of the new, encrypted DB instance.",
        f"5. After thorough testing and confirmation, decommission and delete the old unencrypted DB instance '{instance_id}' to avoid further charges.",
        "For all new RDS instances, ensure 'Enable encryption' is selected during creation."
    ]
    
    tf_instance_id_sanitized = sanitize_for_terraform_resource_name(instance_id)
    terraform_snippet = f"""
# When creating a new RDS instance with Terraform, ensure 'storage_encrypted' is true.
resource "aws_db_instance" "encrypted_rds_instance_{tf_instance_id_sanitized}" {{
  # ... other required arguments like allocated_storage, engine, instance_class, db_name, username, password ...
  identifier             = "{instance_id}-encrypted" # Example: new instance identifier
  storage_encrypted      = true
  # kms_key_id             = "arn:aws:kms:REGION:ACCOUNT_ID:key/YOUR_CMK_ID" # Optional: For CMK

  # Note: If you are replacing an existing unencrypted instance, 
  # you would typically create this new encrypted instance, migrate data, 
  # update application endpoints, and then decommission the old instance resource.
}}
"""

    # Since direct IaC modification for existing unencrypted is complex, iac_remediation focuses on new creation.
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions="The provided Terraform shows how to create a new RDS instance with encryption. For existing unencrypted instances, follow the manual snapshot, copy (with encryption), and restore process. Then update your IaC to reflect the new encrypted instance and remove the old one."
    )

    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation, # Provided for new resources
        compliance_standards=finding.compliance_standards or ["CIS AWS Benchmark 6.1"],
        reference_links=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html"]
    )

def get_rds_public_access_guidance(finding: models.Finding) -> RemediationOutputV2:
    instance_id = finding.details.get("RdsInstanceId", finding.resource_id.split('/')[-1])
    engine = finding.details.get("RdsEngine", "Unknown Engine")
    endpoint = finding.details.get("RdsEndpoint", "N/A")

    issue_summary = f"RDS instance '{instance_id}' is publicly accessible."
    technical_details = (
        f"RDS instance '{instance_id}' (Engine: {engine}, Endpoint: {endpoint}) is configured to be publicly accessible. "
        "This significantly increases its attack surface and risk of unauthorized access. Access should generally be restricted to within your VPC."
    )
    manual_steps = [
        f"Navigate to the RDS console -> Databases -> Select instance '{instance_id}'.",
        "Click 'Modify'.",
        "Scroll to the 'Connectivity' section.",
        "Under 'Public access', select 'No'.",
        "Review and ensure that 'VPC security groups' are appropriately configured to allow access only from necessary sources within your VPC (e.g., application servers, bastion hosts).",
        "Choose when to apply changes (immediately or during the next maintenance window, noting potential brief connectivity interruption).",
        "Save changes.",
        "If external access is absolutely required, consider using a bastion host, VPN, or AWS PrivateLink instead of direct public accessibility."
    ]
    
    tf_instance_id_sanitized = sanitize_for_terraform_resource_name(instance_id)
    terraform_snippet = f"""
resource "aws_db_instance" "{tf_instance_id_sanitized}" {{
  # Assuming this RDS instance '{instance_id}' is managed by Terraform.
  # Find your existing resource block for this instance.
  # ... (other arguments like allocated_storage, engine, instance_class, etc.)
  identifier = "{instance_id}"
  
  publicly_accessible = false

  # Ensure `vpc_security_group_ids` are set to security groups that allow
  # access only from within your VPC as needed.
  # vpc_security_group_ids = ["sg-xxxxxxxxxxxxxxxxx"]
}}
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions=f"Update the `publicly_accessible` attribute to `false` in your Terraform configuration for RDS instance '{instance_id}'. Ensure VPC security groups are correctly configured for private access."
    )

    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or ["CIS AWS Benchmark 6.3"],
        reference_links=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html#USER_VPC.WorkingWithRDSInstanceinaVPC"]
    )

def get_rds_automated_backups_guidance(finding: models.Finding) -> RemediationOutputV2:
    instance_id = finding.details.get("RdsInstanceId", finding.resource_id.split('/')[-1])
    current_retention = finding.details.get("BackupRetentionPeriod", 0)

    issue_summary = f"RDS instance '{instance_id}' has automated backups disabled or an insufficient retention period."
    technical_details = (
        f"Automated backups are crucial for point-in-time recovery (PITR) and disaster recovery. The current backup retention period for '{instance_id}' is {current_retention} days. "
        "A recommended retention period is typically 7 days or more, depending on recovery objectives and compliance requirements (1-35 days allowed by RDS)."
    )
    manual_steps = [
        f"Navigate to the RDS console -> Databases -> Select instance '{instance_id}'.",
        "Click 'Modify'.",
        "Scroll to the 'Backup' section.",
        "Set 'Backup retention period' to a suitable value greater than 0 (e.g., 7 days or more).",
        "Optionally, configure a 'Backup window' that suits your operational needs.",
        "Save changes. Enabling backups or changing retention might incur a brief I/O suspension during the initial backup window if one wasn't set."
    ]
    
    tf_instance_id_sanitized = sanitize_for_terraform_resource_name(instance_id)
    terraform_snippet = f"""
resource "aws_db_instance" "{tf_instance_id_sanitized}" {{
  identifier = "{instance_id}"
  # ... other arguments ...

  backup_retention_period = 7  # Or your desired retention period (1-35)
  # backup_window           = "03:00-04:00" # Optional: preferred backup window
}}
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions=f"Update the `backup_retention_period` for RDS instance '{instance_id}' in your Terraform configuration to an appropriate value (e.g., 7 or more)."
    )
    
    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or [],
        reference_links=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html"]
    )

def get_rds_deletion_protection_guidance(finding: models.Finding) -> RemediationOutputV2:
    instance_id = finding.details.get("RdsInstanceId", finding.resource_id.split('/')[-1])

    issue_summary = f"Deletion protection is disabled for RDS instance '{instance_id}'."
    technical_details = (
        "Enabling deletion protection for RDS instances prevents accidental deletion of critical databases. "
        "Once enabled, the instance cannot be deleted until this protection is explicitly disabled."
    )
    manual_steps = [
        f"Navigate to the RDS console -> Databases -> Select instance '{instance_id}'.",
        "Click 'Modify'.",
        "Scroll to the 'Deletion protection' section near the bottom.",
        "Check the box for 'Enable deletion protection'.",
        "Choose when to apply changes and click 'Continue'.",
        "Review changes and click 'Modify DB Instance'."
    ]

    tf_instance_id_sanitized = sanitize_for_terraform_resource_name(instance_id)
    terraform_snippet = f"""
resource "aws_db_instance" "{tf_instance_id_sanitized}" {{
  identifier = "{instance_id}"
  # ... other arguments ...

  deletion_protection = true
}}
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions=f"Set `deletion_protection = true` in your Terraform configuration for RDS instance '{instance_id}'."
    )

    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or [],
        reference_links=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteInstance.html#USER_DeleteInstance.DeletionProtection"]
    )

def get_rds_multi_az_guidance(finding: models.Finding) -> RemediationOutputV2:
    instance_id = finding.details.get("RdsInstanceId", finding.resource_id.split('/')[-1])
    engine = finding.details.get("RdsEngine", "Unknown Engine")
    current_multi_az = finding.details.get("MultiAZ", False)

    issue_summary = f"RDS instance '{instance_id}' is not configured for Multi-AZ deployment."
    technical_details = (
        f"Multi-AZ deployment for RDS instance '{instance_id}' (Engine: {engine}) is currently '{current_multi_az}'. "
        "It provides high availability and failover support by creating a synchronous standby replica in a different Availability Zone, increasing resilience against AZ failures. "
        "This incurs additional cost for the standby instance. Enabling Multi-AZ on an existing instance may cause downtime."
    )
    manual_steps = [
        f"If high availability is required for '{instance_id}':",
        f"  - Navigate to the RDS console -> Databases -> Select instance '{instance_id}'. Click 'Modify'.",
        "  - Under 'Availability & durability', select 'Create standby instance' (or ensure 'Multi-AZ deployment' is set to Yes).",
        "  - Choose when to apply changes (be aware of potential downtime).",
        "  - Review and apply changes."
    ]

    tf_instance_id_sanitized = sanitize_for_terraform_resource_name(instance_id)
    terraform_snippet = f"""
resource "aws_db_instance" "{tf_instance_id_sanitized}" {{
  identifier = "{instance_id}"
  # ... other arguments ...

  multi_az = true
}}
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions=f"Set `multi_az = true` in your Terraform configuration for RDS instance '{instance_id}'. Be aware of potential downtime when applying to an existing instance."
    )

    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or ["AWS Well-Architected Framework - Reliability Pillar"],
        reference_links=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html"]
    )

def get_rds_minor_version_upgrade_guidance(finding: models.Finding) -> RemediationOutputV2:
    instance_id = finding.details.get("RdsInstanceId", finding.resource_id.split('/')[-1])
    auto_minor_version_upgrade = finding.details.get("AutoMinorVersionUpgrade", False)

    issue_summary = f"Automatic minor version upgrades are disabled for RDS instance '{instance_id}'."
    technical_details = (
        f"RDS instance '{instance_id}' has automatic minor version upgrades set to '{auto_minor_version_upgrade}'. "
        "Enabling this feature helps ensure your database receives the latest bug fixes and security patches from AWS during scheduled maintenance windows. "
        "Major version upgrades remain a manual process."
    )
    manual_steps = [
        f"Navigate to the RDS console -> Databases -> Select instance '{instance_id}'.",
        "Click 'Modify'.",
        "Scroll to the 'Maintenance' section.",
        "Check the box for 'Enable auto minor version upgrade'.",
        "Choose when to apply changes and click 'Continue'.",
        "Review and apply changes."
    ]
    
    tf_instance_id_sanitized = sanitize_for_terraform_resource_name(instance_id)
    terraform_snippet = f"""
resource "aws_db_instance" "{tf_instance_id_sanitized}" {{
  identifier = "{instance_id}"
  # ... other arguments ...

  auto_minor_version_upgrade = true
}}
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions=f"Set `auto_minor_version_upgrade = true` in your Terraform configuration for RDS instance '{instance_id}'."
    )

    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or [],
        reference_links=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_UpgradeDBInstance.AutoMinorVersionUpgrade.html"]
    )

def get_rds_performance_insights_guidance(finding: models.Finding) -> RemediationOutputV2:
    instance_id = finding.details.get("RdsInstanceId", finding.resource_id.split('/')[-1])
    pi_enabled = finding.details.get("PerformanceInsightsEnabled", False)
    pi_retention = finding.details.get("PerformanceInsightsRetentionPeriod", 0)

    issue_summary = f"Performance Insights is disabled or has minimal retention for RDS instance '{instance_id}'."
    technical_details = (
        f"RDS instance '{instance_id}' has Performance Insights enabled: '{pi_enabled}' with retention: {pi_retention} days. "
        "Performance Insights helps diagnose performance bottlenecks by visualizing database load. A typical retention is 7 days (free tier) or longer for extended analysis."
    )
    manual_steps = [
        f"Navigate to the RDS console -> Databases -> Select instance '{instance_id}'.",
        "Click 'Modify'.",
        "Scroll to the 'Performance Insights' section.",
        "Check 'Enable Performance Insights'.",
        "Set 'Retention period' to a desired value (e.g., 7 days for free tier, or longer for extended analysis - check pricing).",
        "Optionally, select a KMS key for Performance Insights data encryption.",
        "Choose when to apply changes and save."
    ]

    tf_instance_id_sanitized = sanitize_for_terraform_resource_name(instance_id)
    terraform_snippet = f"""
resource "aws_db_instance" "{tf_instance_id_sanitized}" {{
  identifier = "{instance_id}"
  # ... other arguments ...

  performance_insights_enabled          = true
  performance_insights_retention_period = 7 # Or your desired retention (check pricing for >7 days)
  # performance_insights_kms_key_id     = "YOUR_KMS_KEY_ARN" # Optional
}}
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions=f"Update the Terraform configuration for RDS instance '{instance_id}' to enable Performance Insights and set an appropriate retention period."
    )

    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or [],
        reference_links=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PerfInsights.html"]
    )

def get_rds_enhanced_monitoring_guidance(finding: models.Finding) -> RemediationOutputV2:
    instance_id = finding.details.get("RdsInstanceId", finding.resource_id.split('/')[-1])
    monitoring_interval = finding.details.get("MonitoringInterval", 0) # Assuming 0 means disabled
    monitoring_role_arn = finding.details.get("MonitoringRoleArn", "Not Configured")

    issue_summary = f"Enhanced Monitoring is disabled or not optimally configured for RDS instance '{instance_id}'."
    technical_details = (
        f"RDS instance '{instance_id}' has Enhanced Monitoring interval: {monitoring_interval}s (Role: {monitoring_role_arn}). "
        "Enhanced Monitoring provides OS-level metrics. An interval (e.g., 60s) and an IAM role are required."
    )
    manual_steps = [
        f"Navigate to the RDS console -> Databases -> Select instance '{instance_id}'.",
        "Click 'Modify'.",
        "Scroll to the 'Monitoring' section.",
        "Enable 'Enhanced Monitoring'.",
        "Select a 'Monitoring Role'. If one doesn't exist, you may need to create one with the `AmazonRDSEnhancedMonitoringRole` policy (or equivalent permissions). The console might offer to create one for you.",
        "Set 'Granularity' to a desired interval (e.g., 1, 5, 10, 15, 30, or 60 seconds). Consider cost implications for higher granularity.",
        "Save changes."
    ]
    
    tf_instance_id_sanitized = sanitize_for_terraform_resource_name(instance_id)
    # Note: Creating the IAM role for enhanced monitoring is a prerequisite.
    terraform_snippet = f"""
# Prerequisite: An IAM role with the AmazonRDSEnhancedMonitoringRole policy (or equivalent).
# resource "aws_iam_role" "rds_enhanced_monitoring_role_{tf_instance_id_sanitized}" {{
#   name = "rds-enhanced-monitoring-role-{tf_instance_id_sanitized}"
#   assume_role_policy = jsonencode({{
#     Version = "2012-10-17",
#     Statement = [
#       {{
#         Effect    = "Allow",
#         Principal = {{ "Service" = "monitoring.rds.amazonaws.com" }},
#         Action    = "sts:AssumeRole"
#       }}
#     ]
#   }})
# }}
# resource "aws_iam_role_policy_attachment" "rds_enhanced_monitoring_attach_{tf_instance_id_sanitized}" {{
#   role       = aws_iam_role.rds_enhanced_monitoring_role_{tf_instance_id_sanitized}.name
#   policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
# }}

resource "aws_db_instance" "{tf_instance_id_sanitized}" {{
  identifier = "{instance_id}"
  # ... other arguments ...

  monitoring_interval    = 60 # Example: 60 seconds. Valid values: 0 (disabled), 1, 5, 10, 15, 30, 60.
  monitoring_role_arn    = "YOUR_RDS_ENHANCED_MONITORING_ROLE_ARN" # Replace with your role ARN
  # depends_on = [aws_iam_role_policy_attachment.rds_enhanced_monitoring_attach_{tf_instance_id_sanitized}] # If creating role in same config
}}
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions=f"Ensure an IAM role with permissions for Enhanced Monitoring exists. Update the Terraform configuration for RDS instance '{instance_id}' to set `monitoring_interval` (e.g., 60) and `monitoring_role_arn`."
    )

    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or [],
        reference_links=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Monitoring.OS.html"]
    )

def get_rds_log_exports_guidance(finding: models.Finding) -> RemediationOutputV2:
    instance_id = finding.details.get("RdsInstanceId", finding.resource_id.split('/')[-1])
    # Analyzer should provide which logs are *not* enabled, or current exports if available
    # For now, assume the finding implies some common logs are not exported.
    missing_log_types_example = finding.details.get("missing_log_types", ["audit", "error", "general", "slowquery"]) # Example, make this detail-driven
    current_exports = finding.details.get("current_log_exports", [])

    issue_summary = f"Recommended database log exports are not fully enabled for RDS instance '{instance_id}'."
    technical_details = (
        f"Exporting database logs (e.g., audit, error, general, slowquery) to CloudWatch Logs allows for centralized monitoring, analysis, and alerting. "
        f"Currently configured exports for '{instance_id}': {current_exports}. Consider enabling: {missing_log_types_example}. Log export availability depends on the RDS engine and version."
    )
    manual_steps = [
        f"Navigate to the RDS console -> Databases -> Select instance '{instance_id}'.",
        "Click 'Modify'.",
        "Scroll to the 'Log exports' section.",
        f"Select the log types you wish to export to CloudWatch Logs (e.g., {', '.join(missing_log_types_example)}).",
        "Note: Specific log types available depend on the database engine.",
        "Choose when to apply changes and save.",
        "Ensure appropriate IAM permissions exist for RDS to publish logs to CloudWatch Logs if this is the first time enabling log exports."
    ]

    tf_instance_id_sanitized = sanitize_for_terraform_resource_name(instance_id)
    # Enabling specific logs in TF means listing all logs to be enabled.
    # Users need to merge this with their existing list if they have other logs already enabled.
    terraform_snippet = f"""
resource "aws_db_instance" "{tf_instance_id_sanitized}" {{
  identifier = "{instance_id}"
  # ... other arguments ...

  # Add to this list based on your requirements and engine support.
  # This example enables common ones; it will overwrite existing settings if not merged.
  enabled_cloudwatch_logs_exports = ["audit", "error", "general", "slowquery"]
}}
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions=(
            f"Update the `enabled_cloudwatch_logs_exports` list in your Terraform configuration for RDS instance '{instance_id}'. "
            "Ensure you include all desired log types, as this attribute overwrites existing settings. "
            "Available log types depend on the database engine."
        )
    )

    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or [],
        reference_links=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_LogAccess.html"]
    )


# Placeholder for new function - needs to be created
def get_rds_iam_db_auth_guidance(finding: models.Finding) -> RemediationOutputV2:
    instance_id = finding.details.get("RdsInstanceId", finding.resource_id.split('/')[-1])
    iam_auth_enabled = finding.details.get("IAMDatabaseAuthenticationEnabled", False)
    issue_summary = f"IAM Database Authentication is not optimally configured for RDS instance '{instance_id}'."
    technical_details = f"IAM Database Authentication for instance '{instance_id}' is currently set to '{iam_auth_enabled}'. Enabling it enhances security by allowing authentication via IAM users and roles instead of traditional database passwords."
    manual_steps=[
        f"Navigate to the RDS console -> Databases -> Select instance '{instance_id}'.",
        "Click 'Modify'.",
        "Scroll to the 'Database authentication' section.",
        "Select 'Password and IAM database authentication'.",
        "Apply changes (this may require a brief restart depending on the engine and other pending modifications).",
        "Ensure relevant IAM users/roles have policies granting `rds-db:connect` permission to the specific DB instance resource."
    ]
    tf_instance_id_sanitized = sanitize_for_terraform_resource_name(instance_id)
    terraform_snippet = f"""
resource "aws_db_instance" "{tf_instance_id_sanitized}" {{
  identifier = "{instance_id}"
  # ... other arguments ...

  iam_database_authentication_enabled = true
}}
"""
    iac_remediation = IacRemediation(
        tool=IacTool.TERRAFORM,
        code_snippet=terraform_snippet.strip(),
        apply_instructions=f"Set `iam_database_authentication_enabled = true` in your Terraform configuration for RDS instance '{instance_id}'."
    )
    return RemediationOutputV2(
        finding_id=str(finding.id),
        issue_summary=issue_summary,
        technical_details=technical_details,
        manual_steps=manual_steps,
        iac_remediation=iac_remediation,
        compliance_standards=finding.compliance_standards or ["CIS AWS Benchmark 6.6"],
        reference_links=["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html"]
    ) 

# --- RDS Guidance Map ---
RDS_GUIDANCE_MAP: Dict[tuple[str, str], Callable[[models.Finding], RemediationOutputV2]] = {
    ("AWS::RDS::DBInstance", "storage encryption disabled"): get_rds_storage_encryption_guidance,
    ("AWS::RDS::DBInstance", "is publicly accessible"): get_rds_public_access_guidance,
    ("AWS::RDS::DBInstance", "automated backups disabled"): get_rds_automated_backups_guidance,
    ("AWS::RDS::DBInstance", "deletion protection disabled"): get_rds_deletion_protection_guidance,
    ("AWS::RDS::DBInstance", "not configured for multi-az"): get_rds_multi_az_guidance,
    ("AWS::RDS::DBInstance", "automatic minor version upgrades disabled"): get_rds_minor_version_upgrade_guidance,
    ("AWS::RDS::DBInstance", "performance insights disabled"): get_rds_performance_insights_guidance,
    ("AWS::RDS::DBInstance", "enhanced monitoring disabled"): get_rds_enhanced_monitoring_guidance,
    ("AWS::RDS::DBInstance", "log exports not enabled"): get_rds_log_exports_guidance, 
    # Add new one for IAM DB Auth if analyzer creates specific title
    ("AWS::RDS::DBInstance", "iam database authentication enabled"): get_rds_iam_db_auth_guidance, # Needs this function
}