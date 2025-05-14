# Placeholder for s3 analyzer logic 

import uuid
import datetime
from typing import Dict, List, Optional, Any, Callable
import traceback
import json # For parsing policy documents

from loguru import logger
from sqlalchemy.orm import Session

# Assuming schemas and models are accessible via absolute import paths
from app.api.v1.schemas import FindingSeverity, FindingCategory, Finding # Pydantic schema
from app.db import models # DB Model
from app.db.graph_db import Neo4jClient # Import Neo4j Client
from .graph_queries import s3_graph_queries # Import the new graph query module

def analyze_s3(
    db: Session, 
    db_client: Neo4jClient, # Add Neo4j client parameter
    account_id: str, 
    scan_id: uuid.UUID, 
    region: str, # S3 buckets have regions, analysis might run per region or globally
    # s3_resources: List[Dict[str, Any]], # No longer needed if using graph
    create_finding_callback: Callable[..., models.Finding]
) -> int:
    """Analyze S3 resources using graph data and save findings to DB."""
    findings_created = 0
    scan_id_str = str(scan_id) # For logging within query functions
    logger.info(f"[{scan_id_str}] Starting S3 analysis for account {account_id} in region {region} using graph data.")

    # Check 1: Public Access Block Enabled (CIS 1.1.1)
    # TODO: Implement PAB check using graph query (e.g., MATCH (b:S3Bucket) RETURN b.Name, b.PublicAccessBlockConfiguration)
    # Then parse the PublicAccessBlockConfiguration JSON string here.
    # For now, this check is skipped as it requires parsing the JSON prop from the graph node.

    # Check 2: Public ACLs (Using Graph Query)
    try:
        public_acl_buckets = s3_graph_queries.check_public_acls(db_client, account_id, region, scan_id_str)
        for data in public_acl_buckets:
            bucket_name = data.get('BucketName')
            bucket_arn = data.get('BucketArn')
            bucket_region_from_node = data.get('BucketRegion', region) 
            permission = data.get('PublicPermission')
            grantee_uri_full = data.get('PublicGranteeURI', '')
            grantee = grantee_uri_full.split('/')[-1] if grantee_uri_full else 'Unknown'
            
            severity = FindingSeverity.HIGH if "WRITE" in str(permission).upper() or "FULL_CONTROL" in str(permission).upper() else FindingSeverity.MEDIUM
            
            details_for_finding = {
                "bucket_name": bucket_name,
                "permission": permission,
                "grantee_uri": grantee_uri_full,
                "grantee": grantee
            }
            create_finding_callback(
                db=db, 
                account_id=account_id, scan_id=scan_id, region=bucket_region_from_node,
                resource_id=bucket_arn, 
                resource_type="AWS::S3::Bucket",
                title=f"S3 bucket '{bucket_name}' allows public access via ACL ({permission} to {grantee})",
                description=f"The bucket ACL grants {permission} permission to {grantee}. Rely on bucket policies and enable Public Access Block instead. Grantee URI: {grantee_uri_full}",
                severity=severity, category=FindingCategory.PUBLIC_EXPOSURE,
                compliance_standards=["CIS AWS Benchmark 1.1.2"],
                remediation_steps=[
                    f"Ensure 'BlockPublicAcls' and 'IgnorePublicAcls' are enabled in the Public Access Block settings for bucket '{bucket_name}' (Strongly Recommended).",
                    f"Alternatively, review and remove specific public grants from the bucket ACL: S3 console -> Buckets -> '{bucket_name}' -> Permissions -> Access Control List (ACL) -> Edit.",
                    f"Remove grants for 'Everyone (public access)' or 'Authenticated users group (anyone with an AWS account)'."
                ],
                details=details_for_finding
            )
            findings_created += 1
        logger.debug(f"[{scan_id_str}] S3 Public ACL check completed. Found {len(public_acl_buckets)} potential findings.")
    except Exception as e:
        logger.error(f"[{scan_id_str}] Error during S3 Public ACL analysis: {e}")
        logger.error(traceback.format_exc())

    # Check 3: Public Policy (Using Graph Query)
    try:
        public_policy_buckets = s3_graph_queries.check_public_policy(db_client, account_id, region, scan_id_str)
        for data in public_policy_buckets:
            bucket_name = data.get('BucketName')
            bucket_arn = data.get('BucketArn')
            bucket_region_from_node = data.get('BucketRegion', region)
            stmt_sid = data.get('StatementSID')
            actions = data.get('StatementActions')
            principal_json = data.get('StatementPrincipalJson')
            conditions = data.get('StatementConditions', 'None')
            severity = FindingSeverity.HIGH
            if any(action_keyword in str(actions).upper() for action_keyword in ["PUT", "DELETE", ":*", "*"]): 
                severity = FindingSeverity.CRITICAL
            
            details_for_finding = {
                "bucket_name": bucket_name,
                "statement_sid": stmt_sid,
                "statement_actions": actions,
                "statement_principal_json": principal_json,
                "statement_conditions": conditions
            }
            create_finding_callback(
                db=db, account_id=account_id, scan_id=scan_id, region=bucket_region_from_node,
                resource_id=bucket_arn, resource_type="AWS::S3::Bucket",
                title=f"S3 bucket '{bucket_name}' has a public policy statement (SID: {stmt_sid})",
                description=f"The bucket policy contains statement SID '{stmt_sid}' which allows public access for actions: {actions}. Principal: {principal_json}. Conditions: {conditions}. Review for unintended exposure.",
                severity=severity, category=FindingCategory.PUBLIC_EXPOSURE,
                compliance_standards=["CIS AWS Benchmark 1.1.3"],
                remediation_steps=[
                    f"Ensure 'BlockPublicPolicy' and 'RestrictPublicBuckets' are enabled in the Public Access Block settings for bucket '{bucket_name}' (Strongly Recommended).",
                    f"Review the bucket policy: S3 console -> Buckets -> '{bucket_name}' -> Permissions -> Bucket policy -> Edit.",
                    f"Identify and remove or restrict statement SID '{stmt_sid}' that grants unintended public access.",
                    f"If conditions are present, verify they adequately restrict access as intended."
                ],
                details=details_for_finding
            )
            findings_created += 1
        logger.debug(f"[{scan_id_str}] S3 Public Policy check completed. Found {len(public_policy_buckets)} potential findings.")
    except Exception as e:
        logger.error(f"[{scan_id_str}] Error during S3 Public Policy analysis: {e}")
        logger.error(traceback.format_exc())

    # Check 4: Default Encryption Enabled (Using Graph Query)
    try:
        unencrypted_buckets = s3_graph_queries.check_unencrypted(db_client, account_id, region, scan_id_str)
        for data in unencrypted_buckets:
            bucket_name = data.get('BucketName')
            bucket_arn = data.get('BucketArn')
            bucket_region_from_node = data.get('BucketRegion', region)
            config = data.get('EncryptionConfig', 'Not Set')
            
            details_for_finding = {
                "bucket_name": bucket_name,
                "encryption_config": config
            }
            create_finding_callback(
                db=db, account_id=account_id, scan_id=scan_id, region=bucket_region_from_node,
                resource_id=bucket_arn, resource_type="AWS::S3::Bucket",
                title=f"S3 bucket '{bucket_name}' does not have default server-side encryption enabled",
                description=f"Default server-side encryption helps ensure objects are encrypted when stored. Current config: {config}",
                severity=FindingSeverity.MEDIUM, category=FindingCategory.ENCRYPTION,
                compliance_standards=["CIS AWS Benchmark 2.1.1"],
                remediation_steps=[
                    f"Navigate to the S3 console -> Buckets -> '{bucket_name}' -> Properties tab.",
                    f"Under 'Default encryption', click 'Edit'.",
                    f"Select an encryption type (SSE-S3/AES256 is recommended for ease of use, or SSE-KMS for managed keys).",
                    f"Save changes.",
                    f"Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html"
                ],
                details=details_for_finding
            )
            findings_created += 1
        logger.debug(f"[{scan_id_str}] S3 Unencrypted Bucket check completed. Found {len(unencrypted_buckets)} potential findings.")
    except Exception as e:
        logger.error(f"[{scan_id_str}] Error during S3 Unencrypted Bucket analysis: {e}")
        logger.error(traceback.format_exc())

    # Check 5: S3 Bucket Logging Enabled (Using Graph Query)
    try:
        logging_disabled_buckets = s3_graph_queries.check_logging_disabled(db_client, account_id, region, scan_id_str)
        for data in logging_disabled_buckets:
            bucket_name = data.get('BucketName')
            bucket_arn = data.get('BucketArn')
            bucket_region_from_node = data.get('BucketRegion', region)
            details_for_finding = {"bucket_name": bucket_name} # Logging status implied by finding itself
            create_finding_callback(
                db=db, account_id=account_id, scan_id=scan_id, region=bucket_region_from_node,
                resource_id=bucket_arn, resource_type="AWS::S3::Bucket",
                title=f"S3 bucket '{bucket_name}' server access logging is disabled",
                description="Server access logging provides detailed records for the requests that are made to a bucket and is recommended for security and audit purposes.",
                severity=FindingSeverity.LOW, category=FindingCategory.OTHER,
                compliance_standards=["CIS AWS Benchmark 2.6.1"],
                remediation_steps=[
                    f"Choose or create a target S3 bucket (in the same region, cannot be the source bucket) to store the logs. Ensure the S3 Log Delivery group has write permissions to the target bucket.",
                    f"Navigate to the source bucket: S3 console -> Buckets -> '{bucket_name}' -> Properties tab.",
                    f"Under 'Server access logging', click 'Edit'.",
                    f"Enable logging, specify the target bucket, and optionally a prefix.",
                    f"Save changes.",
                    f"Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/enable-server-access-logging.html"
                ],
                details=details_for_finding
            )
            findings_created += 1
        logger.debug(f"[{scan_id_str}] S3 Logging Disabled check completed. Found {len(logging_disabled_buckets)} potential findings.")
    except Exception as e:
        logger.error(f"[{scan_id_str}] Error during S3 Logging Disabled analysis: {e}")
        logger.error(traceback.format_exc())

    # Check 6: S3 Bucket Versioning Enabled
    try:
        versioning_disabled_buckets = s3_graph_queries.check_versioning_disabled(db_client, account_id, region, scan_id_str)
        for data in versioning_disabled_buckets:
            bucket_name = data.get('BucketName')
            bucket_arn = data.get('BucketArn')
            bucket_region_from_node = data.get('BucketRegion', region)
            versioning_status = data.get('VersioningStatus', 'Unknown')
            details_for_finding = {
                "bucket_name": bucket_name,
                "versioning_status": versioning_status
            }
            create_finding_callback(
                db=db, account_id=account_id, scan_id=scan_id, region=bucket_region_from_node,
                resource_id=bucket_arn, resource_type="AWS::S3::Bucket",
                title=f"S3 bucket '{bucket_name}' versioning is not enabled (Status: {versioning_status})",
                description="Versioning helps preserve, retrieve, and restore every version of every object stored in your Amazon S3 bucket.",
                severity=FindingSeverity.LOW, category=FindingCategory.OTHER,
                compliance_standards=["CIS AWS Benchmark 2.2.1"],
                remediation_steps=[
                    f"Navigate to the S3 console -> Buckets -> '{bucket_name}' -> Properties tab.",
                    f"Under 'Bucket Versioning', click 'Edit'.",
                    f"Select 'Enable' and save changes.",
                    f"Note: Enabling versioning cannot be undone, only suspended.",
                    f"Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html"
                ],
                details=details_for_finding
            )
            findings_created += 1
        logger.debug(f"[{scan_id_str}] S3 Versioning Disabled check completed. Found {len(versioning_disabled_buckets)} potential findings.")
    except Exception as e:
        logger.error(f"[{scan_id_str}] Error during S3 Versioning Disabled analysis: {e}")
        logger.error(traceback.format_exc())

    # Check 7: MFA Delete Enabled
    try:
        mfa_delete_disabled_buckets = s3_graph_queries.check_mfa_delete_disabled(db_client, account_id, region, scan_id_str)
        for data in mfa_delete_disabled_buckets:
            bucket_name = data.get('BucketName')
            bucket_arn = data.get('BucketArn')
            bucket_region_from_node = data.get('BucketRegion', region)
            mfa_delete_status = data.get('MFADeleteStatus', 'Unknown/Disabled')
            versioning_status = data.get('VersioningStatus', 'Enabled') # From query logic
            details_for_finding = {
                "bucket_name": bucket_name,
                "mfa_delete_status": mfa_delete_status,
                "versioning_status": versioning_status 
            }
            create_finding_callback(
                db=db, account_id=account_id, scan_id=scan_id, region=bucket_region_from_node,
                resource_id=bucket_arn, resource_type="AWS::S3::Bucket",
                title=f"S3 bucket '{bucket_name}' does not have MFA Delete enabled (Status: {mfa_delete_status})",
                description="MFA Delete adds another layer of security to prevent accidental or malicious object deletion when versioning is enabled.",
                severity=FindingSeverity.LOW, category=FindingCategory.OTHER,
                compliance_standards=["CIS AWS Foundations Benchmark 2.2.1"],
                remediation_steps=[
                    f"Enabling MFA Delete requires using the AWS CLI or SDKs and must be done by the root account user.",
                    f"Prerequisites: Versioning must be enabled on bucket '{bucket_name}'. Root account must have an MFA device configured.",
                    f"Command Example (Root User): `aws s3api put-bucket-versioning --bucket {bucket_name} --versioning-configuration Status=Enabled,MFADelete=Enabled --mfa \"arn:aws:iam::ROOT_ACCOUNT_ID:mfa/ROOT_MFA_DEVICE_NAME CODE\"`",
                    f"Replace placeholders with your root account ID, MFA device name/serial, and the current MFA code.",
                    f"Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/MultiFactorAuthenticationDelete.html"
                ],
                details=details_for_finding
            )
            findings_created += 1
        logger.debug(f"[{scan_id_str}] S3 MFA Delete Disabled check completed. Found {len(mfa_delete_disabled_buckets)} potential findings.")
    except Exception as e:
        logger.error(f"[{scan_id_str}] Error during S3 MFA Delete Disabled analysis: {e}")
        logger.error(traceback.format_exc())

    # --- OLD Logic based on s3_resources list (Remove/Comment Out) ---
    # findings_created = 0
    # for resource in s3_resources:
    #     if resource.get("Type") != "Bucket": continue
    #     ...
    # --- End OLD Logic ---

    logger.info(f"[{scan_id_str}] Completed S3 analysis for account {account_id} in region {region}. Findings created: {findings_created}")
    return findings_created 