# Placeholder for rds analyzer logic 

import uuid
import datetime
from typing import Dict, List, Optional, Any, Callable
import traceback
import json # Although not used currently, keep for potential future policy checks

from loguru import logger
from sqlalchemy.orm import Session

# Assuming schemas and models are accessible via absolute import paths
from app.api.v1.schemas import FindingSeverity, FindingCategory, Finding # Pydantic schema
from app.db import models # DB Model
from app.db.graph_db import Neo4jClient # Import Neo4j Client
from .graph_queries import rds_graph_queries # Import the new graph query module

def analyze_rds(
    db: Session, 
    db_client: Neo4jClient,
    account_id: str, 
    scan_id: uuid.UUID, 
    region: str, 
    rds_resources: List[Dict[str, Any]], # Kept for potential fallback, but graph queries are primary
    create_finding_callback: Callable[..., models.Finding] # Callback function
) -> int:
    """Analyze collected RDS resources using graph data and save findings to DB."""
    findings_created = 0
    scan_id_str = str(scan_id)
    logger.info(f"[{scan_id_str}] Starting RDS analysis for account {account_id} in region {region} using graph data.")

    # Check 1: Publicly Accessible RDS Instance
    try:
        public_instances = rds_graph_queries.check_public_rds_instances(db_client, account_id, region, scan_id_str)
        for data in public_instances:
            instance_id = data.get('RdsInstanceId')
            instance_arn = data.get('RdsInstanceArn')
            details_for_finding = {
                "RdsInstanceId": instance_id,
                "RdsInstanceArn": instance_arn,
                "RdsEngine": data.get('RdsEngine'),
                "RdsEndpoint": data.get('RdsEndpoint', 'N/A'),
                "RdsStatus": data.get('RdsStatus'),
                "VpcId": data.get('VpcId')
            }
            create_finding_callback(
                db=db, account_id=account_id, scan_id=scan_id, region=region,
                resource_id=instance_arn, resource_type="AWS::RDS::DBInstance",
                title=f"RDS instance '{instance_id}' is publicly accessible",
                description=f"RDS instance '{instance_id}' (Engine: {data.get('RdsEngine')}, Endpoint: {data.get('RdsEndpoint', 'N/A')}) is publicly accessible.",
                severity=FindingSeverity.HIGH, category=FindingCategory.PUBLIC_EXPOSURE,
                details=details_for_finding
            )
            findings_created += 1
        logger.debug(f"[{scan_id_str}] RDS Publicly Accessible check completed. Found {len(public_instances)} potential findings.")
    except Exception as e:
        logger.error(f"[{scan_id_str}] Error during RDS Publicly Accessible analysis: {e}")
        logger.error(traceback.format_exc())

    # Check 2: Unencrypted RDS Instance
    try:
        unencrypted_instances = rds_graph_queries.check_unencrypted_rds_instances(db_client, account_id, region, scan_id_str)
        for data in unencrypted_instances:
            instance_id = data.get('RdsInstanceId')
            instance_arn = data.get('RdsInstanceArn')
            details_for_finding = {
                "RdsInstanceId": instance_id,
                "RdsInstanceArn": instance_arn,
                "RdsEngine": data.get('RdsEngine'),
                "StorageEncrypted": data.get('StorageEncrypted', False) # from graph_queries it is `db.StorageEncrypted`
            }
            create_finding_callback(
                db=db, account_id=account_id, scan_id=scan_id, region=region,
                resource_id=instance_arn, resource_type="AWS::RDS::DBInstance",
                title=f"RDS instance '{instance_id}' storage is not encrypted",
                description=f"Storage for RDS instance '{instance_id}' (Engine: {data.get('RdsEngine')}) is not encrypted.",
                severity=FindingSeverity.MEDIUM, category=FindingCategory.ENCRYPTION,
                details=details_for_finding
            )
            findings_created += 1
        logger.debug(f"[{scan_id_str}] RDS Unencrypted check completed. Found {len(unencrypted_instances)} potential findings.")
    except Exception as e:
        logger.error(f"[{scan_id_str}] Error during RDS Unencrypted analysis: {e}")
        logger.error(traceback.format_exc())

    # Check 3: Automated Backups Disabled
    try:
        backup_disabled_instances = rds_graph_queries.check_automated_backups_disabled(db_client, account_id, region, scan_id_str)
        for data in backup_disabled_instances:
            instance_id = data.get('RdsInstanceId')
            instance_arn = data.get('RdsInstanceArn')
            details_for_finding = {
                "RdsInstanceId": instance_id,
                "RdsInstanceArn": instance_arn,
                "RdsEngine": data.get('RdsEngine'),
                "BackupRetentionPeriod": data.get('BackupRetentionPeriod', 0) # from graph query
            }
            create_finding_callback(
                db=db, account_id=account_id, scan_id=scan_id, region=region,
                resource_id=instance_arn, resource_type="AWS::RDS::DBInstance",
                title=f"RDS instance '{instance_id}' has automated backups disabled",
                description="Automated backups (BackupRetentionPeriod > 0) are crucial for point-in-time recovery.",
                severity=FindingSeverity.MEDIUM, category=FindingCategory.OTHER,
                details=details_for_finding
            )
            findings_created += 1
        logger.debug(f"[{scan_id_str}] RDS Automated Backups Disabled check completed. Found {len(backup_disabled_instances)} potential findings.")
    except Exception as e:
        logger.error(f"[{scan_id_str}] Error during RDS Automated Backups Disabled analysis: {e}")
        logger.error(traceback.format_exc())

    # Check 4: Multi-AZ Disabled
    try:
        multi_az_disabled_instances = rds_graph_queries.check_multi_az_disabled(db_client, account_id, region, scan_id_str)
        for data in multi_az_disabled_instances:
            instance_id = data.get('RdsInstanceId')
            instance_arn = data.get('RdsInstanceArn')
            details_for_finding = {
                "RdsInstanceId": instance_id,
                "RdsInstanceArn": instance_arn,
                "RdsEngine": data.get('RdsEngine'),
                "MultiAZ": data.get('MultiAZ', False) # from graph query
            }
            create_finding_callback(
                db=db, account_id=account_id, scan_id=scan_id, region=region,
                resource_id=instance_arn, resource_type="AWS::RDS::DBInstance",
                title=f"RDS instance '{instance_id}' is not configured for Multi-AZ deployment",
                description="Multi-AZ deployment enhances database availability.",
                severity=FindingSeverity.LOW, category=FindingCategory.OTHER,
                details=details_for_finding
            )
            findings_created += 1
        logger.debug(f"[{scan_id_str}] RDS Multi-AZ Disabled check completed. Found {len(multi_az_disabled_instances)} potential findings.")
    except Exception as e:
        logger.error(f"[{scan_id_str}] Error during RDS Multi-AZ Disabled analysis: {e}")
        logger.error(traceback.format_exc())

    # Check 5: Deletion Protection Disabled
    try:
        del_protection_disabled = rds_graph_queries.check_deletion_protection_disabled(db_client, account_id, region, scan_id_str)
        for data in del_protection_disabled:
            instance_id = data.get('RdsInstanceId')
            instance_arn = data.get('RdsInstanceArn')
            details_for_finding = {
                "RdsInstanceId": instance_id,
                "RdsInstanceArn": instance_arn,
                "RdsEngine": data.get('RdsEngine'),
                "DeletionProtection": data.get('DeletionProtection', False) # from graph query
            }
            create_finding_callback(
                db=db, account_id=account_id, scan_id=scan_id, region=region,
                resource_id=instance_arn, resource_type="AWS::RDS::DBInstance",
                title=f"RDS instance '{instance_id}' does not have deletion protection enabled",
                description="Deletion protection prevents accidental database deletion.",
                severity=FindingSeverity.LOW, category=FindingCategory.OTHER,
                details=details_for_finding
            )
            findings_created += 1
        logger.debug(f"[{scan_id_str}] RDS Deletion Protection Disabled check completed. Found {len(del_protection_disabled)} potential findings.")
    except Exception as e:
        logger.error(f"[{scan_id_str}] Error during RDS Deletion Protection Disabled analysis: {e}")
        logger.error(traceback.format_exc())

    # Check 6: IAM DB Authentication Disabled
    try:
        iam_auth_disabled = rds_graph_queries.check_iam_db_auth_disabled(db_client, account_id, region, scan_id_str)
        for data in iam_auth_disabled:
            instance_id = data.get('RdsInstanceId')
            instance_arn = data.get('RdsInstanceArn')
            details_for_finding = {
                "RdsInstanceId": instance_id,
                "RdsInstanceArn": instance_arn,
                "RdsEngine": data.get('RdsEngine'),
                "IAMDatabaseAuthenticationEnabled": data.get('IAMDatabaseAuthenticationEnabled', False) # from graph query
            }
            create_finding_callback(
                db=db, account_id=account_id, scan_id=scan_id, region=region,
                resource_id=instance_arn, resource_type="AWS::RDS::DBInstance",
                title=f"RDS instance '{instance_id}' does not have IAM database authentication enabled",
                description="IAM database authentication enhances security over traditional password authentication.",
                severity=FindingSeverity.MEDIUM, category=FindingCategory.IAM,
                details=details_for_finding
            )
            findings_created += 1
        logger.debug(f"[{scan_id_str}] RDS IAM DB Auth Disabled check completed. Found {len(iam_auth_disabled)} potential findings.")
    except Exception as e:
        logger.error(f"[{scan_id_str}] Error during RDS IAM DB Auth Disabled analysis: {e}")
        logger.error(traceback.format_exc())

    logger.info(f"[{scan_id_str}] Completed RDS analysis for account {account_id} in region {region}. Findings created: {findings_created}")
    return findings_created 