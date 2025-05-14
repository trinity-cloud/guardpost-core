from typing import List, Dict, Any
from app.db.graph_db import Neo4jClient
from loguru import logger

def check_public_acls(db_client: Neo4jClient, account_id: str, region: str, scan_id: str) -> List[Dict[str, Any]]:
    """Finds S3 buckets potentially public via ACL grants."""
    logger.debug(f"[{scan_id}] graph_query: Checking S3 Public ACLs for account {account_id} in region {region}")
    query = """
    MATCH (b:S3Bucket {account_id: $account_id})
    // Optionally filter by region: AND b.Region = $region -> Note: S3 ACLs/Buckets might be better queried globally by account_id only?
    MATCH (b)-[:HAS_ACL_GRANT]->(g:S3ACLGrant)
    WHERE g.GranteeURI IS NOT NULL 
      AND g.GranteeURI IN [
        'http://acs.amazonaws.com/groups/global/AllUsers',
        'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
      ]
    RETURN 
      b.Name AS BucketName,
      b.arn AS BucketArn,
      b.Region AS BucketRegion,
      g.Permission AS PublicPermission,
      g.GranteeURI AS PublicGranteeURI
    LIMIT 500 // Limit results for safety
    """
    # Decide if region filtering is appropriate here or should be done by the caller
    params = {"account_id": account_id} # Removed region for global check
    # params = {"account_id": account_id, "region": region} # If filtering by region
    try:
        results = db_client.run(query, parameters=params)
        return results
    except Exception as e:
        logger.error(f"[{scan_id}] Error in S3 Public ACL graph query: {e}")
        return []

def check_public_policy(db_client: Neo4jClient, account_id: str, region: str, scan_id: str) -> List[Dict[str, Any]]:
    """Finds S3 buckets potentially public via Policy statements."""
    logger.debug(f"[{scan_id}] graph_query: Checking S3 Public Policies for account {account_id} in region {region}")
    query = """
    MATCH (b:S3Bucket {account_id: $account_id})
    MATCH (b)-[:HAS_POLICY_STATEMENT]->(stmt:S3BucketPolicyStatement)
    WHERE stmt.Effect = 'Allow' AND stmt.IsPrincipalWildcard = true 
    AND size([action IN stmt.Action WHERE 
        action STARTS WITH 's3:Get' OR action STARTS WITH 's3:List' OR 
        action STARTS WITH 's3:Put' OR action STARTS WITH 's3:Delete' OR
        action = 's3:*' OR action = '*'
    ]) > 0
    RETURN b.Name AS BucketName, b.arn AS BucketArn, b.Region AS BucketRegion,
           stmt.Sid AS StatementSID, stmt.OriginalPrincipalBlockJson AS StatementPrincipalJson,
           stmt.Action AS StatementActions, stmt.Resource AS StatementResources,
           stmt.ConditionJson AS StatementConditions
    LIMIT 500
    """
    params = {"account_id": account_id}
    try:
        results = db_client.run(query, parameters=params)
        return results
    except Exception as e:
        logger.error(f"[{scan_id}] Error in S3 Public Policy graph query: {e}")
        return []

def check_unencrypted(db_client: Neo4jClient, account_id: str, region: str, scan_id: str) -> List[Dict[str, Any]]:
    """Finds S3 buckets without default encryption."""
    logger.debug(f"[{scan_id}] graph_query: Checking S3 Unencrypted Buckets for account {account_id} in region {region}")
    query = """
    MATCH (b:S3Bucket {account_id: $account_id})
    WHERE b.ServerSideEncryptionConfiguration IS NULL 
       OR (NOT b.ServerSideEncryptionConfiguration CONTAINS 'AES256' AND 
           NOT b.ServerSideEncryptionConfiguration CONTAINS 'aws:kms')
    RETURN b.Name AS BucketName, b.arn AS BucketArn, b.Region AS BucketRegion,
           b.ServerSideEncryptionConfiguration AS EncryptionConfig
    LIMIT 500
    """
    params = {"account_id": account_id}
    try:
        results = db_client.run(query, parameters=params)
        return results
    except Exception as e:
        logger.error(f"[{scan_id}] Error in S3 Unencrypted Bucket graph query: {e}")
        return []

def check_logging_disabled(db_client: Neo4jClient, account_id: str, region: str, scan_id: str) -> List[Dict[str, Any]]:
    """Finds S3 buckets with server access logging disabled."""
    logger.debug(f"[{scan_id}] graph_query: Checking S3 Logging Disabled for account {account_id} in region {region}")
    query = """
    MATCH (b:S3Bucket {account_id: $account_id})
    WHERE b.LoggingConfiguration IS NULL OR b.LoggingConfiguration = "{}"
    RETURN b.Name AS BucketName, b.arn AS BucketArn, b.Region AS BucketRegion
    LIMIT 500
    """
    params = {"account_id": account_id}
    try:
        results = db_client.run(query, parameters=params)
        return results
    except Exception as e:
        logger.error(f"[{scan_id}] Error in S3 Logging Disabled graph query: {e}")
        return []

def check_versioning_disabled(db_client: Neo4jClient, account_id: str, region: str, scan_id: str) -> List[Dict[str, Any]]:
    """Finds S3 buckets with versioning not enabled."""
    logger.debug(f"[{scan_id}] graph_query: Checking S3 Versioning Disabled for account {account_id} in region {region}")
    query = """
    MATCH (b:S3Bucket {account_id: $account_id})
    WHERE b.VersioningStatus IS NULL OR b.VersioningStatus <> 'Enabled'
    RETURN b.Name AS BucketName, b.arn AS BucketArn, b.Region AS BucketRegion,
           b.VersioningStatus AS VersioningStatus
    LIMIT 500
    """
    params = {"account_id": account_id}
    try:
        results = db_client.run(query, parameters=params)
        return results
    except Exception as e:
        logger.error(f"[{scan_id}] Error in S3 Versioning Disabled graph query: {e}")
        return []

def check_mfa_delete_disabled(db_client: Neo4jClient, account_id: str, region: str, scan_id: str) -> List[Dict[str, Any]]:
    """Finds S3 buckets with versioning enabled but MFA Delete disabled."""
    logger.debug(f"[{scan_id}] graph_query: Checking S3 MFA Delete Disabled for account {account_id} in region {region}")
    query = """
    MATCH (b:S3Bucket {account_id: $account_id})
    WHERE b.VersioningStatus = 'Enabled' 
      AND (b.MFADeleteStatus IS NULL OR b.MFADeleteStatus <> 'Enabled')
    RETURN b.Name AS BucketName, b.arn AS BucketArn, b.Region AS BucketRegion,
           b.MFADeleteStatus AS MFADeleteStatus
    LIMIT 500
    """
    params = {"account_id": account_id}
    try:
        results = db_client.run(query, parameters=params)
        return results
    except Exception as e:
        logger.error(f"[{scan_id}] Error in S3 MFA Delete Disabled graph query: {e}")
        return []

# Add other S3 graph query functions here (check_public_policy, check_unencrypted, etc.) 