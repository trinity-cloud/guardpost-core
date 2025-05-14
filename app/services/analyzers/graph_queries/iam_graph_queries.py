from typing import List, Dict, Any
from app.db.graph_db import Neo4jClient
from loguru import logger

def check_roles_with_broad_trust(db_client: Neo4jClient, account_id: str, scan_id: str, limit: int = 500) -> List[Dict[str, Any]]:
    """Finds IAM Roles with overly permissive trust policies based on parsed properties."""
    logger.debug(f"[{scan_id}] graph_query: Checking IAM Roles with broad trust for account {account_id}")
    query = """
    MATCH (r:IamRole {account_id: $account_id}) // Filter by account
    WHERE r.IsAnonymousTrusted = true 
       OR (r.AWSTrustedPrincipalIdentifiers IS NOT NULL AND (
            '*' IN r.AWSTrustedPrincipalIdentifiers OR 
            ('arn:aws:iam::' + r.account_id + ':root' IN r.AWSTrustedPrincipalIdentifiers) OR 
            ANY(arn IN r.AWSTrustedPrincipalIdentifiers WHERE arn STARTS WITH 'arn:aws:iam::' AND arn ENDS WITH ':root')
           )
          )
       OR (r.UnknownTrustedPrincipalIdentifiers IS NOT NULL AND '*' IN r.UnknownTrustedPrincipalIdentifiers)
    RETURN
      r.RoleName AS RoleName,
      r.arn AS RoleArn,
      r.IsAnonymousTrusted AS IsConsideredAnonymousAccess,
      r.AWSTrustedPrincipalIdentifiers AS AwsAccountsTrusted,
      r.ServiceTrustedPrincipalIdentifiers AS ServicesTrusted,
      r.FederatedTrustedPrincipalIdentifiers AS FederatedPrincipalsTrusted,
      r.SAMLTrustedPrincipalIdentifiers AS SAMLPrincipalsTrusted,
      r.OIDCTrustedPrincipalIdentifiers AS OIDCPrincipalsTrusted,
      r.CanonicalUserTrustedPrincipalIdentifiers AS CanonicalUsersTrusted,
      r.UnknownTrustedPrincipalIdentifiers AS UnknownPrincipalsTrusted,
      r.AssumeRolePolicyDocument AS OriginalTrustPolicyDocument,
      r.TrustPolicyConditions AS Conditions 
    ORDER BY r.RoleName
    LIMIT $limit
    """
    params = {"account_id": account_id, "limit": limit}
    try:
        results = db_client.run(query, parameters=params)
        return results
    except Exception as e:
        logger.error(f"[{scan_id}] Error in IAM Roles with Broad Trust graph query: {e}")
        return []

def check_iam_policies_granting_full_admin(db_client: Neo4jClient, account_id: str, scan_id: str, limit: int = 500) -> List[Dict[str, Any]]:
    """Finds customer-managed IAM policies granting full admin (*:*) via statements."""
    logger.debug(f"[{scan_id}] graph_query: Checking IAM Policies for *:* admin grants for account {account_id}")
    query = """
    MATCH (p:IamPolicy {account_id: $account_id}) // Filter by account 
    WHERE p.IsAwsManaged = false 
    MATCH (p)-[:CONTAINS_STATEMENT]->(stmt:IamPolicyStatement)
    WHERE stmt.Effect = 'Allow'
      AND ('*' IN stmt.Action OR '*:*' IN stmt.Action) 
      AND '*' IN stmt.Resource 
    // Optional: Exclude if restrictive conditions exist
    // AND (stmt.ConditionJson IS NULL OR stmt.ConditionJson = "{}") 
    RETURN DISTINCT
      p.PolicyName AS PolicyName,
      p.arn AS PolicyArn,
      stmt.Sid AS StatementSID,
      stmt.Action AS StatementActions,
      stmt.Resource AS StatementResources,
      stmt.ConditionJson AS StatementConditions
    ORDER BY PolicyName, StatementSID
    LIMIT $limit
    """
    params = {"account_id": account_id, "limit": limit}
    try:
        results = db_client.run(query, parameters=params)
        return results
    except Exception as e:
        logger.error(f"[{scan_id}] Error in IAM Policy *:* graph query: {e}")
        return []

def check_users_with_inactive_keys(db_client: Neo4jClient, account_id: str, scan_id: str, limit: int = 500) -> List[Dict[str, Any]]:
    """Finds IAM users with inactive access keys."""
    logger.debug(f"[{scan_id}] graph_query: Checking IAM Users for inactive keys for account {account_id}")
    query = """
    MATCH (u:IamUser {account_id: $account_id}) // Filter by account
    WHERE u.AccessKeys IS NOT NULL AND u.AccessKeys <> "[]"
    WITH u, apoc.convert.fromJsonList(u.AccessKeys) AS keys
    UNWIND keys AS key
    WITH u, key 
    WHERE key.Status = 'Inactive' 
    RETURN DISTINCT
      u.UserName AS UserName,
      u.arn AS UserArn,
      key.AccessKeyId AS InactiveAccessKeyId,
      key.CreateDate AS KeyCreateDate
    ORDER BY UserName, KeyCreateDate
    LIMIT $limit
    """
    params = {"account_id": account_id, "limit": limit}
    try:
        results = db_client.run(query, parameters=params)
        return results
    except Exception as e:
        # Check for specific error indicating APOC is missing
        if "Unknown function 'apoc.convert.fromJsonList'" in str(e):
             logger.error(f"[{scan_id}] APOC function error checking inactive keys. APOC procedures may not be installed or enabled in Neo4j.")
        logger.error(f"[{scan_id}] Error in IAM User Inactive Keys graph query: {e}")
        return []

def check_users_with_old_active_keys(db_client: Neo4jClient, account_id: str, scan_id: str, key_age_days: int = 90, limit: int = 500) -> List[Dict[str, Any]]:
    """Finds IAM users with active access keys older than key_age_days."""
    logger.debug(f"[{scan_id}] graph_query: Checking IAM Users for active keys older than {key_age_days} days for account {account_id}")
    query = """
    WITH duration({days: $key_age_days}) AS key_threshold, datetime() as now
    MATCH (u:IamUser {account_id: $account_id}) 
    WHERE u.AccessKeys IS NOT NULL AND u.AccessKeys <> "[]"
    WITH u, now, key_threshold, apoc.convert.fromJsonList(u.AccessKeys) AS keys
    UNWIND keys AS key
    WITH u, now, key_threshold, key 
    WHERE key.Status = 'Active' 
      AND key.CreateDate IS NOT NULL 
      AND datetime(key.CreateDate) < (now - key_threshold)
    RETURN DISTINCT
      u.UserName AS UserName,
      u.arn AS UserArn,
      key.AccessKeyId AS OldAccessKeyId,
      key.CreateDate AS KeyCreateDate,
      key.Status AS KeyStatus
    ORDER BY UserName, KeyCreateDate
    LIMIT $limit
    """
    params = {"account_id": account_id, "key_age_days": key_age_days, "limit": limit}
    try:
        results = db_client.run(query, parameters=params)
        return results
    except Exception as e:
        if "Unknown function" in str(e): # Catch APOC or datetime errors
             logger.error(f"[{scan_id}] APOC/Date function error checking old keys. APOC procedures may not be installed/enabled or date conversion failed.")
        logger.error(f"[{scan_id}] Error in IAM User Old Active Keys graph query: {e}")
        return []

# Add other IAM graph query functions here (inactive keys, old keys, *:* policy check refinement, etc.) 