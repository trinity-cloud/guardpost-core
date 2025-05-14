from typing import List, Dict, Any, Optional
from app.db.graph_db import Neo4jClient
from loguru import logger

def check_lambdas_with_sensitive_env_vars(db_client: Neo4jClient, account_id: str, region: str, scan_id: str, limit: int = 500) -> List[Dict[str, Any]]:
    """Finds Lambda functions where HasPotentiallySensitiveEnv is true."""
    logger.debug(f"[{scan_id}] graph_query: Checking Lambdas with sensitive env vars for account {account_id} in region {region}")
    query = """
    MATCH (fn:LambdaFunction {account_id: $account_id, region: $region})
    WHERE fn.HasPotentiallySensitiveEnv = true
    RETURN
      fn.FunctionName AS FunctionName,
      fn.arn AS FunctionArn,
      fn.Region AS Region, // Note: region is already filtered in MATCH
      fn.Runtime AS Runtime,
      fn.PotentiallySensitiveEnvKeys AS SensitiveKeysFound,
      fn.EnvironmentVariablesJson AS AllEnvVars
    ORDER BY FunctionName
    LIMIT $limit
    """
    params = {"account_id": account_id, "region": region, "limit": limit}
    try:
        results = db_client.run(query, parameters=params)
        return results
    except Exception as e:
        logger.error(f"[{scan_id}] Error in Lambdas with Sensitive Env Vars graph query: {e}")
        return []

def check_lambdas_invokable_by_unauthorized(db_client: Neo4jClient, account_id: str, region: str, scan_id: str, check_services: Optional[List[str]] = None, limit: int = 500) -> List[Dict[str, Any]]:
    """Finds Lambda functions invokable by potentially unauthorized principals based on resource policy statements."""
    logger.debug(f"[{scan_id}] graph_query: Checking Lambdas invokable by unauthorized for account {account_id} in region {region}")
    
    base_principal_checks = [
        "stmt.IsPrincipalWildcard = true",
        "size([p IN stmt.Principal_AWS WHERE p <> '' AND p <> fn.account_id AND p <> ('arn:aws:iam::' + fn.account_id + ':root') AND p <> '*' ]) > 0"
    ]
    
    query_params = {"account_id": account_id, "region": region, "limit": limit}
    service_check_clause_parts = []

    if check_services:
        for idx, service in enumerate(check_services):
            param_name = f'check_service_{idx}'
            query_params[param_name] = service
            service_check_clause_parts.append(f"p = ${param_name}")
        if service_check_clause_parts:
            base_principal_checks.append(f"size([p IN stmt.Principal_Service WHERE {' OR '.join(service_check_clause_parts)}]) > 0")

    principal_where_clause = " OR \n        ".join(base_principal_checks)

    query = f"""
    MATCH (fn:LambdaFunction {{account_id: $account_id, region: $region}})
    MATCH (fn)-[:HAS_RESOURCE_POLICY_STATEMENT]->(stmt:LambdaResourcePolicyStatement)
    WHERE stmt.Effect = 'Allow'
      AND (
        {principal_where_clause}
      )
      AND (
        'lambda:InvokeFunction' IN stmt.Action OR '*' IN stmt.Action OR 'lambda:*' IN stmt.Action
      )
    RETURN DISTINCT
      fn.FunctionName AS FunctionName,
      fn.arn AS FunctionArn,
      stmt.Sid AS StatementSID,
      stmt.Principal_AWS AS StatementAWSAccess,
      stmt.Principal_Service AS StatementServiceAccess,
      stmt.IsPrincipalWildcard AS StatementHasWildcardPrincipal,
      stmt.Action AS StatementActions,
      stmt.ConditionJson AS StatementConditions
    ORDER BY FunctionName, StatementSID
    LIMIT $limit
    """
    
    try:
        results = db_client.run(query, parameters=query_params)
        return results
    except Exception as e:
        logger.error(f"[{scan_id}] Error in Lambdas Invokable by Unauthorized graph query: {e}")
        return []

# Add other Lambda graph query functions here (e.g., for Event Source Mappings if needed for findings) 