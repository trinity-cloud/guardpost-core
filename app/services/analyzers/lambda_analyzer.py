# Placeholder for lambda analyzer logic 

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
from app.providers.aws_provider import AwsProvider # Import AwsProvider
from app.db.graph_db import Neo4jClient # Import Neo4j Client
from .graph_queries import lambda_graph_queries # Import the new graph query module
# --- Helper function for Policy Analysis ---
def _check_policy_document_for_risks(policy_document: Dict[str, Any]) -> List[str]:
    """Checks a policy document dictionary for overly permissive Allow statements."""
    risky_sids = []
    if not policy_document or not isinstance(policy_document, dict):
        return risky_sids

    statements = policy_document.get('Statement', [])
    if not isinstance(statements, list):
        statements = [statements] # Handle single statement case

    for i, statement in enumerate(statements):
        if not isinstance(statement, dict): continue

        effect = statement.get('Effect')
        action = statement.get('Action')
        resource = statement.get('Resource')
        sid = statement.get('Sid', f'Statement-{i+1}')

        if effect == 'Allow':
            is_risky = False
            # Check for Action: "*" or Action: "*:*"
            if action == '*' or action == '*:*':
                is_risky = True
            elif isinstance(action, list) and ('*' in action or '*:*' in action):
                is_risky = True
            
            # Check for Resource: "*"
            if resource == '*':
                is_risky = True
            elif isinstance(resource, list) and '*' in resource:
                 is_risky = True
            
            # TODO: Add check for iam:PassRole with Resource: "*"

            if is_risky:
                risky_sids.append(sid)
               
    return risky_sids

# --- Main Analyzer Function ---
def analyze_lambda(
    db: Session, 
    db_client: Neo4jClient,
    account_id: str, 
    scan_id: uuid.UUID, 
    region: str, 
    lambda_resources: List[Dict[str, Any]], # Currently unused as checks are graph-based
    aws_provider: AwsProvider, 
    create_finding_callback: Callable[..., models.Finding]
) -> int:
    """Analyze collected Lambda functions using graph data and save findings to DB."""
    findings_created = 0
    scan_id_str = str(scan_id)
    logger.info(f"[{scan_id_str}] Starting Lambda analysis for account {account_id} in region {region} using graph data.")

    # Check 1: Lambda with Potentially Sensitive Environment Variables
    try:
        sensitive_env_lambdas = lambda_graph_queries.check_lambdas_with_sensitive_env_vars(
            db_client, account_id, region, scan_id_str
        )
        for data in sensitive_env_lambdas:
            func_name = data.get('FunctionName')
            func_arn = data.get('FunctionArn')
            sensitive_keys = data.get('SensitiveKeysFound', [])
            all_env_vars = data.get('AllEnvVars') # Could be large, handle with care in details
            runtime = data.get('Runtime')

            details_for_finding = {
                "function_name": func_name,
                "function_arn": func_arn, # For completeness in details
                "sensitive_keys_found": sensitive_keys,
                "all_env_vars_json": all_env_vars, # Pass as JSON string or dict
                "runtime": runtime
            }
            create_finding_callback(
                db=db, account_id=account_id, scan_id=scan_id, region=region,
                resource_id=func_arn, resource_type="AWS::Lambda::Function",
                title=f"Lambda function '{func_name}' has potentially sensitive environment variables",
                description=f"The following environment variable keys suggest sensitive data: {sensitive_keys}. Storing secrets in environment variables is discouraged.",
                severity=FindingSeverity.MEDIUM, category=FindingCategory.IAM, # Consider a more specific category if available
                details=details_for_finding
            )
            findings_created += 1
    except Exception as e:
        logger.error(f"[{scan_id_str}] Error during Lambda Sensitive Env Var analysis: {e}")
        logger.error(traceback.format_exc())

    # Check 2: Lambda Invokable by Unauthorized Principal
    try:
        unauth_invokable_lambdas = lambda_graph_queries.check_lambdas_invokable_by_unauthorized(
            db_client, account_id, region, scan_id_str
        )
        for data in unauth_invokable_lambdas:
            func_name = data.get('FunctionName')
            func_arn = data.get('FunctionArn')
            stmt_sid = data.get('StatementSID', 'N/A') # Ensure SID default if missing
            actions = data.get('StatementActions')
            aws_principals = data.get('StatementAWSAccess')
            service_principals = data.get('StatementServiceAccess')
            has_wildcard = data.get('StatementHasWildcardPrincipal')
            conditions = data.get('StatementConditions')

            desc_detail = f"Statement SID '{stmt_sid}' allows actions: {actions}."
            if has_wildcard:
                desc_detail += " Principal is wildcard ('*')."
            elif aws_principals and any(p for p in aws_principals if p != account_id and not p.endswith(f':{account_id}:root')):
                 desc_detail += f" Principal includes external AWS accounts/principals: {aws_principals}."
            elif service_principals: # Add detail for service principals if present
                 desc_detail += f" Principal includes service principals: {service_principals}."
            
            details_for_finding = {
                "function_name": func_name,
                "function_arn": func_arn,
                "statement_sid": stmt_sid,
                "statement_actions": actions,
                "statement_aws_access": aws_principals,
                "statement_service_access": service_principals,
                "statement_has_wildcard_principal": has_wildcard,
                "statement_conditions": conditions
            }
            create_finding_callback(
                db=db, account_id=account_id, scan_id=scan_id, region=region,
                resource_id=func_arn, resource_type="AWS::Lambda::Function",
                title=f"Lambda function '{func_name}' may be invokable by unauthorized principals (SID: {stmt_sid})",
                description=f"The resource policy for Lambda function '{func_name}' contains a statement that could allow unintended invocation. {desc_detail} Conditions: {conditions or 'None'}.",
                severity=FindingSeverity.HIGH, category=FindingCategory.PUBLIC_EXPOSURE,
                details=details_for_finding
            )
            findings_created += 1
    except Exception as e:
        logger.error(f"[{scan_id_str}] Error during Lambda Unauthorized Invocation analysis: {e}")
        logger.error(traceback.format_exc())

    # TODO: Add check for Lambda Event Source Mappings (e.g., disabled, problematic states) if needed for findings.

    logger.info(f"[{scan_id_str}] Completed Lambda analysis for account {account_id} in region {region}. Findings created: {findings_created}")
    return findings_created 