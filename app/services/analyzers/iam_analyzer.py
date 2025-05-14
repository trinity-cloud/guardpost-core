# Placeholder for iam analyzer logic 

import uuid
import datetime
from typing import Dict, List, Optional, Any, Callable, Tuple # Import Callable, Tuple
import traceback
import json # For parsing policy documents
import re

from loguru import logger
from sqlalchemy.orm import Session
from botocore.exceptions import ClientError

# Assuming schemas and models are accessible via absolute import paths
from app.api.v1.schemas import FindingSeverity, FindingCategory, Finding # Pydantic schema
from app.db import models # DB Model
from app.db.graph_db import Neo4jClient # Import Neo4j Client
from app.providers.aws_provider import AwsProvider # Import AwsProvider
from .graph_queries import iam_graph_queries # Import the new graph query module
# Note: We will pass the create_finding function/method as a callback

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

# --- Helper Functions for Relationship Analysis ---

def _analyze_trust_relationships(roles: List[Dict[str, Any]], account_id: str) -> List[Dict]:
    """Analyzes trust policies to derive CAN_ASSUME relationships."""
    can_assume_rels = []
    logger.debug(f"Analyzing trust policies for {len(roles)} roles.")
    for role_data in roles:
        role_arn = role_data.get('arn')
        if not role_arn:
            logger.warning("Skipping role in trust analysis due to missing ARN.")
            continue

        trusted_principals_info = role_data.get('properties', {}).get('AWSTrustedPrincipalIdentifiers', []) + \
                                  role_data.get('properties', {}).get('ServiceTrustedPrincipalIdentifiers', []) + \
                                  role_data.get('properties', {}).get('FederatedTrustedPrincipalIdentifiers', []) + \
                                  role_data.get('properties', {}).get('SAMLTrustedPrincipalIdentifiers', []) + \
                                  role_data.get('properties', {}).get('OIDCTrustedPrincipalIdentifiers', []) + \
                                  role_data.get('properties', {}).get('CanonicalUserTrustedPrincipalIdentifiers', []) + \
                                  role_data.get('properties', {}).get('UnknownTrustedPrincipalIdentifiers', [])
        trust_conditions_list = role_data.get('properties', {}).get('TrustPolicyConditions', []) # This is List[Dict]

        # Basic mapping - This doesn't easily correlate specific principals back to their *exact* conditions
        # from the new structured properties. We might need the original parsed list for that precise mapping.
        # For now, let's just link principals, conditions can be viewed on the role node.
        
        # Simplified logic: Iterate through identified principals and link them
        for principal_id in trusted_principals_info:
            source_node_id = None
            source_node_label = None
            if principal_id == '*':
                 source_node_id = "*"
                 source_node_label = "WildcardPrincipal"
            elif principal_id.startswith('arn:aws:iam::') and ':root' in principal_id:
                 # Extract account ID for Account node
                 match = re.match(r'arn:aws:iam::(\d{12}):root', principal_id)
                 source_node_id = match.group(1) if match else account_id # Fallback?
                 source_node_label = "AwsAccount"
            elif principal_id.startswith('arn:aws:iam::') and ':role/' in principal_id:
                 source_node_id = principal_id
                 source_node_label = "IamRole"
            elif principal_id.startswith('arn:aws:iam::') and ':user/' in principal_id:
                 source_node_id = principal_id
                 source_node_label = "IamUser"
            elif principal_id.startswith('arn:aws:iam::') and (':saml-provider/' in principal_id or ':oidc-provider/' in principal_id):
                 source_node_id = principal_id
                 source_node_label = "FederatedPrincipal" # Need to create these nodes
            elif '.amazonaws.com' in principal_id or '.amazon.com' in principal_id: # Simple check for service principal
                 source_node_id = principal_id
                 source_node_label = "ServicePrincipal"
            # Add CanonicalUser if needed

            if source_node_id and source_node_label:
                can_assume_rels.append({
                    'source_label': source_node_label,
                    'source_id': source_node_id,
                    'target_label': 'IamRole',
                    'target_id': role_arn,
                    'properties': { # Keep minimal for now, conditions are on the node
                         # 'condition_json': json.dumps(conditions_for_this_principal) # Complex to map back
                    }
                })
            else:
                logger.debug(f"Could not map principal ID '{principal_id}' to a source node for role {role_arn}")

    logger.info(f"Generated {len(can_assume_rels)} potential CAN_ASSUME relationships.")
    return can_assume_rels

def _analyze_permission_policies(principals: List[Dict[str, Any]]) -> List[Dict]:
    """Analyzes inline and attached policies to derive CAN_ACCESS relationships (Refined implementation)."""
    can_access_rels = []
    logger.debug(f"Analyzing permissions for {len(principals)} principals (Users/Roles).")

    # Define simplified permission levels
    PERMISSION_LEVELS = {
        "FULL_ACCESS": 5, # Highest
        "PERMISSIONS": 4, # iam:* like actions
        "WRITE": 3,       # Create, Delete, Put, Update
        "READ": 2,        # Get, List, Describe
        "LIST": 1,        # List only
        "UNKNOWN": 0      # Default / Unclassified
    }
    # Reverse map for getting level name from score
    LEVEL_NAMES = {v: k for k, v in PERMISSION_LEVELS.items()}

    # Map action prefixes/patterns to levels (simplified, needs expansion)
    # TODO: Expand this mapping significantly
    ACTION_LEVEL_MAP = {
        "iam:": PERMISSION_LEVELS["PERMISSIONS"], # High risk
        "sts:": PERMISSION_LEVELS["PERMISSIONS"], # AssumeRole etc.
        "ec2:RunInstances": PERMISSION_LEVELS["WRITE"],
        "ec2:TerminateInstances": PERMISSION_LEVELS["WRITE"],
        "ec2:StartInstances": PERMISSION_LEVELS["WRITE"],
        "ec2:StopInstances": PERMISSION_LEVELS["WRITE"],
        "ec2:ModifyInstanceAttribute": PERMISSION_LEVELS["WRITE"],
        "ec2:Create*": PERMISSION_LEVELS["WRITE"],
        "ec2:Delete*": PERMISSION_LEVELS["WRITE"],
        "ec2:Describe*": PERMISSION_LEVELS["READ"],
        "ec2:Get*": PERMISSION_LEVELS["READ"],
        "s3:Put*": PERMISSION_LEVELS["WRITE"],
        "s3:Delete*": PERMISSION_LEVELS["WRITE"],
        "s3:Create*": PERMISSION_LEVELS["WRITE"],
        "s3:Get*": PERMISSION_LEVELS["READ"],
        "s3:List*": PERMISSION_LEVELS["LIST"],
        "rds:Create*": PERMISSION_LEVELS["WRITE"],
        "rds:Delete*": PERMISSION_LEVELS["WRITE"],
        "rds:Modify*": PERMISSION_LEVELS["WRITE"],
        "rds:Describe*": PERMISSION_LEVELS["READ"],
        "lambda:Create*": PERMISSION_LEVELS["WRITE"],
        "lambda:Delete*": PERMISSION_LEVELS["WRITE"],
        "lambda:Update*": PERMISSION_LEVELS["WRITE"],
        "lambda:Invoke*": PERMISSION_LEVELS["WRITE"], # Invocation can be write-like
        "lambda:Get*": PERMISSION_LEVELS["READ"],
        "lambda:List*": PERMISSION_LEVELS["LIST"],
    }

    for principal in principals:
        principal_arn = principal.get('arn')
        if not principal_arn: continue

        # Store highest permission level found per resource pattern
        resource_permissions: Dict[str, int] = {}
        resource_conditions: Dict[str, Any] = {}

        # Combine all policy documents for this principal
        all_policy_docs = []
        inline_policies = principal.get('properties', {}).get('InlinePoliciesJson', {})
        for policy_name, policy_json_str in inline_policies.items():
            try:
                policy_doc = json.loads(policy_json_str)
                if policy_doc and "_ErrorFetchingPolicy" not in policy_doc:
                    all_policy_docs.append(policy_doc)
            except json.JSONDecodeError:
                logger.warning(f"Could not parse inline policy JSON for {principal_arn}/{policy_name}")
        
        attached_docs = principal.get('properties', {}).get('AttachedManagedPolicyDocumentsJson', {})
        for policy_arn, policy_json_str in attached_docs.items():
            try:
                policy_doc = json.loads(policy_json_str)
                if policy_doc and "_ErrorFetchingDocument" not in policy_doc:
                    all_policy_docs.append(policy_doc)
            except json.JSONDecodeError:
                 logger.warning(f"Could not parse attached policy JSON for {principal_arn} from {policy_arn}")

        # Analyze statements from all combined policies
        for policy_doc in all_policy_docs:
            statements = policy_doc.get('Statement', [])
            if not isinstance(statements, list): statements = [statements]

            for statement in statements:
                if not isinstance(statement, dict) or statement.get('Effect') != 'Allow':
                    continue

                actions = statement.get('Action', [])
                if not isinstance(actions, list): actions = [actions]
                
                resources = statement.get('Resource', [])
                if not isinstance(resources, list): resources = [resources]
                
                condition = statement.get('Condition')

                # Determine permission level for this statement
                current_level = PERMISSION_LEVELS["UNKNOWN"]
                has_admin_action = False
                for action in actions:
                    if not isinstance(action, str): continue
                    if action == '*' or action == '*:*':
                        current_level = PERMISSION_LEVELS["FULL_ACCESS"]
                        has_admin_action = True
                        break # Max level found for this statement
                    # Check prefixes
                    for prefix, level in ACTION_LEVEL_MAP.items():
                         # Handle potential wildcards in map keys
                        if prefix.endswith('*') and action.startswith(prefix[:-1]):
                             current_level = max(current_level, level)
                        elif action == prefix:
                             current_level = max(current_level, level)
                
                if current_level == PERMISSION_LEVELS["UNKNOWN"]:
                     # If no match, maybe default to READ? Or log?
                     logger.trace(f"Could not determine permission level for actions: {actions}")

                # Apply this level to all resources in the statement
                for resource_pattern in resources:
                    if not isinstance(resource_pattern, str): continue
                    
                    # Check for full admin combination
                    if has_admin_action and resource_pattern == '*':
                         permission_level = PERMISSION_LEVELS["FULL_ACCESS"]
                    else:
                         permission_level = current_level
                    
                    # Update the highest permission level seen for this resource pattern
                    resource_permissions[resource_pattern] = max(
                        resource_permissions.get(resource_pattern, PERMISSION_LEVELS["UNKNOWN"]),
                        permission_level
                    )
                    # Store condition if this statement granted the highest level so far
                    # TODO: How to combine conditions if multiple statements grant same max level?
                    # For now, just store the condition from the last statement that set the max level.
                    if resource_permissions[resource_pattern] == permission_level and condition:
                         resource_conditions[resource_pattern] = condition

        # Generate CAN_ACCESS relationship data from aggregated permissions
        for resource_pattern, level_score in resource_permissions.items():
            if level_score > PERMISSION_LEVELS["UNKNOWN"]:
                # Focus on creating relationships for specific ARNs in Sprint 3
                # TODO: Refine target identification - map patterns to nodes where possible
                target_label = "Resource" # Default generic label
                target_id = resource_pattern # Use the pattern itself for now
                is_specific_resource = False
                if resource_pattern != '*' and resource_pattern.startswith('arn:aws:'):
                    is_specific_resource = True # Assume specific ARN if it starts with arn:
                    # Future: Try to map ARN to specific node label/ID
                    # Example: if ':s3:::' in resource_pattern: target_label = 'S3Bucket'

                # Only create relationship data for specific resources in this iteration
                if is_specific_resource or level_score == PERMISSION_LEVELS["FULL_ACCESS"]: # Create for full admin even if resource=* 
                     if level_score == PERMISSION_LEVELS["FULL_ACCESS"]: 
                          target_label = "Resource" # Keep generic for full admin
                          target_id = "*" # Use wildcard symbol for target_id

                     condition = resource_conditions.get(resource_pattern)
                     can_access_rels.append({
                         'source_id': principal_arn,
                         'target_id': target_id, # Specific ARN or '*' for Full Admin
                         'target_label': target_label, # Specific or Generic 'Resource'
                         'properties': {
                             'permission_level': LEVEL_NAMES.get(level_score, 'UNKNOWN'),
                             'condition_json': json.dumps(condition) if condition else None,
                             'resource_pattern': resource_pattern # Include original pattern for context
                         }
                     })

    logger.info(f"Generated {len(can_access_rels)} potential CAN_ACCESS relationships (refined analysis).")
    return can_access_rels

# Removed the class context, this is now a standalone function
def analyze_iam(
    db: Session, 
    db_client: Neo4jClient,
    account_id: str, 
    scan_id: uuid.UUID, 
    region: str, # Keep region for consistency, though IAM is global
    iam_resources: List[Dict[str, Any]],
    aws_provider: AwsProvider, # Add aws_provider parameter
    create_finding_callback: Callable[..., models.Finding] # Callback function
) -> Dict[str, Any]: # Return dict with findings and relationship data
    """Analyze collected IAM resources, create findings, and derive relationship data."""
    scan_id_str = str(scan_id)
    logger.info(f"[{scan_id_str}] Starting IAM analysis and relationship derivation for account {account_id}")
    findings_created = 0
    relationships_to_create = {"CAN_ASSUME": [], "CAN_ACCESS": []}
    
    # Prepare data structures from iam_resources list
    users = [r for r in iam_resources if r.get('resource_type') == 'IamUser']
    roles = [r for r in iam_resources if r.get('resource_type') == 'IamRole']
    policies = [r for r in iam_resources if r.get('resource_type') == 'IamPolicy']
    groups = [r for r in iam_resources if r.get('resource_type') == 'IamGroup']
    account_settings_list = [r for r in iam_resources if r.get('resource_type') == 'AccountSettings']
    
    account_settings = account_settings_list[0] if account_settings_list else None
    iam_client = aws_provider.get_client('iam') # Get client once

    # --- Finding Generation (Existing Logic) ---
    # Check 1: Root Account MFA (Uses AccountSettings data if available)
    try:
        if account_settings:
            summary_map = account_settings.get('properties', {}).get('AccountSummary', {})
            account_summary_error = account_settings.get('properties', {}).get('AccountSummaryError')
            if account_summary_error:
                logger.error(f"[{scan_id_str}] Scanner reported error fetching account summary: {account_summary_error}")
            elif summary_map and summary_map.get('AccountMFAEnabled', 0) != 1:
                details_for_finding = {"account_mfa_enabled": False}
                finding = create_finding_callback(
                    db=db, account_id=account_id, scan_id=scan_id, region="global",
                    resource_id=f"arn:aws:iam::{account_id}:root", resource_type="AWS::IAM::RootAccount",
                    title="Root Account MFA Not Enabled",
                    description="Multi-Factor Authentication (MFA) is not enabled for the AWS root account.",
                    severity=FindingSeverity.HIGH, category=FindingCategory.IAM,
                    details=details_for_finding
                )
                if finding: findings_created += 1
        else:
            # If no summary fetched (e.g., permission issue caught by scanner or settings object missing)
            logger.warning(f"[{scan_id_str}] AccountSettings data missing or empty, skipping root MFA check.")
    except Exception as e:
        logger.error(f"[{scan_id_str}] Error during root MFA check logic: {e}")

    # Check 2: IAM Password Policy (Uses AccountSettings data)
    try:
        if account_settings:
            policy_data = account_settings.get('properties', {}).get('PasswordPolicy')
            policy_error = account_settings.get('properties', {}).get('PasswordPolicyError')
            logger.debug(f"[{scan_id_str}] Checking Password Policy: policy_data={policy_data}, policy_error={policy_error}") # DEBUG
            
            # --- Potential Issue Area ---
            if (policy_data is None or policy_data == {}) and policy_error is None: 
                # No policy exists - THIS SHOULD TRIGGER FINDING
                details_for_finding = {"password_policy_exists": False, "policy_data": policy_data}
                finding = create_finding_callback(
                    db=db, account_id=account_id, scan_id=scan_id, region="global",
                    resource_id=f"arn:aws:iam::{account_id}:account", resource_type="AWS::IAM::Account",
                    title="IAM Password Policy Not Configured",
                    description="An IAM password policy is not configured for the account, potentially allowing weak user passwords.",
                    severity=FindingSeverity.MEDIUM, category=FindingCategory.IAM,
                    details=details_for_finding
                )
                if finding: findings_created += 1
            elif policy_data: # Policy exists, optional strength checks could go here
                logger.info(f"[{scan_id_str}] IAM password policy found for account {account_id}.")
            elif policy_error:
                logger.error(f"[{scan_id_str}] Scanner reported error retrieving IAM password policy: {policy_error}")
        else:
            logger.warning(f"[{scan_id_str}] AccountSettings data missing or empty, skipping password policy check.")
    except Exception as e:
         logger.error(f"[{scan_id_str}] Error during password policy check logic: {e}")

    # Check 3: MFA for IAM Users with Console Password
    try:
        logger.debug(f"[{scan_id_str}] Checking IAM Users for missing MFA...")
        user_count_mfa = 0
        for user in users:
            user_props = user.get('properties', {})
            user_name = user_props.get('UserName') 
            user_arn = user.get('arn')            
            if not user_name or not user_arn: continue
            
            has_console_password = user_props.get('PasswordLastUsed') is not None
            has_mfa = user_props.get('HasMfaEnabled') # Get from property

            if has_console_password and has_mfa == False: # Check boolean property
                details_for_finding = {"user_name": user_name, "has_mfa": has_mfa, "has_console_password": has_console_password}
                finding = create_finding_callback(
                    db=db, account_id=account_id, scan_id=scan_id, region="global",
                    resource_id=user_arn, resource_type="AWS::IAM::User",
                    title=f"IAM User '{user_name}' with Console Access Has No MFA",
                    description=f"The IAM user '{user_name}' has console access enabled but does not have Multi-Factor Authentication (MFA) configured.",
                    severity=FindingSeverity.MEDIUM, category=FindingCategory.IAM,
                    details=details_for_finding
                )
                findings_created += 1
                user_count_mfa += 1
        logger.debug(f"[{scan_id_str}] Missing MFA check completed. Found {user_count_mfa} potential findings.")
    except Exception as e:
        logger.error(f"[{scan_id_str}] Error during IAM User MFA check: {e}")
        logger.error(traceback.format_exc())

    # Check 4: Unused IAM User Credentials
    try:
        logger.debug(f"[{scan_id_str}] Checking for recently unused IAM user passwords...")
        ninety_days_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=90)

        for user in users:
            user_props = user.get('properties', {})
            user_arn = user.get('arn') # Get ARN from top level
            user_name = user_props.get('UserName')
            if not user_name or not user_arn:
                # Log again specifically for this check
                log_user_repr = repr(user)[:200]
                logger.warning(f"[{scan_id_str}] Skipping user in Unused Creds check due to missing UserName or Arn: {log_user_repr}")
                continue

            # Check Password Last Used (if applicable)
            password_last_used_str = user_props.get('PasswordLastUsed') # Correctly access from user_props
            if password_last_used_str:
                 # Ensure it's offset-aware before comparison
                password_last_used = password_last_used_str.replace(tzinfo=datetime.timezone.utc) if password_last_used_str.tzinfo is None else password_last_used_str

                if password_last_used < ninety_days_ago:
                    details_for_finding = {"user_name": user_name, "password_last_used": str(password_last_used_str)}
                    finding = create_finding_callback(
                        db=db, account_id=account_id, scan_id=scan_id, region="global",
                        resource_id=user_arn, resource_type="AWS::IAM::User",
                        title=f"IAM User '{user_name}' Password Not Used Recently",
                        description=f"The IAM user '{user_name}' has a console password that hasn't been used in over 90 days (last used: {password_last_used_str}). Consider disabling or removing the password.",
                        severity=FindingSeverity.LOW, category=FindingCategory.IAM,
                        details=details_for_finding
                    )
                    if finding: findings_created += 1

            # Check Access Keys Last Used
            try:
                if iam_client: # Ensure client was created
                    paginator = iam_client.get_paginator('list_access_keys')
                    for page in paginator.paginate(UserName=user_name):
                        for key_metadata in page.get('AccessKeyMetadata', []):
                            access_key_id = key_metadata.get('AccessKeyId')
                            if not access_key_id: continue

                            key_last_used_response = iam_client.get_access_key_last_used(AccessKeyId=access_key_id)
                            last_used_date_str = key_last_used_response.get('AccessKeyLastUsed', {}).get('LastUsedDate')

                            if last_used_date_str:
                                 # Ensure it's offset-aware before comparison
                                 last_used_date = last_used_date_str.replace(tzinfo=datetime.timezone.utc) if last_used_date_str.tzinfo is None else last_used_date_str
                                 if last_used_date < ninety_days_ago:
                                    details_for_finding = {"user_name": user_name, "access_key_id": access_key_id, "last_used_date": str(last_used_date_str)}
                                    finding = create_finding_callback(
                                        db=db, account_id=account_id, scan_id=scan_id, region="global",
                                        resource_id=f"{user_arn}/accesskey/{access_key_id}", resource_type="AWS::IAM::AccessKey",
                                        title=f"IAM Access Key '{access_key_id}' for User '{user_name}' Not Used Recently",
                                        description=f"The access key '{access_key_id}' for user '{user_name}' has not been used in over 90 days (last used: {last_used_date_str}). Consider deactivating or deleting it.",
                                        severity=FindingSeverity.LOW, category=FindingCategory.IAM,
                                        details=details_for_finding
                                    )
                                    if finding: findings_created += 1
                            else: # Key has never been used
                                key_create_date_str = key_metadata.get('CreateDate')
                                # Ensure create_date is offset-aware before comparison
                                key_create_date = key_create_date_str.replace(tzinfo=datetime.timezone.utc) if key_create_date_str and key_create_date_str.tzinfo is None else key_create_date_str
                                
                                if key_create_date and key_create_date < ninety_days_ago:
                                    details_for_finding = {"user_name": user_name, "access_key_id": access_key_id, "create_date": str(key_create_date_str)}
                                    finding = create_finding_callback(
                                        db=db, account_id=account_id, scan_id=scan_id, region="global",
                                        resource_id=f"{user_arn}/accesskey/{access_key_id}", resource_type="AWS::IAM::AccessKey",
                                        title=f"IAM Access Key '{access_key_id}' for User '{user_name}' Never Used",
                                        description=f"The access key '{access_key_id}' (created: {key_create_date_str}) for user '{user_name}' has never been used and is older than 90 days. Consider deleting it.",
                                        severity=FindingSeverity.MEDIUM, category=FindingCategory.IAM, # Higher severity as it's never used
                                        details=details_for_finding
                                    )
                                    if finding: findings_created += 1
                else:
                     logger.warning(f"[{scan_id_str}] Could not create IAM client, skipping access key check for user {user_name}.")

            except ClientError as e:
                logger.error(f"[{scan_id_str}] Error checking access keys for user {user_name}: {e}")
            except Exception as e:
                logger.error(f"[{scan_id_str}] Unexpected error checking access keys for user {user_name}: {e}")

    except Exception as e:
        logger.error(f"[{scan_id_str}] Error during unused password check: {e}")
        logger.error(traceback.format_exc())

    # Check 4b: Inactive Access Keys (Uses Graph Query via helper)
    try:
        inactive_key_results = iam_graph_queries.check_users_with_inactive_keys(db_client, account_id, scan_id_str)
        for data in inactive_key_results:
            user_name = data.get('UserName')
            user_arn = data.get('UserArn')
            key_id = data.get('InactiveAccessKeyId')
            create_date = data.get('KeyCreateDate')
            details_for_finding = data.copy()
            details_for_finding["key_status"] = "Inactive"
            create_finding_callback(
                db=db, account_id=account_id, scan_id=scan_id, region="global",
                resource_id=f"{user_arn}/accesskey/{key_id}", resource_type="AWS::IAM::AccessKey",
                title=f"IAM User '{user_name}' has Inactive Access Key",
                description=f"The access key '{key_id}' (created: {create_date}) for user '{user_name}' is Inactive. Consider deleting it if no longer needed.",
                severity=FindingSeverity.LOW, category=FindingCategory.IAM,
                details=details_for_finding
            )
            findings_created += 1
        logger.debug(f"[{scan_id_str}] Inactive key check completed. Found {len(inactive_key_results)} potential findings.")
    except Exception as e:
        logger.error(f"[{scan_id_str}] Error during inactive key analysis: {e}")
        logger.error(traceback.format_exc())

    # Check 4c: Old Active Access Keys (Uses Graph Query via helper)
    try:
        # Define age threshold (e.g., 90 days) - make configurable later?
        KEY_AGE_THRESHOLD_DAYS = 90 
        old_key_results = iam_graph_queries.check_users_with_old_active_keys(db_client, account_id, scan_id_str, key_age_days=KEY_AGE_THRESHOLD_DAYS)
        for data in old_key_results:
            user_name = data.get('UserName')
            user_arn = data.get('UserArn')
            key_id = data.get('OldAccessKeyId')
            create_date = data.get('KeyCreateDate')
            details_for_finding = data.copy()
            details_for_finding["key_age_days"] = KEY_AGE_THRESHOLD_DAYS
            create_finding_callback(
                db=db, account_id=account_id, scan_id=scan_id, region="global",
                resource_id=f"{user_arn}/accesskey/{key_id}", resource_type="AWS::IAM::AccessKey",
                title=f"IAM User '{user_name}' has Active Access Key older than {KEY_AGE_THRESHOLD_DAYS} days",
                description=f"The active access key '{key_id}' (created: {create_date}) for user '{user_name}' has not been rotated in over {KEY_AGE_THRESHOLD_DAYS} days. Regular rotation is recommended.",
                severity=FindingSeverity.MEDIUM, category=FindingCategory.IAM,
                details=details_for_finding
            )
            findings_created += 1
        logger.debug(f"[{scan_id_str}] Old active key check completed. Found {len(old_key_results)} potential findings.")
    except Exception as e:
        logger.error(f"[{scan_id_str}] Error during old active key analysis: {e}")
        logger.error(traceback.format_exc())

    # Check 5: IAM Policies Allowing Full Admin Access ('*:*') 
    # Refined to use graph query for customer-managed policies
    # Still needs logic for inline policies
    try:
        admin_policies = iam_graph_queries.check_iam_policies_granting_full_admin(db_client, account_id, scan_id_str)
        for data in admin_policies:
            policy_name = data.get('PolicyName')
            policy_arn = data.get('PolicyArn')
            stmt_sid = data.get('StatementSID')
            details_for_finding = data.copy()
            create_finding_callback(
                db=db, account_id=account_id, scan_id=scan_id, region="global",
                resource_id=policy_arn, resource_type="AWS::IAM::Policy", # Finding is for the policy itself
                title=f"IAM Policy '{policy_name}' Grants Full Admin Access (*:*)",
                description=f"The customer-managed policy '{policy_name}' contains a statement (SID: {stmt_sid}) allowing Action='*' on Resource='*'.",
                severity=FindingSeverity.CRITICAL, category=FindingCategory.IAM,
                details=details_for_finding
            )
            findings_created += 1
        
        # TODO: Add logic here to check inline policies from users/roles/groups using check_policy_doc_for_admin helper?
        # This part still needs access to the properties like InlinePoliciesJson from the iam_resources list.
        # Option 1: Pass iam_resources list to this function.
        # Option 2: Query users/roles/groups from graph AND retrieve InlinePoliciesJson property.
        # Let's do Option 1 for now, assuming iam_resources is still available.
        logger.debug(f"[{scan_id_str}] Checking inline policies for *:*...")
        inline_admin_count = 0
        for principal in users + roles + groups:
            principal_props = principal.get('properties', {})
            principal_arn = principal.get('arn')
            resource_type_label = principal.get("resource_type", "Principal") # User/Role/Group
            principal_name = principal_props.get('UserName') or principal_props.get('RoleName') or principal_props.get('GroupName')
            if not principal_name or not principal_arn: continue
            
            inline_policies = principal_props.get('InlinePoliciesJson', {})
            for policy_name, policy_json_str in inline_policies.items():
                try:
                    policy_doc = json.loads(policy_json_str)
                    if "_ErrorFetchingPolicy" in policy_doc: continue
                    if check_policy_doc_for_admin(policy_doc):
                        details_for_finding = {"principal_name": principal_name, "policy_name": policy_name, "policy_document": policy_doc}
                        create_finding_callback(
                            db=db, account_id=account_id, scan_id=scan_id, region="global",
                            resource_id=f"{principal_arn}/inline-policy/{policy_name}", resource_type="AWS::IAM::InlinePolicy",
                            title=f"Inline Policy on {resource_type_label} '{principal_name}' Grants Full Admin Access",
                            description=f"The inline policy '{policy_name}' attached to {resource_type_label} '{principal_name}' contains a statement allowing Action='*' on Resource='*'.",
                            severity=FindingSeverity.CRITICAL, category=FindingCategory.IAM,
                            details=details_for_finding
                        )
                        findings_created += 1
                        inline_admin_count += 1
                except json.JSONDecodeError:
                    logger.warning(f"[{scan_id_str}] Could not parse inline policy JSON '{policy_name}' for {principal_arn}")
        logger.debug(f"[{scan_id_str}] Inline policy *:* check completed. Found {inline_admin_count} potential findings.")

    except Exception as e:
        logger.error(f"[{scan_id_str}] Error during IAM Policy *:* check: {e}")
        logger.error(traceback.format_exc())

    # Check 6: Support Role for Incident Investigation
    try:
        support_role_found = False
        expected_role_name = "SecurityAuditRole" # Example name, make this configurable
        for role in roles:
            if role.get('RoleName') == expected_role_name:
                 # Further check if the role has appropriate permissions (e.g., SecurityAudit policy)
                 # Requires listing attached policies for the role
                 # Simplified: just check for existence by name
                 support_role_found = True
                 logger.info(f"[{scan_id_str}] Found potential incident support role: {expected_role_name}")
                 break # Found it

        if not support_role_found:
             details_for_finding = {"expected_role_name": expected_role_name}
             finding = create_finding_callback(
                 db=db, account_id=account_id, scan_id=scan_id, region="global",
                 resource_id=f"arn:aws:iam::{account_id}:account", resource_type="AWS::IAM::Account",
                 title=f"Dedicated IAM Role for Incident Investigation Not Found",
                 description=f"A dedicated IAM role (e.g., '{expected_role_name}') with necessary permissions for incident investigation and response appears to be missing.",
                 severity=FindingSeverity.LOW, category=FindingCategory.IAM,
                 details=details_for_finding
             )
             if finding: findings_created += 1

    except Exception as e:
        logger.error(f"[{scan_id_str}] Error during support role check logic: {e}")
        logger.error(traceback.format_exc())

    # Check 7: Expired SSL/TLS Certificates
    try:
        paginator = iam_client.get_paginator('list_server_certificates')
        now = datetime.datetime.now(datetime.timezone.utc)
        for page in paginator.paginate():
            for cert_meta in page.get('ServerCertificateMetadataList', []):
                cert_name = cert_meta.get('ServerCertificateName')
                cert_arn = cert_meta.get('Arn')
                expiration_date_str = cert_meta.get('Expiration')

                if expiration_date_str:
                     # Ensure it's offset-aware before comparison
                    expiration_date = expiration_date_str.replace(tzinfo=datetime.timezone.utc) if expiration_date_str.tzinfo is None else expiration_date_str
                    if expiration_date < now:
                        details_for_finding = {"certificate_name": cert_name, "expiration_date": str(expiration_date_str)}
                        finding = create_finding_callback(
                            db=db, account_id=account_id, scan_id=scan_id, region="global", # Certs are global
                            resource_id=cert_arn, resource_type="AWS::IAM::ServerCertificate",
                            title=f"Expired Server Certificate '{cert_name}' Found in IAM",
                            description=f"The server certificate '{cert_name}' stored in IAM expired on {expiration_date_str}. Expired certificates can cause service disruptions.",
                            severity=FindingSeverity.MEDIUM, category=FindingCategory.IAM,
                            details=details_for_finding
                        )
                        if finding: findings_created += 1
                    # Optional: Add check for certificates expiring soon (e.g., < 30 days)
                    elif expiration_date < (now + datetime.timedelta(days=30)):
                         details_for_finding = {"certificate_name": cert_name, "expiration_date": str(expiration_date_str)}
                         finding = create_finding_callback(
                            db=db, account_id=account_id, scan_id=scan_id, region="global",
                            resource_id=cert_arn, resource_type="AWS::IAM::ServerCertificate",
                            title=f"Server Certificate '{cert_name}' Expires Soon",
                            description=f"The server certificate '{cert_name}' stored in IAM will expire on {expiration_date_str} (within 30 days).",
                            severity=FindingSeverity.LOW, category=FindingCategory.IAM,
                            details=details_for_finding
                        )
                         if finding: findings_created += 1

    except ClientError as e:
        logger.error(f"[{scan_id_str}] Error checking server certificates: {e}")
    except Exception as e:
         logger.error(f"[{scan_id_str}] Error during server certificate check logic: {e}")

    # Check 8: Roles with Broad Trust (Uses Graph Query via helper)
    try:
        broad_trust_roles = iam_graph_queries.check_roles_with_broad_trust(db_client, account_id, scan_id_str)
        for data in broad_trust_roles:
            role_name = data.get('RoleName')
            role_arn = data.get('RoleArn')
            aws_trusted = data.get('AwsAccountsTrusted', [])
            svc_trusted = data.get('ServicesTrusted', [])
            unknown_trusted = data.get('UnknownPrincipalsTrusted', [])
            is_anon = data.get('IsConsideredAnonymousAccess')
            # Construct a summary description
            trust_summary = f"IsAnonymousTrusted={is_anon}. AWSPrincipals={aws_trusted}. ServicePrincipals={svc_trusted}. UnknownPrincipals={unknown_trusted}."
            
            details_for_finding = {
                "role_name": role_name,
                "trust_details": trust_summary,
                "conditions": str(data.get('Conditions', 'None')), # Pass conditions as string for now
                "original_trust_policy_document": data.get('OriginalTrustPolicyDocument') # For full context
            }
            create_finding_callback(
                db=db, account_id=account_id, scan_id=scan_id, region="global",
                resource_id=role_arn, resource_type="AWS::IAM::Role",
                title=f"IAM Role '{role_name}' has an overly permissive trust policy",
                description=f"The trust policy for role '{role_name}' allows broad access. Review details. Principals: {trust_summary} Conditions: {data.get('Conditions', 'None')}",
                severity=FindingSeverity.HIGH, category=FindingCategory.IAM,
                details=details_for_finding
            )
            findings_created += 1
        logger.debug(f"[{scan_id_str}] Role broad trust check completed. Found {len(broad_trust_roles)} potential findings.")
    except Exception as e:
        logger.error(f"[{scan_id_str}] Error during Role Broad Trust analysis: {e}")
        logger.error(traceback.format_exc())

    # --- Relationship Derivation --- 
    try:
        can_assume_relationships = _analyze_trust_relationships(roles, account_id)
        relationships_to_create["CAN_ASSUME"] = can_assume_relationships
    except Exception as e:
        logger.error(f"[{scan_id_str}] Failed to analyze trust relationships: {e}")
        logger.error(traceback.format_exc())
        
    try:
        # Combine users and roles for permission analysis
        principals_with_policies = [p for p in users + roles if 
                                   p.get('properties', {}).get('InlinePoliciesJson') or 
                                   p.get('relationships', {}).get('attached_managed_policy_arns')] # Check relationships for attached policies
        can_access_relationships = _analyze_permission_policies(principals_with_policies)
        relationships_to_create["CAN_ACCESS"] = can_access_relationships
    except Exception as e:
         logger.error(f"[{scan_id_str}] Failed to analyze permission policies: {e}")
         logger.error(traceback.format_exc())

    logger.info(f"[{scan_id_str}] Completed IAM analysis. Findings: {findings_created}. Relationships: CAN_ASSUME={len(relationships_to_create['CAN_ASSUME'])}, CAN_ACCESS={len(relationships_to_create['CAN_ACCESS'])}")
    
    # Return findings count and relationship data
    return {
        "findings_created": findings_created,
        "relationships_to_create": relationships_to_create
    }

# Helper function to check for '*' Action with '*' Resource in a statement
def check_statement_for_admin(statement):
    effect = statement.get("Effect")
    action = statement.get("Action")
    resource = statement.get("Resource")

    if effect == "Allow":
        # Check Action
        action_has_star = False
        if isinstance(action, str) and action == "*":
            action_has_star = True
        elif isinstance(action, list) and "*" in action:
            action_has_star = True

        # Check Resource
        resource_has_star = False
        if isinstance(resource, str) and resource == "*":
            resource_has_star = True
        elif isinstance(resource, list) and "*" in resource:
            resource_has_star = True

        if action_has_star and resource_has_star:
            return True
    return False

# Helper function to check a policy document
def check_policy_doc_for_admin(policy_document):
    if not policy_document or "Statement" not in policy_document:
        return False
    statements = policy_document["Statement"]
    if not isinstance(statements, list): # Handle case where Statement is a single dict
        statements = [statements]
    for statement in statements:
        if check_statement_for_admin(statement):
            return True
    return False

# Helper function to check a policy document for risks
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