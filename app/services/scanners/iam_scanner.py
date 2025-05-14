import datetime
import json # For storing complex objects like policies
from typing import Dict, List, Any
import traceback
import re # For parsing principals

from loguru import logger

from app.providers.aws_provider import AwsProvider
from app.services.scanners.utils import format_tags

# Helper function to parse principals and conditions from AssumeRolePolicyDocument
def _parse_trusted_principals_with_conditions(policy_document: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Parses trusted principals and associated conditions from a trust policy."""
    principals_info = []
    if not policy_document or 'Statement' not in policy_document:
        return principals_info

    statements = policy_document.get('Statement', [])
    if not isinstance(statements, list):
        statements = [statements] # Handle single statement

    for statement in statements:
        # Ensure statement is a dict and has the required keys
        if not isinstance(statement, dict) or statement.get('Effect') != 'Allow' or 'Principal' not in statement:
            continue
        
        # Assign principal_data here, OUTSIDE the inner checks
        principal_data = statement['Principal']
        condition_data = statement.get('Condition') # Capture Condition block
        sid = statement.get('Sid') # Capture SID for context

        extracted_principals = []
        if isinstance(principal_data, dict):
            for principal_type, identifiers in principal_data.items():
                if isinstance(identifiers, list):
                    for identifier in identifiers:
                        extracted_principals.append({"type": principal_type, "identifier": identifier})
                else:
                    extracted_principals.append({"type": principal_type, "identifier": identifiers})
        elif isinstance(principal_data, str):
            extracted_principals.append({"type": "Unknown", "identifier": principal_data}) # e.g., "*"
        
        # Associate condition with each extracted principal from this statement
        for principal in extracted_principals:
            principals_info.append({
                "type": principal["type"],
                "identifier": principal["identifier"],
                "condition": condition_data, # Add condition block
                "statement_sid": sid # Add SID for reference
            })
            
    return principals_info

def scan_iam(aws_provider: AwsProvider) -> List[Dict[str, Any]]:
    """Scan core IAM resources: Users, Roles, Customer Managed Policies, including inline/attached policy details."""
    iam_client = aws_provider.get_client("iam")
    resources = []
    account_id = aws_provider.account_id
    # --- New: Keep track of all policy ARNs found ---
    all_policy_arns_found = set()
    # --- New: Keep track of ARNs for policies already added as full resource items ---
    processed_policy_arns = set()

    try:
        # --- 1. Scan Roles --- 
        logger.debug(f"Scanning IAM Roles for account {account_id}...")
        role_count = 0
        paginator = iam_client.get_paginator('list_roles')
        for page in paginator.paginate():
            for role_summary in page.get('Roles', []):
                role_name = role_summary.get('RoleName')
                role_arn = role_summary.get('Arn')
                role_id = role_summary.get('RoleId')
                tags = format_tags(role_summary.get('Tags', []))
                assume_role_policy_doc = role_summary.get('AssumeRolePolicyDocument', {})

                # Get additional details (LastUsed)
                role_last_used = None
                try:
                    role_info = iam_client.get_role(RoleName=role_name)
                    role_last_used = role_info.get('Role', {}).get('RoleLastUsed', {})
                except Exception as role_info_e:
                    logger.warning(f"Could not get role details (for LastUsed) for role {role_name}: {role_info_e}")

                # Get attached managed policies (ARNs and Documents)
                attached_policy_arns = []
                attached_managed_policy_docs = {}
                try:
                    policy_paginator = iam_client.get_paginator('list_attached_role_policies')
                    for policy_page in policy_paginator.paginate(RoleName=role_name):
                        for attached_policy in policy_page.get('AttachedPolicies', []):
                            policy_arn = attached_policy.get('PolicyArn')
                            if not policy_arn: continue
                            attached_policy_arns.append(policy_arn)
                            all_policy_arns_found.add(policy_arn) # --- New: Add ARN to the set ---
                            # Fetch the document for the default version
                            try:
                                policy_info = iam_client.get_policy(PolicyArn=policy_arn)
                                default_version_id = policy_info.get('Policy', {}).get('DefaultVersionId')
                                if default_version_id:
                                    policy_version = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=default_version_id)
                                    policy_document = policy_version.get('PolicyVersion', {}).get('Document')
                                    if policy_document:
                                        attached_managed_policy_docs[policy_arn] = policy_document
                            except Exception as policy_doc_e:
                                logger.warning(f"Could not get policy document for attached policy {policy_arn} on role {role_name}: {policy_doc_e}")
                                attached_managed_policy_docs[policy_arn] = {"_ErrorFetchingDocument": str(policy_doc_e)}

                except Exception as attached_policy_e:
                    logger.warning(f"Could not list attached policies for role {role_name}: {attached_policy_e}")

                # Get inline policies
                inline_policies_json = {}
                try:
                    policy_paginator = iam_client.get_paginator('list_role_policies')
                    for policy_page in policy_paginator.paginate(RoleName=role_name):
                        for policy_name in policy_page.get('PolicyNames', []):
                            try:
                                policy_detail = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                                inline_policies_json[policy_name] = json.dumps(policy_detail.get('PolicyDocument', {}))
                            except Exception as inline_e:
                                logger.warning(f"Could not get inline policy {policy_name} for role {role_name}: {inline_e}")
                                inline_policies_json[policy_name] = json.dumps({"_ErrorFetchingPolicy": str(inline_e)})
                except Exception as list_inline_e:
                    logger.warning(f"Could not list inline policies for role {role_name}: {list_inline_e}")

                # Parse trusted principals with conditions
                parsed_trust_policy_details = _parse_trusted_principals_with_conditions(assume_role_policy_doc)

                # Initialize new structured properties for trust policy
                aws_trusted_identifiers = []
                service_trusted_identifiers = []
                federated_trusted_identifiers = []
                saml_trusted_identifiers = []
                oidc_trusted_identifiers = [] # Web Identity Federation
                canonical_user_trusted_identifiers = []
                unknown_trusted_identifiers = [] # For '*' or other direct string principals
                
                is_anonymous_trusted = False # Flag for anonymous or broad wildcard access
                trust_policy_conditions = [] # Store all condition blocks

                for entry in parsed_trust_policy_details:
                    principal_type = entry.get("type")
                    principal_identifier = entry.get("identifier")
                    condition = entry.get("condition")

                    if condition: # Collect all conditions
                        trust_policy_conditions.append({
                            "statement_sid": entry.get("statement_sid"),
                            "principal_type": principal_type,
                            "principal_identifier": principal_identifier,
                            "condition_block": condition
                        })

                    if principal_identifier == "*":
                        is_anonymous_trusted = True # General wildcard principal

                    if principal_type == "AWS":
                        aws_trusted_identifiers.append(principal_identifier)
                        if principal_identifier == "*" or (isinstance(principal_identifier, str) and ":root" in principal_identifier and not condition):
                            # Consider root access to any account or own account without conditions as highly permissive
                            is_anonymous_trusted = True 
                    elif principal_type == "Service":
                        service_trusted_identifiers.append(principal_identifier)
                    elif principal_type == "Federated":
                        federated_trusted_identifiers.append(principal_identifier)
                    elif principal_type == "SAML": # Specific SAML type if parser differentiates
                        saml_trusted_identifiers.append(principal_identifier)
                    elif principal_type == "OIDC": # Specific OIDC type if parser differentiates
                        oidc_trusted_identifiers.append(principal_identifier)
                    elif principal_type == "CanonicalUser":
                        canonical_user_trusted_identifiers.append(principal_identifier)
                    elif principal_type == "Unknown": # Typically means the principal was just "*"
                        unknown_trusted_identifiers.append(principal_identifier)
                        if principal_identifier == "*":
                           is_anonymous_trusted = True


                role_properties = {
                    'RoleId': role_id,
                    'RoleName': role_name,
                    'Path': role_summary.get('Path'),
                    'CreateDate': role_summary.get('CreateDate').isoformat() if role_summary.get('CreateDate') else None,
                    'AssumeRolePolicyDocument': json.dumps(assume_role_policy_doc), # Keep original for audit
                    'Description': role_summary.get('Description'),
                    'MaxSessionDuration': role_summary.get('MaxSessionDuration'),
                    'RoleLastUsedDate': role_last_used.get('LastUsedDate').isoformat() if role_last_used and role_last_used.get('LastUsedDate') else None,
                    'RoleLastUsedRegion': role_last_used.get('Region') if role_last_used else None,
                    'InlinePoliciesJson': inline_policies_json,
                    # 'AttachedManagedPolicyDocumentsJson': {arn: json.dumps(doc) for arn, doc in attached_managed_policy_docs.items()},
                    
                    # New structured trust policy properties
                    'AWSTrustedPrincipalIdentifiers': list(set(aws_trusted_identifiers)), # Ensure uniqueness
                    'ServiceTrustedPrincipalIdentifiers': list(set(service_trusted_identifiers)),
                    'FederatedTrustedPrincipalIdentifiers': list(set(federated_trusted_identifiers)),
                    'SAMLTrustedPrincipalIdentifiers': list(set(saml_trusted_identifiers)),
                    'OIDCTrustedPrincipalIdentifiers': list(set(oidc_trusted_identifiers)),
                    'CanonicalUserTrustedPrincipalIdentifiers': list(set(canonical_user_trusted_identifiers)),
                    'UnknownTrustedPrincipalIdentifiers': list(set(unknown_trusted_identifiers)),
                    'IsAnonymousTrusted': is_anonymous_trusted,
                    'TrustPolicyConditions': trust_policy_conditions # This list of dicts will be JSON serialized by node_props_preparer
                }
                
                resources.append({
                    'arn': role_arn,
                    'resource_id': role_id,
                    'resource_type': 'IamRole',
                    'region': 'global',
                    'account_id': account_id,
                    'properties': role_properties,
                    'relationships': {
                        'attached_managed_policy_arns': attached_policy_arns,
                        'tags': tags
                    }
                })
                role_count += 1
        logger.debug(f"Found and processed details for {role_count} IAM Roles.")

        # --- 2. Scan Policies (Customer Managed) ---
        logger.debug(f"Scanning IAM Policies (Customer Managed) for account {account_id}...")
        policy_count = 0
        paginator = iam_client.get_paginator('list_policies')
        for page in paginator.paginate(Scope='Local'): # Customer managed only
            for policy_summary in page.get('Policies', []):
                policy_arn = policy_summary['Arn']
                policy_id = policy_summary['PolicyId']
                policy_name = policy_summary['PolicyName']
                all_policy_arns_found.add(policy_arn) # --- New: Add ARN to the set ---
                processed_policy_arns.add(policy_arn) # --- New: Mark as processed ---
                tags = format_tags(policy_summary.get('Tags', []))
                policy_document = None
                default_version_id = policy_summary.get('DefaultVersionId')

                if default_version_id:
                    try:
                        policy_version = iam_client.get_policy_version(
                            PolicyArn=policy_arn,
                            VersionId=default_version_id
                        )
                        policy_document = policy_version.get('PolicyVersion', {}).get('Document')
                    except Exception as pv_e:
                        logger.warning(f"Could not get policy document for {policy_arn} version {default_version_id}: {pv_e}")

                # Prepare the IamPolicy node itself
                iam_policy_properties = {
                    'PolicyId': policy_id,
                    'PolicyName': policy_name,
                    'Path': policy_summary.get('Path'),
                    'DefaultVersionId': default_version_id,
                    'AttachmentCount': policy_summary.get('AttachmentCount'),
                    'IsAttachable': policy_summary.get('IsAttachable'),
                    'CreateDate': policy_summary.get('CreateDate').isoformat() if policy_summary.get('CreateDate') else None,
                    'UpdateDate': policy_summary.get('UpdateDate').isoformat() if policy_summary.get('UpdateDate') else None,
                    'PolicyDocument': json.dumps(policy_document) if policy_document else None, # Keep original for audit
                    'IsAwsManaged': False
                }

                resources.append({
                    'arn': policy_arn,
                    'resource_id': policy_id,
                    'resource_type': 'IamPolicy',
                    'region': 'global',
                    'account_id': account_id,
                    'properties': iam_policy_properties,
                    'relationships': {
                        'tags': tags
                    }
                })
                policy_count += 1
                
                # --- Get Entities attached to this Customer Managed Policy ---
                attached_user_names = []
                attached_group_names = []
                attached_role_names = []
                try:
                    paginator_entities = iam_client.get_paginator('list_entities_for_policy')
                    # Iterate through all attached entities
                    for page_entities in paginator_entities.paginate(PolicyArn=policy_arn):
                        for user in page_entities.get('PolicyUsers', []):
                            attached_user_names.append(user.get('UserName'))
                        for group in page_entities.get('PolicyGroups', []):
                            attached_group_names.append(group.get('GroupName'))
                        for role in page_entities.get('PolicyRoles', []):
                            attached_role_names.append(role.get('RoleName'))
                    # Add to the relationships of the IamPolicy resource just created
                    # Find the resource in the list (it's the last one added of type IamPolicy with this ARN)
                    for res in reversed(resources): # Search backwards for efficiency
                        if res['resource_type'] == 'IamPolicy' and res['arn'] == policy_arn:
                            res['relationships']['attached_user_names'] = list(set(filter(None, attached_user_names)))
                            res['relationships']['attached_group_names'] = list(set(filter(None, attached_group_names)))
                            res['relationships']['attached_role_names'] = list(set(filter(None, attached_role_names)))
                            break
                except Exception as list_entities_e:
                    logger.warning(f"Could not list entities for customer policy {policy_arn}: {list_entities_e}")
                # --- End Get Attached Entities ---

                # --- New: Parse IamPolicy PolicyDocument into IamPolicyStatement nodes ---
                if policy_document and isinstance(policy_document, dict): # policy_document is a dict here, not JSON str
                    statements = policy_document.get('Statement', [])
                    if not isinstance(statements, list):
                        statements = [statements] # Handle single statement object
                    
                    for stmt_idx, statement in enumerate(statements):
                        if not isinstance(statement, dict):
                            logger.warning(f"Skipping non-dict statement in IamPolicy {policy_arn}: {statement}")
                            continue

                        sid = statement.get('Sid', f'Stmt{stmt_idx}')
                        effect = statement.get('Effect')
                        action_block = statement.get('Action')
                        not_action_block = statement.get('NotAction')
                        resource_block = statement.get('Resource')
                        not_resource_block = statement.get('NotResource')
                        condition_block = statement.get('Condition')

                        actions = []
                        if isinstance(action_block, str): actions = [action_block]
                        elif isinstance(action_block, list): actions = action_block

                        not_actions = []
                        if isinstance(not_action_block, str): not_actions = [not_action_block]
                        elif isinstance(not_action_block, list): not_actions = not_action_block

                        resources_list = []
                        if isinstance(resource_block, str): resources_list = [resource_block]
                        elif isinstance(resource_block, list): resources_list = resource_block
                        
                        not_resources_list = []
                        if isinstance(not_resource_block, str): not_resources_list = [not_resource_block]
                        elif isinstance(not_resource_block, list): not_resources_list = not_resource_block

                        statement_id = f"{policy_id}-{sid}" # Combine policy ID and statement SID for uniqueness
                        statement_arn = f"{policy_arn}/statement/{sid}" # Pseudo ARN

                        resources.append({
                            'arn': statement_arn,
                            'resource_id': statement_id,
                            'resource_type': 'IamPolicyStatement',
                            'region': 'global', # IAM policies are global
                            'account_id': account_id,
                            'properties': {
                                'Sid': sid,
                                'Effect': effect,
                                'Action': actions,
                                'NotAction': not_actions,
                                'Resource': resources_list,
                                'NotResource': not_resources_list,
                                'ConditionJson': json.dumps(condition_block) if condition_block else None,
                            },
                            'relationships': {
                                'applies_to_policy_arn': policy_arn
                            }
                        })
                # --- End New IamPolicyStatement parsing ---
        logger.debug(f"Found {policy_count} Customer Managed IAM Policies and their statements.")

        # --- 3. Scan Users --- 
        logger.debug(f"Scanning IAM Users for account {account_id}...")
        user_count = 0
        paginator = iam_client.get_paginator('list_users')
        for page in paginator.paginate():
            for user_summary in page.get('Users', []):
                user_name = user_summary['UserName']
                user_arn = user_summary['Arn']
                user_id = user_summary['UserId']
                tags = format_tags(user_summary.get('Tags', []))
                attached_policy_arns = []
                attached_managed_policy_docs = {}

                # Get attached managed policies (ARNs and Documents)
                try:
                    policy_paginator = iam_client.get_paginator('list_attached_user_policies')
                    for policy_page in policy_paginator.paginate(UserName=user_name):
                         for attached_policy in policy_page.get('AttachedPolicies', []):
                            policy_arn = attached_policy.get('PolicyArn')
                            if not policy_arn: continue
                            attached_policy_arns.append(policy_arn)
                            all_policy_arns_found.add(policy_arn) # --- New: Add ARN to the set ---
                            # Fetch the document for the default version
                            try:
                                policy_info = iam_client.get_policy(PolicyArn=policy_arn)
                                default_version_id = policy_info.get('Policy', {}).get('DefaultVersionId')
                                if default_version_id:
                                    policy_version = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=default_version_id)
                                    policy_document = policy_version.get('PolicyVersion', {}).get('Document')
                                    if policy_document:
                                        attached_managed_policy_docs[policy_arn] = policy_document
                            except Exception as policy_doc_e:
                                logger.warning(f"Could not get policy document for attached policy {policy_arn} on user {user_name}: {policy_doc_e}")
                                attached_managed_policy_docs[policy_arn] = {"_ErrorFetchingDocument": str(policy_doc_e)}
                except Exception as policy_e:
                    logger.warning(f"Could not get attached policies for user {user_name}: {policy_e}")
                
                # Get inline policies
                inline_policies_json = {}
                try:
                    policy_paginator = iam_client.get_paginator('list_user_policies')
                    for policy_page in policy_paginator.paginate(UserName=user_name):
                        for policy_name in policy_page.get('PolicyNames', []):
                            try:
                                policy_detail = iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)
                                inline_policies_json[policy_name] = json.dumps(policy_detail.get('PolicyDocument', {}))
                            except Exception as inline_e:
                                logger.warning(f"Could not get inline policy {policy_name} for user {user_name}: {inline_e}")
                                inline_policies_json[policy_name] = json.dumps({"_ErrorFetchingPolicy": str(inline_e)})
                except Exception as list_inline_e:
                     logger.warning(f"Could not list inline policies for user {user_name}: {list_inline_e}")

                # --- Get MFA Devices ---
                mfa_devices = []
                has_mfa_enabled = False
                try:
                    mfa_response = iam_client.list_mfa_devices(UserName=user_name)
                    mfa_devices = mfa_response.get('MFADevices', [])
                    if mfa_devices:
                        has_mfa_enabled = True # Simple flag if any MFA exists
                        # Could store serial numbers if needed: mfa_serial_numbers = [d['SerialNumber'] for d in mfa_devices]
                except Exception as mfa_e:
                    logger.warning(f"Could not list MFA devices for user {user_name}: {mfa_e}")

                # --- Get Access Keys ---
                access_key_details = []
                try:
                    key_paginator = iam_client.get_paginator('list_access_keys')
                    for key_page in key_paginator.paginate(UserName=user_name):
                        for key_meta in key_page.get('AccessKeyMetadata', []):
                            access_key_details.append({
                                'AccessKeyId': key_meta.get('AccessKeyId'),
                                'Status': key_meta.get('Status'), # Active / Inactive
                                'CreateDate': key_meta.get('CreateDate').isoformat() if key_meta.get('CreateDate') else None
                            })
                except Exception as key_e:
                    logger.warning(f"Could not list access keys for user {user_name}: {key_e}")
                # --- End Access Key fetch ---

                # Define user properties in a separate dict first
                user_properties = {
                    'UserId': user_id,
                    'UserName': user_name,
                    'Path': user_summary.get('Path'),
                    'CreateDate': user_summary.get('CreateDate').isoformat() if user_summary.get('CreateDate') else None,
                    'PasswordLastUsed': user_summary.get('PasswordLastUsed').isoformat() if user_summary.get('PasswordLastUsed') else None,
                    'InlinePoliciesJson': inline_policies_json,
                    # 'AttachedManagedPolicyDocumentsJson': {arn: json.dumps(doc) for arn, doc in attached_managed_policy_docs.items()}, # Removed
                    'HasMfaEnabled': has_mfa_enabled,
                    'AccessKeys': access_key_details # List of dicts, will be JSON serialized by preparer
                }
                # Now append the user resource using user_properties
                resources.append({
                    'arn': user_arn,
                    'resource_id': user_id,
                    'resource_type': 'IamUser',
                    'region': 'global',
                    'account_id': account_id,
                    'properties': user_properties, # Use the dict here
                    'relationships': {
                        'attached_managed_policy_arns': attached_policy_arns,
                        'tags': tags
                    }
                })

                resources.append({
                    'arn': user_arn,
                    'resource_id': user_id,
                    'resource_type': 'IamUser',
                    'region': 'global',
                    'account_id': account_id,
                    'properties': user_properties,
                    'relationships': {
                        'attached_managed_policy_arns': attached_policy_arns,
                        'tags': tags
                    }
                })
                user_count += 1
        logger.debug(f"Found and processed details for {user_count} IAM Users.")

        # --- 4. Scan Groups ---
        logger.debug(f"Scanning IAM Groups for account {account_id}...")
        group_count = 0
        paginator_groups = iam_client.get_paginator('list_groups')
        for page_groups in paginator_groups.paginate():
            for group_summary in page_groups.get('Groups', []):
                group_name = group_summary.get('GroupName')
                group_arn = group_summary.get('Arn')
                group_id = group_summary.get('GroupId')
                if not group_name or not group_arn or not group_id:
                    logger.warning(f"Skipping group summary with missing name, ARN, or ID: {group_summary}")
                    continue
                
                member_user_arns = []
                group_attached_policy_arns = []
                group_inline_policies_json = {}
                
                # Get group members (users)
                try:
                    # Use paginator for get_group if many users per group are expected, but likely overkill
                    group_details = iam_client.get_group(GroupName=group_name)
                    for user in group_details.get('Users', []):
                        if user.get('Arn'):
                            member_user_arns.append(user['Arn'])
                except Exception as get_group_e:
                    logger.warning(f"Could not get members for group {group_name}: {get_group_e}")

                # Get attached managed policies
                try:
                    paginator_attached = iam_client.get_paginator('list_attached_group_policies')
                    for page_attached in paginator_attached.paginate(GroupName=group_name):
                        for attached_policy in page_attached.get('AttachedPolicies', []):
                            policy_arn = attached_policy.get('PolicyArn')
                            if policy_arn:
                                group_attached_policy_arns.append(policy_arn)
                                all_policy_arns_found.add(policy_arn) # Track for AWS managed policy creation
                except Exception as list_attached_e:
                     logger.warning(f"Could not list attached policies for group {group_name}: {list_attached_e}")

                # Get inline policies
                try:
                    paginator_inline = iam_client.get_paginator('list_group_policies')
                    for page_inline in paginator_inline.paginate(GroupName=group_name):
                        for policy_name in page_inline.get('PolicyNames', []):
                            try:
                                policy_detail = iam_client.get_group_policy(GroupName=group_name, PolicyName=policy_name)
                                group_inline_policies_json[policy_name] = json.dumps(policy_detail.get('PolicyDocument', {}))
                            except Exception as get_inline_e:
                                logger.warning(f"Could not get inline policy {policy_name} for group {group_name}: {get_inline_e}")
                                group_inline_policies_json[policy_name] = json.dumps({"_ErrorFetchingPolicy": str(get_inline_e)})
                except Exception as list_inline_e:
                    logger.warning(f"Could not list inline policies for group {group_name}: {list_inline_e}")

                resources.append({
                    'arn': group_arn,
                    'resource_id': group_id,
                    'resource_type': 'IamGroup',
                    'region': 'global',
                    'account_id': account_id,
                    'properties': {
                        'GroupId': group_id,
                        'GroupName': group_name,
                        'Path': group_summary.get('Path'),
                        'CreateDate': group_summary.get('CreateDate').isoformat() if group_summary.get('CreateDate') else None,
                        'InlinePoliciesJson': group_inline_policies_json
                    },
                    'relationships': {
                        'member_user_arns': member_user_arns,
                        'attached_managed_policy_arns': group_attached_policy_arns,
                        'tags': {} # Groups don't have tags via list_groups/get_group
                    }
                })
                group_count += 1
        logger.debug(f"Found and processed details for {group_count} IAM Groups.")
        # --- End Group Scan ---






        # --- New: Create resource items for unprocessed (AWS Managed) policies ---
        aws_policy_count = 0
        logger.debug(f"Processing {len(all_policy_arns_found)} unique policy ARNs found attached or managed...")
        for policy_arn in all_policy_arns_found:
            if policy_arn in processed_policy_arns:
                continue # Skip policies already added as full resource items
            
            # Check if it looks like an AWS managed policy
            if policy_arn.startswith('arn:aws:iam::aws:policy/'):
                try:
                    policy_name = policy_arn.split('/')[-1]
                    # Use ARN as resource_id for AWS managed for simplicity, Neo4j PK is ARN anyway
                    policy_id_part = f"aws/{policy_name}" # Create a pseudo ID
                    
                    resources.append({
                        'arn': policy_arn,
                        'resource_id': policy_arn, # Use ARN as resource_id for these simplified nodes
                        'resource_type': 'IamPolicy',
                        'region': 'global',
                        'account_id': account_id, # Associate with the scanned account
                        'properties': {
                            'PolicyId': policy_id_part, # Pseudo ID
                            'PolicyName': policy_name,
                            'arn': policy_arn,
                            'IsAwsManaged': True, # Mark as AWS managed
                            # We don't fetch the document here, it's in the user/role properties if needed
                        },
                        'relationships': {}
                    })
                    aws_policy_count += 1
                    processed_policy_arns.add(policy_arn) # Mark as processed
                    
                    # --- Get Entities attached to this AWS Managed Policy Stub ---
                    attached_user_names_aws = []
                    attached_group_names_aws = []
                    attached_role_names_aws = []
                    try:
                        paginator_entities_aws = iam_client.get_paginator('list_entities_for_policy')
                        for page_entities_aws in paginator_entities_aws.paginate(PolicyArn=policy_arn):
                            for user in page_entities_aws.get('PolicyUsers', []):
                                attached_user_names_aws.append(user.get('UserName'))
                            for group in page_entities_aws.get('PolicyGroups', []):
                                attached_group_names_aws.append(group.get('GroupName'))
                            for role in page_entities_aws.get('PolicyRoles', []):
                                attached_role_names_aws.append(role.get('RoleName'))
                        # Add to the relationships of the IamPolicy resource just created
                        # The resource is the last one appended inside this loop iteration
                        resources[-1]['relationships']['attached_user_names'] = list(set(filter(None, attached_user_names_aws)))
                        resources[-1]['relationships']['attached_group_names'] = list(set(filter(None, attached_group_names_aws)))
                        resources[-1]['relationships']['attached_role_names'] = list(set(filter(None, attached_role_names_aws)))
                    except Exception as list_entities_aws_e:
                        logger.warning(f"Could not list entities for AWS policy {policy_arn}: {list_entities_aws_e}")
                    # --- End Get Attached Entities ---
                except Exception as parse_e:
                     logger.warning(f"Failed to parse AWS managed policy ARN {policy_arn}: {parse_e}")
            else:
                # This case should ideally not happen if customer managed logic is correct
                logger.warning(f"Found unprocessed policy ARN that is not AWS managed and wasn't processed earlier: {policy_arn}")

        logger.debug(f"Created resource entries for {aws_policy_count} attached AWS Managed IAM Policies.")
        # --- End New Section ---

        # --- 4. Scan Account Settings (Password Policy, Summary) ---
        account_settings = {
             'resource_id': f"{account_id}-AccountSettings",
             'resource_type': 'AccountSettings',
             'region': 'global',
             'account_id': account_id,
             'properties': {},
             'relationships': {}
        }
        logger.debug(f"Getting IAM Account Summary for account {account_id}...")
        try:
             summary = iam_client.get_account_summary()
             account_settings['properties']['AccountSummary'] = summary.get('SummaryMap', {})
        except Exception as summary_e:
            logger.error(f"Could not get IAM account summary: {summary_e}")
            account_settings['properties']['AccountSummaryError'] = str(summary_e)
            
        logger.debug(f"Getting IAM Password Policy for account {account_id}...")
        try:
            password_policy = iam_client.get_account_password_policy()
            account_settings['properties']['PasswordPolicy'] = password_policy.get('PasswordPolicy', {})
        except iam_client.exceptions.NoSuchEntityException:
             logger.info("No account password policy found.")
             account_settings['properties']['PasswordPolicy'] = None
        except Exception as pp_e:
            logger.error(f"Could not get IAM password policy: {pp_e}")
            account_settings['properties']['PasswordPolicyError'] = str(pp_e)
        
        if account_settings['properties']:
             resources.append(account_settings)

    except Exception as e:
        logger.error(f"Error scanning IAM for account {account_id}: {str(e)}")
        logger.error(traceback.format_exc())

    return resources 