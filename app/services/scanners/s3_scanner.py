import traceback
import json # For policy document
import hashlib # For generating grant IDs
from typing import List, Dict, Any

from loguru import logger
from botocore.exceptions import ClientError # Import ClientError

from app.providers.aws_provider import AwsProvider
from app.services.scanners.utils import format_tags, _parse_s3_policy_principals # Import new helper

# --- Helper function to parse S3 Bucket Policy Principals ---
# MOVED TO UTILS.PY
# def _parse_s3_policy_principals(principal_block: Any) -> Dict[str, Any]:
#    ...
# --- End Helper ---

def scan_s3(aws_provider: AwsProvider) -> List[Dict[str, Any]]:
    """Scan S3 buckets and their configurations, extracting ACL grants as separate nodes."""
    s3_client = aws_provider.get_client("s3")
    # Use the provider's resolved account ID
    account_id = aws_provider.account_id 
    resources = []
    
    try:
        logger.debug(f"Scanning S3 Buckets for account {account_id}...")
        buckets = s3_client.list_buckets()
        bucket_list = buckets.get("Buckets", [])
        logger.debug(f"Found {len(bucket_list)} S3 Buckets initially.")

        for bucket in bucket_list:
            bucket_name = bucket["Name"]
            # S3 ARN format: arn:aws:s3:::bucket_name
            arn = f"arn:aws:s3:::{bucket_name}"
            creation_date = bucket['CreationDate'].isoformat() if bucket.get('CreationDate') else None
            logger.debug(f"Processing bucket: {bucket_name}")
            
            bucket_region = None
            try:
                # Determine the bucket's region
                location_response = s3_client.get_bucket_location(Bucket=bucket_name)
                # LocationConstraint is None for us-east-1
                bucket_region = location_response.get('LocationConstraint') or 'us-east-1' 
            except Exception as loc_e:
                 logger.warning(f"Could not get location for bucket {bucket_name}: {loc_e}. Skipping detail checks.")
                 # Create a minimal record indicating the error
                 resources.append({
                    'arn': arn,
                    'resource_id': bucket_name,
                    'resource_type': 'S3Bucket',
                    'region': 'unknown',
                    'account_id': account_id,
                    'properties': {'Name': bucket_name, 'CreationDate': creation_date, '_Error_Location': str(loc_e)},
                    'relationships': {}
                 })
                 continue

            # Get tags (requires correct region client potentially)
            tags = {}
            policy = None
            policy_str = None # Initialize policy_str to None
            policy_status = None
            acl_grants = []
            public_access_block = {}
            encryption = {}
            versioning_status = 'Disabled'
            mfa_delete = 'Disabled'
            logging_config = None
            
            try:
                regional_s3_client = aws_provider.get_client("s3", region=bucket_region)
            except Exception as client_e:
                 logger.warning(f"Could not create regional S3 client for {bucket_region} for bucket {bucket_name}: {client_e}. Storing error.")
                 # Store error but continue to add basic info
                 properties = {
                     'Name': bucket_name,
                     'CreationDate': creation_date,
                     '_Error_RegionalClient': str(client_e)
                 }
                 resources.append({
                     'arn': arn,
                     'resource_id': bucket_name,
                     'resource_type': 'S3Bucket',
                     'region': bucket_region,
                     'account_id': account_id,
                     'properties': properties,
                     'relationships': {}
                 })
                 continue # Skip detailed checks if client fails

            # Get Tags
            try:
                 tag_response = regional_s3_client.get_bucket_tagging(Bucket=bucket_name)
                 tags = format_tags(tag_response.get('TagSet', []))
            except regional_s3_client.exceptions.ClientError as tag_e:
                if tag_e.response.get('Error', {}).get('Code') == 'NoSuchTagSet':
                     logger.debug(f"No tags found for bucket {bucket_name}")
                else:
                     logger.warning(f"Could not get tags for bucket {bucket_name}: {tag_e}")
            except Exception as tag_e: # Catch other potential errors
                 logger.warning(f"Unexpected error getting tags for bucket {bucket_name}: {tag_e}")
            
            # Get Public Access Block
            try:
                pab_response = regional_s3_client.get_public_access_block(Bucket=bucket_name)
                public_access_block = pab_response.get('PublicAccessBlockConfiguration', {})
            except regional_s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
                logger.debug(f"No Public Access Block configuration found for bucket {bucket_name}")
                public_access_block = {} # Represent as empty / default (all false)
            except Exception as pab_e:
                 logger.warning(f"Could not get Public Access Block for bucket {bucket_name}: {pab_e}")
                 public_access_block = {'_Error': str(pab_e)}

            # Get Bucket Policy Status (Public or not) & Policy Document
            try:
                policy_status_response = regional_s3_client.get_bucket_policy_status(Bucket=bucket_name)
                policy_status = policy_status_response.get('PolicyStatus', {}).get('IsPublic', False)
            except ClientError as e: # More general catch
                if e.response.get('Error', {}).get('Code') == 'NoSuchBucketPolicy':
                    logger.debug(f"Policy status check indicates no policy for bucket {bucket_name} (NoSuchBucketPolicy from GetBucketPolicyStatus).")
                    policy_status = False # No policy means not public via policy
                else:
                    logger.warning(f"Could not get policy status for bucket {bucket_name} (ClientError): {e}")
                    policy_status = None # Indicate unknown status due to error
            except Exception as ps_e:
                logger.warning(f"Could not get policy status for bucket {bucket_name}: {ps_e}")
                policy_status = None # Indicate unknown status due to error
            
            try:
                policy_response = regional_s3_client.get_bucket_policy(Bucket=bucket_name)
                policy_str = policy_response.get('Policy') # Returns stringified JSON
                if policy_str:
                    try:
                        policy_doc = json.loads(policy_str)
                        statements = policy_doc.get('Statement', [])
                        if not isinstance(statements, list):
                            statements = [statements] # Handle single statement object
                        
                        for stmt_idx, statement in enumerate(statements):
                            if not isinstance(statement, dict):
                                logger.warning(f"Skipping non-dict statement in bucket policy for {bucket_name}: {statement}")
                                continue

                            sid = statement.get('Sid', f'Stmt{stmt_idx}')
                            effect = statement.get('Effect')
                            principal_block = statement.get('Principal')
                            action_block = statement.get('Action')
                            not_action_block = statement.get('NotAction')
                            resource_block = statement.get('Resource')
                            not_resource_block = statement.get('NotResource')
                            condition_block = statement.get('Condition')

                            parsed_principals = _parse_s3_policy_principals(principal_block)

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

                            statement_id = f"{bucket_name}-{sid}" # Simple ID for now
                            statement_arn = f"{arn}/policystatement/{sid}" # Pseudo ARN

                            resources.append({
                                'arn': statement_arn,
                                'resource_id': statement_id,
                                'resource_type': 'S3BucketPolicyStatement',
                                'region': bucket_region,
                                'account_id': account_id,
                                'properties': {
                                    'Sid': sid,
                                    'Effect': effect,
                                    'Principal_AWS': parsed_principals['aws_principals'],
                                    'Principal_Service': parsed_principals['service_principals'],
                                    'Principal_CanonicalUser': parsed_principals['canonical_user_principals'],
                                    'Principal_Federated': parsed_principals['federated_principals'],
                                    'IsPrincipalWildcard': parsed_principals['is_wildcard_principal'],
                                    'OriginalPrincipalBlockJson': json.dumps(parsed_principals['original_principal_block']) if parsed_principals['original_principal_block'] else None,
                                    'Action': actions,
                                    'NotAction': not_actions,
                                    'Resource': resources_list,
                                    'NotResource': not_resources_list,
                                    'ConditionJson': json.dumps(condition_block) if condition_block else None,
                                },
                                'relationships': {
                                    'applies_to_bucket_arn': arn,
                                    'applies_to_bucket_name': bucket_name
                                }
                            })
                    except json.JSONDecodeError as json_e:
                        logger.warning(f"Could not parse policy JSON for bucket {bucket_name}: {json_e}. Policy string: {policy_str}")
                        policy = json.dumps({'_ErrorParsingPolicy': str(json_e), '_OriginalPolicyString': policy_str}) # Keep original bad string
                    except Exception as parse_stmt_e:
                        logger.error(f"Error processing policy statements for bucket {bucket_name}: {parse_stmt_e}")
                        policy = json.dumps({'_ErrorProcessingStatements': str(parse_stmt_e), '_OriginalPolicyString': policy_str})
                else: # policy_str is None
                    policy = None # Ensure policy property on bucket is None if no policy string

            except ClientError as e: # More general catch for get_bucket_policy
                if e.response.get('Error', {}).get('Code') == 'NoSuchBucketPolicy':
                    logger.debug(f"No bucket policy document found for bucket {bucket_name} (NoSuchBucketPolicy from GetBucketPolicy).")
                    policy = None
                else:
                    logger.warning(f"Could not get policy document for bucket {bucket_name} (ClientError): {e}")
                    policy = json.dumps({'_Error': str(e)}) # Store error as JSON
            except Exception as policy_e:
                 logger.warning(f"Could not get policy document for bucket {bucket_name}: {policy_e}")
                 policy = json.dumps({'_Error': str(policy_e)}) # Store error as JSON

            # Get Bucket ACL (only grants needed typically)
            try:
                acl_response = regional_s3_client.get_bucket_acl(Bucket=bucket_name)
                acl_grants_raw = acl_response.get('Grants', [])
                for grant in acl_grants_raw:
                    grantee = grant.get('Grantee', {})
                    permission = grant.get('Permission')
                    grantee_type = grantee.get('Type')
                    grantee_id = grantee.get('ID')
                    grantee_uri = grantee.get('URI')
                    grantee_display_name = grantee.get('DisplayName')
                    
                    if not permission or not grantee_type:
                        logger.warning(f"Skipping incomplete ACL grant for bucket {bucket_name}: {grant}")
                        continue
                        
                    # Generate a unique ID for the grant
                    grant_identifier = grantee_id or grantee_uri # Use ID if available, else URI
                    if not grant_identifier:
                         logger.warning(f"Skipping ACL grant for bucket {bucket_name} with no Grantee ID or URI: {grant}")
                         continue
                         
                    hasher = hashlib.md5()
                    identity_string = f"{bucket_name}-{grantee_type}-{grant_identifier}-{permission}"
                    hasher.update(identity_string.encode('utf-8'))
                    grant_id = hasher.hexdigest()
                    grant_arn = f"arn:aws:s3:::{bucket_name}/acl/grant/{grant_id}" # Pseudo ARN

                    resources.append({
                        'arn': grant_arn,
                        'resource_id': grant_id,
                        'resource_type': 'S3ACLGrant',
                        'region': bucket_region, # Grant is tied to the bucket's region conceptually
                        'account_id': account_id,
                        'properties': {
                            'GranteeType': grantee_type,
                            'GranteeID': grantee_id,
                            'GranteeURI': grantee_uri,
                            'GranteeDisplayName': grantee_display_name,
                            'Permission': permission
                        },
                        'relationships': {
                            'applies_to_bucket_name': bucket_name
                        }
                    })

            except Exception as acl_e:
                 logger.error(f"Could not process ACL for bucket {bucket_name}: {acl_e}")
                 # Optionally add an error marker to the bucket node or skip grants

            # Get Encryption Config
            try:
                enc_response = regional_s3_client.get_bucket_encryption(Bucket=bucket_name)
                encryption = enc_response.get('ServerSideEncryptionConfiguration', {})
            except regional_s3_client.exceptions.ServerSideEncryptionConfigurationNotFoundError:
                 logger.debug(f"No SSE configuration found for bucket {bucket_name}")
                 encryption = {} # Represent as default / none
            except Exception as enc_e:
                 logger.warning(f"Could not get Encryption for bucket {bucket_name}: {enc_e}")
                 encryption = {'_Error': str(enc_e)}
            
            # Get Versioning Config
            try:
                ver_response = regional_s3_client.get_bucket_versioning(Bucket=bucket_name)
                versioning_status = ver_response.get('Status', 'Disabled') # Can be Enabled or Suspended
                mfa_delete = ver_response.get('MFADelete', 'Disabled') # Can be Enabled or Disabled
            except Exception as ver_e:
                logger.warning(f"Could not get Versioning for bucket {bucket_name}: {ver_e}")
                versioning_status = {'_Error': str(ver_e)}
                mfa_delete = {'_Error': str(ver_e)}
            
            # Get Logging Config
            try:
                log_response = regional_s3_client.get_bucket_logging(Bucket=bucket_name)
                logging_config = log_response.get('LoggingEnabled') # Contains TargetBucket, TargetPrefix
            except Exception as log_e:
                logger.warning(f"Could not get Logging for bucket {bucket_name}: {log_e}")
                logging_config = {'_Error': str(log_e)}

            # Assemble final resource dictionary
            properties = {
                'Name': bucket_name,
                'CreationDate': creation_date,
                'Region': bucket_region,
                'PublicAccessBlockConfiguration': public_access_block,
                'IsPublicByPolicy': policy_status,
                'Policy': policy_str if policy_str else None, # Store original policy string (might be None)
                'ServerSideEncryptionConfiguration': encryption, # Store dict or error dict
                'VersioningStatus': versioning_status, # Store status string or error dict
                'MFADeleteStatus': mfa_delete, # Store status string or error dict
                'LoggingConfiguration': logging_config # Store dict or error dict or None
            }
            
            resources.append({
                'arn': arn,
                'resource_id': bucket_name,
                'resource_type': 'S3Bucket',
                'region': bucket_region,
                'account_id': account_id,
                'properties': properties,
                'relationships': {
                    'tags': tags
                    # S3 doesn't have many direct structural relationships to other resources
                }
            })
        
        logger.debug(f"Processed details for {len(resources)} S3 Buckets.")

    except Exception as e:
        logger.error(f"Error scanning S3 for account {account_id}: {str(e)}")
        logger.error(traceback.format_exc())
        # Consider adding a placeholder error resource
        # resources.append({'Type': 'Error', 'Details': {'Service': 'S3', 'Account': account_id, 'Error': str(e)}})

    return resources 