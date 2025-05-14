import traceback
import json # For complex dicts like VpcConfig
from typing import List, Dict, Any

from loguru import logger

from app.providers.aws_provider import AwsProvider
from app.services.scanners.utils import format_tags, _parse_s3_policy_principals # Add tag support and principal parser

def scan_lambda(aws_provider: AwsProvider, region: str) -> List[Dict[str, Any]]:
    """Scan Lambda functions in a specific region, formatted for graph builder."""
    lambda_client = aws_provider.get_client("lambda", region=region)
    resources = []
    account_id = aws_provider.account_id
    func_count = 0

    try:
        logger.debug(f"Scanning Lambda Functions in {region} for account {account_id}...")
        paginator = lambda_client.get_paginator('list_functions')
        functions_list = []
        for page in paginator.paginate():
            functions_list.extend(page.get('Functions', []))
        
        logger.debug(f"Found {len(functions_list)} Lambda Functions in {region}. Fetching details...")
        
        for function_summary in functions_list:
            func_name = function_summary.get('FunctionName')
            func_arn = function_summary.get('FunctionArn')
            if not func_name or not func_arn:
                logger.warning(f"Skipping function summary without Name or ARN: {function_summary}")
                continue
            
            properties = {}
            relationships = {}
            # Use ARN as the primary resource ID for consistency
            resource_id = func_arn 

            try:
                # Get main configuration
                function_config = lambda_client.get_function_configuration(FunctionName=func_name)
                
                # Get tags separately
                try:
                    tag_response = lambda_client.list_tags(Resource=func_arn)
                    tags = format_tags(tag_response.get('Tags', {}))
                except Exception as tag_e:
                    logger.warning(f"Could not get tags for Lambda {func_name} ({func_arn}): {tag_e}")
                    tags = {"_Error_Tags": str(tag_e)}
                
                # Extract Properties
                vpc_config = function_config.get('VpcConfig', {})
                tracing_config = function_config.get('TracingConfig', {})
                dead_letter_config = function_config.get('DeadLetterConfig', {})
                environment_vars = function_config.get('Environment', {}).get('Variables')

                # -- Parse Environment Variables for sensitive keys --
                potentially_sensitive_keys = []
                has_potentially_sensitive_env = False
                if environment_vars:
                    sensitive_keywords = {'SECRET', 'PASSWORD', 'API_KEY', 'TOKEN', 'PASSWD'}
                    for key in environment_vars.keys():
                        key_upper = key.upper()
                        for keyword in sensitive_keywords:
                            if keyword in key_upper:
                                potentially_sensitive_keys.append(key)
                                has_potentially_sensitive_env = True
                                break # Move to next key once a keyword is found
                # Ensure uniqueness (though unlikely for keys)
                potentially_sensitive_keys = list(set(potentially_sensitive_keys))
                # -- End Environment Variable Parsing --

                properties = {
                    'FunctionName': func_name,
                    'Runtime': function_config.get('Runtime'),
                    'Handler': function_config.get('Handler'),
                    'CodeSize': function_config.get('CodeSize'),
                    'Timeout': function_config.get('Timeout'),
                    'MemorySize': function_config.get('MemorySize'),
                    'LastModified': function_config.get('LastModified'),
                    'Description': function_config.get('Description'),
                    'VpcConfig': json.dumps(vpc_config) if vpc_config else None,
                    'TracingConfigMode': tracing_config.get('Mode'),
                    'DeadLetterTargetArn': dead_letter_config.get('TargetArn'),
                    'EnvironmentVariablesJson': json.dumps(environment_vars) if environment_vars else None,
                    'PotentiallySensitiveEnvKeys': potentially_sensitive_keys,
                    'HasPotentiallySensitiveEnv': has_potentially_sensitive_env,
                    'KMSKeyArn': function_config.get('KMSKeyArn'),
                    'Architectures': function_config.get('Architectures', []),
                    'EphemeralStorageSize': function_config.get('EphemeralStorage', {}).get('Size')
                    # Add Layers, FileSystemConfigs if needed
                }

                # Extract Relationships
                role_arn = function_config.get('Role')
                subnet_ids = vpc_config.get('SubnetIds', [])
                security_group_ids = vpc_config.get('SecurityGroupIds', [])
                dlq_target_arn = dead_letter_config.get('TargetArn') # Can be SQS or SNS

                relationships = {
                    'execution_role_arn': role_arn,
                    'subnet_ids': subnet_ids,
                    'security_group_ids': security_group_ids,
                    'dlq_target_arn': dlq_target_arn,
                    'tags': tags
                    # TODO: Consider relationships to Layers, EFS
                }

                # Get Function URL Config (optional)
                try:
                    url_config = lambda_client.get_function_url_config(FunctionName=func_name)
                    properties['FunctionUrlConfig'] = {
                        'AuthType': url_config.get('AuthType'),
                        'FunctionUrl': url_config.get('FunctionUrl'),
                        'Cors': url_config.get('Cors')
                    }
                except lambda_client.exceptions.ResourceNotFoundException:
                    properties['FunctionUrlConfig'] = None # No URL config exists
                except Exception as url_e:
                    logger.warning(f"Could not get Function URL config for {func_name}: {url_e}")
                    properties['FunctionUrlConfig'] = {'_Error': str(url_e)}

            except Exception as config_e:
                 logger.warning(f"Could not get full configuration for Lambda {func_name} ({func_arn}): {config_e}")
                 properties = {
                     'FunctionName': func_name,
                     '_Error_Configuration': str(config_e)
                 }
                 relationships = {'tags': {"_Error_Tags": "Skipped due to config error"}}

            # -- Get Lambda Resource Policy --
            lambda_policy_str = None
            try:
                policy_response = lambda_client.get_policy(FunctionName=func_name)
                lambda_policy_str = policy_response.get('Policy') # Stringified JSON
            except lambda_client.exceptions.ResourceNotFoundException:
                logger.debug(f"No resource policy found for Lambda {func_name}.")
            except Exception as policy_e:
                logger.warning(f"Could not get resource policy for Lambda {func_name}: {policy_e}")
                # Optionally store error in properties of LambdaFunction node
                properties['ResourcePolicyError'] = str(policy_e)
            
            # Add original policy string to properties if found
            if lambda_policy_str:
                 properties['ResourcePolicyJson'] = lambda_policy_str

                # --- Parse Lambda Policy into Statement nodes ---
                 try:
                     policy_doc = json.loads(lambda_policy_str)
                     statements = policy_doc.get('Statement', [])
                     if not isinstance(statements, list):
                         statements = [statements] 
                     
                     for stmt_idx, statement in enumerate(statements):
                         if not isinstance(statement, dict):
                             logger.warning(f"Skipping non-dict statement in Lambda resource policy for {func_name}: {statement}")
                             continue

                         sid = statement.get('Sid', f'LambdaStmt{stmt_idx}')
                         effect = statement.get('Effect')
                         principal_block = statement.get('Principal')
                         action_block = statement.get('Action')
                         resource_from_stmt = statement.get('Resource') # Usually the function ARN itself
                         condition_block = statement.get('Condition')

                         # Use the S3 principal parser for now, it handles AWS/Service/* etc.
                         # We might need a more specific one if Lambda uses other principal types often.
                         parsed_principals = _parse_s3_policy_principals(principal_block)

                         actions = []
                         if isinstance(action_block, str): actions = [action_block]
                         elif isinstance(action_block, list): actions = action_block

                         statement_id = f"{func_arn}-{sid}" 
                         statement_arn = f"{func_arn}/resourcepolicy/statement/{sid}" # Pseudo ARN

                         resources.append({
                             'arn': statement_arn,
                             'resource_id': statement_id,
                             'resource_type': 'LambdaResourcePolicyStatement',
                             'region': region,
                             'account_id': account_id,
                             'properties': {
                                 'Sid': sid,
                                 'Effect': effect,
                                 'Principal_AWS': parsed_principals['aws_principals'],
                                 'Principal_Service': parsed_principals['service_principals'],
                                 'IsPrincipalWildcard': parsed_principals['is_wildcard_principal'],
                                 'OriginalPrincipalBlockJson': json.dumps(parsed_principals['original_principal_block']) if parsed_principals['original_principal_block'] else None,
                                 'Action': actions,
                                 'Resource': resource_from_stmt,
                                 'ConditionJson': json.dumps(condition_block) if condition_block else None,
                             },
                             'relationships': {
                                 'applies_to_lambda_arn': func_arn
                             }
                         })
                 except json.JSONDecodeError as json_e:
                     logger.warning(f"Could not parse Lambda resource policy JSON for {func_name}: {json_e}. Policy string: {lambda_policy_str}")
                     properties['ResourcePolicyError'] = f"JSONDecodeError: {json_e}"
                 except Exception as parse_stmt_e:
                     logger.error(f"Error processing Lambda resource policy statements for {func_name}: {parse_stmt_e}")
                     properties['ResourcePolicyError'] = f"StatementProcessingError: {parse_stmt_e}"
                 # --- End Lambda Policy Parsing ---
            # -- End Lambda Resource Policy --

            # Append the structured resource data
            resources.append({
                'arn': func_arn,
                'resource_id': resource_id, # Using ARN as primary ID
                'resource_type': 'LambdaFunction',
                'region': region,
                'account_id': account_id,
                'properties': {k: v for k, v in properties.items() if v is not None},
                'relationships': relationships
            })
            func_count += 1
            
        logger.debug(f"Processed details for {func_count} Lambda Functions in {region}.")

        # --- Scan Event Source Mappings ---
        logger.debug(f"Scanning Lambda Event Source Mappings in {region}...")
        esm_count = 0
        try:
            paginator_esm = lambda_client.get_paginator('list_event_source_mappings')
            for page_esm in paginator_esm.paginate():
                for mapping in page_esm.get('EventSourceMappings', []):
                    uuid = mapping.get('UUID')
                    if not uuid: continue # Need UUID as primary ID
                    
                    function_arn = mapping.get('FunctionArn')
                    event_source_arn = mapping.get('EventSourceArn')
                    # Construct a pseudo-ARN for the mapping
                    esm_arn = f"arn:aws:lambda:{region}:{account_id}:event-source-mapping/{uuid}"

                    resources.append({
                        'arn': esm_arn,
                        'resource_id': uuid, # Use UUID as resource_id
                        'resource_type': 'LambdaEventSourceMapping',
                        'region': region,
                        'account_id': account_id,
                        'properties': {
                            'UUID': uuid,
                            'BatchSize': mapping.get('BatchSize'),
                            'MaximumBatchingWindowInSeconds': mapping.get('MaximumBatchingWindowInSeconds'),
                            'ParallelizationFactor': mapping.get('ParallelizationFactor'),
                            'EventSourceArn': event_source_arn,
                            'FunctionArn': function_arn,
                            'LastModified': mapping.get('LastModified').isoformat() if mapping.get('LastModified') else None,
                            'LastProcessingResult': mapping.get('LastProcessingResult'),
                            'State': mapping.get('State'),
                            'StateTransitionReason': mapping.get('StateTransitionReason'),
                            'StartingPosition': mapping.get('StartingPosition'), # For Kinesis/DynamoDB
                            'BisectBatchOnFunctionError': mapping.get('BisectBatchOnFunctionError'),
                            'MaximumRetryAttempts': mapping.get('MaximumRetryAttempts')
                            # Add other specific config fields if needed (e.g., Queues, Topics, TumblingWindowInSeconds, FunctionResponseTypes)
                        },
                        'relationships': {
                            'function_arn': function_arn,
                            'event_source_arn': event_source_arn
                        }
                    })
                    esm_count += 1
            logger.debug(f"Found {esm_count} Lambda Event Source Mappings in {region}.")
        except Exception as esm_e:
            logger.error(f"Error scanning Lambda Event Source Mappings in {region}: {esm_e}")
        # --- End Event Source Mapping Scan ---

    except Exception as e:
        logger.error(f"Error scanning Lambda in {region} for account {account_id}: {str(e)}")
        logger.error(traceback.format_exc())

    return resources 