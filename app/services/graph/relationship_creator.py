import logging
from typing import Any, Dict, List, Tuple, Optional

from app.core.exceptions import DatabaseError
from app.db.graph_db import Neo4jClient
# Import constants and utility functions needed for create_relationships
from app.services.graph.constants import RESOURCE_TYPE_TO_LABEL, RESOURCE_TYPE_PRIMARY_KEY
from app.services.graph.utils import _get_pk_value


def execute_relationship_queries(
    client: Neo4jClient, 
    is_enabled: bool, 
    queries_params_list: List[Tuple[str, Dict[str, Any]]],
    logger: logging.Logger
):
    """Executes a list of relationship Cypher queries."""
    if not is_enabled:
        logger.info("Relationship query execution skipped as graph builder is not enabled.")
        return
        
    logger.info(f"Executing {len(queries_params_list)} relationship queries...")
    success_count = 0
    fail_count = 0
    for query, params_dict in queries_params_list:
        try:
            client.run(query, parameters=params_dict)
            success_count += 1
        except DatabaseError as e:
            # Log params that might contain sensitive info carefully
            logger.error(f"Failed relationship query. Error: {e} Query: {query[:500]}... Params: {list(params_dict.keys())}")
            fail_count += 1
        except Exception as e:
            logger.error(f"Unexpected error on relationship query. Error: {e} Query: {query[:500]}... Params: {list(params_dict.keys())}")
            fail_count += 1
    logger.info(f"Relationship query execution complete. Success: {success_count}, Failed: {fail_count}")

def create_relationships(
    resource_data: Dict[str, Any], 
    deferred_rels_data: Dict[str, List], 
    logger: logging.Logger
) -> List[Tuple[str, Dict[str, Any]]]:
    """Generates relationship creation queries for a single resource."""
    resource_type = resource_data.get('resource_type')
    source_label = RESOURCE_TYPE_TO_LABEL.get(resource_type)
    source_pk_field = RESOURCE_TYPE_PRIMARY_KEY.get(source_label)

    if not source_label or not source_pk_field:
        return [] # Skip if source type or PK is not defined

    source_pk_value = _get_pk_value(resource_data, source_pk_field, source_label) # _get_pk_value is from .utils
    if source_pk_value is None:
        return []

    relationships = resource_data.get('relationships', {})
    queries_params: List[Tuple[str, Dict[str, Any]]] = []
    param_counter = 0

    def add_rel_query(src_lbl, src_pkf, src_pkv, rel_type, tgt_lbl, tgt_pkf, tgt_pkv, rel_props=None):
        nonlocal param_counter
        if not tgt_pkv:
            logger.trace(f"Skipping {rel_type} from {src_lbl} {src_pkv} to {tgt_lbl}: target PK value missing.")
            return
        
        param_src = f"src_p_{param_counter}"
        param_tgt = f"tgt_p_{param_counter}"
        current_params = {param_src: src_pkv, param_tgt: tgt_pkv}
        props_cypher = ""
        if rel_props:
            props_param = f"props_{param_counter}"
            current_params[props_param] = {k: v for k, v in rel_props.items() if v is not None} # Clean None props
            if current_params[props_param]: # Only add SET if there are non-None props
                props_cypher = f" SET r = ${props_param}" # Overwrite props

        query = (
            f"MATCH (src:{src_lbl} {{{src_pkf}: ${param_src}}}), "
            f"(tgt:{tgt_lbl} {{{tgt_pkf}: ${param_tgt}}}) "
            f"MERGE (src)-[r:{rel_type}]->(tgt)"
            f"{props_cypher}"
        )
        queries_params.append((query, current_params))
        param_counter += 1

    # --- Define Relationship Logic --- 

    # 0. Resource -> Region [IN_REGION] & Account -> Region [CONTAINS]
    account_id = resource_data.get('account_id')
    region_name = resource_data.get('region')
    if region_name and region_name != 'global' and account_id:
        add_rel_query(source_label, source_pk_field, source_pk_value, 'IN_REGION', 'Region', 'id', region_name)
        add_rel_query('AwsAccount', 'id', account_id, 'CONTAINS', 'Region', 'id', region_name)
    elif account_id and source_label != 'AwsAccount': # Link global resources to account
            add_rel_query('AwsAccount', 'id', account_id, 'CONTAINS', source_label, source_pk_field, source_pk_value)
    
    # 1. Resource -> Tag [HAS_TAG]
    if relationships.get('tags'):
        for key, value in relationships['tags'].items():
                add_rel_query(source_label, source_pk_field, source_pk_value, 'HAS_TAG', 'Tag', 'key_value', f"{key}||{value}")

    # 2. EC2Instance -> Subnet [IN_SUBNET]
    if source_label == 'Ec2Instance' and relationships.get('subnet_id'):
        add_rel_query(source_label, source_pk_field, source_pk_value, 'IN_SUBNET', 'Subnet', 'resource_id', relationships['subnet_id'])

    # 3. Subnet -> VPC [IN_VPC]
    if source_label == 'Subnet' and relationships.get('vpc_id'):
        add_rel_query(source_label, source_pk_field, source_pk_value, 'IN_VPC', 'Vpc', 'resource_id', relationships['vpc_id'])

    # 4. EC2Instance -> Role [INSTANCE_PROFILE_FOR]
    if source_label == 'Ec2Instance' and relationships.get('iam_role_arn'): # Uses derived role ARN
            add_rel_query('IamRole', 'arn', relationships['iam_role_arn'], 'INSTANCE_PROFILE_FOR', source_label, source_pk_field, source_pk_value)

    # 5. SecurityGroup -> Resource [APPLIES_TO] - Store for deferred creation
    if source_label in ['Ec2Instance', 'DbInstance', 'LambdaFunction'] and relationships.get('security_group_ids'):
        rel_type = 'APPLIES_TO'
        if rel_type not in deferred_rels_data: deferred_rels_data[rel_type] = []
        for sg_id in relationships['security_group_ids']:
            deferred_rels_data[rel_type].append((
                'SecurityGroup', 'resource_id', sg_id, rel_type, 
                source_label, source_pk_field, source_pk_value, None
            ))

    # 6. Principal -> Policy [HAS_POLICY]
    if source_label in ['IamRole', 'IamUser'] and relationships.get('attached_managed_policy_arns'):
        for policy_arn in relationships['attached_managed_policy_arns']:
            add_rel_query(source_label, source_pk_field, source_pk_value, 'HAS_POLICY', 'IamPolicy', 'arn', policy_arn)

    # 6a. Group -> User [HAS_MEMBER]
    if source_label == 'IamGroup' and relationships.get('member_user_arns'):
        for user_arn in relationships['member_user_arns']:
            add_rel_query(
                source_label,                               # src_lbl (IamGroup)
                source_pk_field,                            # src_pkf (arn)
                source_pk_value,                            # src_pkv (group arn)
                'HAS_MEMBER',                               # rel_type
                'IamUser',                                  # tgt_lbl
                RESOURCE_TYPE_PRIMARY_KEY.get('IamUser'),  # tgt_pkf (arn)
                user_arn                                    # tgt_pkv
            )

    # 6b. Group -> Policy [HAS_POLICY]
    if source_label == 'IamGroup' and relationships.get('attached_managed_policy_arns'):
        for policy_arn in relationships['attached_managed_policy_arns']:
            add_rel_query(
                source_label,                               # src_lbl (IamGroup)
                source_pk_field,                            # src_pkf (arn)
                source_pk_value,                            # src_pkv (group arn)
                'HAS_POLICY',                               # rel_type
                'IamPolicy',                                # tgt_lbl
                RESOURCE_TYPE_PRIMARY_KEY.get('IamPolicy'), # tgt_pkf (arn)
                policy_arn                                  # tgt_pkv
            )

    # 7. RouteTable -> Subnet [ASSOCIATED_WITH]
    if source_label == 'RouteTable' and relationships.get('associated_subnet_ids'):
            for subnet_id in relationships['associated_subnet_ids']:
                add_rel_query(source_label, source_pk_field, source_pk_value, 'ASSOCIATED_WITH', 'Subnet', 'resource_id', subnet_id)

    # 8. RouteTable -> Target (IGW, NAT GW, Instance etc) [ROUTES_TO]
    if source_label == 'RouteTable' and relationships.get('routes_targets'):
            for route_target in relationships['routes_targets']:
                target_id = route_target.get('target_id')
                target_type_scanner = route_target.get('target_type') # Type from scanner
                target_label = RESOURCE_TYPE_TO_LABEL.get(target_type_scanner)
                target_pk_field = RESOURCE_TYPE_PRIMARY_KEY.get(target_label) if target_label else None

                if target_id and target_label and target_pk_field:
                    rel_props = {'destination': route_target.get('destination')} if route_target.get('destination') else None
                    add_rel_query(source_label, source_pk_field, source_pk_value, 'ROUTES_TO', target_label, target_pk_field, target_id, rel_props=rel_props)
                elif target_id and target_type_scanner != 'local': # Ignore 'local' routes silently
                    logger.warning(f"Could not map route target type '{target_type_scanner}' (ID: {target_id}) to a graph node for RT {source_pk_value}.")

    # 9. InternetGateway -> VPC [ATTACHED_TO]
    if source_label == 'InternetGateway' and relationships.get('attached_vpc_id'):
        add_rel_query(source_label, source_pk_field, source_pk_value, 'ATTACHED_TO', 'Vpc', 'resource_id', relationships['attached_vpc_id'])
    
    # 10. NatGateway -> Subnet [IN_SUBNET]
    if source_label == 'NatGateway' and relationships.get('subnet_id'):
            add_rel_query(source_label, source_pk_field, source_pk_value, 'IN_SUBNET', 'Subnet', 'resource_id', relationships['subnet_id'])

    # 11. NatGateway -> Vpc [IN_VPC]
    if source_label == 'NatGateway' and relationships.get('vpc_id'):
            add_rel_query(source_label, source_pk_field, source_pk_value, 'IN_VPC', 'Vpc', 'resource_id', relationships['vpc_id'])

    # 12. EBSVolume -> Ec2Instance [ATTACHED_TO_INSTANCE]
    if source_label == 'EBSVolume' and relationships.get('attached_instance_id'):
            add_rel_query(source_label, source_pk_field, source_pk_value, 'ATTACHED_TO_INSTANCE', 'Ec2Instance', 'resource_id', relationships['attached_instance_id'])

    # 13. DbInstance -> Vpc [IN_VPC]
    if source_label == 'DbInstance' and relationships.get('vpc_id'):
        add_rel_query(source_label, source_pk_field, source_pk_value, 'IN_VPC', 'Vpc', 'resource_id', relationships['vpc_id'])
    
    # 14. DbInstance -> Monitoring Role [USES_MONITORING_ROLE]
    if source_label == 'DbInstance' and relationships.get('monitoring_role_arn'):
        add_rel_query(source_label, source_pk_field, source_pk_value, 'USES_MONITORING_ROLE', 'IamRole', 'arn', relationships['monitoring_role_arn'])

    # 15. LambdaFunction -> Execution Role [USES_ROLE]
    if source_label == 'LambdaFunction' and relationships.get('execution_role_arn'):
        add_rel_query(source_label, source_pk_field, source_pk_value, 'USES_ROLE', 'IamRole', 'arn', relationships['execution_role_arn'])
        
    # 16. LambdaFunction -> Subnet [IN_SUBNET]
    if source_label == 'LambdaFunction' and relationships.get('subnet_ids'):
        for subnet_id in relationships['subnet_ids']:
            add_rel_query(source_label, source_pk_field, source_pk_value, 'IN_SUBNET', 'Subnet', 'resource_id', subnet_id)

    # 17. SecurityGroupRule -> SecurityGroup [ALLOWS]
    if source_label == 'SecurityGroupRule' and relationships.get('parent_security_group_id'):
        add_rel_query(
            source_label,             # src_lbl: SecurityGroupRule
            source_pk_field,          # src_pkf: resource_id (for SecurityGroupRule)
            source_pk_value,          # src_pkv: actual resource_id of the rule
            'ALLOWS',                 # rel_type
            'SecurityGroup',          # tgt_lbl
            RESOURCE_TYPE_PRIMARY_KEY.get('SecurityGroup'), # tgt_pkf: resource_id (for SecurityGroup)
            relationships['parent_security_group_id'] # tgt_pkv: ID of the parent SecurityGroup
        )

    # 18. S3Bucket -> S3ACLGrant [HAS_ACL_GRANT]
    # Note: This relationship originates from the S3ACLGrant resource item read by the loop
    if source_label == 'S3ACLGrant' and relationships.get('applies_to_bucket_name'):
        bucket_name = relationships['applies_to_bucket_name']
        # S3Bucket uses resource_id as PK, which is set to bucket_name by s3_scanner
        add_rel_query(
            'S3Bucket',                                 # src_lbl
            RESOURCE_TYPE_PRIMARY_KEY.get('S3Bucket'), # src_pkf
            bucket_name,                                # src_pkv 
            'HAS_ACL_GRANT',                          # rel_type
            source_label,                             # tgt_lbl (S3ACLGrant)
            source_pk_field,                          # tgt_pkf (resource_id for S3ACLGrant)
            source_pk_value                           # tgt_pkv (resource_id of the S3ACLGrant)
        )

    # 19. S3BucketPolicyStatement -> S3Bucket [APPLIES_TO_BUCKET] (or S3Bucket -> Statement [HAS_POLICY_STATEMENT])
    # Let's model it as S3Bucket -[:HAS_POLICY_STATEMENT]-> S3BucketPolicyStatement
    # This means when processing an S3BucketPolicyStatement, we link its parent bucket TO it.
    if source_label == 'S3BucketPolicyStatement' and relationships.get('applies_to_bucket_arn'):
        bucket_arn = relationships['applies_to_bucket_arn']
        # S3Bucket primary key is 'resource_id', but its ARN is also unique and often used for lookup.
        # The s3_scanner creates S3Bucket with resource_id = bucket_name and arn = arn:aws:s3:::bucket_name
        # If applies_to_bucket_arn is available, we should use that for matching.
        # Let's assume we match S3Bucket on its 'arn' for this relationship for clarity, 
        # ensure S3Bucket nodes have 'arn' as a queryable property (it is, as it's the PK for IamRole etc)
        
        # We need the S3Bucket to be the source and S3BucketPolicyStatement to be the target
        # add_rel_query(src_lbl, src_pkf, src_pkv, rel_type, tgt_lbl, tgt_pkf, tgt_pkv, rel_props=None)
        add_rel_query(
            'S3Bucket',                                     # src_lbl
            'arn',                                          # src_pkf for S3Bucket (using ARN)
            bucket_arn,                                     # src_pkv (ARN of the S3Bucket)
            'HAS_POLICY_STATEMENT',                         # rel_type
            source_label,                                 # tgt_lbl (S3BucketPolicyStatement)
            source_pk_field,                              # tgt_pkf (primary key of S3BucketPolicyStatement, which is 'arn')
            source_pk_value                               # tgt_pkv (ARN of the S3BucketPolicyStatement)
        )

    # 20. IamPolicy -> IamPolicyStatement [CONTAINS_STATEMENT]
    # Similar to S3, this logic runs when processing the IamPolicyStatement resource.
    if source_label == 'IamPolicyStatement' and relationships.get('applies_to_policy_arn'):
        policy_arn = relationships['applies_to_policy_arn']
        # IamPolicy primary key is 'arn'
        add_rel_query(
            'IamPolicy',                                    # src_lbl
            RESOURCE_TYPE_PRIMARY_KEY.get('IamPolicy'),    # src_pkf ('arn')
            policy_arn,                                     # src_pkv (ARN of the IamPolicy)
            'CONTAINS_STATEMENT',                           # rel_type
            source_label,                                 # tgt_lbl (IamPolicyStatement)
            source_pk_field,                              # tgt_pkf (primary key of IamPolicyStatement, which is 'arn')
            source_pk_value                               # tgt_pkv (ARN of the IamPolicyStatement)
        )

    # 21. DbSubnetGroup -> VPC [IN_VPC]
    if source_label == 'DbSubnetGroup' and relationships.get('vpc_id'):
        add_rel_query(
            source_label,                                       # src_lbl (DbSubnetGroup)
            source_pk_field,                                    # src_pkf (resource_id)
            source_pk_value,                                    # src_pkv (subnet group name)
            'IN_VPC',                                           # rel_type
            'Vpc',                                              # tgt_lbl
            RESOURCE_TYPE_PRIMARY_KEY.get('Vpc'),              # tgt_pkf (resource_id)
            relationships['vpc_id']                             # tgt_pkv (vpc_id)
        )
        
    # 22. DbSubnetGroup -> Subnet [CONTAINS_SUBNET]
    if source_label == 'DbSubnetGroup' and relationships.get('subnet_ids'):
        for subnet_id in relationships['subnet_ids']:
            add_rel_query(
                source_label,                                   # src_lbl (DbSubnetGroup)
                source_pk_field,                                # src_pkf (resource_id)
                source_pk_value,                                # src_pkv (subnet group name)
                'CONTAINS_SUBNET',                              # rel_type
                'Subnet',                                       # tgt_lbl
                RESOURCE_TYPE_PRIMARY_KEY.get('Subnet'),       # tgt_pkf (resource_id)
                subnet_id                                       # tgt_pkv 
            )

    # 23. Policy -> Attached Entities [ATTACHED_TO]
    if source_label == 'IamPolicy':
        # Attach to Users
        if relationships.get('attached_user_names'):
            for user_name in relationships['attached_user_names']:
                add_rel_query(
                    source_label,    # src: IamPolicy
                    source_pk_field, # src_pkf: arn
                    source_pk_value, # src_pkv: policy arn
                    'ATTACHED_TO',   # rel_type
                    'IamUser',       # tgt_lbl
                    'UserName',      # tgt_pkf: Match user by UserName 
                                     # (Note: Assumes UserName is unique and indexed, or performance may suffer)
                                     # Using ARN would be safer if scanner provided it.
                    user_name        # tgt_pkv
                )
        # Attach to Groups
        if relationships.get('attached_group_names'):
            for group_name in relationships['attached_group_names']:
                 add_rel_query(
                    source_label,    # src: IamPolicy
                    source_pk_field, # src_pkf: arn
                    source_pk_value, # src_pkv: policy arn
                    'ATTACHED_TO',   # rel_type
                    'IamGroup',      # tgt_lbl
                    'GroupName',     # tgt_pkf: Match group by GroupName
                    group_name       # tgt_pkv
                )
        # Attach to Roles
        if relationships.get('attached_role_names'):
            for role_name in relationships['attached_role_names']:
                 add_rel_query(
                    source_label,    # src: IamPolicy
                    source_pk_field, # src_pkf: arn
                    source_pk_value, # src_pkv: policy arn
                    'ATTACHED_TO',   # rel_type
                    'IamRole',       # tgt_lbl
                    'RoleName',      # tgt_pkf: Match role by RoleName
                    role_name        # tgt_pkv
                )

    # 24. Lambda Function -> Lambda Resource Policy Statement [HAS_RESOURCE_POLICY_STATEMENT]
    if source_label == 'LambdaResourcePolicyStatement' and relationships.get('applies_to_lambda_arn'):
        lambda_arn = relationships['applies_to_lambda_arn']
        # LambdaFunction primary key is 'arn'
        add_rel_query(
            'LambdaFunction',                                 # src_lbl
            RESOURCE_TYPE_PRIMARY_KEY.get('LambdaFunction'), # src_pkf ('arn')
            lambda_arn,                                     # src_pkv (ARN of the Lambda Function)
            'HAS_RESOURCE_POLICY_STATEMENT',                # rel_type
            source_label,                                 # tgt_lbl (LambdaResourcePolicyStatement)
            source_pk_field,                              # tgt_pkf (primary key of Statement, which is 'arn')
            source_pk_value                               # tgt_pkv (ARN of the Statement)
        )

    # 25. Event Source Mapping -> Lambda Function [TRIGGERS]
    if source_label == 'LambdaEventSourceMapping' and relationships.get('function_arn'):
        function_arn = relationships['function_arn']
        add_rel_query(
            source_label,    # src: LambdaEventSourceMapping
            source_pk_field, # src_pkf: resource_id (UUID)
            source_pk_value, # src_pkv: UUID
            'TRIGGERS',      # rel_type
            'LambdaFunction',# tgt_lbl
            'arn',           # tgt_pkf: Match Lambda by ARN
            function_arn     # tgt_pkv
        )

    # 26. Event Source Mapping -> Source Service [READS_FROM] / [TRIGGERED_BY] (ARN parsing needed)
    if source_label == 'LambdaEventSourceMapping' and relationships.get('event_source_arn'):
        event_source_arn = relationships['event_source_arn']
        # Basic ARN parsing to guess target type - This needs refinement!
        target_label = None
        target_pk_field = 'arn' # Assume ARN is PK for most
        target_pk_value = event_source_arn
        
        if ':sqs:' in event_source_arn:
            # TODO: Add SqsQueue node type in constants & scanner
            # target_label = 'SqsQueue' 
            logger.warning(f"Relationship from ESM {source_pk_value} to SQS {event_source_arn} skipped: SqsQueue node type not implemented.")
        elif ':dynamodb:' in event_source_arn and '/stream/' in event_source_arn:
            # TODO: Add DynamoDbStream node type? Or link to DynamoDbTable?
            # target_label = 'DynamoDbStream' 
            logger.warning(f"Relationship from ESM {source_pk_value} to DynamoDB Stream {event_source_arn} skipped: DynamoDbStream node type not implemented.")
        elif ':kinesis:' in event_source_arn:
             # TODO: Add KinesisStream node type
            # target_label = 'KinesisStream'
            logger.warning(f"Relationship from ESM {source_pk_value} to Kinesis Stream {event_source_arn} skipped: KinesisStream node type not implemented.")
        # Add more cases for S3 (via SQS?), Kafka, etc. as needed
        
        if target_label: # Only create if we identified a target type
            add_rel_query(
                source_label,    # src: LambdaEventSourceMapping
                source_pk_field, # src_pkf: resource_id (UUID)
                source_pk_value, # src_pkv: UUID
                'READS_FROM',    # rel_type 
                target_label,    # tgt_lbl (e.g., SqsQueue)
                target_pk_field, # tgt_pkf (usually arn)
                target_pk_value  # tgt_pkv (event source arn)
            )
        elif event_source_arn: # Log if ARN exists but type unknown
            logger.info(f"Could not determine target node type for Event Source ARN: {event_source_arn} from ESM {source_pk_value}")

    # Add other simple relationship logic here...

    return queries_params

def create_deferred_relationships_grouped(
    client: Neo4jClient, 
    is_enabled: bool, 
    deferred_rels_data: Dict[str, List[Tuple[str, str, str, str, str, str, str, Optional[Dict[str, Any]]]]],
    logger: logging.Logger
):
    """Creates deferred relationships grouped by type."""
    if not is_enabled:
        logger.info("Deferred relationship creation skipped as graph builder is not enabled.")
        return
    
    total_rels_created = 0
    logger.info(f"Creating deferred relationships for types: {list(deferred_rels_data.keys())}")
    
    for rel_type, relationships in deferred_rels_data.items():
        logger.info(f"Creating {len(relationships)} deferred '{rel_type}' relationships...")
        queries_params = []
        for i, (src_label, src_pk_field, src_pk_val, _, tgt_label, tgt_pk_field, tgt_pk_val, rel_props) in enumerate(relationships):
            if not all([src_label, src_pk_field, src_pk_val, tgt_label, tgt_pk_field, tgt_pk_val]):
                logger.warning(f"Skipping deferred {rel_type} due to missing data.")
                continue
            
            param_src = f"src_{i}"
            param_tgt = f"tgt_{i}"
            current_params = {param_src: src_pk_val, param_tgt: tgt_pk_val}
            props_cypher = ""
            if rel_props:
                props_param = f"props_{i}"
                current_params[props_param] = {k: v for k, v in rel_props.items() if v is not None}
                if current_params[props_param]: 
                    props_cypher = f" SET r = ${props_param}"
            
            query = (
                f"MATCH (src:{src_label} {{{src_pk_field}: ${param_src}}}), "
                f"(tgt:{tgt_label} {{{tgt_pk_field}: ${param_tgt}}}) "
                f"MERGE (src)-[r:{rel_type}]->(tgt)"
                f"{props_cypher}"
            )
            queries_params.append((query, current_params))
        
        # Execute queries for this relationship type
        execute_relationship_queries(client, is_enabled, queries_params, logger)
        total_rels_created += len(queries_params) # Count successful attempts passed to execute
    
    logger.info(f"Finished creating {total_rels_created} deferred relationships attempts.") 