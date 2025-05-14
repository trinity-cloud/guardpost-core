import logging
from typing import Dict, List

from app.db.graph_db import Neo4jClient
from app.services.graph.constants import RESOURCE_TYPE_TO_LABEL # Import the constant

def ensure_indexes_constraints(
    client: Neo4jClient, 
    is_enabled: bool, 
    logger: logging.Logger,
    resource_type_to_label: Dict[str, str] # Pass the mapping as an argument
):
    """Creates indexes and constraints defined in the schema. Safe to run multiple times."""
    if not is_enabled:
        logger.info("Schema management skipped as graph builder is not enabled.")
        return
             
    logger.info("Ensuring graph schema indexes and constraints...")
    
    constraints = [
        "CREATE CONSTRAINT unique_AwsAccount_id IF NOT EXISTS FOR (n:AwsAccount) REQUIRE n.id IS UNIQUE",
        "CREATE CONSTRAINT unique_Region_id IF NOT EXISTS FOR (n:Region) REQUIRE n.id IS UNIQUE",
        "CREATE CONSTRAINT unique_Ec2Instance_resource_id IF NOT EXISTS FOR (n:Ec2Instance) REQUIRE n.resource_id IS UNIQUE",
        "CREATE CONSTRAINT unique_IamRole_arn IF NOT EXISTS FOR (n:IamRole) REQUIRE n.arn IS UNIQUE",
        "CREATE CONSTRAINT unique_IamPolicy_arn IF NOT EXISTS FOR (n:IamPolicy) REQUIRE n.arn IS UNIQUE",
        "CREATE CONSTRAINT unique_IamUser_arn IF NOT EXISTS FOR (n:IamUser) REQUIRE n.arn IS UNIQUE",
        "CREATE CONSTRAINT unique_SecurityGroup_resource_id IF NOT EXISTS FOR (n:SecurityGroup) REQUIRE n.resource_id IS UNIQUE",
        "CREATE CONSTRAINT unique_Vpc_resource_id IF NOT EXISTS FOR (n:Vpc) REQUIRE n.resource_id IS UNIQUE",
        "CREATE CONSTRAINT unique_Subnet_resource_id IF NOT EXISTS FOR (n:Subnet) REQUIRE n.resource_id IS UNIQUE",
        "CREATE CONSTRAINT unique_RouteTable_resource_id IF NOT EXISTS FOR (n:RouteTable) REQUIRE n.resource_id IS UNIQUE",
        "CREATE CONSTRAINT unique_InternetGateway_resource_id IF NOT EXISTS FOR (n:InternetGateway) REQUIRE n.resource_id IS UNIQUE",
        "CREATE CONSTRAINT unique_NatGateway_resource_id IF NOT EXISTS FOR (n:NatGateway) REQUIRE n.resource_id IS UNIQUE",
        "CREATE CONSTRAINT unique_EBSVolume_resource_id IF NOT EXISTS FOR (n:EBSVolume) REQUIRE n.resource_id IS UNIQUE",
        "CREATE CONSTRAINT unique_S3Bucket_resource_id IF NOT EXISTS FOR (n:S3Bucket) REQUIRE n.resource_id IS UNIQUE",
        "CREATE CONSTRAINT unique_DbInstance_arn IF NOT EXISTS FOR (n:DbInstance) REQUIRE n.arn IS UNIQUE",
        "CREATE CONSTRAINT unique_LambdaFunction_arn IF NOT EXISTS FOR (n:LambdaFunction) REQUIRE n.arn IS UNIQUE",
        "CREATE CONSTRAINT unique_Tag_key_value IF NOT EXISTS FOR (n:Tag) REQUIRE n.key_value IS UNIQUE", 
        "CREATE CONSTRAINT unique_ServicePrincipal_name IF NOT EXISTS FOR (n:ServicePrincipal) REQUIRE n.name IS UNIQUE",
        "CREATE CONSTRAINT unique_FederatedPrincipal_id IF NOT EXISTS FOR (n:FederatedPrincipal) REQUIRE n.id IS UNIQUE",
        "CREATE CONSTRAINT unique_CanonicalUser_id IF NOT EXISTS FOR (n:CanonicalUser) REQUIRE n.id IS UNIQUE",
    ]

    indexes = []
    resource_labels_with_common_props = [lbl for lbl in resource_type_to_label.values() if lbl and lbl not in ["Tag", "ServicePrincipal", "FederatedPrincipal", "CanonicalUser", "AwsAccount", "Region"]]
    resource_labels_with_region = [lbl for lbl in resource_labels_with_common_props if not lbl.startswith("Iam")]
    resource_labels_with_account = [lbl for lbl in resource_labels_with_common_props if lbl != "Region"]

    for label in resource_labels_with_common_props:
            indexes.append(f"CREATE INDEX node_type_index_{label} IF NOT EXISTS FOR (n:{label}) ON (n.type)")
            indexes.append(f"CREATE INDEX node_account_id_index_{label} IF NOT EXISTS FOR (n:{label}) ON (n.account_id)")
    for label in resource_labels_with_region:
            indexes.append(f"CREATE INDEX node_region_index_{label} IF NOT EXISTS FOR (n:{label}) ON (n.region)")

    indexes.extend([
        "CREATE INDEX IamRole_name_idx IF NOT EXISTS FOR (n:IamRole) ON (n.name)",
        "CREATE INDEX IamPolicy_name_idx IF NOT EXISTS FOR (n:IamPolicy) ON (n.name)",
        "CREATE INDEX IamUser_name_idx IF NOT EXISTS FOR (n:IamUser) ON (n.UserName)",
        "CREATE INDEX SecurityGroup_name_idx IF NOT EXISTS FOR (n:SecurityGroup) ON (n.name)",
        "CREATE INDEX DbInstance_engine_idx IF NOT EXISTS FOR (n:DbInstance) ON (n.engine)",
        "CREATE INDEX LambdaFunction_runtime_idx IF NOT EXISTS FOR (n:LambdaFunction) ON (n.runtime)",
    ])
    
    commands = constraints + indexes
    
    for command in commands:
        try:
            if client and client._driver: # Ensure client is valid
                client.run(command)
            else:
                logger.warning("Skipping schema command execution as client is not enabled or driver not initialized.")
                break 
            logger.debug(f"Successfully executed schema command: {command}")
        except Exception as e:
            logger.warning(f"Failed schema command '{command}': {e}") 