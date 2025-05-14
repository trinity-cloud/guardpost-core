# graph/constants.py

# Centralized definitions for Neo4j graph schema mappings

# Mapping from resource_type string (from scanner output) to Neo4j Node Label
RESOURCE_TYPE_TO_LABEL = {
    "AwsAccount": "AwsAccount",
    "Region": "Region",
    "Ec2Instance": "Ec2Instance",
    "IamRole": "IamRole",
    "IamPolicy": "IamPolicy",
    "SecurityGroup": "SecurityGroup",
    "SecurityGroupRule": "SecurityGroupRule",
    "Vpc": "Vpc",
    "Subnet": "Subnet",
    "RouteTable": "RouteTable",
    "InternetGateway": "InternetGateway",
    "NatGateway": "NatGateway",
    "EBSVolume": "EBSVolume",
    "IamUser": "IamUser",
    "ServicePrincipal": "ServicePrincipal",
    "S3Bucket": "S3Bucket",
    "DbInstance": "DbInstance",
    "LambdaFunction": "LambdaFunction",
    "S3ACLGrant": "S3ACLGrant",
    "Tag": "Tag",
    "RegionSettings": None, # Not a node
    "AccountSettings": None, # Not a node
    "Error": None,
    "FederatedPrincipal": "FederatedPrincipal", # Used in IAM analysis
    "CanonicalUser": "CanonicalUser", # Used in IAM analysis
    "WildcardPrincipal": None, # Not a node
    "S3BucketPolicyStatement": "S3BucketPolicyStatement",
    "IamPolicyStatement": "IamPolicyStatement",
    "DbSubnetGroup": "DbSubnetGroup",
    "IamGroup": "IamGroup",
    "LambdaResourcePolicyStatement": "LambdaResourcePolicyStatement",
    "LambdaEventSourceMapping": "LambdaEventSourceMapping",
    # Add new resource types here as scanners are added
}

# Define primary keys used for MERGE operations (should match node properties)
RESOURCE_TYPE_PRIMARY_KEY = {
    "AwsAccount": "id",
    "Region": "id",
    "Ec2Instance": "resource_id",
    "IamRole": "arn",
    "IamPolicy": "arn",
    "SecurityGroup": "resource_id",
    "SecurityGroupRule": "resource_id",
    "Vpc": "resource_id",
    "Subnet": "resource_id",
    "RouteTable": "resource_id",
    "InternetGateway": "resource_id",
    "NatGateway": "resource_id",
    "EBSVolume": "resource_id",
    "IamUser": "arn",
    "ServicePrincipal": "name",
    "Tag": "key_value",
    "S3Bucket": "resource_id",
    "DbInstance": "arn",
    "LambdaFunction": "arn",
    "S3ACLGrant": "resource_id",
    "FederatedPrincipal": "id",
    "CanonicalUser": "id",
    "S3BucketPolicyStatement": "arn",
    "IamPolicyStatement": "arn",
    "DbSubnetGroup": "resource_id", # Using DBSubnetGroupName as resource_id in scanner
    "IamGroup": "arn",
    "LambdaResourcePolicyStatement": "arn",
    "LambdaEventSourceMapping": "resource_id", # Using UUID as resource_id in scanner
    # Add PKs for new node types here
} 