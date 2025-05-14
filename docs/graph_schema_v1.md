# AWS Resource Graph Schema v1

This document outlines the initial Neo4j graph schema used by the AWS CSPM Core project.
The graph models AWS resources discovered during scans and their relationships.

**Schema Version:** 1.0
**Date:** July 2024

## Core Concepts

*   **Nodes:** Represent individual AWS resources, accounts, regions, or other entities like tags.
*   **Labels:** Applied to nodes to indicate their type (e.g., `:Ec2Instance`, `:IamRole`, `:Vpc`). Nodes can have multiple labels if appropriate (though less common in this initial schema).
*   **Properties:** Key-value pairs stored on nodes and relationships, containing configuration details, status, identifiers, etc. (e.g., `arn`, `id`, `name`, `region`, `is_public`).
*   **Relationships:** Directed edges connecting nodes, representing how resources interact or are associated (e.g., `INSTANCE_IN_SUBNET`, `HAS_POLICY`, `ROUTES_TO`). Relationship types are indicated by the edge type.

## Node Labels and Key Properties

*(Note: This is the initial set based on Sprint 2 scope. Additional nodes and properties will be added.)*

1.  **`:AwsAccount`**
    *   `id`: AWS Account ID (e.g., `123456789012`) - *Primary Key*
2.  **`:Region`**
    *   `name`: AWS Region Name (e.g., `us-east-1`) - *Primary Key within Account*
3.  **`:Ec2Instance`**
    *   `arn`: Full ARN
    *   `id`: Instance ID (e.g., `i-0abcdef1234567890`) - *Primary Key*
    *   `state`: Current state (e.g., `running`, `stopped`)
    *   `image_id`: AMI ID
    *   `instance_type`: EC2 instance type
    *   `public_ip`: Public IP address (if assigned)
    *   `private_ip`: Private IP address
    *   `launch_time`: Instance launch time
    *   `imds_v2_required`: Boolean indicating if IMDSv2 is enforced
    *   `region`: AWS Region
    *   `account_id`: AWS Account ID
4.  **`:IamRole`**
    *   `arn`: Full ARN - *Primary Key*
    *   `id`: Role ID
    *   `name`: Role Name
    *   `trust_policy`: JSON string of the assume role policy document
    *   `region`: (Typically global, but can be associated with regional scans)
    *   `account_id`: AWS Account ID
5.  **`:IamPolicy`**
    *   `arn`: Full ARN - *Primary Key*
    *   `id`: Policy ID
    *   `name`: Policy Name
    *   `type`: (`AWS Managed`, `Customer Managed`, `Inline` - Note: Inline needs careful handling)
    *   `policy_document`: JSON string of the latest policy version document
    *   `region`: (Typically global)
    *   `account_id`: AWS Account ID
6.  **`:SecurityGroup`**
    *   `id`: Security Group ID (e.g., `sg-0abcdef1234567890`) - *Primary Key*
    *   `name`: Security Group Name
    *   `description`: Description
    *   `vpc_id`: VPC ID it belongs to
    *   `ingress_rules`: JSON string representing inbound rules
    *   `egress_rules`: JSON string representing outbound rules
    *   `region`: AWS Region
    *   `account_id`: AWS Account ID
7.  **`:Vpc`**
    *   `id`: VPC ID (e.g., `vpc-0abcdef1234567890`) - *Primary Key*
    *   `cidr_block`: Primary IPv4 CIDR block
    *   `is_default`: Boolean indicating if it's the default VPC
    *   `region`: AWS Region
    *   `account_id`: AWS Account ID
8.  **`:Subnet`**
    *   `id`: Subnet ID (e.g., `subnet-0abcdef1234567890`) - *Primary Key*
    *   `cidr_block`: IPv4 CIDR block
    *   `availability_zone`: Availability Zone
    *   `map_public_ip_on_launch`: Boolean
    *   `vpc_id`: VPC ID it belongs to
    *   `region`: AWS Region
    *   `account_id`: AWS Account ID
9.  **`:RouteTable`**
    *   `id`: Route Table ID (e.g., `rtb-0abcdef1234567890`) - *Primary Key*
    *   `vpc_id`: VPC ID it belongs to
    *   `routes`: JSON string representing the routes
    *   `is_main`: Boolean indicating if it's the main route table for a VPC (via associations)
    *   `region`: AWS Region
    *   `account_id`: AWS Account ID
10. **`:InternetGateway`**
    *   `id`: Internet Gateway ID (e.g., `igw-0abcdef1234567890`) - *Primary Key*
    *   `vpc_id`: VPC ID it's attached to (derived from attachments)
    *   `region`: AWS Region
    *   `account_id`: AWS Account ID
11. **`:NatGateway`** (Added based on `scan_vpc`)
    *   `id`: NAT Gateway ID (e.g., `nat-0abcdef1234567890`) - *Primary Key*
    *   `subnet_id`: Subnet ID it resides in
    *   `vpc_id`: VPC ID it belongs to
    *   `state`: Current state
    *   `connectivity_type`: (`public` or `private`)
    *   `region`: AWS Region
    *   `account_id`: AWS Account ID
12. **`:Tag`**
    *   `key`: Tag key string
    *   `value`: Tag value string
    *   *Composite Primary Key: (`key`, `value`)*
13. **`:S3Bucket`**
    *   `arn`: Full ARN (e.g., `arn:aws:s3:::bucket-name`)
    *   `name`: Bucket Name (e.g., `bucket-name`) - *Primary Key (maps to resource_id)*
    *   `region`: AWS Region bucket resides in
    *   `account_id`: AWS Account ID
    *   `creation_date`: ISO 8601 timestamp
    *   `public_access_block`: JSON string of PublicAccessBlockConfiguration
    *   `is_public_by_policy`: Boolean (based on GetBucketPolicyStatus)
    *   `policy`: JSON string of the bucket policy (or error)
    *   `acl_grants`: JSON string of ACL grants (or error)
    *   `encryption`: JSON string of ServerSideEncryptionConfiguration (or error)
    *   `versioning_status`: String (`Enabled`, `Suspended`, `Disabled`) or JSON error
    *   `mfa_delete_status`: String (`Enabled`, `Disabled`) or JSON error
    *   `logging_config`: JSON string of LoggingEnabled config (or error or null)
14. **`:DbInstance`** (From RDS)
    *   `arn`: Full DB Instance ARN (e.g., `arn:aws:rds:...:db:...`) - *Primary Key*
    *   `resource_id`: DB Instance Identifier (e.g., `my-db-instance`) - *Primary Key*
    *   `region`: AWS Region
    *   `account_id`: AWS Account ID
    *   `db_instance_class`: Instance class (e.g., `db.t3.micro`)
    *   `engine`: DB Engine (e.g., `postgres`, `mysql`)
    *   `engine_version`: Engine version string
    *   `db_instance_status`: Status string (e.g., `available`)
    *   `publicly_accessible`: Boolean
    *   `storage_encrypted`: Boolean
    *   `kms_key_id`: ARN of KMS key if encrypted
    *   `multi_az`: Boolean
    *   `deletion_protection`: Boolean
    *   `iam_database_authentication_enabled`: Boolean
    *   `auto_minor_version_upgrade`: Boolean
    *   `allocated_storage`: Integer (GB)
    *   `backup_retention_period`: Integer (Days)
    *   `db_subnet_group_name`: String (Name of associated subnet group)
    *   `vpc_security_groups`: JSON string of VpcSecurityGroupMembership list
    *   (Other properties like Endpoint, Parameter Groups, etc., stored as needed)
15. **`:LambdaFunction`**
    *   `arn`: Function ARN - *Primary Key (maps to resource_id)*
    *   `resource_id`: Function ARN
    *   `region`: AWS Region
    *   `account_id`: AWS Account ID
    *   `function_name`: Function Name
    *   `runtime`: Runtime identifier (e.g., `python3.9`)
    *   `handler`: Function handler name
    *   `memory_size`: Integer (MB)
    *   `timeout`: Integer (seconds)
    *   `vpc_config`: JSON string of VpcConfig
    *   `tracing_config_mode`: String (`Active` or `PassThrough`)
    *   `kms_key_arn`: ARN of KMS key if used
    *   `architectures`: List of strings (e.g., `[x86_64]`)
    *   `function_url_config`: Dict (or null or JSON error string)

## Relationship Types

*(Note: Relationships originate FROM the first node type listed)*

1.  **`CONTAINS`**: `(:AwsAccount)-[:CONTAINS]->(:Region)`
    *   Connects an account to the regions it contains discovered resources in.
2.  **`IN_REGION`**: `(:*)-[:IN_REGION]->(:Region)`
    *   Connects a regional resource (EC2, VPC, Subnet, SG, etc.) to its region node.
3.  **`INSTANCE_IN_SUBNET`**: `(:Ec2Instance)-[:INSTANCE_IN_SUBNET]->(:Subnet)`
4.  **`SUBNET_IN_VPC`**: `(:Subnet)-[:SUBNET_IN_VPC]->(:Vpc)`
5.  **`APPLIES_TO`**: `(:SecurityGroup)-[:APPLIES_TO]->(:Ec2Instance)` (Or other interfaces like Lambda, RDS)
    *   Indicates an SG is attached to a resource.
6.  **`ROUTES_TO`**: `(:RouteTable)-[:ROUTES_TO]->(:InternetGateway | :NatGateway | :Ec2Instance | ...)`
    *   Represents a route entry.
    *   Properties: `destination_cidr` (String).
7.  **`ASSOCIATED_WITH`**: `(:RouteTable)-[:ASSOCIATED_WITH]->(:Subnet)`
    *   Indicates explicit or main route table association.
8.  **`ATTACHED_TO`**: `(:InternetGateway)-[:ATTACHED_TO]->(:Vpc)`
9.  **`HAS_ROLE`**: `(:Ec2Instance)-[:HAS_ROLE]->(:IamRole)` (From instance profile)
10. **`HAS_POLICY`**: `(:IamRole | :IamUser | :IamGroup)-[:HAS_POLICY]->(:IamPolicy)`
    *   Connects a principal to an attached managed or inline policy.
11. **`TRUSTS`**: `(:IamRole)-[:TRUSTS]->(:AwsAccount | :IamRole | :IamUser | :ServicePrincipal | ...)`
    *   Derived from the Assume Role Policy Document. Target node type varies based on Principal.
    *   Needs careful modeling of principal types.
12. **`CAN_ASSUME`**: *(Inverse of TRUSTS, potentially redundant or useful for specific queries)* `(:Principal)-[:CAN_ASSUME]->(:IamRole)`
13. **`ALLOWS_ACCESS`**: *Modeled differently for simplicity - stored as properties on `:SecurityGroup` node for now.*
    *   Future: Could be `(:SecurityGroupRule)-[:ALLOWS_INGRESS_FROM]->(:SecurityGroup | :Cidr)` or `(:SecurityGroup)-[r:ALLOWS_INGRESS]->(:SecurityGroup)` with rule details as properties on `r`.
14. **`HAS_TAG`**: `(:Ec2Instance | :Vpc | :Subnet | ...)-[:HAS_TAG]->(:Tag)`
    *   Connects any taggable resource to its corresponding Tag nodes.

## Indexing Strategy (Initial Recommendations)

*   Create unique constraints on primary key properties for core node types:
    *   `AwsAccount(id)`
    *   `Region(name)` (Consider composite with account if needed)
    *   `Ec2Instance(id)`
    *   `IamRole(arn)`
    *   `IamPolicy(arn)`
    *   `SecurityGroup(id)`
    *   `Vpc(id)`
    *   `Subnet(id)`
    *   `RouteTable(id)`
    *   `InternetGateway(id)`
    *   `NatGateway(id)`
    *   `Tag(key, value)`
*   Create standard indexes on commonly queried properties like `name`, `region`, `account_id` for relevant nodes.

## Example Cypher Queries (Illustrative)

*   **Find all EC2 instances in a specific VPC:**
    ```cypher
    MATCH (vpc:Vpc {id: $vpcId})<-[:SUBNET_IN_VPC]-(subnet:Subnet)<-[:INSTANCE_IN_SUBNET]-(instance:Ec2Instance)
    RETURN instance.id, instance.private_ip
    ```
*   **Find Security Groups allowing public SSH access:**
    ```cypher
    // This relies on parsing the ingress_rules property effectively
    MATCH (sg:SecurityGroup)
    WHERE sg.ingress_rules CONTAINS '0.0.0.0/0' AND sg.ingress_rules CONTAINS 'port: 22' // Simplified logic
    RETURN sg.id
    ```
*   **Find Roles that a specific EC2 instance can assume (via its Instance Profile Role):**
    ```cypher
    MATCH (instance:Ec2Instance {id: $instanceId})-[:HAS_ROLE]->(role:IamRole)
    RETURN role.arn
    ```

*(This schema provides the foundation. It will evolve as more scanners and analysis capabilities are added.)* 