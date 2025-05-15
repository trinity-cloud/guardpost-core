# GuardPost Core: Graph Schema Overview

GuardPost Core utilizes a Neo4j graph database to model your AWS environment. This graph-centric approach allows for powerful analysis of resource relationships and potential security risks that are often missed by traditional tools.

## Core Concepts

*   **Nodes:** Represent AWS resources (e.g., `Ec2Instance`, `S3Bucket`, `IamRole`) or logical constructs (e.g., `IamPolicyStatement`, `SecurityGroupRule`). Each node has a primary label corresponding to its resource type and may have additional labels.
*   **Properties:** Nodes store configuration details and metadata specific to the resource they represent. For a detailed list of properties captured for key resources, see the [AWS Resource Properties](./aws_resource_properties.md) document.
*   **Relationships:** Directed, typed connections between nodes that describe how resources are interconnected or influence each other. Examples include:
    *   Structural: `CONTAINS`, `IN_REGION`, `IN_VPC`
    *   Access/Permissions: `HAS_POLICY`, `CAN_ASSUME`, `ALLOWS_ACCESS` (or similar based on security group rules)
    *   Association: `APPLIES_TO` (e.g., Security Group to EC2 Instance), `ATTACHED_TO` (e.g., EBS Volume to EC2 Instance)

## Node Labels and Properties

*(Based on known scanners: IAM, EC2, S3, VPC, EBS, Lambda, RDS)*

Nodes generally share common properties:
*   `id`: String (Primary Key - Often ARN or resource ID, unique within its type/account/region scope. **Note:** For S3Bucket, this is the bucket name.)
*   `arn`: String (Full ARN, usually matches `id` or is derived)
*   `account_id`: String (Derived from ARN)
*   `region`: String (Derived from ARN or API response, 'global' for IAM etc.)
*   `type`: String (AWS Resource Type Name, e.g., `AWS::EC2::Instance`)
*   `name`: String (Common name tag or property, optional)
*   `tags`: Map (Key-value string pairs from AWS tags)
*   `last_updated`: Datetime (Timestamp of last scan/update of this node)

### 1. Core Structural Nodes
*   **`AWSAccount`**
    *   `id`: String (Account ID)
    *   `name`: String (Alias, optional)
    *   `properties`: Map (Account summary data from `get_account_summary`, optional)
    *   `password_policy`: Map (Password policy details, optional)
*   **`Region`**
    *   `id`: String (Region Code, e.g., `us-east-1`)
    *   `name`: String
    *   `properties`: Map (Regional settings like `EbsEncryptionByDefault`, optional)

### 2. IAM Nodes
*   **`IAMUser`**
    *   `id`/`arn`: String (ARN)
    *   `user_id`: String
    *   `name`: String
    *   `path`: String
    *   `created_date`: Datetime
    *   `password_last_used`: Datetime (Optional)
    *   *(MFA details deferred for now)*
    *   *(PermissionsBoundary deferred for now)*
*   **`IAMRole`**
    *   `id`/`arn`: String (ARN)
    *   `role_id`: String
    *   `name`: String
    *   `path`: String
    *   `trust_policy_json`: String (AssumeRolePolicyDocument)
    *   `description`: String (Optional)
    *   `max_session_duration`: Integer
    *   `created_date`: Datetime
    *   `last_used_date`: Datetime (Optional)
    *   `last_used_region`: String (Optional)
    *   `blast_radius_count`: Integer (Optional) 
    *   `blast_radius_score`: Float (Optional) 
    *   `blast_radius_calculated_at`: Datetime (Optional) 
*   **`IAMGroup`**
    *   `id`/`arn`: String (ARN)
    *   `group_id`: String
    *   `name`: String
    *   `path`: String
    *   `created_date`: Datetime
*   **`IAMPolicy`** (Managed Policies - Customer & AWS)
    *   `id`/`arn`: String (ARN)
    *   `policy_id`: String
    *   `name`: String
    *   `path`: String
    *   `is_aws_managed`: Boolean
    *   `is_attachable`: Boolean
    *   `attachment_count`: Integer
    *   `default_version_id`: String
    *   `policy_document_json`: String (Optional - fetched for Customer Managed, stored as JSON string)
    *   `create_date`: Datetime
    *   `update_date`: Datetime

### 3. EC2 Nodes
*   **`EC2Instance`**
    *   `id`: String (Instance ID, e.g., `i-1234567890abcdef0`)
    *   `arn`: String
    *   `instance_type`: String
    *   `image_id`: String
    *   `state`: String (e.g., running, stopped)
    *   `public_ip`: String (Optional)
    *   `private_ip`: String (Optional)
    *   `subnet_id`: String
    *   `vpc_id`: String
    *   `launch_time`: Datetime
    *   `iam_instance_profile_arn`: String (Optional)
    *   `metadata_options`: Map (Containing State, HttpTokens, HttpPutResponseHopLimit, HttpEndpoint, InstanceMetadataTags)
    *   `blast_radius_count`: Integer (Optional) 
    *   `blast_radius_score`: Float (Optional) 
    *   `blast_radius_calculated_at`: Datetime (Optional) 
*   **`EBSVolume`**
    *   `id`: String (Volume ID, e.g., `vol-0abcdef1234567890`)
    *   `arn`: String
    *   `volume_type`: String
    *   `size_gb`: Integer
    *   `encrypted`: Boolean
    *   `kms_key_id`: String (Optional)
    *   `state`: String
    *   `availability_zone`: String
    *   `create_time`: Datetime
*   **`ENI`** (Elastic Network Interface)
    *   `id`: String (Interface ID, e.g., `eni-abcdef1234567890`)
    *   `arn`: String
    *   `subnet_id`: String
    *   `vpc_id`: String
    *   `private_ip_address`: String
    *   `public_ip_address`: String (Optional)
    *   `description`: String (Optional)
    *   `status`: String
*   **`SecurityGroup`**
    *   `id`: String (Group ID, e.g., `sg-1234567890abcdef0`)
    *   `arn`: String
    *   `name`: String
    *   `description`: String
    *   `vpc_id`: String (Optional - for EC2-Classic)
    *   `owner_id`: String (Account ID)
    *   `ip_permissions_json`: String (JSON dump of IpPermissions)
    *   `ip_permissions_egress_json`: String (JSON dump of IpPermissionsEgress)
    *   `blast_radius_count`: Integer (Optional) 
    *   `blast_radius_score`: Float (Optional) 
    *   `blast_radius_calculated_at`: Datetime (Optional) 

### 4. VPC Nodes
*   **`VPC`**
    *   `id`: String (VPC ID, e.g., `vpc-abcdef1234567890`)
    *   `arn`: String
    *   `cidr_block`: String
    *   `is_default`: Boolean
    *   `state`: String
    *   `instance_tenancy`: String
*   **`Subnet`**
    *   `id`: String (Subnet ID, e.g., `subnet-1234567890abcdef0`)
    *   `arn`: String
    *   `cidr_block`: String
    *   `vpc_id`: String
    *   `availability_zone`: String
    *   `availability_zone_id`: String
    *   `map_public_ip_on_launch`: Boolean
    *   `state`: String
*   **`RouteTable`**
    *   `id`: String (Route Table ID, e.g., `rtb-abcdef1234567890`)
    *   `arn`: String
    *   `vpc_id`: String
    *   `is_main`: Boolean (Derived from associations)
    *   `routes_json`: String (JSON dump of Routes list)
    *   `associations_json`: String (JSON dump of Associations list)
*   **`InternetGateway`**
    *   `id`: String (Gateway ID, e.g., `igw-abcdef1234567890`)
    *   `arn`: String
    *   `attachments_json`: String (JSON dump of Attachments list)
*   **`NatGateway`**
    *   `id`: String (Gateway ID, e.g., `nat-abcdef1234567890`)
    *   `arn`: String
    *   `subnet_id`: String
    *   `vpc_id`: String
    *   `state`: String
    *   `connectivity_type`: String
    *   `addresses_json`: String (JSON dump of NatGatewayAddresses list)

### 5. S3 Nodes
*   **`S3Bucket`**
    *   `id`/`arn`: String (ARN: `arn:aws:s3:::bucket-name`)
    *   `name`: String (Bucket Name - used as the `id` property)
    *   `creation_date`: Datetime
    *   `region`: String (Determined by `get_bucket_location`)
    *   `public_access_block`: Map (Configuration from `get_public_access_block`)
    *   `is_public_by_policy`: Boolean (Result from `get_bucket_policy_status`, optional)
    *   `policy_json`: String (Optional, result from `get_bucket_policy`)
    *   `acl_grants_json`: String (JSON dump of Grants from `get_bucket_acl`)
    *   `encryption_config`: Map (From `get_bucket_encryption`, optional)
    *   `versioning_status`: String (Enabled/Suspended/Disabled)
    *   `mfa_delete_status`: String (Enabled/Disabled)
    *   `logging_config`: Map (From `get_bucket_logging`, optional)
    *   `blast_radius_count`: Integer (Optional) 
    *   `blast_radius_score`: Float (Optional) 
    *   `blast_radius_calculated_at`: Datetime (Optional) 

### 6. Lambda Nodes
*   **`LambdaFunction`**
    *   `id`/`arn`: String (Function ARN)
    *   `name`: String
    *   `runtime`: String
    *   `handler`: String
    *   `code_size_bytes`: Integer
    *   `role_arn`: String (Used for EXECUTION_ROLE relationship)
    *   `memory_size_mb`: Integer
    *   `timeout_seconds`: Integer
    *   `vpc_config_json`: String (JSON dump of VpcConfig, optional)
    *   `tracing_config_mode`: String (Active/PassThrough)
    *   `dead_letter_target_arn`: String (Optional)
    *   `environment_variables_json`: String (JSON dump of Env Vars, optional)
    *   `kms_key_arn`: String (Optional)
    *   `architectures`: List[String]
    *   `ephemeral_storage_size_mb`: Integer (Optional)
    *   `last_modified`: Datetime
    *   `function_url_config`: Map (Optional)

### 7. RDS Nodes
*   **`DbInstance`** *(Formerly `RDSInstance`. Aligned with scanner output `resource_type`)*
    *   `id`/`arn`: String (DB Instance ARN)
    *   `db_instance_identifier`: String (Acts as resource_id in scanner output)
    *   `engine`: String (e.g., postgres, mysql)
    *   `engine_version`: String
    *   `instance_class`: String
    *   `publicly_accessible`: Boolean
    *   `storage_encrypted`: Boolean
    *   `kms_key_id`: String (Optional)
    *   `multi_az`: Boolean
    *   `vpc_id`: String (Derived from Subnet Group)
    *   `db_subnet_group_name`: String
    *   `vpc_security_group_ids`: List[String]
    *   `iam_database_authentication_enabled`: Boolean
    *   `deletion_protection`: Boolean
    *   `auto_minor_version_upgrade`: Boolean
    *   `monitoring_role_arn`: String (Optional)
    *   `performance_insights_enabled`: Boolean
    *   `create_time`: Datetime
    *(Many other properties captured by scanner stored in `properties` map, e.g., Endpoint, Storage, Backup, ParameterGroups, etc.)*

---

## Relationship Types and Properties

### 1. Foundational Relationships
*   **`CONTAINS`**: Hierarchical ownership/location.
    *   `AWSAccount` -> `Region`
    *   `Region` -> `VPC`
    *   `VPC` -> `Subnet`, `RouteTable`, `InternetGateway`, `NatGateway`, `SecurityGroup`
    *   `AWSAccount` -> `S3Bucket`
    *   `AWSAccount` -> `IAMUser`, `IAMRole`, `IAMGroup`, `IAMPolicy`
*   **`LOCATED_IN`**: Resource location within a region.
    *   `EC2Instance` -> `Region`
    *   `LambdaFunction` -> `Region`
    *   `RDSInstance` -> `Region`
    *   `EBSVolume` -> `Region`
    *   *(May not be needed if region is always a node property)*
*   **`RESOURCE_TAG`**: *(Alternative to `tags` property)*
    *   `ResourceNode` -[:`HAS_TAG`]-> `Tag` (if Tag is a node: `Tag {key, value}`)

### 2. Network Relationships
*   **`ASSOCIATED_WITH`**: Connecting VPC components.
    *   `Subnet` -> `RouteTable` (From RouteTable associations)
    *   `RouteTable` -> `InternetGateway` / `NatGateway` (Derived from routes)
    *   `InternetGateway` -> `VPC` (From IGW attachments)
*   **`ROUTES_TO`**: Potential traffic flow (derived from RouteTable routes).
    *   `RouteTable` -> `InternetGateway`
    *   `RouteTable` -> `NatGateway`
    *   `RouteTable` -> `ENI`
    *   `RouteTable` -> `VPCPeeringConnection`
    *   `RouteTable` -> `TransitGateway`
    *   `Subnet` -> `NatGateway`
    *   `EC2Instance` -> `EC2Instance` (Via Security Group rules - *complex derivation*)
*   **`MEMBER_OF`**: Security group membership.
    *   `EC2Instance` -> `SecurityGroup`
    *   `RDSInstance` -> `SecurityGroup`
    *   `LambdaFunction` -> `SecurityGroup`
*   **`INSTANCE_OF`**: ENI to Instance.
    *   `ENI` -> `EC2Instance`
*   **`SECURITY_RULE`**: Representing SG rules.
    *   `SecurityGroup` -[:`INGRESS_RULE` {protocol: string, port_range: string, source_type: string, source: string}]-> `SecurityGroup` / `CIDRNode`
    *   `SecurityGroup` -[:`EGRESS_RULE` {protocol: string, port_range: string, destination_type: string, destination: string}]-> `SecurityGroup` / `CIDRNode`
    *(Modeling CIDRs as separate nodes might be useful)*
*   **`IN_SUBNET`**: Resource placement in subnet.
    *   `EC2Instance` -> `Subnet`
    *   `ENI` -> `Subnet`
    *   `NatGateway` -> `Subnet`
    *   `RDSInstance` -> `Subnet` (Via Subnet Group membership)
    *   `LambdaFunction` -> `Subnet` (Via VPC Config)

### 3. Compute/Storage Relationships
*   **`ATTACHED_TO`**: Physical/logical attachment.
    *   `EBSVolume` -> `EC2Instance`
    *   **`INSTANCE_PROFILE_FOR`**: Links an IAM Role used as an instance profile.
        *   `IAMRole` -> `EC2Instance`
        *   *(Properties could include the Instance Profile ARN if needed)*

### 4. IAM Relationships
*   **`MEMBER_OF`**: User/Group membership.
    *   `IAMUser` -> `IAMGroup`
*   **`APPLIES_TO`**: *DEPRECATED* - Use `HAS_POLICY`.
*   **`CAN_ASSUME`** [NEW in v1.1]
    *   **Connects:** `IAMPrincipal` (`IAMRole`, `IAMUser`, `AWSAccount`, `AWSService`, `FederatedUser`, etc.) -> `IAMRole`
    *   **Direction:** Source assumes Target
    *   **Properties:** `condition_keys`: list[string], `external_id_required`: boolean, `mfa_required`: boolean (All Optional)
*   **`CAN_ACCESS`** [NEW in v1.1] *(Represents effective access derived from policies)*
    *   **Connects:** `IAMPrincipal` (`IAMRole`, `IAMUser`) -> `ResourceNode`
    *   **Direction:** Source principal can access Target resource
    *   **Properties:** `permission_level`: string (Enum: READ, WRITE, LIST, TAGGING, PERMISSIONS, FULL_ACCESS), `condition_json`: string (Optional), `via_relationship`: string (Optional - e.g., 'InstanceProfile')
*   **`HAS_POLICY`**: Link Principal to the Managed Policy node.
    *   **Connects:** `IAMRole`/`IAMUser`/`IAMGroup` -> `IAMPolicy`
    *   *(Note: Inline policies are usually stored as properties, not separate nodes/relationships)*
*   **`HAS_PERMISSION`** [NEW in v1.1] - *DEFERRING*. `CAN_ACCESS` captures the higher-level intent for now. Modeling every single action/resource permission as a relationship is likely too granular initially.

### 5. Service Relationships
*   **`INVOKES`**: Lambda invocation (potentially complex to model fully).
    *   `DataSourceNode` (e.g., `S3Bucket`, `APIGatewayRoute`) -> `LambdaFunction`
*   **`EXECUTION_ROLE`**: Service execution role.
    *   `LambdaFunction` -> `IAMRole`
    *   `DbInstance` -> `IAMRole` (For Monitoring Role)
*   **`LOGS_TO`**: Service logging target.
    *   `S3Bucket` -> `S3Bucket` (Target Bucket for Logging)
*   **`DLQ_TARGET`**: Dead Letter Queue target.
    *   `LambdaFunction` -> `SQSQueue` / `SNSTopic` (Need nodes for SQS/SNS)

---

## Mandatory Indexes

*   **Node Primary Keys/Identifiers:**
    *   `AWSAccount(id)`
    *   `Region(id)`
    *   `IAMUser(arn)`
    *   `IAMRole(arn)`
    *   `IAMGroup(arn)`
    *   `IAMPolicy(arn)`
    *   `EC2Instance(id)`
    *   `EBSVolume(id)`
    *   `ENI(id)`
    *   `SecurityGroup(id)`
    *   `VPC(id)`
    *   `Subnet(id)`
    *   `RouteTable(id)`
    *   `InternetGateway(id)`
    *   `NatGateway(id)`
    *   `S3Bucket(name)`
    *   `LambdaFunction(arn)`
    *   `DbInstance(arn)`

*   **Common Lookup/Filter Properties:**
    *   `IAMRole(name)`
    *   Node `type` property: `CREATE INDEX node_type_index IF NOT EXISTS FOR (n) ON (n.type)` - *Critical for `list_resources`*
    *   Node `region` property: `CREATE INDEX node_region_index IF NOT EXISTS FOR (n) ON (n.region)` - *Critical for `list_resources`*
    *   Node `account_id` property: `CREATE INDEX node_account_id_index IF NOT EXISTS FOR (n) ON (n.account_id)` - *Critical for `list_resources`*
    *   *(Consider composite indexes later if needed, e.g., on (account_id, region, type))*
    *   *(Index on `tags` requires specific modeling - e.g., Map properties are not directly indexable in older Neo4j versions. Could index specific tag keys if known, or model tags as separate nodes)*

*   **Relationship Property Indexes:** *(Deferred)*


## Evolution

The graph schema is continually evolving to capture more detail and enable more sophisticated security analyses. Future enhancements will focus on deeper permission modeling, network path analysis, and tracking data flows.

This overview provides a starting point for understanding the GuardPost Core security graph. For specific property details, please refer to the [AWS Resource Properties](./aws_resource_properties.md). 