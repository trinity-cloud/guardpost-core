# GuardPost Core: Graph Data Model (AWS Resource Properties)

GuardPost Core builds a graph database (Neo4j) by scanning your AWS environment and extracting key configuration details from various services. This document provides an overview of the primary AWS resources modeled and the essential security-relevant properties captured for each. Understanding this data model can help advanced users write custom Cypher queries for deeper security analysis.

*(This is a summary based on `planning/guardpost-core/sprint_3_aws_properties.md`. Refer to the source code, particularly scanner modules in `app/services/scanners/`, for the most precise list of all properties extracted.)*

## General Principles

*   **Nodes:** Each discovered AWS resource (e.g., an EC2 instance, S3 bucket, IAM user) is represented as a node in the graph, labeled by its AWS resource type (e.g., `Ec2Instance`, `S3Bucket`).
*   **Properties:** Nodes have properties that store their configuration details and metadata.
*   **Relationships:** Relationships connect nodes to represent how resources interact or are associated (e.g., an `Ec2Instance` `APPLIES_TO` a `SecurityGroup`, an `IAMUser` `HAS_POLICY` an `IamPolicy`).

## Key Services and Resource Properties

### 1. EC2 (Elastic Compute Cloud)

*   **`Ec2Instance` Nodes:**
    *   Essential IDs: `instanceId`, `arn`
    *   State & Network: `state.name`, `publicIpAddress`, `privateIpAddress`, `vpcId`, `subnetId`
    *   Security Context: `securityGroups` (IDs of associated SGs), `iamInstanceProfile.arn`
    *   Metadata Security: `MetadataOptions_HttpTokens` (for IMDSv2 status), `MetadataOptions_HttpEndpoint`
    *   Contextual: `tags`, `imageId`, `launchTime`
*   **`SecurityGroup` Nodes:**
    *   IDs: `groupId`, `groupName`
    *   Context: `description`, `vpcId`
    *   Ingress/Egress Rules: Parsed into properties or related nodes detailing `ipProtocol`, `fromPort`, `toPort`, `cidrIp` (crucial for `0.0.0.0/0`), and source/destination `groupId`s for SG-to-SG rules.
*   **`Vpc` Nodes:** `vpcId`, `cidrBlock`, `isDefault`
*   **`Subnet` Nodes:** `subnetId`, `vpcId`, `cidrBlock`, `mapPublicIpOnLaunch`

### 2. IAM (Identity and Access Management)

*   **`IamUser` Nodes:**
    *   IDs: `userId`, `userName`, `arn`
    *   Security Posture: `passwordLastUsed`, `HasMfaEnabled` (derived boolean)
    *   Access Keys: `AccessKeys` (JSON list of key objects with `accessKeyId`, `status`, `createDate`)
*   **`IamGroup` Nodes:**
    *   IDs: `groupId`, `groupName`, `arn`
    *   Relationships: `HAS_MEMBER` to `IamUser` nodes, `HAS_POLICY` to `IamPolicy` nodes (for attached managed policies).
    *   Inline Policies: `InlinePoliciesJson` (JSON string of inline policy names and documents).
*   **`IamRole` Nodes:**
    *   IDs: `roleId`, `roleName`, `arn`
    *   Trust Policy: `AssumeRolePolicyDocument` (JSON string), and parsed properties like `AWSTrustedPrincipalIdentifiers`, `IsAnonymousTrusted`, `TrustPolicyConditions`.
    *   Relationships: `HAS_POLICY` to `IamPolicy` nodes.
    *   Inline Policies: `InlinePoliciesJson`.
*   **`IamPolicy` Nodes (Customer-Managed Policies):**
    *   IDs: `policyId`, `policyName`, `arn`
    *   Policy Document: The full JSON policy document is decomposed into `IamPolicyStatement` nodes linked via `CONTAINS_STATEMENT` relationships.
*   **`IamPolicyStatement` Nodes:**
    *   Properties: `Sid`, `Effect`, `Action` (list), `Resource` (list), `NotAction`, `NotResource`, `Condition` (JSON string).
    *   Relationships: Linked from `IamPolicy`, `S3BucketPolicyStatement`, etc.

### 3. S3 (Simple Storage Service)

*   **`S3Bucket` Nodes:**
    *   ID: `name` (bucket name), `arn`
    *   Access Control: `BlockPublicAccessConfiguration` (parsed properties), ACLs (modeled via `S3ACLGrant` relationships/nodes).
    *   Encryption: `ServerSideEncryptionConfiguration` (parsed details).
    *   Other Settings: `VersioningConfiguration`, `LoggingConfiguration`.
*   **`S3BucketPolicyStatement` Nodes:**
    *   Linked from `S3Bucket` via `HAS_POLICY_STATEMENT`.
    *   Properties: `Sid`, `Effect`, `Principal` (JSON), `Action` (list), `Resource` (list), `Condition` (JSON string).
*   **`S3ACLGrant` Nodes (or similar representation):**
    *   Details specific ACL grants, including `GranteeURI` (to identify `AllUsers` or `AuthenticatedUsers`) and `Permission`.

### 4. RDS (Relational Database Service)

*   **`DbInstance` Nodes:**
    *   IDs: `dBInstanceIdentifier`, `arn`
    *   Configuration: `engine`, `engineVersion`, `publiclyAccessible`, `storageEncrypted`, `kmsKeyId`.
    *   Network: `endpoint.address`, `endpoint.port`, `vpcSecurityGroups` (list of SG IDs), `dBSubnetGroup.subnetGroupName`.
*   **`DbSubnetGroup` Nodes:**
    *   Properties: `dBSubnetGroupName`, `vpcId`.
    *   Relationships: `CONTAINS_SUBNET` to `Subnet` nodes.

### 5. Lambda (Serverless Compute)

*   **`LambdaFunction` Nodes:**
    *   IDs: `functionName`, `functionArn`
    *   Configuration: `runtime`, `role` (IAM role ARN), `timeout`, `memorySize`.
    *   Network: `VpcConfig` (parsed for `subnetIds`, `securityGroupIds`).
    *   Environment Variables: Original `EnvironmentVariablesJson` stored, plus `HasPotentiallySensitiveEnv` (boolean) and `PotentiallySensitiveEnvKeys` (list) based on keyword analysis.
*   **`LambdaResourcePolicyStatement` Nodes:**
    *   Linked from `LambdaFunction`.
    *   Properties: `Sid`, `Effect`, `Principal` (JSON), `Action` (list), `Resource` (list), `Condition` (JSON string).
*   **`LambdaEventSourceMapping` Nodes:**
    *   Properties: `uuid`, `eventSourceArn`, `state`.
    *   Relationships: `TRIGGERS` to the `LambdaFunction`.

This model provides a rich, interconnected view of your AWS environment, forming the basis for GuardPost Core's security analysis and remediation capabilities. For the most detailed and up-to-date information, refer to the scanner modules within the codebase. 