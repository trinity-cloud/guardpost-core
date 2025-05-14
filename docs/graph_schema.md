# GuardPost Core: Graph Schema Overview

GuardPost Core utilizes a Neo4j graph database to model your AWS environment. This graph-centric approach allows for powerful analysis of resource relationships and potential security risks that are often missed by traditional tools.

## Core Concepts

*   **Nodes:** Represent AWS resources (e.g., `Ec2Instance`, `S3Bucket`, `IamRole`) or logical constructs (e.g., `IamPolicyStatement`, `SecurityGroupRule`). Each node has a primary label corresponding to its resource type and may have additional labels.
*   **Properties:** Nodes store configuration details and metadata specific to the resource they represent. For a detailed list of properties captured for key resources, see the [AWS Resource Properties](./aws_resource_properties.md) document.
*   **Relationships:** Directed, typed connections between nodes that describe how resources are interconnected or influence each other. Examples include:
    *   Structural: `CONTAINS`, `IN_REGION`, `IN_VPC`
    *   Access/Permissions: `HAS_POLICY`, `CAN_ASSUME`, `ALLOWS_ACCESS` (or similar based on security group rules)
    *   Association: `APPLIES_TO` (e.g., Security Group to EC2 Instance), `ATTACHED_TO` (e.g., EBS Volume to EC2 Instance)

## Key Node Labels (Examples)

*   `AWSAccount`
*   `Region`
*   `Ec2Instance`
*   `SecurityGroup`
*   `SecurityGroupRule` (representing an individual rule within a Security Group)
*   `IamUser`
*   `IamRole`
*   `IamPolicy`
*   `IamPolicyStatement` (representing an individual statement within an IAM policy)
*   `S3Bucket`
*   `S3BucketPolicyStatement` (representing an individual statement within an S3 bucket policy)
*   `S3ACLGrant` (representing an individual S3 ACL grant)
*   `DbInstance` (for RDS)
*   `LambdaFunction`
*   `LambdaResourcePolicyStatement`
*   `Vpc`
*   `Subnet`
*   `InternetGateway`
*   `RouteTable`

## Key Relationship Types (Examples)

*   `CONTAINS` (e.g., Account CONTAINS Region, Region CONTAINS VPC)
*   `IN_REGION` (e.g., Ec2Instance IN_REGION Region)
*   `APPLIES_TO` (e.g., SecurityGroup APPLIES_TO Ec2Instance)
*   `ALLOWS` (e.g., SecurityGroupRule ALLOWS traffic - details in properties)
*   `HAS_POLICY` (e.g., IamUser HAS_POLICY IamPolicy)
*   `CONTAINS_STATEMENT` (e.g., IamPolicy CONTAINS_STATEMENT IamPolicyStatement)
*   `CAN_ASSUME` (e.g., IamUser CAN_ASSUME IamRole, or IamRole CAN_ASSUME IamRole)
*   `ROUTES_TO` (e.g., Subnet ROUTES_TO InternetGateway via a RouteTable)
*   `INSTANCE_PROFILE_FOR` (e.g., IamRole INSTANCE_PROFILE_FOR Ec2Instance)
*   `TRIGGERS` (e.g., LambdaEventSourceMapping TRIGGERS LambdaFunction)

## Evolution

The graph schema is continually evolving to capture more detail and enable more sophisticated security analyses. Future enhancements will focus on deeper permission modeling, network path analysis, and tracking data flows.

This overview provides a starting point for understanding the GuardPost Core security graph. For specific property details, please refer to the [AWS Resource Properties](./aws_resource_properties.md). 