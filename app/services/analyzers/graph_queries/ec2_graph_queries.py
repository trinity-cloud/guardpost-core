from typing import List, Dict, Any, Optional
from app.db.graph_db import Neo4jClient
from loguru import logger

def check_internet_exposed_instances(db_client: Neo4jClient, account_id: str, region: str, scan_id: str, sensitive_ports: Optional[List[int]] = None, limit: int = 500) -> List[Dict[str, Any]]:
    """Finds EC2 instances exposed to the internet on sensitive ports via security groups."""
    logger.debug(f"[{scan_id}] graph_query: Checking Internet Exposed EC2 Instances for account {account_id} in region {region}")

    if sensitive_ports is None:
        sensitive_ports = [22, 3389, 3306, 1433, 5432, 27017, 1521, 6379]

    port_conditions = []
    for port in sensitive_ports:
        port_conditions.append(f"(sgr.IpProtocol = 'tcp' AND sgr.FromPort <= {port} AND sgr.ToPort >= {port})")
    port_where_clause = " OR \n    ".join(port_conditions)

    query = f"""
    MATCH (sgr:SecurityGroupRule)-[:ALLOWS]->(sg:SecurityGroup)-[:APPLIES_TO]->(i:Ec2Instance)
    WHERE i.account_id = $account_id AND i.region = $region // Scope to account and region
      AND sgr.CidrIpv4 = '0.0.0.0/0' 
      AND sgr.RuleType = 'ingress'
      AND (
        {port_where_clause}
      )
    RETURN 
      i.InstanceId AS InstanceId, 
      i.arn AS InstanceArn,
      i.PublicIpAddress AS Ec2PublicIp,
      i.State AS Ec2State,
      sg.GroupId AS SecurityGroupId, 
      sg.GroupName AS SecurityGroupName, 
      sgr.IpProtocol AS Protocol, 
      sgr.FromPort AS PortOpened, 
      sgr.ToPort AS PortRangeEnd,
      sgr.Description AS RuleDescription
    LIMIT $limit
    """
    
    params = {"account_id": account_id, "region": region, "limit": limit}
    
    try:
        results = db_client.run(query, parameters=params)
        return results 
    except Exception as e:
        logger.error(f"[{scan_id}] Error in Internet Exposed EC2 Instances graph query: {e}")
        return []

def check_instances_not_enforcing_imdsv2(db_client: Neo4jClient, account_id: str, region: str, scan_id: str, limit: int = 500) -> List[Dict[str, Any]]:
    """Finds EC2 instances where IMDSv2 is not strictly enforced."""
    logger.debug(f"[{scan_id}] graph_query: Checking EC2 Instances for IMDSv2 enforcement for account {account_id} in region {region}")
    query = """
    MATCH (i:Ec2Instance {account_id: $account_id, region: $region})
    WHERE i.MetadataOptions_HttpTokens = 'optional' 
    RETURN
      i.InstanceId AS InstanceId,
      i.arn AS InstanceArn,
      i.region AS Region, 
      i.State AS InstanceState,
      i.MetadataOptions_HttpTokens AS HttpTokensSetting,
      i.MetadataOptions_State AS MetadataServiceState,
      i.MetadataOptions_HttpPutResponseHopLimit AS HopLimit,
      i.MetadataOptionsJson AS FullMetadataOptions
    ORDER BY InstanceId
    LIMIT $limit
    """
    params = {"account_id": account_id, "region": region, "limit": limit}
    try:
        results = db_client.run(query, parameters=params)
        return results 
    except Exception as e:
        logger.error(f"[{scan_id}] Error in IMDSv2 Enforcement graph query: {e}")
        return []

# Add other EC2 graph query functions here (e.g., IMDSv2 check) 