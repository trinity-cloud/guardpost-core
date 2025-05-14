from typing import List, Dict, Any
from app.db.graph_db import Neo4jClient
from loguru import logger

def check_public_rds_instances(db_client: Neo4jClient, account_id: str, region: str, scan_id: str, limit: int = 500) -> List[Dict[str, Any]]:
    """Finds publicly accessible RDS DB instances."""
    logger.debug(f"[{scan_id}] graph_query: Checking Publicly Accessible RDS Instances for account {account_id} in region {region}")
    query = """
    MATCH (db:DbInstance {account_id: $account_id, region: $region})
    WHERE db.PubliclyAccessible = true
    RETURN 
      db.DBInstanceIdentifier AS RdsInstanceId, 
      db.arn AS RdsInstanceArn,
      db.Engine AS RdsEngine, 
      db.EndpointAddress AS RdsEndpoint,
      db.DBInstanceStatus AS RdsStatus,
      db.VpcId AS VpcId
    LIMIT $limit
    """
    params = {"account_id": account_id, "region": region, "limit": limit}
    try:
        results = db_client.run(query, parameters=params)
        return results
    except Exception as e:
        logger.error(f"[{scan_id}] Error in Publicly Accessible RDS graph query: {e}")
        return []

def check_unencrypted_rds_instances(db_client: Neo4jClient, account_id: str, region: str, scan_id: str, limit: int = 500) -> List[Dict[str, Any]]:
    """Finds unencrypted RDS DB instances."""
    logger.debug(f"[{scan_id}] graph_query: Checking Unencrypted RDS Instances for account {account_id} in region {region}")
    query = """
    MATCH (db:DbInstance {account_id: $account_id, region: $region})
    WHERE db.StorageEncrypted = false
    RETURN 
      db.DBInstanceIdentifier AS RdsInstanceId, 
      db.arn AS RdsInstanceArn,
      db.Engine AS RdsEngine
    LIMIT $limit
    """
    params = {"account_id": account_id, "region": region, "limit": limit}
    try:
        results = db_client.run(query, parameters=params)
        return results
    except Exception as e:
        logger.error(f"[{scan_id}] Error in Unencrypted RDS graph query: {e}")
        return []

def check_automated_backups_disabled(db_client: Neo4jClient, account_id: str, region: str, scan_id: str, limit: int = 500) -> List[Dict[str, Any]]:
    """Finds RDS instances with automated backups disabled (BackupRetentionPeriod is 0)."""
    logger.debug(f"[{scan_id}] graph_query: Checking RDS Automated Backups Disabled for account {account_id} in region {region}")
    query = """
    MATCH (db:DbInstance {account_id: $account_id, region: $region})
    WHERE db.BackupRetentionPeriod = 0
    RETURN 
      db.DBInstanceIdentifier AS RdsInstanceId, 
      db.arn AS RdsInstanceArn,
      db.Engine AS RdsEngine
    LIMIT $limit
    """
    params = {"account_id": account_id, "region": region, "limit": limit}
    try:
        results = db_client.run(query, parameters=params)
        return results
    except Exception as e:
        logger.error(f"[{scan_id}] Error in RDS Automated Backups Disabled graph query: {e}")
        return []

def check_multi_az_disabled(db_client: Neo4jClient, account_id: str, region: str, scan_id: str, limit: int = 500) -> List[Dict[str, Any]]:
    """Finds RDS instances (relevant engines) with Multi-AZ disabled."""
    logger.debug(f"[{scan_id}] graph_query: Checking RDS Multi-AZ Disabled for account {account_id} in region {region}")
    # Relevant engines where Multi-AZ is a common HA feature
    relevant_engines = ['postgres', 'mysql', 'mariadb', 'sqlserver', 'oracle'] 
    query = """
    MATCH (db:DbInstance {account_id: $account_id, region: $region})
    WHERE db.MultiAZ = false AND db.Engine IN $relevant_engines
    RETURN 
      db.DBInstanceIdentifier AS RdsInstanceId, 
      db.arn AS RdsInstanceArn,
      db.Engine AS RdsEngine
    LIMIT $limit
    """
    params = {"account_id": account_id, "region": region, "limit": limit, "relevant_engines": relevant_engines}
    try:
        results = db_client.run(query, parameters=params)
        return results
    except Exception as e:
        logger.error(f"[{scan_id}] Error in RDS Multi-AZ Disabled graph query: {e}")
        return []

def check_deletion_protection_disabled(db_client: Neo4jClient, account_id: str, region: str, scan_id: str, limit: int = 500) -> List[Dict[str, Any]]:
    """Finds RDS instances with deletion protection disabled."""
    logger.debug(f"[{scan_id}] graph_query: Checking RDS Deletion Protection Disabled for account {account_id} in region {region}")
    query = """
    MATCH (db:DbInstance {account_id: $account_id, region: $region})
    WHERE db.DeletionProtection = false
    RETURN 
      db.DBInstanceIdentifier AS RdsInstanceId, 
      db.arn AS RdsInstanceArn,
      db.Engine AS RdsEngine
    LIMIT $limit
    """
    params = {"account_id": account_id, "region": region, "limit": limit}
    try:
        results = db_client.run(query, parameters=params)
        return results
    except Exception as e:
        logger.error(f"[{scan_id}] Error in RDS Deletion Protection Disabled graph query: {e}")
        return []

def check_iam_db_auth_disabled(db_client: Neo4jClient, account_id: str, region: str, scan_id: str, limit: int = 500) -> List[Dict[str, Any]]:
    """Finds RDS instances with IAM database authentication disabled."""
    logger.debug(f"[{scan_id}] graph_query: Checking RDS IAM DB Auth Disabled for account {account_id} in region {region}")
    query = """
    MATCH (db:DbInstance {account_id: $account_id, region: $region})
    WHERE db.IAMDatabaseAuthenticationEnabled = false
    RETURN 
      db.DBInstanceIdentifier AS RdsInstanceId, 
      db.arn AS RdsInstanceArn,
      db.Engine AS RdsEngine
    LIMIT $limit
    """
    params = {"account_id": account_id, "region": region, "limit": limit}
    try:
        results = db_client.run(query, parameters=params)
        return results
    except Exception as e:
        logger.error(f"[{scan_id}] Error in RDS IAM DB Auth Disabled graph query: {e}")
        return [] 