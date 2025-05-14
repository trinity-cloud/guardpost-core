# schedulers/post_scan_tasks.py

import uuid
from typing import List, Dict, Any, Optional
import datetime

from loguru import logger

from app.db.graph_db import get_neo4j_client_sync # Sync client for query
from app.services.tasks.blast_radius_calculator import calculate_node_blast_radius
from app.core.config import settings
# Import the constants
from app.services.graph.constants import RESOURCE_TYPE_TO_LABEL, RESOURCE_TYPE_PRIMARY_KEY

# Define which node labels should have blast radius calculated
# Align with docs/blast_radius.md
TARGET_LABELS_FOR_BLAST_RADIUS = [
    "IamRole",
    "SecurityGroup",
    "Ec2Instance",
    "S3Bucket",
    "IamUser",
    "LambdaFunction",
    "DbInstance",
]

def schedule_blast_radius_calculations(
    scan_id: uuid.UUID, 
    account_id: str, 
    region: Optional[str] = None
):
    """
    Queries the graph for relevant nodes 
    and schedules background tasks to calculate their blast radius.

    Args:
        scan_id: The ID of the scan that just completed.
        account_id: The AWS account ID.
        region: Optional region filter (if scan was regional).
    """
    logger.info(f"[{scan_id}] Scheduling blast radius calculations for account {account_id} {f'in region {region}' if region else 'globally'}...")
    
    neo4j_client = None
    nodes_to_calculate = []
    try:
        neo4j_client = get_neo4j_client_sync()
        if not neo4j_client:
            logger.error("Failed to get Neo4j client for scheduling blast radius.")
            return

        # --- TEMP DEBUG: Count target nodes before time filter ---
        temp_count_query_parts = []
        for label_to_count in TARGET_LABELS_FOR_BLAST_RADIUS:
            temp_count_query_parts.append(f"MATCH (n:{label_to_count} {{account_id: $account_id}}) RETURN count(n) as count, '{label_to_count}' as label")
        temp_full_count_query = " UNION ALL ".join(temp_count_query_parts)
        try:
            logger.debug(f"TEMP DEBUG: Pre-filter node counts query: {temp_full_count_query}")
            pre_filter_counts = neo4j_client.run(temp_full_count_query, parameters={"account_id": account_id})
            logger.debug(f"TEMP DEBUG: Pre-filter node counts for account {account_id}: {pre_filter_counts}")
        except Exception as e_count:
            logger.error(f"TEMP DEBUG: Error during pre-filter node count: {e_count}")
        # --- END TEMP DEBUG ---

        params = {"account_id": account_id}
        if region:
             params["region"] = region
        
        union_query_parts = []
        
        for label in TARGET_LABELS_FOR_BLAST_RADIUS:
            pk_field = RESOURCE_TYPE_PRIMARY_KEY.get(label)
            if not pk_field:
                logger.error(f"Cannot query for blast radius: No primary key defined for target label '{label}'")
                continue 
                
            query_part = f"MATCH (n:{label}) WHERE n.account_id = $account_id"
            
            if region:
                 query_part += f" AND (n.region = $region OR n.region = 'global' OR n.region IS NULL)"
            
            union_query_parts.append(f"{query_part} RETURN DISTINCT labels(n) as labels, n.{pk_field} as id")
            
        if not union_query_parts:
            logger.info(f"[{scan_id}] No target labels configured or valid for blast radius calculation.")
            return
            
        full_query = " UNION ".join(union_query_parts)
        logger.debug(f"Blast radius node query: {full_query} PARAMS: {params}")
        
        results = neo4j_client.run(full_query, parameters=params)
        
        processed_node_ids = set() 
        for record in results:
            node_id = record["id"]
            labels = record["labels"]
            
            if not node_id:
                 logger.warning(f"Query returned record with missing ID: {record}")
                 continue
            
            if node_id in processed_node_ids:
                 continue

            primary_label = next((lbl for lbl in labels if lbl in TARGET_LABELS_FOR_BLAST_RADIUS), None)
            
            if primary_label:
                 logger.debug(f"[{scan_id}] Adding node to schedule: ID={node_id}, Label={primary_label}")
                 nodes_to_calculate.append((node_id, primary_label))
                 processed_node_ids.add(node_id)
            else:
                 logger.warning(f"Could not determine primary target label for node ID {node_id} with labels {labels}")

    except Exception as e:
        logger.error(f"[{scan_id}] Error querying nodes for blast radius calculation: {e}", exc_info=True)
        return 
    finally:
        if neo4j_client:
            neo4j_client.close()

    scheduled_count = 0
    logger.info(f"[{scan_id}] Found {len(nodes_to_calculate)} nodes to schedule for blast radius calculation.")
    for node_id, node_label in nodes_to_calculate:
        try:
            calculate_node_blast_radius.delay(node_id=node_id, node_label=node_label)
            scheduled_count += 1
        except Exception as task_e:
            logger.error(f"[{scan_id}] Failed to schedule blast radius task for {node_label} {node_id}: {task_e}")

    logger.info(f"[{scan_id}] Scheduled {scheduled_count} / {len(nodes_to_calculate)} blast radius calculation tasks.") 