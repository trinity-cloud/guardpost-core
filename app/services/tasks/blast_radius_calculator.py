# tasks/blast_radius_calculator.py

from loguru import logger
from celery import shared_task # Assuming Celery is used

from app.db.graph_db import get_neo4j_client_sync # Sync client for tasks
from app.services.graph_metrics import GraphMetricsCalculator

@shared_task(name="tasks.calculate_node_blast_radius")
def calculate_node_blast_radius(node_id: str, node_label: str):
    """Celery task to calculate and update blast radius for a single node."""
    print(f"CELERY_TASK_STARTED: Calculating blast radius for {node_label} {node_id}") # DEBUG PRINT
    logger.info(f"Background task started: Calculate blast radius for {node_label} {node_id}")
    
    neo4j_client = None
    try:
        # Get a synchronous Neo4j client instance suitable for background tasks
        neo4j_client = get_neo4j_client_sync()
        if not neo4j_client:
             logger.error("Failed to get Neo4j client in background task.")
             # Optionally raise error to trigger Celery retry
             # raise ConnectionError("Failed to get Neo4j client")
             return # Exit task if client fails

        calculator = GraphMetricsCalculator(neo4j_client)
        calculator.update_node_blast_radius(node_id, node_label)
        
        logger.info(f"Background task finished: Calculate blast radius for {node_label} {node_id}")

    except Exception as e:
        logger.error(f"Error in blast radius background task for {node_label} {node_id}: {e}", exc_info=True)
        # Depending on Celery config, task might retry on failure
        # raise # Re-raise to allow Celery retry mechanisms if configured
    finally:
        if neo4j_client:
            neo4j_client.close() 