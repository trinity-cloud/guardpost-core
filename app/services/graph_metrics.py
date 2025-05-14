# graph_metrics.py

import datetime
from typing import Dict, List, Optional, Set, Tuple, Any

from loguru import logger

from app.db.graph_db import Neo4jClient
from app.core.config import settings # To get depth limit, and now weights
# Import the constants
from app.services.graph.constants import RESOURCE_TYPE_TO_LABEL, RESOURCE_TYPE_PRIMARY_KEY

class GraphMetricsCalculator:
    """Calculates metrics derived from the graph structure, like blast radius."""

    def __init__(self, neo4j_client: Neo4jClient):
        self.client = neo4j_client
        self.max_depth = settings.BLAST_RADIUS_MAX_DEPTH
        self.relationship_weights = settings.RELATIONSHIP_WEIGHTS
        self.is_enabled = bool(self.client and self.client._driver) # Added from graph_builder for consistency

    def _get_relationship_weight(self, rel_type: str, rel_properties: Optional[Dict] = None, target_node_labels: Optional[List[str]] = None) -> float:
        """Gets the weight for a given relationship type, potentially considering properties and target node type."""
        # TODO: Move RELATIONSHIP_WEIGHTS to config - DONE
        
        # Handle specific cases first
        if rel_type == "CAN_ACCESS" and rel_properties:
            level = rel_properties.get("permission_level")
            if level == "FULL_ACCESS": return self.relationship_weights.get("CAN_ACCESS_FULL_ACCESS", self.relationship_weights["DEFAULT"])
            if level == "PERMISSIONS": return self.relationship_weights.get("CAN_ACCESS_PERMISSIONS", self.relationship_weights["DEFAULT"])
            if level == "WRITE": return self.relationship_weights.get("CAN_ACCESS_WRITE", self.relationship_weights["DEFAULT"])
            if level == "READ": return self.relationship_weights.get("CAN_ACCESS_READ", self.relationship_weights["DEFAULT"])
            if level == "LIST": return self.relationship_weights.get("CAN_ACCESS_LIST", self.relationship_weights["DEFAULT"])
            # Fallback for CAN_ACCESS if level not mapped or missing
            logger.warning(f"Unknown or missing permission_level '{level}' for CAN_ACCESS, using default weight.")
            return self.relationship_weights["DEFAULT"]
        
        if rel_type == "ROUTES_TO":
            if target_node_labels and "InternetGateway" in target_node_labels:
                return self.relationship_weights.get("ROUTES_TO_INTERNET_GATEWAY", self.relationship_weights.get("ROUTES_TO", self.relationship_weights["DEFAULT"])) # Specific or fallback ROUTES_TO
            elif target_node_labels and "NatGateway" in target_node_labels:
                return self.relationship_weights.get("ROUTES_TO_NAT_GATEWAY", self.relationship_weights.get("ROUTES_TO", self.relationship_weights["DEFAULT"]))    
            # Default weight for other ROUTES_TO if not specified or target unknown
            return self.relationship_weights.get("ROUTES_TO", self.relationship_weights["DEFAULT"])

        # Default fallback
        return self.relationship_weights.get(rel_type, self.relationship_weights["DEFAULT"])

    def calculate_blast_radius(self, start_node_id: str, start_node_label: str) -> Optional[Dict[str, Any]]:
        """
        Calculates the blast radius score and count for a given starting node
        using the Weighted N-Hop Traversal algorithm.

        Args:
            start_node_id: The primary key value of the starting node.
            start_node_label: The Neo4j label of the starting node.

        Returns:
            A dictionary containing {'score': float, 'count': int} or None if calculation fails.
        """
        if not self.is_enabled:
            logger.warning("GraphMetricsCalculator is not enabled (Neo4j client missing). Skipping blast radius calculation.")
            return None
            
        logger.debug(f"Calculating blast radius for {start_node_label} {start_node_id} up to depth {self.max_depth}")
        
        pk_field = RESOURCE_TYPE_PRIMARY_KEY.get(start_node_label) 
        if not pk_field:
            logger.error(f"Cannot calculate blast radius: No primary key defined for label '{start_node_label}'")
            return None
            
        total_score = 0.0
        nodes_visited_ids = set() # Store elementIds to handle cycles
        queue = [] # Stores tuples of (elementId, depth)

        # 1. Find the starting node elementId
        try:
            start_node_query = f"MATCH (n:{start_node_label} {{{pk_field}: $start_id}}) RETURN elementId(n) AS id LIMIT 1"
            result = self.client.run(start_node_query, parameters={"start_id": start_node_id})
            start_node_element_id = result[0]["id"] if result else None
            if not start_node_element_id:
                logger.warning(f"Blast radius start node not found: {start_node_label} {start_node_id}")
                return None
            nodes_visited_ids.add(start_node_element_id)
            queue.append((start_node_element_id, 0))
        except Exception as e:
            logger.error(f"Failed to find start node {start_node_label} {start_node_id}: {e}")
            return None

        # 2. Perform BFS Traversal
        while queue:
            current_element_id, current_depth = queue.pop(0)

            if current_depth >= self.max_depth:
                logger.trace(f"Reached max depth {self.max_depth} at node {current_element_id}.")
                continue

            # 3. Find outgoing neighbors and relationships for the current node
            # Using OPTIONAL MATCH to handle nodes with no outgoing relationships gracefully
            try:
                neighbor_query = (
                    f"MATCH (n) WHERE elementId(n) = $element_id "
                    f"OPTIONAL MATCH (n)-[r]->(m) "
                    f"RETURN elementId(n) as current_id, type(r) AS rel_type, properties(r) as rel_props, elementId(m) AS neighbor_id, labels(m) as neighbor_labels"
                )
                neighbors_result = self.client.run(neighbor_query, parameters={"element_id": current_element_id})
            except Exception as e:
                logger.error(f"Error querying neighbors for node {current_element_id}: {e}")
                continue # Skip to next node in queue

            for record in neighbors_result:
                neighbor_id = record["neighbor_id"]
                rel_type = record["rel_type"]
                rel_props = record["rel_props"]
                neighbor_labels = record["neighbor_labels"]

                # Skip if optional match found no outgoing relationship
                if neighbor_id is None or rel_type is None:
                    continue

                if neighbor_id not in nodes_visited_ids:
                    nodes_visited_ids.add(neighbor_id)
                    
                    # Get weight and add to score
                    weight = self._get_relationship_weight(rel_type, rel_props, neighbor_labels)
                    # Apply decay factor: weight / (depth + 1) to give full weight at depth 0
                    total_score += weight / (current_depth + 1.0) 
                    
                    # Enqueue neighbor
                    queue.append((neighbor_id, current_depth + 1))
        
        # 4. Final calculation
        blast_radius_count = len(nodes_visited_ids) - 1 # Exclude start node
        blast_radius_score = round(total_score, 2)

        logger.info(f"Blast radius for {start_node_label} {start_node_id}: Count={blast_radius_count}, Score={blast_radius_score}")
        return {"score": blast_radius_score, "count": blast_radius_count}

    def update_node_blast_radius(self, node_id: str, node_label: str):
        """Calculates and updates blast radius properties on a specific node."""
        if not self.client or not self.is_enabled:
             logger.warning("Neo4j client not available, skipping blast radius update.")
             return

        calculated_metrics = self.calculate_blast_radius(node_id, node_label)

        if calculated_metrics is not None:
            # Update the node in Neo4j
            try:
                pk_field = RESOURCE_TYPE_PRIMARY_KEY.get(node_label)
                if not pk_field:
                    logger.error(f"Cannot update blast radius: No primary key defined for label '{node_label}'")
                    return
                
                update_query = (
                    f"MATCH (n:{node_label}) WHERE n.{pk_field} = $node_id "
                    f"SET n.blast_radius_score = $score, "
                    f"    n.blast_radius_count = $count, "
                    f"    n.blast_radius_calculated_at = datetime({{timezone: 'UTC'}})"
                )
                params = {
                    "node_id": node_id,
                    "score": calculated_metrics['score'],
                    "count": calculated_metrics['count']
                }
                self.client.run(update_query, parameters=params)
                logger.debug(f"Successfully updated blast radius for {node_label} {node_id}")
            except Exception as e:
                logger.error(f"Failed to update blast radius properties for {node_label} {node_id}: {e}") 