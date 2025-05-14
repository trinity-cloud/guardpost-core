# iam_relationship_builder.py

from typing import Dict, List, Any, Tuple
from loguru import logger

# Placeholder for mapping principal IDs/types to actual graph nodes
# This might involve querying the graph or using a pre-built map
def _get_source_node_match(principal_label: str, principal_id: str, param_key: str) -> Tuple[str, Dict[str, Any]]:
    """Generates MATCH clause and params for the source principal node."""
    # Special handling for wildcard or specific account IDs/Service Principals
    if principal_label == "WildcardPrincipal":
        # We might not create a node for '*', handle differently or skip
        logger.debug(f"Skipping relationship from WildcardPrincipal source.")
        return "", {}
    elif principal_label == "AwsAccount":
        match_clause = f"(src:{principal_label} {{id: ${param_key}}})"
        params = {param_key: principal_id}
    elif principal_label == "ServicePrincipal":
         # Assume ServicePrincipal nodes are merged by name
        match_clause = f"(src:{principal_label} {{name: ${param_key}}})"
        params = {param_key: principal_id}
    elif principal_label in ["IamRole", "IamUser"]:
        # Roles/Users are identified by ARN
        match_clause = f"(src:{principal_label} {{arn: ${param_key}}})"
        params = {param_key: principal_id}
    # Add FederatedPrincipal, CanonicalUser if needed
    else:
        logger.warning(f"Unsupported source principal label '{principal_label}' for CAN_ASSUME relationship.")
        return "", {}
    return match_clause, params

def build_can_assume_relationship_queries(relationship_data: List[Dict]) -> List[Tuple[str, Dict[str, Any]]]:
    """
    Generates Cypher MERGE queries to create CAN_ASSUME relationships.

    Args:
        relationship_data: A list of dictionaries, where each dictionary represents
                           a CAN_ASSUME relationship derived by the analyzer, e.g.:
                           {
                               'source_label': 'IamRole',
                               'source_id': 'arn:aws:iam::111:role/SourceRole',
                               'target_label': 'IamRole',
                               'target_id': 'arn:aws:iam::111:role/TargetRole',
                               'properties': {'condition_json': '{...}', 'statement_sid': 'Stmt1'}
                           }

    Returns:
        A list of tuples, each containing a Cypher query string and its parameters dict.
    """
    queries_params = []
    logger.info(f"Generating Cypher for {len(relationship_data)} CAN_ASSUME relationships...")

    for i, rel in enumerate(relationship_data):
        src_label = rel.get('source_label')
        src_id = rel.get('source_id')
        tgt_label = rel.get('target_label') # Should always be IamRole for CAN_ASSUME
        tgt_id = rel.get('target_id') # Target Role ARN
        rel_props = rel.get('properties', {})

        if not all([src_label, src_id, tgt_label == 'IamRole', tgt_id]):
            logger.warning(f"Skipping invalid CAN_ASSUME relationship data: {rel}")
            continue

        src_param_key = f"src_id_{i}"
        tgt_param_key = f"tgt_id_{i}"
        props_param_key = f"props_{i}"

        source_match_clause, source_params = _get_source_node_match(src_label, src_id, src_param_key)
        
        if not source_match_clause:
            continue # Skip if source node can't be matched

        target_match_clause = f"(tgt:{tgt_label} {{arn: ${tgt_param_key}}})" # Target is always an IamRole by ARN
        target_params = {tgt_param_key: tgt_id}

        # Combine params
        query_params = {**source_params, **target_params}

        rel_props_cypher = ""
        if rel_props:
            query_params[props_param_key] = rel_props
            rel_props_cypher = f" SET r += ${props_param_key}"

        query = (
            f"MATCH {source_match_clause}, {target_match_clause} "
            f"MERGE (src)-[r:CAN_ASSUME]->(tgt)"
            f"{rel_props_cypher}"
        )

        queries_params.append((query, query_params))

    logger.info(f"Generated {len(queries_params)} Cypher queries for CAN_ASSUME relationships.")
    return queries_params

def build_can_access_relationship_queries(relationship_data: List[Dict]) -> List[Tuple[str, Dict[str, Any]]]:
    """
    Generates Cypher MERGE queries to create CAN_ACCESS relationships based on 
    refined analyzer output, focusing on specific resource ARNs.

    Args:
        relationship_data: A list of dictionaries representing CAN_ACCESS relationships,
                           e.g., {
                               'source_id': principal_arn, 
                               'target_id': specific_resource_arn or '*', 
                               'target_label': 'S3Bucket' or 'Resource', 
                               'properties': {
                                   'permission_level': 'READ',
                                   'condition_json': '{...}',
                                   'resource_pattern': 'arn:aws:s3:::my-bucket/*'
                               }
                           }

    Returns:
        A list of tuples (Cypher query string, parameters dict).
    """
    queries_params = []
    logger.info(f"Generating Cypher for {len(relationship_data)} CAN_ACCESS relationships...")
    # logger.warning("CAN_ACCESS relationship building is currently basic/placeholder based on admin access detection.")
    # TODO: Enhance this significantly to handle specific resource patterns and permission levels.

    for i, rel in enumerate(relationship_data):
        # Assume source is always IamRole or IamUser, identified by ARN
        src_label = "IamPrincipal" # Could refine if analyzer passes specific label
        src_pk_field = "arn"
        src_id = rel.get('source_id') 
        
        tgt_label = rel.get('target_label') # Label determined by analyzer (e.g., S3Bucket, Ec2Instance, or generic Resource)
        tgt_pk_field = "arn" # Assume target is identified by ARN for specific resources
        tgt_id = rel.get('target_id') # Specific ARN or potentially '*' for FULL_ACCESS
        
        rel_props = rel.get('properties', {})

        if not all([src_id, tgt_id, tgt_label]):
            logger.warning(f"Skipping invalid CAN_ACCESS relationship data: {rel}")
            continue
            
        # --- Skip relationships to non-specific targets for now --- 
        # Only create relationships where target_id is a specific ARN.
        # The analyzer currently maps FULL_ACCESS/'*' to target_id='*'. We skip creating these.
        # Future enhancement: Create a relationship to a special 'WildcardResource' node for '*'.
        if not tgt_id.startswith('arn:aws:'):
            logger.debug(f"Skipping CAN_ACCESS relationship from {src_id} to non-specific target '{tgt_id}'")
            continue
        # ----------------------------------------------------------
        
        src_param = f"src_id_{i}"
        tgt_param = f"tgt_id_{i}"
        props_param = f"props_{i}"
        
        # Assume src_label could be IamUser or IamRole for matching
        # Use generic label match first, specific labels can be added later if needed
        # MATCH (src {arn: $src_param}) WHERE labels(src) IN ['IamUser', 'IamRole']
        source_match_clause = f"(src {{{src_pk_field}: ${src_param}}})" 
        
        # Attempt to match target using ARN. The node must exist from the scan.
        target_match_clause = f"(tgt {{{tgt_pk_field}: ${tgt_param}}})" 
        # Optional: Add WHERE clause to ensure target has the expected label if provided by analyzer
        # target_match_clause = f"(tgt:{tgt_label} {{{tgt_pk_field}: ${tgt_param}}})"

        query_params = {src_param: src_id, tgt_param: tgt_id}
        
        props_cypher = ""
        if rel_props:
             # Clean props before setting
            cleaned_props = {k: v for k, v in rel_props.items() if v is not None}
            if cleaned_props:
                 query_params[props_param] = cleaned_props
                 props_cypher = f" SET r = ${props_param}" # Overwrite relationship properties
        
        query = (
            f"MATCH {source_match_clause}, {target_match_clause} "
            f"MERGE (src)-[r:CAN_ACCESS]->(tgt)"
            f"{props_cypher}"
        )
        queries_params.append((query, query_params))

    logger.info(f"Generated {len(queries_params)} Cypher queries for specific CAN_ACCESS relationships.")
    return queries_params 