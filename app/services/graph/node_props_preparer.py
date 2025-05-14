import json
import datetime
from typing import Dict, Any, Optional
from loguru import logger

def prepare_node_properties(
    label: str,
    primary_key_value: Optional[str], # For logging context
    resource_data: Dict[str, Any],
    initial_properties: Dict[str, Any]
) -> Dict[str, Any]:
    """Prepares a dictionary of node properties for Neo4j storage.
    Ensures essential fields are present, handles tags, and serializes complex types.
    """
    props = initial_properties.copy()

    # Ensure core identifying properties are present
    if 'arn' not in props and resource_data.get('arn'): 
        props['arn'] = resource_data['arn']
    if 'id' not in props and resource_data.get('id'): 
        props['id'] = resource_data['id']
    if 'resource_id' not in props and resource_data.get('resource_id'): 
        props['resource_id'] = resource_data['resource_id']
    if 'account_id' not in props and resource_data.get('account_id'): 
        props['account_id'] = resource_data['account_id']
    if 'region' not in props and resource_data.get('region'): 
        props['region'] = resource_data['region']
    if 'type' not in props and resource_data.get('resource_type'): 
        props['type'] = resource_data['resource_type']
    if 'name' not in props and resource_data.get('name'): 
        props['name'] = resource_data['name']

    # Handle 'tags' specifically - ensure it's a JSON string if it was a dict
    # Tags might come from resource_data.properties or resource_data.relationships.tags
    tags_to_serialize = None
    if 'tags' in props and isinstance(props['tags'], dict):
        tags_to_serialize = props['tags']
    elif 'tags' not in props and isinstance(resource_data.get('relationships', {}).get('tags'), dict):
        tags_to_serialize = resource_data['relationships']['tags']
    
    if tags_to_serialize is not None:
        try:
            props['tags'] = json.dumps(tags_to_serialize, default=str)
        except TypeError as e_tags:
            logger.warning(f"Could not serialize tags for {label} {primary_key_value}: {e_tags}. Storing as string.")
            props['tags'] = str(tags_to_serialize)
    elif 'tags' in props and not isinstance(props['tags'], str): # If tags exists but not dict or str, stringify
        props['tags'] = str(props['tags'])

    props['last_updated'] = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # --- Helper to check if a list contains only primitive types ---
    def is_list_of_primitives(lst: list) -> bool:
        if not lst: # Empty list is fine
            return True
        return all(isinstance(item, (str, int, float, bool, type(None))) for item in lst)
    # --- End helper ---

    final_props_for_cypher = {}
    # Define keys for properties that are lists of complex objects and should be JSON serialized
    # Example: TrustPolicyConditions is List[Dict]
    json_serialize_list_keys = ['TrustPolicyConditions'] 

    for k, v in props.items():
        if isinstance(v, dict):
            try:
                final_props_for_cypher[k] = json.dumps(v, default=str)
            except TypeError as e_serialize:
                logger.warning(f"Could not serialize dictionary property '{k}' to JSON for node {label} {primary_key_value}: {e_serialize}. Storing as string representation.")
                final_props_for_cypher[k] = str(v)
        elif isinstance(v, list):
            # Serialize if it's a list of complex objects (not all primitives) 
            # OR if the key is in our explicit list for JSON serialization (e.g., TrustPolicyConditions)
            if k in json_serialize_list_keys or not is_list_of_primitives(v):
                try:
                    final_props_for_cypher[k] = json.dumps(v, default=str)
                except TypeError as e_serialize:
                    logger.warning(f"Could not serialize list property '{k}' to JSON for node {label} {primary_key_value}: {e_serialize}. Storing as string representation.")
                    final_props_for_cypher[k] = str(v)
            else: # It's a list of primitives, keep as is for Neo4j
                final_props_for_cypher[k] = v 
        elif v is not None: # Keep primitive types and non-None values
            final_props_for_cypher[k] = v
        # None values are implicitly skipped by not being added to final_props_for_cypher
        
    # --- Add specific logging for S3ACLGrant before returning ---
    if label == 'S3ACLGrant':
        logger.info(f"PREPARE_NODE_PROPS_S3ACLGRANT: Final props for {label} {primary_key_value}: {final_props_for_cypher}")
    # --- End specific logging ---
            
    return final_props_for_cypher 