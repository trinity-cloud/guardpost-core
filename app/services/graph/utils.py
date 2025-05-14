import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Helper to get primary key value robustly
def _get_pk_value(resource_data: Dict[str, Any], pk_field: str, label: str) -> Optional[str]:
    """Gets the primary key value, checking common variations."""
    pk_value = resource_data.get(pk_field)
    if pk_value is None:
        # Try common alternatives based on scanner patterns
        if pk_field == 'resource_id':
            pk_value = resource_data.get('arn') or resource_data.get('id')
        elif pk_field == 'arn':
            pk_value = resource_data.get('resource_id') or resource_data.get('id')
        elif pk_field == 'id' and label == 'Region': # Special case for Region
             pk_value = resource_data.get('name')
        # Add other specific fallbacks if needed
    
    if pk_value is None:
         logger.warning(f"Missing primary key value for field '{pk_field}' in resource: {resource_data.get('arn') or resource_data.get('resource_id') or resource_data.get('id')}")
    return pk_value 