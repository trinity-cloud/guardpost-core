import json
import logging
from typing import Any, Dict, List, Optional, Tuple
import re
import datetime
import uuid

from sqlalchemy.orm import Session # Import Session for analyzer

from app.core.config import settings
from app.db.graph_db import Neo4jClient
from app.core.exceptions import DatabaseError
from app.providers.aws_provider import AwsProvider # Import AwsProvider for analyzer
from app.services.analyzers import iam_analyzer # Import the analyzer module
from app.services.graph import iam_relationship_builder # Import the new relationship builder
# Import the constants
from app.services.graph.constants import RESOURCE_TYPE_TO_LABEL, RESOURCE_TYPE_PRIMARY_KEY 
from app.services.graph.node_props_preparer import prepare_node_properties # New Import
from app.services.graph.utils import _get_pk_value # Import from new utils module
from app.services.graph.relationship_creator import execute_relationship_queries, create_relationships, create_deferred_relationships_grouped # Import new function
from app.services.graph.schema_manager import ensure_indexes_constraints # Import new function

logger = logging.getLogger(__name__)

# Mapping from resource_type string to Neo4j Node Label
# Keep this consistent with docs/graph_schema_v1.1.md
# --- REMOVED: Moved to constants.py --- 
# RESOURCE_TYPE_TO_LABEL = {...}

# Define primary keys for MERGE operations (must exist in resource data)
# --- REMOVED: Moved to constants.py --- 
# RESOURCE_TYPE_PRIMARY_KEY = {...}

class GraphBuilder:
    """Builds the Neo4j graph from scanned AWS resource data."""

    def __init__(self, neo4j_client: Neo4jClient):
        self.client = neo4j_client
        # TODO: Implement chosen graph update strategy (Task 2.2)
        # For now, assume WIPE_AND_RELOAD for simplicity during refactor
        self.rebuild_strategy = "WIPE_AND_RELOAD" # Placeholder
        # self.rebuild_strategy = settings.GRAPH_REBUILD_STRATEGY
        if not self.client or not self.client._driver: # Check if client is initialized
            logger.warning("Neo4j client not available. GraphBuilder initialized in disabled state.")
            self.is_enabled = False
        else:
             self.is_enabled = True

    def _wipe_graph(self):
        """Wipes all nodes and relationships from the graph."""
        logger.info("Wiping existing graph data (strategy: WIPE_AND_RELOAD)...")
        try:
            self.client.run("MATCH (n) DETACH DELETE n")
            logger.info("Graph wipe complete.")
        except DatabaseError as e:
            logger.error(f"Failed to wipe graph: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during graph wipe: {e}")
            raise

    def _upsert_node(self, resource_data: Dict[str, Any]):
        """Creates or updates a single node in the graph using MERGE."""
        resource_type = resource_data.get('resource_type')
        label = RESOURCE_TYPE_TO_LABEL.get(resource_type)
        
        if not label:
            logger.trace(f"Skipping node creation for resource_type '{resource_type}'.")
            return

        primary_key_field = RESOURCE_TYPE_PRIMARY_KEY.get(label)
        if not primary_key_field:
            logger.warning(f"Skipping node {resource_data.get('arn') or resource_data.get('resource_id')} ({label}): No primary key defined for MERGE.")
            return

        primary_key_value = _get_pk_value(resource_data, primary_key_field, label)
        if primary_key_value is None:
            return

        # Log raw data for EC2 instances for easier debugging if issues persist with them
        # if label == 'Ec2Instance': 
        #     try:
        #         logger.debug(f"GRAPH_BUILDER_EC2INSTANCE_RAW_DATA: {json.dumps(resource_data, indent=2, default=str)}")
        #     except Exception as e_log:
        #         logger.error(f"Error logging Ec2Instance raw data for {primary_key_value}: {e_log}")

        initial_props = resource_data.get('properties', {})
        
        # Call the new preparer function
        final_props_for_cypher = prepare_node_properties(
            label=label, 
            primary_key_value=primary_key_value, 
            resource_data=resource_data, 
            initial_properties=initial_props
        )

        params = {'props': final_props_for_cypher}
        
        if primary_key_field == 'key_value': # Specific handling for Tag nodes
            key_prop = final_props_for_cypher.get('key')
            value_prop = final_props_for_cypher.get('value')
            if key_prop is None or value_prop is None:
                 logger.warning(f"Skipping Tag node due to missing key or value in final props for Cypher. Original PK: {primary_key_value}")
                 return
            merge_on = f"{{ key: $key_param, value: $value_param }}"
            params['key_param'] = key_prop
            params['value_param'] = value_prop 
            # $props will still set all properties including key, value, key_value etc.
        else:
            merge_on = f"{{ {primary_key_field}: ${primary_key_field} }}"
            params[primary_key_field] = primary_key_value
        
        set_clause = f"n = $props"

        query = f"MERGE (n:{label} {merge_on}) SET {set_clause} RETURN elementId(n)"
        try:
            logger.debug(f"GRAPH_BUILDER_UPSERT_PRE_RUN: Query for {label} {primary_key_value}: {query}")
            try:
                params_json = json.dumps(params, indent=2, default=str) 
            except TypeError:
                params_json = "Error serializing params for logging"
            logger.debug(f"GRAPH_BUILDER_UPSERT_PRE_RUN: Params for {label} {primary_key_value}: {params_json}")
            
            result = self.client.run(query, parameters=params)
            logger.info(f"GRAPH_BUILDER_UPSERT_SUCCESS: Successfully upserted {label} {primary_key_value}. Result: {result}")
        except DatabaseError as e:
            logger.error(f"GRAPH_BUILDER_UPSERT_DB_ERROR: Failed to upsert node {label} {primary_key_value}. Query: {query}. Error: {e}", exc_info=True)
            try:
                params_json_error = json.dumps(params, indent=2, default=str)
            except TypeError:
                params_json_error = "Error serializing params for error logging"
            logger.error(f"GRAPH_BUILDER_UPSERT_DB_ERROR_PARAMS: Params for failed upsert of {label} {primary_key_value}: {params_json_error}")
        except Exception as e:
            logger.error(f"GRAPH_BUILDER_UPSERT_UNEXPECTED_ERROR: Unexpected error upserting node {label} {primary_key_value}. Query: {query}. Error: {e}", exc_info=True)
            try:
                params_json_unexpected_error = json.dumps(params, indent=2, default=str)
            except TypeError:
                params_json_unexpected_error = "Error serializing params for unexpected error logging"
            logger.error(f"GRAPH_BUILDER_UPSERT_UNEXPECTED_ERROR_PARAMS: Params for failed upsert of {label} {primary_key_value}: {params_json_unexpected_error}")

    def _upsert_base_nodes(self, all_resources_flat: List[Dict[str, Any]]):
        """Upsert foundational nodes: AwsAccount, Region, ServicePrincipal, Tag."""
        accounts = set()
        regions = set()
        service_principals = set()
        tags_set = set()

        for resource in all_resources_flat:
            account_id = resource.get('account_id')
            region = resource.get('region')
            if account_id: accounts.add(account_id)
            if region and region != 'global': regions.add(region)

            # Extract service principals from role trusts
            if resource.get('resource_type') == 'IamRole':
                trusts = resource.get('relationships', {}).get('trusted_principals_with_conditions', [])
                for trust in trusts:
                    if trust.get('type') == 'Service':
                        service_principals.add(trust.get('identifier'))
            
            # Extract tags
            tags = resource.get('relationships', {}).get('tags', {})
            if tags:
                for key, value in tags.items():
                    tags_set.add((key, value))

        logger.info(f"Found {len(accounts)} accounts, {len(regions)} regions, {len(service_principals)} service principals, {len(tags_set)} tags.")

        # Upsert Account Nodes
        for acc_id in accounts:
            acc_data = {'resource_type': 'AwsAccount', 'id': acc_id, 'properties': {'id': acc_id}}
            self._upsert_node(acc_data)

        # Upsert Region Nodes
        for reg_name in regions:
             reg_data = {'resource_type': 'Region', 'id': reg_name, 'properties': {'id': reg_name, 'name': reg_name}}
             self._upsert_node(reg_data)
        
        # Upsert ServicePrincipal Nodes
        for sp_name in service_principals:
             if sp_name: # Ensure not None or empty
                sp_data = {'resource_type': 'ServicePrincipal', 'name': sp_name, 'properties': {'name': sp_name}}
                self._upsert_node(sp_data)
                
        # Upsert Tag Nodes
        for key, value in tags_set:
                         tag_data = {
                'resource_type': 'Tag',
                             'key_value': f"{key}||{value}", 
                             'properties': {'key': key, 'value': value, 'key_value': f"{key}||{value}"}
                         }
                         self._upsert_node(tag_data)

        logger.info("Finished upserting base nodes (Account, Region, ServicePrincipal, Tag).")

    def build_graph(self, aws_provider: AwsProvider, db_session: Session, all_resources: Dict[str, Dict[str, List[Any]]]):
        """Builds the graph from the aggregated scanner results, including IAM analysis."""
        if not self.is_enabled:
            logger.info("GraphBuilder is disabled. Skipping graph build.")
            return

        logger.info(f"Starting graph build process. Strategy: {self.rebuild_strategy}")
        start_time = datetime.datetime.now()

        if self.rebuild_strategy == "WIPE_AND_RELOAD":
            try:
                self._wipe_graph()
            except Exception:
                logger.error("Graph wipe failed. Aborting graph build.", exc_info=True)
                return 
        
        all_resources_flat: List[Dict[str, Any]] = []
        iam_resources_list: List[Dict[str, Any]] = []
        for service, regions_data in all_resources.items():
            is_global = service == "iam"
            for region, resource_list in regions_data.items():
                 if isinstance(resource_list, list):
                      for res in resource_list:
                           if isinstance(res, dict):
                                if 'account_id' not in res: res['account_id'] = aws_provider.account_id
                                if 'region' not in res: res['region'] = region
                                all_resources_flat.append(res)
                                if is_global and res.get('resource_type') in ['IamUser', 'IamRole', 'IamPolicy', 'AccountSettings']:
                                     iam_resources_list.append(res)
                 else:
                    logger.warning(f"Unexpected data format for {service}/{region}. Expected list, got {type(resource_list)}")

        if not all_resources_flat:
            logger.warning("No resources found to build graph after flattening.")
            return

        derived_iam_relationships = {"CAN_ASSUME": [], "CAN_ACCESS": []}
        if iam_resources_list:
            try:
                analyzer_output = iam_analyzer.analyze_iam(
                    db=db_session, 
                    db_client=self.client,
                    account_id=aws_provider.account_id,
                    scan_id=uuid.uuid4(),
                    region='global',
                    iam_resources=iam_resources_list,
                    aws_provider=aws_provider, 
                    create_finding_callback=lambda *args, **kwargs: None
                )
                derived_iam_relationships = analyzer_output.get("relationships_to_create", derived_iam_relationships)
            except Exception as e:
                logger.error(f"IAM Analysis failed during graph build: {e}", exc_info=True)

        self._upsert_base_nodes(all_resources_flat)
        
        logger.info(f"Upserting primary resource nodes from {len(all_resources_flat)} total flattened resources...")
        node_count = 0
        for resource in all_resources_flat:
            label = RESOURCE_TYPE_TO_LABEL.get(resource.get('resource_type'))
            if label in ['AwsAccount', 'Region', 'ServicePrincipal', 'Tag', None]: 
                continue
            self._upsert_node(resource)
            node_count += 1
        logger.info(f"Finished upserting {node_count} primary resource nodes.")

        logger.info("Generating relationship queries...")
        all_relationship_queries: List[Tuple[str, Dict[str, Any]]] = []
        deferred_relationships: Dict[str, List] = {}

        for resource in all_resources_flat:
            queries = create_relationships(resource, deferred_relationships, logger)
            all_relationship_queries.extend(queries)
            
        can_assume_queries = iam_relationship_builder.build_can_assume_relationship_queries(
            derived_iam_relationships.get("CAN_ASSUME", [])
        )
        all_relationship_queries.extend(can_assume_queries)
        
        can_access_queries = iam_relationship_builder.build_can_access_relationship_queries(
            derived_iam_relationships.get("CAN_ACCESS", [])
        )
        all_relationship_queries.extend(can_access_queries)

        execute_relationship_queries(self.client, self.is_enabled, all_relationship_queries, logger)
        create_deferred_relationships_grouped(self.client, self.is_enabled, deferred_relationships, logger)
        ensure_indexes_constraints(self.client, self.is_enabled, logger, RESOURCE_TYPE_TO_LABEL)
        
        end_time = datetime.datetime.now()
        duration = end_time - start_time
        logger.info(f"Graph build completed in {duration}.")

# Example usage (for structure, remove or guard with if __name__)
if __name__ == '__main__':
    # This block should not run normally, requires mocking or actual client
    # from app.db.graph_db import Neo4jClient # Assuming run from root with python -m
    
    # # Mock Neo4jClient or provide real one
    # class MockNeo4jClient:
    #     def run(self, query, parameters=None):
    #         print(f"MOCK RUN: {query} PARAMS: {parameters}")
    #         return [{}]
    #     def close(self):
    #         print("MOCK CLOSE")
    #     _driver = True # Simulate initialized driver

    # mock_client = MockNeo4jClient()
    # builder = GraphBuilder(mock_client)
    # builder.is_enabled = True
    
    # # Example resource data (replace with actual structure)
    # mock_resources = {
    #     "ec2": {
    #         "us-east-1": [
    #             {
    #                 'arn': 'arn:aws:ec2:us-east-1:123:instance/i-123', 'resource_id': 'i-123',
    #                 'resource_type': 'Ec2Instance', 'region': 'us-east-1', 'account_id': '123',
    #                 'properties': {'InstanceId': 'i-123', 'State': 'running'},
    #                 'relationships': {'subnet_id': 'subnet-abc', 'vpc_id': 'vpc-xyz', 'tags': {'Name': 'TestInstance'}}
    #             }
    #         ]
    #     },
    #     "vpc": {
    #         "us-east-1": [
    #              {
    #                 'arn': 'arn:aws:ec2:us-east-1:123:subnet/subnet-abc', 'resource_id': 'subnet-abc',
    #                 'resource_type': 'Subnet', 'region': 'us-east-1', 'account_id': '123',
    #                 'properties': {'SubnetId': 'subnet-abc', 'VpcId': 'vpc-xyz'},
    #                 'relationships': {'vpc_id': 'vpc-xyz', 'tags': {'Tier': 'Private'}}
    #             },
    #              {
    #                 'arn': 'arn:aws:ec2:us-east-1:123:vpc/vpc-xyz', 'resource_id': 'vpc-xyz',
    #                 'resource_type': 'Vpc', 'region': 'us-east-1', 'account_id': '123',
    #                 'properties': {'VpcId': 'vpc-xyz'},
    #                 'relationships': {'tags': {}}
    #             }
    #         ]
    #     }
    # }
    
    # print("--- Testing Graph Build ---")
    # builder.build_graph(mock_resources) # Requires AwsProvider and db_session too
    # print("--- Graph Build Test Complete ---")
    pass # Keep passive if run directly 