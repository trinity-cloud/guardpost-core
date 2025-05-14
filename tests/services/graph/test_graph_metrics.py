# tests/services/graph/test_graph_metrics.py

import pytest
from unittest.mock import MagicMock, patch
import datetime

# Assuming path adjustments or proper installation allow importing
from app.services.graph_metrics import GraphMetricsCalculator
from app.services.graph.constants import RESOURCE_TYPE_TO_LABEL, RESOURCE_TYPE_PRIMARY_KEY

# Mock Neo4j Client for testing
@pytest.fixture
def mock_neo4j_client():
    client = MagicMock()
    # Mock the run method to return controlled results
    client.run.return_value = [] # Default empty result
    return client

# Mock settings
@pytest.fixture
def mock_settings():
    settings = MagicMock()
    settings.BLAST_RADIUS_MAX_DEPTH = 3
    # Mock other settings if needed
    return settings

# Test Suite for GraphMetricsCalculator
class TestGraphMetricsCalculator:

    # Inject mocks using fixture names
    def test_init(self, mock_neo4j_client, mock_settings):
        with patch('app.services.graph_metrics.settings', mock_settings): # Patch settings import
            calculator = GraphMetricsCalculator(mock_neo4j_client)
            assert calculator.client == mock_neo4j_client
            assert calculator.max_depth == 3
            assert calculator.is_enabled is True # Assuming client mock is valid

    def test_get_relationship_weight(self, mock_neo4j_client, mock_settings):
        # Test weighting logic
        with patch('app.services.graph_metrics.settings', mock_settings):
            calculator = GraphMetricsCalculator(mock_neo4j_client)
            assert calculator._get_relationship_weight("CAN_ASSUME") == 10.0
            assert calculator._get_relationship_weight("UNKNOWN_REL") == 0.1 # Default
            # TODO: Add tests for CAN_ACCESS levels when logic is refined
            pass

    def test_calculate_blast_radius_start_node_not_found(self, mock_neo4j_client, mock_settings):
        # Test case where start node doesn't exist
        mock_neo4j_client.run.return_value = [] # Simulate node not found
        with patch('app.services.graph_metrics.settings', mock_settings):
            calculator = GraphMetricsCalculator(mock_neo4j_client)
            result = calculator.calculate_blast_radius("nonexistent-role", "IamRole")
            assert result is None
            mock_neo4j_client.run.assert_called_once()

    def test_calculate_blast_radius_no_neighbors(self, mock_neo4j_client, mock_settings):
        # Test case with start node but no outgoing relationships
        start_node_element_id = "element-1"
        # Mock finding the start node, then finding no neighbors
        mock_neo4j_client.run.side_effect = [
            [{"id": start_node_element_id}], # First call finds start node
            []                         # Second call finds no neighbors
        ]
        with patch('app.services.graph_metrics.settings', mock_settings):
            calculator = GraphMetricsCalculator(mock_neo4j_client)
            result = calculator.calculate_blast_radius("role-arn-1", "IamRole")
            assert result == {"score": 0.0, "count": 0}
            assert mock_neo4j_client.run.call_count == 2

    def test_calculate_blast_radius_simple_path(self, mock_neo4j_client, mock_settings):
        # Test a simple path with known weights: (Start)-[REL_A]->(B)-[REL_B]->(C)
        # Depth 0: StartNode (element_id_start)
        # Depth 1: NodeB (element_id_b) via REL_A (weight_a)
        # Depth 2: NodeC (element_id_c) via REL_B (weight_b)
        start_node_id = "role-arn-start"
        start_node_label = "IamRole"
        pk_field_start = RESOURCE_TYPE_PRIMARY_KEY.get(start_node_label)

        element_id_start = "start_el_id"
        element_id_b = "b_el_id"
        element_id_c = "c_el_id"

        rel_a_type = "CAN_ASSUME"
        rel_b_type = "ROUTES_TO"

        weight_a = 10.0 # From RELATIONSHIP_WEIGHTS
        weight_b = 5.0  # From RELATIONSHIP_WEIGHTS

        # Expected score = (weight_a / (0+1)) + (weight_b / (1+1))
        expected_score = weight_a / 1.0 + weight_b / 2.0 
        expected_count = 2 # NodeB and NodeC

        # Configure mock_neo4j_client.run to return data for each step of BFS
        mock_neo4j_client.run.side_effect = [
            # 1. Find start node
            [{ "id": element_id_start }], 
            # 2. Neighbors of StartNode (element_id_start) -> NodeB
            [
                {
                    "rel_type": rel_a_type, 
                    "rel_props": {},
                    "neighbor_id": element_id_b,
                    "neighbor_labels": ["IamRole"] # Example label for NodeB
                }
            ],
            # 3. Neighbors of NodeB (element_id_b) -> NodeC
            [
                {
                    "rel_type": rel_b_type, 
                    "rel_props": {},
                    "neighbor_id": element_id_c,
                    "neighbor_labels": ["InternetGateway"] # Example label for NodeC
                }
            ],
            # 4. Neighbors of NodeC (element_id_c) -> None (end of path)
            [] 
        ]

        with patch('app.services.graph_metrics.settings', mock_settings):
            calculator = GraphMetricsCalculator(mock_neo4j_client)
            # Ensure the mock RELATIONSHIP_WEIGHTS are used by the calculator instance for this test
            calculator.relationship_weights = { 
                rel_a_type: weight_a, 
                rel_b_type: weight_b, 
                "DEFAULT": 0.1 
            }
            
            result = calculator.calculate_blast_radius(start_node_id, start_node_label)

            assert result is not None
            assert result["score"] == expected_score
            assert result["count"] == expected_count

            # Verify the Cypher queries made
            # Query 1: Find start node
            expected_start_node_query = f"MATCH (n:{start_node_label} {{{pk_field_start}: $start_id}}) RETURN elementId(n) AS id LIMIT 1"
            # Query 2: Neighbors of StartNode
            expected_neighbor_query_start = f"MATCH (n) WHERE elementId(n) = $element_id OPTIONAL MATCH (n)-[r]->(m) RETURN elementId(n) as current_id, type(r) AS rel_type, properties(r) as rel_props, elementId(m) AS neighbor_id, labels(m) as neighbor_labels"
            # Query 3: Neighbors of NodeB
            expected_neighbor_query_b = expected_neighbor_query_start # Same query structure
            # Query 4: Neighbors of NodeC
            expected_neighbor_query_c = expected_neighbor_query_start # Same query structure

            assert mock_neo4j_client.run.call_count == 4
            calls = mock_neo4j_client.run.call_args_list
            assert calls[0][0][0] == expected_start_node_query
            assert calls[0][1]['parameters'] == {"start_id": start_node_id}
            
            assert calls[1][0][0] == expected_neighbor_query_start
            assert calls[1][1]['parameters'] == {"element_id": element_id_start}

            assert calls[2][0][0] == expected_neighbor_query_b
            assert calls[2][1]['parameters'] == {"element_id": element_id_b}

            assert calls[3][0][0] == expected_neighbor_query_c
            assert calls[3][1]['parameters'] == {"element_id": element_id_c}
        # TODO: Implement more complex graph simulations
        pass

    def test_calculate_blast_radius_depth_limit(self, mock_neo4j_client, mock_settings):
        # Test that traversal stops at max_depth (default 3 from mock_settings)
        # Path: (Start)-[A]->(B)-[B]->(C)-[C]->(D)-[D]->(E)
        # Max depth 3 means we should score A, B, C and count B, C, D
        start_node_id = "role-arn-start"
        start_node_label = "IamRole"
        pk_field_start = RESOURCE_TYPE_PRIMARY_KEY.get(start_node_label)

        el_id = {char: f"{char}_el_id" for char in ['start', 'b', 'c', 'd', 'e']}

        rels = {
            "REL_A": ("CAN_ASSUME", 10.0),
            "REL_B": ("ROUTES_TO", 5.0),
            "REL_C": ("APPLIES_TO", 4.0),
            "REL_D": ("CONTAINS", 0.1) # This one should be ignored due to depth
        }

        # Expected score:
        # Depth 0 -> 1: REL_A (10.0 / 1.0) = 10.0
        # Depth 1 -> 2: REL_B (5.0 / 2.0)  = 2.5
        # Depth 2 -> 3: REL_C (4.0 / 3.0)  = 1.333...
        expected_score = round(rels["REL_A"][1]/1.0 + rels["REL_B"][1]/2.0 + rels["REL_C"][1]/3.0, 2)
        expected_count = 3 # Nodes B, C, D

        mock_neo4j_client.run.side_effect = [
            # 1. Find start node
            [{ "id": el_id['start'] }],
            # 2. Neighbors of Start (el_id['start']) -> B
            [{"rel_type": rels["REL_A"][0], "rel_props": {}, "neighbor_id": el_id['b'], "neighbor_labels": ["IamRole"]}],
            # 3. Neighbors of B (el_id['b']) -> C
            [{"rel_type": rels["REL_B"][0], "rel_props": {}, "neighbor_id": el_id['c'], "neighbor_labels": ["InternetGateway"]}],
            # 4. Neighbors of C (el_id['c']) -> D
            [{"rel_type": rels["REL_C"][0], "rel_props": {}, "neighbor_id": el_id['d'], "neighbor_labels": ["Ec2Instance"]}],
            # 5. Neighbors of D (el_id['d']) -> E (This is depth 3->4, should not be processed further for score if max_depth = 3)
            # The query for D's neighbors will run, but its results won't be added to queue for score.
            [{"rel_type": rels["REL_D"][0], "rel_props": {}, "neighbor_id": el_id['e'], "neighbor_labels": ["Subnet"]}],
            # 6. Neighbors of E (el_id['e']) - Should not be called if depth limit works
             [] # If it were called, it would be empty
        ]

        with patch('app.services.graph_metrics.settings', mock_settings):
            calculator = GraphMetricsCalculator(mock_neo4j_client)
            calculator.relationship_weights = {rt: w for rt, (rt_name, w) in rels.items()} 
            calculator.relationship_weights["DEFAULT"] = 0.01 # ensure only specified weights are significant
            
            # Override specific CAN_ACCESS weights if necessary for this test, though not used here
            # calculator.relationship_weights["CAN_ACCESS_FULL_ACCESS"] = 8.0 

            result = calculator.calculate_blast_radius(start_node_id, start_node_label)

            assert result is not None
            assert result["score"] == expected_score
            assert result["count"] == expected_count
            
            # Start node query + 1 query per node up to max_depth (start, B, C, D)
            # Query for D's children will run, but E won't be added to queue for further processing.
            assert mock_neo4j_client.run.call_count == 5 

            calls = mock_neo4j_client.run.call_args_list
            assert calls[0][1]['parameters'] == {"start_id": start_node_id}
            assert calls[1][1]['parameters'] == {"element_id": el_id['start']}
            assert calls[2][1]['parameters'] == {"element_id": el_id['b']}
            assert calls[3][1]['parameters'] == {"element_id": el_id['c']}
            assert calls[4][1]['parameters'] == {"element_id": el_id['d']} 
        pass

    def test_calculate_blast_radius_cycle_detection(self, mock_neo4j_client, mock_settings):
        # Test that cycles are handled correctly: (Start)-[A]->(B)-[B]->(Start)
        # Score should only include REL_A once. Count should be 1 (NodeB).
        start_node_id = "role-arn-cycle"
        start_node_label = "IamRole"
        pk_field_start = RESOURCE_TYPE_PRIMARY_KEY.get(start_node_label)

        el_id_start = "start_cycle_el_id"
        el_id_b = "b_cycle_el_id"

        rel_a_type = "CAN_ASSUME" # Start -> B
        rel_b_type = "CAN_ASSUME" # B -> Start (Cycle)

        weight_a = 10.0
        # weight_b would also be 10.0 but shouldn't be counted again due to cycle

        # Expected score = weight_a / 1.0 (NodeB is at depth 1)
        expected_score = weight_a / 1.0
        expected_count = 1 # Only NodeB is counted as a new node

        mock_neo4j_client.run.side_effect = [
            # 1. Find start node
            [{ "id": el_id_start }],
            # 2. Neighbors of Start (el_id_start) -> NodeB
            [
                {
                    "rel_type": rel_a_type, 
                    "rel_props": {},
                    "neighbor_id": el_id_b,
                    "neighbor_labels": ["IamRole"]
                }
            ],
            # 3. Neighbors of NodeB (el_id_b) -> StartNode (cycle)
            [
                {
                    "rel_type": rel_b_type, 
                    "rel_props": {},
                    "neighbor_id": el_id_start, # Points back to start
                    "neighbor_labels": ["IamRole"]
                }
            ]
            # No further calls should be made as StartNode is already visited
        ]

        with patch('app.services.graph_metrics.settings', mock_settings):
            calculator = GraphMetricsCalculator(mock_neo4j_client)
            calculator.relationship_weights = { 
                rel_a_type: weight_a, 
                rel_b_type: weight_a, # Same weight for this type
                "DEFAULT": 0.1 
            }

            result = calculator.calculate_blast_radius(start_node_id, start_node_label)

            assert result is not None
            assert result["score"] == expected_score
            assert result["count"] == expected_count

            # Start node query, N(Start) query, N(B) query
            assert mock_neo4j_client.run.call_count == 3

            calls = mock_neo4j_client.run.call_args_list
            assert calls[0][1]['parameters'] == {"start_id": start_node_id}
            assert calls[1][1]['parameters'] == {"element_id": el_id_start}
            assert calls[2][1]['parameters'] == {"element_id": el_id_b}
        pass

    def test_update_node_blast_radius_success(self, mock_neo4j_client, mock_settings):
        # Test the update logic
        node_id = "role-arn-1"
        node_label = "IamRole"
        pk_field = "arn"
        calc_result = {"score": 15.5, "count": 5}
        expected_query = f"MATCH (n:{node_label} {{{pk_field}: $node_id}}) SET n.blast_radius_score = $score, n.blast_radius_count = $count, n.blast_radius_calculated_at = datetime({{timezone: 'UTC'}}})"
        expected_params = {"node_id": node_id, "score": 15.5, "count": 5}

        with patch('app.services.graph_metrics.settings', mock_settings):
            calculator = GraphMetricsCalculator(mock_neo4j_client)
            # Patch the calculation method itself to return a fixed result
            with patch.object(calculator, 'calculate_blast_radius', return_value=calc_result) as mock_calc:
                calculator.update_node_blast_radius(node_id, node_label)
                mock_calc.assert_called_once_with(node_id, node_label)
                # Verify the final SET query was called with correct params
                # The first call in update_node_blast_radius is calculate_blast_radius
                # The mock_neo4j_client's run method is called by calculate_blast_radius *and* the update SET query.
                # We need to check the *last* call to the mocked run method.
                assert mock_neo4j_client.run.call_count >= 1 # At least the calc call
                # Get the arguments of the last call
                last_call_args, last_call_kwargs = mock_neo4j_client.run.call_args
                assert last_call_args[0] == expected_query
                assert last_call_kwargs.get('parameters') == expected_params

    def test_update_node_blast_radius_calc_fails(self, mock_neo4j_client, mock_settings):
        # Test when calculation returns None
        with patch('app.services.graph_metrics.settings', mock_settings):
            calculator = GraphMetricsCalculator(mock_neo4j_client)
            with patch.object(calculator, 'calculate_blast_radius', return_value=None):
                calculator.update_node_blast_radius("role-arn-1", "IamRole")
                # Check that the update query was NOT called
                # Find the call corresponding to the MATCH/SET query
                update_call_found = False
                for call in mock_neo4j_client.run.call_args_list:
                    if call.args and "SET n.blast_radius_score" in call.args[0]:
                        update_call_found = True
                        break
                assert not update_call_found 