# tests/services/tasks/test_blast_radius_calculator.py

import pytest
from unittest.mock import MagicMock, patch, ANY # Import ANY for flexible arg matching

# Assuming path adjustments or proper installation allow importing
from app.services.tasks.blast_radius_calculator import calculate_node_blast_radius
# Import GraphMetricsCalculator to mock its methods if needed for specific tests
from app.services.graph_metrics import GraphMetricsCalculator 

@patch('app.services.tasks.blast_radius_calculator.get_neo4j_client_sync')
@patch('app.services.tasks.blast_radius_calculator.GraphMetricsCalculator') # This mocks the class itself
def test_calculate_node_blast_radius_success(MockGraphMetricsCalculator, mock_get_neo4j_client_sync):
    """Test the Celery task successful execution path."""
    # Setup mocks
    mock_neo4j_client_instance = MagicMock()
    mock_get_neo4j_client_sync.return_value = mock_neo4j_client_instance
    
    # The MockGraphMetricsCalculator is a mock of the class constructor.
    # .return_value gives us a mock of an *instance* of GraphMetricsCalculator.
    mock_calculator_instance = MockGraphMetricsCalculator.return_value 
    # We don't need to mock the return value of update_node_blast_radius unless testing specific results here

    node_id = "test-node-id-success"
    node_label = "TestLabelSuccess"
    
    # Call the task function directly
    calculate_node_blast_radius(node_id, node_label)
    
    # Assertions
    mock_get_neo4j_client_sync.assert_called_once()
    MockGraphMetricsCalculator.assert_called_once_with(mock_neo4j_client_instance)
    mock_calculator_instance.update_node_blast_radius.assert_called_once_with(node_id, node_label)
    mock_neo4j_client_instance.close.assert_called_once() # Ensure client is closed

@patch('app.services.tasks.blast_radius_calculator.get_neo4j_client_sync')
@patch('app.services.tasks.blast_radius_calculator.GraphMetricsCalculator')
def test_calculate_node_blast_radius_client_init_failure(MockGraphMetricsCalculator, mock_get_neo4j_client_sync):
    """Test task behavior when Neo4j client fails to initialize."""
    mock_get_neo4j_client_sync.return_value = None # Simulate client initialization failure
    
    node_id = "test-node-id-client-fail"
    node_label = "TestLabelClientFail"

    calculate_node_blast_radius(node_id, node_label)
    
    # Assertions
    mock_get_neo4j_client_sync.assert_called_once()
    MockGraphMetricsCalculator.assert_not_called() # Calculator should not be instantiated
    # Client close won't be called if client is None

@patch('app.services.tasks.blast_radius_calculator.get_neo4j_client_sync')
@patch('app.services.tasks.blast_radius_calculator.GraphMetricsCalculator')
def test_calculate_node_blast_radius_calculator_update_fails(MockGraphMetricsCalculator, mock_get_neo4j_client_sync):
    """Test task behavior when the calculator's update_node_blast_radius method raises an exception."""
    mock_neo4j_client_instance = MagicMock()
    mock_get_neo4j_client_sync.return_value = mock_neo4j_client_instance
    
    mock_calculator_instance = MockGraphMetricsCalculator.return_value
    # Simulate the method raising an error
    mock_calculator_instance.update_node_blast_radius.side_effect = Exception("Simulated update failure!")
    
    node_id = "test-node-id-update-fail"
    node_label = "TestLabelUpdateFail"
    
    # The task currently logs the exception and continues, so no exception expected here.
    # If the task were to re-raise, we would use pytest.raises.
    calculate_node_blast_radius(node_id, node_label)
    
    # Assertions
    mock_get_neo4j_client_sync.assert_called_once()
    MockGraphMetricsCalculator.assert_called_once_with(mock_neo4j_client_instance)
    mock_calculator_instance.update_node_blast_radius.assert_called_once_with(node_id, node_label)
    mock_neo4j_client_instance.close.assert_called_once() # Ensure client is closed even on failure

@patch('app.services.tasks.blast_radius_calculator.get_neo4j_client_sync')
@patch('app.services.tasks.blast_radius_calculator.GraphMetricsCalculator')
@patch('app.services.tasks.blast_radius_calculator.logger') # Mock the logger
def test_calculate_node_blast_radius_logs_errors(mock_logger, MockGraphMetricsCalculator, mock_get_neo4j_client_sync):
    """Test that errors during task execution are logged."""
    mock_neo4j_client_instance = MagicMock()
    mock_get_neo4j_client_sync.return_value = mock_neo4j_client_instance
    
    mock_calculator_instance = MockGraphMetricsCalculator.return_value
    simulated_error_message = "Major calculation error!"
    mock_calculator_instance.update_node_blast_radius.side_effect = Exception(simulated_error_message)

    calculate_node_blast_radius("log-test-id", "LogTestLabel")

    # Check if logger.error was called with the expected message context
    # ANY is used because the full log message includes traceback info we don't want to match strictly.
    mock_logger.error.assert_called_once_with(ANY, exc_info=True)
    # Check if the error message is part of the logged string
    logged_message = mock_logger.error.call_args[0][0]
    assert "Error in blast radius background task" in logged_message
    assert "LogTestLabel log-test-id" in logged_message
    assert simulated_error_message in logged_message 