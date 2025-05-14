# tests/services/schedulers/test_post_scan_tasks.py

import pytest
from unittest.mock import MagicMock, patch, call
import datetime
import uuid

# Assuming path adjustments
from app.services.schedulers.post_scan_tasks import schedule_blast_radius_calculations, TARGET_LABELS_FOR_BLAST_RADIUS
from app.services.graph.constants import RESOURCE_TYPE_TO_LABEL, RESOURCE_TYPE_PRIMARY_KEY

# Mock settings directly if they are used by the scheduler (e.g., for Neo4j timeout)
@pytest.fixture
def mock_scheduler_settings():
    settings = MagicMock()
    settings.NEO4J_QUERY_TIMEOUT = 30 # Example timeout for scheduler queries
    return settings

# Mock the Celery task
@patch('app.services.schedulers.post_scan_tasks.calculate_node_blast_radius.delay')
# Mock the Neo4j client used by the scheduler
@patch('app.services.schedulers.post_scan_tasks.get_neo4j_client_sync')
# Patch settings if the scheduler module imports it directly
@patch('app.services.schedulers.post_scan_tasks.settings', new_callable=MagicMock)
def test_schedule_blast_radius_calculations_success_no_region(mock_settings_import, mock_get_client, mock_task_delay, mock_scheduler_settings):
    """Test scheduling logic when nodes are found, no region filter."""
    mock_settings_import.NEO4J_QUERY_TIMEOUT = mock_scheduler_settings.NEO4J_QUERY_TIMEOUT # Apply fixture
    
    mock_client_instance = MagicMock()
    mock_get_client.return_value = mock_client_instance
    
    mock_neo4j_results = [
        {"labels": ["IamRole"], "id": "arn:aws:iam::111:role/Role1"},
        {"labels": ["SecurityGroup"], "id": "sg-123"},
        {"labels": ["Ec2Instance"], "id": "i-abc"},
        {"labels": ["UnwantedLabel", "IamRole"], "id": "arn:aws:iam::111:role/Role2"},
    ]
    mock_client_instance.run.return_value = mock_neo4j_results
    
    scan_id = uuid.uuid4()
    account_id = "111122223333"
    scan_start_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)
    
    schedule_blast_radius_calculations(scan_id, scan_start_time, account_id, region=None)
    
    mock_get_client.assert_called_once()
    mock_client_instance.run.assert_called_once()
    call_args, call_kwargs = mock_client_instance.run.call_args
    query_params = call_kwargs['parameters']
    assert query_params['account_id'] == account_id
    assert query_params['scan_start_iso'] == scan_start_time.isoformat()
    assert 'region' not in query_params
    # Verify query structure (basic checks)
    assert "UNION" in call_args[0]
    for label in TARGET_LABELS_FOR_BLAST_RADIUS:
        assert f"MATCH (n:{label})" in call_args[0]
    assert "n.last_updated >= datetime($scan_start_iso)" in call_args[0]
    
    expected_calls = [
        call(node_id="arn:aws:iam::111:role/Role1", node_label="IamRole"),
        call(node_id="sg-123", node_label="SecurityGroup"),
        call(node_id="i-abc", node_label="Ec2Instance"),
        call(node_id="arn:aws:iam::111:role/Role2", node_label="IamRole"),
    ]
    mock_task_delay.assert_has_calls(expected_calls, any_order=True)
    assert mock_task_delay.call_count == 4
    mock_client_instance.close.assert_called_once()

@patch('app.services.schedulers.post_scan_tasks.calculate_node_blast_radius.delay')
@patch('app.services.schedulers.post_scan_tasks.get_neo4j_client_sync')
@patch('app.services.schedulers.post_scan_tasks.settings', new_callable=MagicMock)
def test_schedule_blast_radius_calculations_with_region(mock_settings_import, mock_get_client, mock_task_delay, mock_scheduler_settings):
    """Test scheduling logic with a region filter."""
    mock_settings_import.NEO4J_QUERY_TIMEOUT = mock_scheduler_settings.NEO4J_QUERY_TIMEOUT

    mock_client_instance = MagicMock()
    mock_get_client.return_value = mock_client_instance
    mock_client_instance.run.return_value = [
         {"labels": ["SecurityGroup"], "id": "sg-456"},
         {"labels": ["IamRole"], "id": "arn:aws:iam::111:role/GlobalRoleInRegionScan"} # Global should still be picked up
    ]
    
    scan_id = uuid.uuid4()
    account_id = "111122223333"
    region = "us-west-2"
    scan_start_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)

    schedule_blast_radius_calculations(scan_id, scan_start_time, account_id, region=region)

    mock_get_client.assert_called_once()
    mock_client_instance.run.assert_called_once()
    call_args, call_kwargs = mock_client_instance.run.call_args
    query_params = call_kwargs['parameters']
    assert query_params['region'] == region
    # Check that region filter is applied for regional resource types, but global types still included
    # Example: MATCH (n:SecurityGroup) WHERE n.account_id = $account_id AND (n.region = $region OR n.region = 'global' OR n.region IS NULL)
    # Example: MATCH (n:IamRole) WHERE n.account_id = $account_id AND (n.region = $region OR n.region = 'global' OR n.region IS NULL)
    assert "(n.region = $region OR n.region = 'global' OR n.region IS NULL)" in call_args[0]
    
    expected_calls = [
        call(node_id="sg-456", node_label="SecurityGroup"),
        call(node_id="arn:aws:iam::111:role/GlobalRoleInRegionScan", node_label="IamRole"),
    ]
    mock_task_delay.assert_has_calls(expected_calls, any_order=True)
    assert mock_task_delay.call_count == 2
    mock_client_instance.close.assert_called_once()

@patch('app.services.schedulers.post_scan_tasks.calculate_node_blast_radius.delay')
@patch('app.services.schedulers.post_scan_tasks.get_neo4j_client_sync')
@patch('app.services.schedulers.post_scan_tasks.settings', new_callable=MagicMock)
def test_schedule_blast_radius_calculations_no_nodes(mock_settings_import, mock_get_client, mock_task_delay, mock_scheduler_settings):
    """Test scheduling logic when Neo4j returns no nodes."""
    mock_settings_import.NEO4J_QUERY_TIMEOUT = mock_scheduler_settings.NEO4J_QUERY_TIMEOUT
    mock_client_instance = MagicMock()
    mock_get_client.return_value = mock_client_instance
    mock_client_instance.run.return_value = []
    
    scan_id = uuid.uuid4()
    account_id = "111122223333"
    scan_start_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)

    schedule_blast_radius_calculations(scan_id, scan_start_time, account_id, region=None)
    
    mock_get_client.assert_called_once()
    mock_client_instance.run.assert_called_once()
    mock_task_delay.assert_not_called()
    mock_client_instance.close.assert_called_once()

@patch('app.services.schedulers.post_scan_tasks.calculate_node_blast_radius.delay')
@patch('app.services.schedulers.post_scan_tasks.get_neo4j_client_sync')
@patch('app.services.schedulers.post_scan_tasks.settings', new_callable=MagicMock)
def test_schedule_blast_radius_calculations_query_fails(mock_settings_import, mock_get_client, mock_task_delay, mock_scheduler_settings):
    """Test scheduling logic when the Neo4j query fails."""
    mock_settings_import.NEO4J_QUERY_TIMEOUT = mock_scheduler_settings.NEO4J_QUERY_TIMEOUT
    mock_client_instance = MagicMock()
    mock_get_client.return_value = mock_client_instance
    mock_client_instance.run.side_effect = Exception("DB connection error")
    
    scan_id = uuid.uuid4()
    account_id = "111122223333"
    scan_start_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)

    schedule_blast_radius_calculations(scan_id, scan_start_time, account_id, region=None)
    
    mock_get_client.assert_called_once()
    mock_client_instance.run.assert_called_once()
    mock_task_delay.assert_not_called()
    mock_client_instance.close.assert_called_once() 