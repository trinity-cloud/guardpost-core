import pytest
from uuid import uuid4
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel

# Import the models and functions to test
from app.services.remediation.schemas import StructuredGuidance, IacNotApplicableGuidance, Guidance
from app.services.remediation.rds_guidance import (
    get_rds_storage_encryption_guidance,
    get_rds_public_access_guidance,
    get_rds_automated_backups_guidance,
    get_rds_deletion_protection_guidance,
    get_rds_multi_az_guidance,
    get_rds_minor_version_upgrade_guidance,
    get_rds_performance_insights_guidance,
    get_rds_enhanced_monitoring_guidance,
    get_rds_log_exports_guidance
)

# Mock Finding model
class MockFinding(BaseModel):
    id: Any = uuid4()
    scan_id: Any = uuid4()
    title: str
    description: str = ""
    severity: str = "high"
    category: str = "database" # Default, adjust per test
    resource_id: str
    resource_type: str = "AWS::RDS::DBInstance"
    region: str = "us-east-1"
    account_id: str = "123456789012"
    created_at: datetime = datetime.utcnow()
    remediation_steps: Optional[List[str]] = []
    compliance_standards: Optional[List[str]] = []

def test_get_rds_storage_encryption_guidance():
    db_id = "my-unencrypted-db"
    finding = MockFinding(
        title=f"RDS Instance {db_id} storage encryption disabled",
        resource_id=db_id
    )
    guidance = get_rds_storage_encryption_guidance(finding)
    assert isinstance(guidance, IacNotApplicableGuidance)
    assert guidance.iac_applicable is False
    assert "must be enabled at creation time" in guidance.reason

def test_get_rds_public_access_guidance():
    db_id = "my-public-db"
    finding = MockFinding(
        title=f"RDS Instance {db_id} is publicly accessible",
        resource_id=db_id
    )
    guidance = get_rds_public_access_guidance(finding)
    assert isinstance(guidance, StructuredGuidance)
    assert guidance.iac_applicable is True
    assert guidance.resource_id == db_id
    assert "Disable public accessibility" in guidance.change_description
    assert guidance.required_change == {"PubliclyAccessible": False}

def test_get_rds_automated_backups_guidance():
    db_id = "my-unbacked-up-db"
    finding = MockFinding(
        title=f"RDS Instance {db_id} automated backups disabled",
        resource_id=db_id
    )
    guidance = get_rds_automated_backups_guidance(finding)
    assert isinstance(guidance, StructuredGuidance)
    assert guidance.iac_applicable is True
    assert guidance.resource_id == db_id
    assert "Enable automated backups" in guidance.change_description
    assert "BackupRetentionPeriod" in guidance.required_change
    assert guidance.required_change["BackupRetentionPeriod"] > 0

def test_get_rds_deletion_protection_guidance():
    db_id = "my-prod-db"
    finding = MockFinding(
        title=f"RDS Instance {db_id} deletion protection disabled",
        resource_id=db_id
    )
    guidance = get_rds_deletion_protection_guidance(finding)
    assert isinstance(guidance, StructuredGuidance)
    assert guidance.iac_applicable is True
    assert guidance.resource_id == db_id
    assert "Enable deletion protection" in guidance.change_description
    assert guidance.required_change == {"DeletionProtection": True}

def test_get_rds_multi_az_guidance():
    db_id = "my-single-az-db"
    finding = MockFinding(
        title=f"RDS Instance {db_id} not configured for multi-az",
        resource_id=db_id
    )
    guidance = get_rds_multi_az_guidance(finding)
    assert isinstance(guidance, StructuredGuidance)
    assert guidance.iac_applicable is True
    assert guidance.resource_id == db_id
    assert "Enable Multi-AZ deployment" in guidance.change_description
    assert guidance.required_change == {"MultiAZ": True}

def test_get_rds_minor_version_upgrade_guidance():
    db_id = "my-static-db"
    finding = MockFinding(
        title=f"RDS Instance {db_id} automatic minor version upgrades disabled",
        resource_id=db_id
    )
    guidance = get_rds_minor_version_upgrade_guidance(finding)
    assert isinstance(guidance, StructuredGuidance)
    assert guidance.iac_applicable is True
    assert guidance.resource_id == db_id
    assert "Enable automatic minor version upgrades" in guidance.change_description
    assert guidance.required_change == {"AutoMinorVersionUpgrade": True}

def test_get_rds_performance_insights_guidance():
    db_id = "my-opaque-db"
    finding = MockFinding(
        title=f"RDS Instance {db_id} performance insights disabled",
        resource_id=db_id
    )
    guidance = get_rds_performance_insights_guidance(finding)
    assert isinstance(guidance, StructuredGuidance)
    assert guidance.iac_applicable is True
    assert guidance.resource_id == db_id
    assert "Enable Performance Insights" in guidance.change_description
    assert guidance.required_change["EnablePerformanceInsights"] is True

def test_get_rds_enhanced_monitoring_guidance():
    db_id = "my-basic-mon-db"
    finding = MockFinding(
        title=f"RDS Instance {db_id} enhanced monitoring disabled",
        resource_id=db_id
    )
    guidance = get_rds_enhanced_monitoring_guidance(finding)
    assert isinstance(guidance, StructuredGuidance)
    assert guidance.iac_applicable is True
    assert guidance.resource_id == db_id
    assert "Enable Enhanced Monitoring" in guidance.change_description
    assert "MonitoringInterval" in guidance.required_change
    assert "SPECIFY_MONITORING_ROLE_ARN" in guidance.required_change["MonitoringRoleArn"]

def test_get_rds_log_exports_guidance():
    db_id = "my-silent-db"
    finding = MockFinding(
        title=f"RDS Instance {db_id} log exports not enabled",
        resource_id=db_id
    )
    guidance = get_rds_log_exports_guidance(finding)
    assert isinstance(guidance, StructuredGuidance)
    assert guidance.iac_applicable is True
    assert guidance.resource_id == db_id
    assert "Enable export of specific database logs" in guidance.change_description
    assert "CloudwatchLogsExportConfiguration" in guidance.required_change
    assert isinstance(guidance.required_change["CloudwatchLogsExportConfiguration"]["EnableLogTypes"], list)
    assert "audit" in guidance.required_change["CloudwatchLogsExportConfiguration"]["EnableLogTypes"] 