import pytest
from uuid import uuid4
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel

# Import the models and functions to test
from app.services.remediation.schemas import StructuredGuidance, IacNotApplicableGuidance, Guidance
from app.services.remediation.s3_guidance import (
    get_s3_public_access_block_guidance,
    get_s3_versioning_guidance,
    get_s3_logging_guidance,
    get_s3_encryption_guidance,
    get_s3_mfa_delete_guidance,
    get_s3_secure_transport_guidance
    # Note: get_s3_public_acl_guidance and get_s3_public_policy_guidance were not refactored in the last step, add tests if/when they are.
)

# Mock Finding model
class MockFinding(BaseModel):
    id: Any = uuid4()
    scan_id: Any = uuid4()
    title: str
    description: str = ""
    severity: str = "high"
    category: str = "s3" # Default, adjust per test
    resource_id: str
    resource_type: str = "AWS::S3::Bucket"
    region: str = "us-east-1"
    account_id: str = "123456789012"
    created_at: datetime = datetime.utcnow()
    remediation_steps: Optional[List[str]] = []
    compliance_standards: Optional[List[str]] = []

def test_get_s3_public_access_block_guidance():
    bucket_name = "my-insecure-bucket"
    finding = MockFinding(
        title=f"Bucket {bucket_name} public access block is not enabled",
        resource_id=bucket_name
    )
    guidance = get_s3_public_access_block_guidance(finding)
    assert isinstance(guidance, StructuredGuidance)
    assert guidance.iac_applicable is True
    assert guidance.resource_id == bucket_name
    assert "Enable all settings within the S3 bucket's Public Access Block" in guidance.change_description
    assert "PublicAccessBlockConfiguration" in guidance.required_change
    assert guidance.required_change["PublicAccessBlockConfiguration"]["BlockPublicAcls"] is True

def test_get_s3_versioning_guidance():
    bucket_name = "my-versionless-bucket"
    finding = MockFinding(
        title=f"Bucket {bucket_name} versioning is not enabled",
        resource_id=bucket_name
    )
    guidance = get_s3_versioning_guidance(finding)
    assert isinstance(guidance, StructuredGuidance)
    assert guidance.iac_applicable is True
    assert guidance.resource_id == bucket_name
    assert "Enable versioning for the S3 bucket" in guidance.change_description
    assert "VersioningConfiguration" in guidance.required_change
    assert guidance.required_change["VersioningConfiguration"]["Status"] == "Enabled"

def test_get_s3_logging_guidance():
    bucket_name = "my-unlogged-bucket"
    finding = MockFinding(
        title=f"Bucket {bucket_name} server access logging is not enabled",
        resource_id=bucket_name
    )
    guidance = get_s3_logging_guidance(finding)
    assert isinstance(guidance, StructuredGuidance)
    assert guidance.iac_applicable is True
    assert guidance.resource_id == bucket_name
    assert "Enable server access logging" in guidance.change_description
    assert "LoggingConfiguration" in guidance.required_change
    assert "SPECIFY_LOGGING_BUCKET_NAME" in guidance.required_change["LoggingConfiguration"]["TargetBucket"]

def test_get_s3_encryption_guidance():
    bucket_name = "my-unencrypted-bucket"
    finding = MockFinding(
        title=f"Bucket {bucket_name} default encryption is not enabled",
        resource_id=bucket_name
    )
    guidance = get_s3_encryption_guidance(finding)
    assert isinstance(guidance, StructuredGuidance)
    assert guidance.iac_applicable is True
    assert guidance.resource_id == bucket_name
    assert "Enable default server-side encryption" in guidance.change_description
    assert "ServerSideEncryptionConfiguration" in guidance.required_change
    assert guidance.required_change["ServerSideEncryptionConfiguration"]["Rules"][0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] == "AES256"

def test_get_s3_mfa_delete_guidance():
    bucket_name = "my-versioned-bucket"
    finding = MockFinding(
        title=f"Bucket {bucket_name} MFA delete is disabled",
        resource_id=bucket_name
    )
    guidance = get_s3_mfa_delete_guidance(finding)
    assert isinstance(guidance, IacNotApplicableGuidance)
    assert guidance.iac_applicable is False
    assert "manual action by the root account" in guidance.reason

def test_get_s3_secure_transport_guidance():
    bucket_name = "my-http-bucket"
    finding = MockFinding(
        title=f"Bucket {bucket_name} does not enforce secure transport",
        resource_id=bucket_name
    )
    guidance = get_s3_secure_transport_guidance(finding)
    assert isinstance(guidance, StructuredGuidance)
    assert guidance.iac_applicable is True
    assert guidance.resource_id == bucket_name
    assert "Enforce secure transport (HTTPS)" in guidance.change_description
    assert "BucketPolicy" in guidance.required_change
    assert isinstance(guidance.required_change["BucketPolicy"]["Statement"], list)
    assert len(guidance.required_change["BucketPolicy"]["Statement"]) > 0 # Check if statement exists
    # Could add more specific checks on the statement content if needed 