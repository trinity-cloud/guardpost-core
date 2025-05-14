import pytest
from uuid import uuid4
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel

# Import the models and functions to test
from app.services.remediation.schemas import StructuredGuidance, IacNotApplicableGuidance, Guidance
from app.services.remediation.iam_guidance import (
    get_iam_password_policy_guidance,
    get_iam_root_mfa_guidance,
    get_iam_user_console_mfa_guidance,
    get_iam_user_unused_password_guidance,
    get_iam_key_unused_guidance,
    get_iam_key_rotation_guidance,
    get_iam_policy_admin_guidance
)

# Mock Finding model for testing (mimics necessary fields from db.models.Finding)
class MockFinding(BaseModel):
    id: Any = uuid4()
    scan_id: Any = uuid4()
    title: str
    description: str = ""
    severity: str = "high"
    category: str = "iam"
    resource_id: str
    resource_type: str
    region: str = "global"
    account_id: str = "123456789012"
    created_at: datetime = datetime.utcnow()
    remediation_steps: Optional[List[str]] = []
    compliance_standards: Optional[List[str]] = []

def test_get_iam_password_policy_guidance():
    finding = MockFinding(
        title="IAM Password Policy is not configured or is weak",
        resource_type="AWS::Account", # Assuming this is the type used
        resource_id="123456789012"
    )
    guidance = get_iam_password_policy_guidance(finding)
    assert isinstance(guidance, StructuredGuidance)
    assert guidance.iac_applicable is True
    assert guidance.change_description == "Configure a strong IAM account password policy."
    assert isinstance(guidance.required_change, dict)
    assert guidance.required_change.get("MinimumPasswordLength") == 14
    assert len(guidance.guidance_notes) > 0
    assert guidance.resource_type == "AWS::Account"

def test_get_iam_root_mfa_guidance():
    finding = MockFinding(
        title="Root Account MFA Not Enabled",
        resource_type="AWS::IAM::RootAccount",
        resource_id="arn:aws:iam::123456789012:root"
    )
    guidance = get_iam_root_mfa_guidance(finding)
    assert isinstance(guidance, IacNotApplicableGuidance)
    assert guidance.iac_applicable is False
    assert "manual action" in guidance.reason.lower()

def test_get_iam_user_console_mfa_guidance():
    user_arn = "arn:aws:iam::123456789012:user/test-user"
    finding = MockFinding(
        title="User test-user console access has no MFA",
        resource_type="AWS::IAM::User",
        resource_id=user_arn
    )
    guidance = get_iam_user_console_mfa_guidance(finding)
    assert isinstance(guidance, StructuredGuidance)
    assert guidance.iac_applicable is True
    assert guidance.resource_id == user_arn
    assert guidance.change_description == "Enable MFA for the IAM user's console access."
    assert guidance.required_change == {"MFAEnabled": True}

def test_get_iam_user_unused_password_guidance():
    user_arn = "arn:aws:iam::123456789012:user/inactive-user"
    finding = MockFinding(
        title="User inactive-user password not used recently (>90 days)",
        resource_type="AWS::IAM::User",
        resource_id=user_arn
    )
    guidance = get_iam_user_unused_password_guidance(finding)
    assert isinstance(guidance, StructuredGuidance)
    assert guidance.resource_id == user_arn
    assert "Disable or remove console password" in guidance.change_description
    assert guidance.required_change == {"LoginProfileExists": False}

def test_get_iam_key_unused_guidance():
    key_id = "AKIAEXAMPLEKEYID"
    finding = MockFinding(
        title=f"Access key {key_id} not used recently (>90 days)",
        resource_type="AWS::IAM::AccessKey",
        resource_id=key_id
    )
    guidance = get_iam_key_unused_guidance(finding)
    assert isinstance(guidance, StructuredGuidance)
    assert guidance.resource_id == key_id
    assert "Deactivate or delete unused" in guidance.change_description
    assert guidance.required_change == {"Status": "Inactive"}

def test_get_iam_key_rotation_guidance():
    key_id = "AKIAOLDEXAMPLEKEY"
    finding = MockFinding(
        title=f"Access key {key_id} not rotated recently (>90 days)",
        resource_type="AWS::IAM::AccessKey",
        resource_id=key_id
    )
    guidance = get_iam_key_rotation_guidance(finding)
    assert isinstance(guidance, IacNotApplicableGuidance)
    assert guidance.iac_applicable is False
    assert "multi-step process" in guidance.reason

def test_get_iam_policy_admin_guidance():
    policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    finding = MockFinding(
        title=f"Policy {policy_arn} allows full admin privileges",
        resource_type="AWS::IAM::Policy", # Or User/Role if attached
        resource_id=policy_arn
    )
    guidance = get_iam_policy_admin_guidance(finding)
    assert isinstance(guidance, StructuredGuidance)
    assert guidance.resource_id == policy_arn
    assert "Replace overly permissive IAM policy" in guidance.change_description
    assert "PolicyStatements" in guidance.required_change
    assert isinstance(guidance.required_change["PolicyStatements"], list) 