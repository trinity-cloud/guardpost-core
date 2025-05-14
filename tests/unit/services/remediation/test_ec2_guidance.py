import pytest
from uuid import uuid4
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel

# Import the models and functions to test
from app.services.remediation.schemas import StructuredGuidance, IacNotApplicableGuidance, Guidance
from app.services.remediation.ec2_guidance import (
    get_sg_unrestricted_ssh_guidance,
    get_sg_unrestricted_rdp_guidance,
    get_sg_unrestricted_egress_guidance,
    get_sg_default_insecure_guidance,
    get_ec2_ebs_encryption_default_guidance,
    get_ec2_ebs_volume_unencrypted_guidance,
    get_ec2_instance_imdsv2_guidance
)

# Mock Finding model (can be shared if placed in a conftest.py later)
class MockFinding(BaseModel):
    id: Any = uuid4()
    scan_id: Any = uuid4()
    title: str
    description: str = ""
    severity: str = "high"
    category: str = "network" # Default, adjust per test
    resource_id: str
    resource_type: str
    region: str = "us-east-1"
    account_id: str = "123456789012"
    created_at: datetime = datetime.utcnow()
    remediation_steps: Optional[List[str]] = []
    compliance_standards: Optional[List[str]] = []

def test_get_sg_unrestricted_ssh_guidance():
    sg_id = "sg-12345ssh"
    finding = MockFinding(
        title=f"Security group '{sg_id}' allows unrestricted ssh access",
        resource_type="AWS::EC2::SecurityGroup",
        resource_id=sg_id
    )
    guidance = get_sg_unrestricted_ssh_guidance(finding)
    assert isinstance(guidance, StructuredGuidance)
    assert guidance.iac_applicable is True
    assert guidance.resource_id == sg_id
    assert "Restrict ingress rule for port 22" in guidance.change_description
    assert "IngressRules" in guidance.required_change
    assert len(guidance.guidance_notes) > 0

def test_get_sg_unrestricted_rdp_guidance():
    sg_id = "sg-56789rdp"
    finding = MockFinding(
        title=f"Security group '{sg_id}' allows unrestricted rdp access",
        resource_type="AWS::EC2::SecurityGroup",
        resource_id=sg_id
    )
    guidance = get_sg_unrestricted_rdp_guidance(finding)
    assert isinstance(guidance, StructuredGuidance)
    assert guidance.iac_applicable is True
    assert guidance.resource_id == sg_id
    assert "Restrict ingress rule for port 3389" in guidance.change_description
    assert "IngressRules" in guidance.required_change

def test_get_sg_unrestricted_egress_guidance():
    sg_id = "sg-abcdeegress"
    finding = MockFinding(
        title=f"Security group '{sg_id}' allows unrestricted egress traffic",
        resource_type="AWS::EC2::SecurityGroup",
        resource_id=sg_id
    )
    guidance = get_sg_unrestricted_egress_guidance(finding)
    assert isinstance(guidance, StructuredGuidance)
    assert guidance.iac_applicable is True
    assert guidance.resource_id == sg_id
    assert "Restrict overly permissive egress rule" in guidance.change_description
    assert "EgressRules" in guidance.required_change

def test_get_sg_default_insecure_guidance():
    sg_id = "sg-defaulteg"
    finding = MockFinding(
        title=f"Default security group '{sg_id}' has custom rules", # Example title
        resource_type="AWS::EC2::SecurityGroup",
        resource_id=sg_id
    )
    guidance = get_sg_default_insecure_guidance(finding)
    assert isinstance(guidance, StructuredGuidance)
    assert guidance.iac_applicable is True
    assert guidance.resource_id == sg_id
    assert "Remove custom rules from the default security group" in guidance.change_description
    assert "IngressRules" in guidance.required_change
    assert "EgressRules" in guidance.required_change

def test_get_ec2_ebs_encryption_default_guidance():
    region = "eu-west-1"
    finding = MockFinding(
        title=f"EBS encryption by default is not enabled in region {region}",
        resource_type="AWS::EC2::RegionalSettings",
        resource_id=region, # Using region as ID
        region=region
    )
    guidance = get_ec2_ebs_encryption_default_guidance(finding)
    assert isinstance(guidance, StructuredGuidance)
    assert guidance.iac_applicable is True
    assert guidance.resource_id == region
    assert guidance.resource_type == "AWS::EC2::RegionalSettings"
    assert "Enable EBS encryption by default" in guidance.change_description
    assert guidance.required_change == {"EbsEncryptionByDefault": True}

def test_get_ec2_ebs_volume_unencrypted_guidance():
    volume_id = "vol-0123456789abcdef0"
    finding = MockFinding(
        title=f"EBS Volume {volume_id} is not encrypted",
        resource_type="AWS::EC2::Volume",
        resource_id=volume_id
    )
    guidance = get_ec2_ebs_volume_unencrypted_guidance(finding)
    assert isinstance(guidance, IacNotApplicableGuidance)
    assert guidance.iac_applicable is False
    assert "manual process" in guidance.reason

def test_get_ec2_instance_imdsv2_guidance():
    instance_id = "i-abcdef1234567890"
    finding = MockFinding(
        title=f"Instance {instance_id} does not require IMDSv2",
        resource_type="AWS::EC2::Instance",
        resource_id=instance_id
    )
    guidance = get_ec2_instance_imdsv2_guidance(finding)
    assert isinstance(guidance, StructuredGuidance)
    assert guidance.iac_applicable is True
    assert guidance.resource_id == instance_id
    assert "Require IMDSv2" in guidance.change_description
    assert "MetadataOptions" in guidance.required_change
    assert guidance.required_change["MetadataOptions"]["HttpTokens"] == "required" 