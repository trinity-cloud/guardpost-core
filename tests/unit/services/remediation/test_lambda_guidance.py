import pytest
from uuid import uuid4
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel

# Import the models and functions to test
from app.services.remediation.schemas import StructuredGuidance, IacNotApplicableGuidance, Guidance
from app.services.remediation.lambda_guidance import (
    get_lambda_public_url_no_auth_guidance,
    get_lambda_tracing_guidance,
    get_lambda_dlq_guidance,
    get_lambda_reserved_concurrency_guidance,
    get_lambda_latest_runtime_guidance
)

# Mock Finding model
class MockFinding(BaseModel):
    id: Any = uuid4()
    scan_id: Any = uuid4()
    title: str
    description: str = ""
    severity: str = "high"
    category: str = "compute" # Default, adjust per test
    resource_id: str
    resource_type: str = "AWS::Lambda::Function"
    region: str = "us-east-1"
    account_id: str = "123456789012"
    created_at: datetime = datetime.utcnow()
    remediation_steps: Optional[List[str]] = []
    compliance_standards: Optional[List[str]] = []

def test_get_lambda_public_url_no_auth_guidance():
    func_name = "my-public-func"
    finding = MockFinding(
        title=f"Lambda function {func_name} function url allows unauthenticated access",
        resource_id=func_name # Assuming function name is used as ID here
    )
    guidance = get_lambda_public_url_no_auth_guidance(finding)
    assert isinstance(guidance, StructuredGuidance)
    assert guidance.iac_applicable is True
    assert guidance.resource_id == func_name
    assert "Change Lambda Function URL authentication type" in guidance.change_description
    assert "FunctionUrlConfig" in guidance.required_change
    assert guidance.required_change["FunctionUrlConfig"]["AuthType"] == "AWS_IAM"

def test_get_lambda_tracing_guidance():
    func_name = "my-untraced-func"
    finding = MockFinding(
        title=f"Lambda function {func_name} active tracing is not enabled",
        resource_id=func_name
    )
    guidance = get_lambda_tracing_guidance(finding)
    assert isinstance(guidance, StructuredGuidance)
    assert guidance.iac_applicable is True
    assert guidance.resource_id == func_name
    assert "Enable AWS X-Ray active tracing" in guidance.change_description
    assert guidance.required_change == {"TracingConfig": {"Mode": "Active"}}

def test_get_lambda_dlq_guidance():
    func_name = "my-erroring-func"
    finding = MockFinding(
        title=f"Lambda function {func_name} dlq is not configured",
        resource_id=func_name
    )
    guidance = get_lambda_dlq_guidance(finding)
    assert isinstance(guidance, StructuredGuidance)
    assert guidance.iac_applicable is True
    assert guidance.resource_id == func_name
    assert "Configure a Dead-Letter Queue" in guidance.change_description
    assert "DeadLetterConfig" in guidance.required_change
    assert "SPECIFY_SQS_OR_SNS_ARN" in guidance.required_change["DeadLetterConfig"]["TargetArn"]

def test_get_lambda_reserved_concurrency_guidance():
    func_name = "my-unreserved-func"
    finding = MockFinding(
        title=f"Lambda function {func_name} reserved concurrency not configured",
        resource_id=func_name
    )
    guidance = get_lambda_reserved_concurrency_guidance(finding)
    assert isinstance(guidance, StructuredGuidance)
    assert guidance.iac_applicable is True
    assert guidance.resource_id == func_name
    assert "Configure reserved concurrency" in guidance.change_description
    assert "ReservedConcurrentExecutions" in guidance.required_change
    assert guidance.required_change["ReservedConcurrentExecutions"] > 0

def test_get_lambda_latest_runtime_guidance():
    func_name = "my-old-runtime-func"
    finding = MockFinding(
        title=f"Lambda function {func_name} uses outdated runtime (e.g., python3.7)",
        resource_id=func_name
    )
    guidance = get_lambda_latest_runtime_guidance(finding)
    assert isinstance(guidance, StructuredGuidance)
    assert guidance.iac_applicable is True
    assert guidance.resource_id == func_name
    assert "Update Lambda function to use a newer" in guidance.change_description
    assert "Runtime" in guidance.required_change
    assert "TARGET_RUNTIME_IDENTIFIER" in guidance.required_change["Runtime"] 