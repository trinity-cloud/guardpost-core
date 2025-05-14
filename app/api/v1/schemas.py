from enum import Enum
from typing import List, Optional, Dict, Any, Union
from pydantic import BaseModel, Field, ConfigDict
from uuid import UUID
from datetime import datetime

# Import the NEW V2 remediation guidance schema
from app.services.remediation.schemas import RemediationOutputV2


# Auth schemas
class Token(BaseModel):
    access_token: str
    token_type: str


class TokenPayload(BaseModel):
    sub: Optional[str] = None


class UserBase(BaseModel):
    email: str


class UserCreate(UserBase):
    password: str


class User(UserBase):
    id: str
    is_active: bool = True


# AWS schemas
class AwsCredentials(BaseModel):
    profile_name: Optional[str] = None
    access_key_id: Optional[str] = None
    secret_access_key: Optional[str] = None
    session_token: Optional[str] = None
    region: Optional[str] = "us-east-1"

    class Config:
        json_schema_extra = {
            "example": {
                "profile_name": "my-aws-profile",
                "region": "us-east-1"
            }
        }


class ScanType(str, Enum):
    QUICK = "quick"
    STANDARD = "standard"
    COMPREHENSIVE = "comprehensive"


class ScanRequest(BaseModel):
    aws_account_id: str
    scan_type: ScanType = ScanType.STANDARD
    regions: Optional[List[str]] = None
    services: Optional[List[str]] = None
    aws_profile_name: Optional[str] = None
    aws_role_arn: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "aws_account_id": "123456789012",
                "scan_type": "standard",
                "regions": ["us-east-1", "us-west-2"],
                "services": ["s3", "ec2", "iam"],
                "aws_profile_name": "my-scan-profile",
                "aws_role_arn": "arn:aws:iam::123456789012:role/MyScanRole"
            }
        }


class ScanStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class Scan(BaseModel):
    id: UUID
    aws_account_id: str
    status: ScanStatus
    scan_type: ScanType
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    progress_percentage: Optional[int] = None
    regions_scanned: Optional[List[str]] = None
    services_scanned: Optional[List[str]] = None

    model_config = ConfigDict(
        from_attributes=True,
    )


# Finding schemas
class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    OTHER = "other"


class FindingCategory(str, Enum):
    IAM = "iam"
    PUBLIC_EXPOSURE = "public_exposure"
    ENCRYPTION = "encryption"
    NETWORK = "network"
    COMPLIANCE = "compliance"
    OTHER = "other"


class Finding(BaseModel):
    id: UUID
    scan_id: UUID
    title: str
    description: str
    severity: FindingSeverity
    category: FindingCategory
    resource_id: str
    resource_type: str
    region: str
    account_id: str
    created_at: datetime
    remediation_steps: Optional[List[str]] = []
    compliance_standards: Optional[List[str]] = []
    details: Optional[Dict[str, Any]] = None

    model_config = ConfigDict(
        from_attributes=True,
    )


# Remediation schema
class FindingRemediation(BaseModel):
    finding_id: UUID
    steps: List[str]
    guidance: Optional[RemediationOutputV2] = None
