import uuid
from sqlalchemy import Column, String, DateTime, Text, ForeignKey, Enum as SAEnum, Integer, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import datetime

from app.db.session import Base
from app.api.v1.schemas import ScanStatus, ScanType, FindingSeverity, FindingCategory # Reuse enums

class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    aws_account_id = Column(String, index=True, nullable=False)
    status = Column(SAEnum(ScanStatus), nullable=False, default=ScanStatus.PENDING)
    scan_type = Column(SAEnum(ScanType), nullable=False)
    start_time = Column(DateTime(timezone=True), default=datetime.datetime.utcnow)
    end_time = Column(DateTime(timezone=True), nullable=True)
    progress_percentage = Column(Integer, nullable=True)
    # Store as JSON or comma-separated string?
    # Using JSON for flexibility, though might be less queryable depending on DB
    regions_scanned = Column(JSON, nullable=True)
    services_scanned = Column(JSON, nullable=True)

    findings = relationship("Finding", back_populates="scan")

class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(SAEnum(FindingSeverity), nullable=False, index=True)
    category = Column(SAEnum(FindingCategory), nullable=False, index=True)
    resource_id = Column(String, index=True, nullable=False)
    resource_type = Column(String, nullable=False)
    region = Column(String, nullable=False, index=True)
    account_id = Column(String, index=True, nullable=False) # Duplicating for easier finding queries
    created_at = Column(DateTime(timezone=True), default=datetime.datetime.utcnow)
    remediation_steps = Column(JSON, nullable=True) # Store list as JSON
    compliance_standards = Column(JSON, nullable=True) # Store list as JSON
    details = Column(JSON, nullable=True)  # Added details column to store enriched analyzer data
    llm_remediation_output = Column(JSON, nullable=True) # Stores LLM-enhanced RemediationOutputV2

    scan = relationship("Scan", back_populates="findings") 