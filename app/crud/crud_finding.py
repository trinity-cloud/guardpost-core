from typing import List, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from app.db import models
from app.api.v1 import schemas # For FindingCreate later, though currently analyzer creates directly


def get_finding(db: Session, finding_id: UUID) -> Optional[models.Finding]:
    """Get a finding by its ID."""
    return db.query(models.Finding).filter(models.Finding.id == finding_id).first()

def list_findings(
    db: Session,
    skip: int = 0,
    limit: int = 1000, # Allow fetching more findings by default?
    account_id: Optional[str] = None,
    scan_id: Optional[UUID] = None,
    severity: Optional[schemas.FindingSeverity] = None,
    category: Optional[schemas.FindingCategory] = None,
    region: Optional[str] = None,
    resource_id: Optional[str] = None,
    resource_type: Optional[str] = None,
) -> List[models.Finding]:
    """List findings with optional filters and pagination."""
    query = db.query(models.Finding)
    if account_id:
        query = query.filter(models.Finding.account_id == account_id)
    if scan_id:
        query = query.filter(models.Finding.scan_id == scan_id)
    if severity:
        query = query.filter(models.Finding.severity == severity)
    if category:
        query = query.filter(models.Finding.category == category)
    if region:
        query = query.filter(models.Finding.region == region)
    if resource_id:
        # Basic substring search might be useful here?
        # Or exact match depending on use case.
        query = query.filter(models.Finding.resource_id == resource_id)
    if resource_type:
        query = query.filter(models.Finding.resource_type == resource_type)

    return query.order_by(models.Finding.created_at.desc()).offset(skip).limit(limit).all()

def create_finding(db: Session, finding: models.Finding) -> models.Finding:
    """Create a new finding record directly using the model object.
    Called by the analyzer service.
    """
    db.add(finding)
    db.commit() # Commit each finding? Or commit in batches?
    db.refresh(finding)
    return finding

# Note: Update/Delete operations for findings might be added later
# for exception management, etc.
# def update_finding(...):
# def delete_finding(...): 