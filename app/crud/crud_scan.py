import datetime
from typing import List, Optional, Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.db import models
from app.api.v1 import schemas # For ScanCreate/ScanUpdate later


def get_scan(db: Session, scan_id: UUID) -> Optional[models.Scan]:
    """Get a scan by its ID."""
    return db.query(models.Scan).filter(models.Scan.id == scan_id).first()

def list_scans(
    db: Session,
    skip: int = 0,
    limit: int = 100,
    account_id: Optional[str] = None,
    status: Optional[schemas.ScanStatus] = None,
) -> List[models.Scan]:
    """List scans with optional filters and pagination."""
    query = db.query(models.Scan)
    if account_id:
        query = query.filter(models.Scan.aws_account_id == account_id)
    if status:
        query = query.filter(models.Scan.status == status)
    return query.order_by(models.Scan.start_time.desc()).offset(skip).limit(limit).all()

def create_scan(db: Session, scan_in: schemas.ScanRequest, scan_id: UUID) -> models.Scan:
    """Create a new scan record."""
    db_scan = models.Scan(
        id=scan_id,
        aws_account_id=scan_in.aws_account_id,
        scan_type=scan_in.scan_type,
        status=schemas.ScanStatus.PENDING, # Initial status
        regions_scanned=scan_in.regions, # Store requested regions
        services_scanned=scan_in.services # Store requested services
        # start_time is default
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)
    return db_scan

def update_scan(
    db: Session,
    scan_id: UUID,
    status: Optional[schemas.ScanStatus] = None,
    progress: Optional[int] = None,
    end_time: Optional[datetime.datetime] = None,
    # Add other fields if needed
) -> Optional[models.Scan]:
    """Update scan status, progress, or end time."""
    db_scan = get_scan(db, scan_id)
    if not db_scan:
        return None

    if status is not None:
        db_scan.status = status
    if progress is not None:
        db_scan.progress_percentage = progress
    if end_time is not None:
        db_scan.end_time = end_time

    db.commit()
    db.refresh(db_scan)
    return db_scan

# Note: Delete operation might not be needed initially
# def delete_scan(db: Session, scan_id: UUID) -> Optional[models.Scan]:
#     ... 