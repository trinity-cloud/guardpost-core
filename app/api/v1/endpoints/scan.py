from typing import Any, List, Optional
import os
from uuid import UUID # Import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session # Import Session
from loguru import logger

from app.api.deps import get_current_user, get_db # Add get_db
from app.api.v1.schemas import ScanRequest, ScanType, Scan # Use DB Scan schema for response
from app.providers.aws_provider import AwsProvider
# Remove AwsScanner dependency, use CRUD directly
# from app.services.aws_scanner import AwsScanner
from app.crud import crud_scan # Import scan CRUD functions

# --- TODO: Background Task Integration --- #
# For now, start_scan is still synchronous. We need to integrate
# a background task runner (like Celery or FastAPI's BackgroundTasks)
# to run the actual scan asynchronously. The start_scan endpoint should
# create the initial DB record and enqueue the task.
from app.services.aws_scanner import AwsScanner # Keep scanner for background task

router = APIRouter()


@router.post("/", response_model=Scan) # Return DB Scan model
async def start_scan(
    scan_request: ScanRequest,
    db: Session = Depends(get_db), # Inject DB Session
    current_user: str = Depends(get_current_user),
    # aws_scanner: AwsScanner = Depends(get_aws_scanner), # Remove direct scanner dependency
) -> Any:
    """
    Start a new AWS scan (Creates DB record, sync execution for now).
    """
    try:
        # --- Provider setup (moved from scanner) ---
        logger.info(f"Creating AwsProvider with Profile: {scan_request.aws_profile_name}, RoleArn: {scan_request.aws_role_arn}")
        aws_provider = AwsProvider(
            profile_name=scan_request.aws_profile_name,
            role_arn=scan_request.aws_role_arn
            # Assuming default region is handled within AwsProvider or can be added here if needed
        )
        logger.info(f"Provider created for account {aws_provider.account_id}")

        # --- Run Scan (Synchronous for now) ---
        # TODO: Refactor to use background tasks
        # In a background task, you'd pass the db session differently
        # or create a new session within the task.
        scanner = AwsScanner() # Instantiate scanner here for sync execution
        db_scan = scanner.start_scan(
            db=db,
            aws_provider=aws_provider,
            scan_type=scan_request.scan_type,
            regions=scan_request.regions,
            services=scan_request.services,
        )

        if not db_scan:
            # This case should be rare if start_scan handles errors internally
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Scan started but failed to retrieve final status.",
            )

        return db_scan # Return the Scan object from DB

    except ConnectionError as ce: # Catch specific connection errors from provider
         logger.error(f"AWS Connection Error during provider setup: {ce}", exc_info=True)
         raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, # Bad request as connection params failed
            detail=f"AWS Connection Error: {str(ce)}",
         )
    except Exception as e:
        logger.error(f"Error in start_scan endpoint: {e}", exc_info=True)
        # Ensure any partially created scan record is marked as FAILED if possible?
        # For now, just raise HTTP exception.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error processing scan request: {str(e)}",
        )


@router.get("/{scan_id}", response_model=Scan)
async def get_scan(
    scan_id: UUID, # Use UUID
    db: Session = Depends(get_db), # Inject DB Session
    current_user: str = Depends(get_current_user),
    # aws_scanner: AwsScanner = Depends(get_aws_scanner), # No longer needed
) -> Any:
    """
    Get scan status and details from DB.
    """
    db_scan = crud_scan.get_scan(db=db, scan_id=scan_id)
    if not db_scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )
    # TODO: Add authorization check - does current_user have access to this scan?
    return db_scan


@router.get("/", response_model=List[Scan])
async def list_scans(
    aws_account_id: Optional[str] = None,
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db), # Inject DB Session
    current_user: str = Depends(get_current_user),
    # aws_scanner: AwsScanner = Depends(get_aws_scanner), # No longer needed
) -> Any:
    """
    List scans from DB, optionally filtered by AWS account ID.
    """
    # TODO: Add authorization check - only list scans accessible by current_user
    scans = crud_scan.list_scans(db=db, account_id=aws_account_id, skip=skip, limit=limit)
    return scans


@router.post("/{scan_id}/blast-radius")
async def trigger_blast_radius(
    scan_id: UUID,
    db: Session = Depends(get_db),
    current_user: str = Depends(get_current_user),
) -> Any:
    """
    Manually trigger blast radius calculations for a specific scan.
    """
    # Get the scan to verify it exists and get account_id
    db_scan = crud_scan.get_scan(db=db, scan_id=scan_id)
    if not db_scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )
    
    # Get account_id from the scan
    account_id = db_scan.aws_account_id
    
    try:
        # Call the scheduler
        from app.services.schedulers.post_scan_tasks import schedule_blast_radius_calculations
        
        # Debug log to track execution
        logger.info(f"Manual blast radius calculation triggered for scan {scan_id}, account {account_id}")
        
        # Call the scheduler function
        scheduled_count = schedule_blast_radius_calculations(
            scan_id=scan_id,
            account_id=account_id,
        )
        
        return {"message": f"Blast radius calculation triggered for scan {scan_id}", "scheduled_tasks": scheduled_count}
    except Exception as e:
        logger.error(f"Error triggering blast radius calculation: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error triggering blast radius calculation: {str(e)}",
        )
