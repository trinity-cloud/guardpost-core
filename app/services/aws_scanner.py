import uuid
import datetime
from typing import Dict, List, Optional, Any
import traceback
import concurrent.futures # Task 5.1: Import required module

from loguru import logger
from sqlalchemy.orm import Session

from app.providers.aws_provider import AwsProvider
# Import schemas explicitly
from app.api.v1 import schemas # Use this to access ScanRequest, ScanStatus, etc.
from app.api.v1.schemas import ScanType, ScanStatus
from app.db import models # Import DB models
from app.crud import crud_scan # Import scan CRUD functions
# Import SecurityAnalyzer to call it after scanning
from app.services.security_analyzer import SecurityAnalyzer
# Import GraphBuilder
from app.services.graph_builder import GraphBuilder
# Import Neo4jClient dependency getter
from app.db.graph_db import get_neo4j_client

# Import the new scanner functions
from app.services.scanners.iam_scanner import scan_iam
from app.services.scanners.s3_scanner import scan_s3
from app.services.scanners.ec2_scanner import scan_ec2
from app.services.scanners.rds_scanner import scan_rds
from app.services.scanners.lambda_scanner import scan_lambda
from app.services.scanners.vpc_scanner import scan_vpc
from app.services.scanners.ebs_scanner import scan_ebs

# Mapping from service name string to scanner function
SCANNER_FUNCTIONS = {
    "iam": scan_iam,
    "s3": scan_s3,
    "ec2": scan_ec2,
    "vpc": scan_vpc,
    "ebs": scan_ebs,
    "rds": scan_rds,
    "lambda": scan_lambda,
}

# Global services that don't run per region
GLOBAL_SERVICES = ["iam", "s3"]

# Services to run per region (excluding global)
# Inferring from SCANNER_FUNCTIONS and GLOBAL_SERVICES might be better
REGIONAL_SERVICES = ["ec2", "vpc", "ebs", "rds", "lambda"]

# Configurable number of worker threads for the scanner
MAX_SCANNER_WORKERS = 10 # Task 5.2: Configurable max workers

class AwsScanner:
    """Service for scanning AWS resources."""

    # Instantiate analyzer here or pass via dependency injection if preferred
    _security_analyzer = SecurityAnalyzer()
    # Instantiate GraphBuilder - potentially get client via dependency?
    # For simplicity, get client directly here or ensure it's available globally
    _neo4j_client = get_neo4j_client()
    _graph_builder = GraphBuilder(neo4j_client=_neo4j_client) if _neo4j_client else None

    def __init__(self):
        """Initialize the AWS scanner service."""
        if not self._graph_builder:
             logger.warning("GraphBuilder not initialized due to missing Neo4j client. Graph features disabled for this scanner instance.")
        pass # No specific initialization needed for now

    def start_scan(
        self,
        db: Session, # Add db Session parameter
        aws_provider: AwsProvider,
        scan_type: ScanType = ScanType.STANDARD,
        regions: Optional[List[str]] = None,
        services: Optional[List[str]] = None,
    ) -> models.Scan: # Return the DB Scan model
        """
        Start a new AWS scan, track progress in DB.
        """
        scan_id = uuid.uuid4()
        account_id = aws_provider.account_id

        scan_request_data = schemas.ScanRequest(
            aws_account_id=account_id,
            scan_type=scan_type,
            regions=regions,
            services=services
        )
        db_scan = crud_scan.create_scan(db=db, scan_in=scan_request_data, scan_id=scan_id)
        logger.info(f"Starting scan {scan_id} for account {account_id}")

        crud_scan.update_scan(db=db, scan_id=scan_id, status=schemas.ScanStatus.IN_PROGRESS)

        all_resources: Dict[str, Dict[str, List[Any]]] = {}
        services_to_scan = services or list(SCANNER_FUNCTIONS.keys()) # Use keys from map

        try:
            if regions:
                 target_regions = regions
                 logger.info(f"[{scan_id}] Using specified regions: {target_regions}")
            else:
                 logger.info(f"[{scan_id}] No regions specified, discovering available EC2 regions...")
                 target_regions = aws_provider.list_regions()
                 logger.info(f"[{scan_id}] Found regions: {target_regions}")
        except Exception as region_e:
             logger.error(f"[{scan_id}] Failed to list regions: {region_e}. Defaulting to provider region: {aws_provider.region}")
             target_regions = [aws_provider.region]
        
        # --- Task 5.2: Define Scan Tasks --- 
        scan_tasks = []
        task_details = {} # To map future to service/region

        for service in services_to_scan:
            if service not in SCANNER_FUNCTIONS:
                logger.warning(f"[{scan_id}] Unknown service '{service}' requested for scan, skipping.")
                continue

            scan_func = SCANNER_FUNCTIONS[service]
            if service in GLOBAL_SERVICES:
                # Global service task
                task_args = (aws_provider,)
                task_key = (service, "global")
                scan_tasks.append((task_key, scan_func, task_args))
            else:
                # Regional service tasks
                for region in target_regions:
                    task_args = (aws_provider, region)
                    task_key = (service, region)
                    scan_tasks.append((task_key, scan_func, task_args))
        
        # Task 5.3: Calculate total tasks for progress
        total_tasks = len(scan_tasks)
        completed_tasks = 0
        if total_tasks == 0:
            logger.warning(f"[{scan_id}] No valid scan tasks defined. Finishing scan.")
            total_steps = 1 # Avoid division by zero
        else:
             # Total steps = Number of tasks + 1 for analysis phase
             total_steps = total_tasks + 1

        logger.info(f"[{scan_id}] Defined {total_tasks} scan tasks across {len(target_regions)} regions for services: {services_to_scan}")
        
        # --- Task 5.2: Perform Real Scanning using ThreadPoolExecutor --- 
        futures_map = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_SCANNER_WORKERS) as executor:
            for task_key, func, args in scan_tasks:
                service, region_or_global = task_key
                future = executor.submit(func, *args)
                futures_map[future] = task_key # Map future to (service, region/global)
            
            logger.info(f"[{scan_id}] Submitted {len(futures_map)} tasks to executor. Processing results...")
            
            # Task 5.2 & 5.3: Process results as completed and update progress
            for future in concurrent.futures.as_completed(futures_map):
                task_key = futures_map[future]
                service, region_or_global = task_key
                try:
                    result = future.result()
                    logger.debug(f"[{scan_id}] Task completed: {service} in {region_or_global}. Found {len(result) if isinstance(result, list) else 'N/A'} resources.")
                    
                    # Aggregate results
                    if service not in all_resources: all_resources[service] = {}
                    all_resources[service][region_or_global] = result
                
                except Exception as exc:
                    logger.error(f"[{scan_id}] Scan task failed for {service} in {region_or_global}: {exc}")
                    # Store error indication? For now, just log and continue.
                    if service not in all_resources: all_resources[service] = {}
                    all_resources[service][region_or_global] = [{"_Error": str(exc)}] # Store error marker
                finally:
                     completed_tasks += 1
                     # Calculate progress based on completed tasks (up to 90% before analysis)
                     progress = int((completed_tasks / total_tasks) * 90) if total_tasks > 0 else 90
                     # Update DB progress (consider throttling this update if needed)
                     try:
                         crud_scan.update_scan(db=db, scan_id=scan_id, progress=progress)
                     except Exception as db_exc:
                          logger.error(f"[{scan_id}] Failed to update scan progress in DB: {db_exc}")

        # --- Trigger Analysis (After all scan tasks are done) ---           
        logger.info(f"[{scan_id}][90%] All scan tasks completed. Analyzing collected resources ({completed_tasks}/{total_tasks} tasks finished successfully/with error)...")
        
        self._security_analyzer.analyze_resources(
            db=db, 
            db_client=self._neo4j_client,
            aws_provider=aws_provider,
            resources=all_resources, 
            scan_id=scan_id
        )
        logger.info(f"[{scan_id}] Resource analysis complete.")

        # --- Trigger Graph Build --- #
        if self._graph_builder and self._graph_builder.is_enabled:
             logger.info(f"[{scan_id}] Starting graph build...")
             try:
                 self._graph_builder.build_graph(aws_provider=aws_provider, db_session=db, all_resources=all_resources)
                 logger.info(f"[{scan_id}] Graph build finished.")
             except Exception as graph_e:
                  logger.error(f"[{scan_id}] Graph build failed: {graph_e}")
                  logger.error(traceback.format_exc())
                  # Optionally update scan status to reflect graph build failure?
        else:
            logger.info(f"[{scan_id}] Skipping graph build (GraphBuilder disabled).")

        # --- Schedule Post-Scan Tasks (e.g., Blast Radius) --- #
        logger.info(f"[{scan_id}] Scheduling post-scan tasks...")
        try:
            from app.services.schedulers.post_scan_tasks import schedule_blast_radius_calculations
            # Ensure scan_start_time is available; db_scan.start_time should be correct
            # scan_start_time is no longer needed for the scheduler
 
            schedule_blast_radius_calculations(
                 scan_id=scan_id, 
                 account_id=aws_provider.account_id,
                 # region=?? # If scan was regional, pass it. For now, assume global context for scheduling after full scan.
                 # For simplicity, let the scheduler query all relevant nodes for the account updated since scan start.
             )
        except Exception as scheduler_e:
            logger.error(f"[{scan_id}] Failed to schedule post-scan tasks: {scheduler_e}", exc_info=True)

        # --- Finalize Scan Status --- #
        # TODO: Determine final status based on whether any tasks failed. 
        # For now, assume COMPLETED if analysis finishes.
        final_status = schemas.ScanStatus.COMPLETED
        # Example logic: 
        # has_errors = any("_Error" in res[0] for service_data in all_resources.values() for res in service_data.values() if isinstance(res, list) and res)
        # final_status = schemas.ScanStatus.COMPLETED_WITH_ERRORS if has_errors else schemas.ScanStatus.COMPLETED
        
        db_scan = crud_scan.update_scan(
            db=db,
            scan_id=scan_id,
            status=final_status,
            progress=100,
            end_time=datetime.datetime.utcnow()
        )
        logger.info(f"Scan {scan_id} finished with status: {final_status}.")

        # except Exception as e: # General exception handling moved outside the parallel block
        #     logger.error(f"Scan {scan_id} failed during parallel execution or analysis: {str(e)}")
        #     logger.error(traceback.format_exc())
        #     db_scan = crud_scan.update_scan(
        #         db=db,
        #         scan_id=scan_id,
        #         status=schemas.ScanStatus.FAILED,
        #         progress=100, # Or current progress?
        #         end_time=datetime.datetime.utcnow()
        #     )

        return db_scan if db_scan else crud_scan.get_scan(db, scan_id)


