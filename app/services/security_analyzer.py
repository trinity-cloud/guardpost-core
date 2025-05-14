import uuid
import datetime
from typing import Dict, List, Optional, Any
import traceback
import json # For parsing policy documents

from loguru import logger
from sqlalchemy.orm import Session # Import Session

from app.providers.aws_provider import AwsProvider
from app.api.v1.schemas import FindingSeverity, FindingCategory, Finding as FindingSchema # Rename to avoid clash with model
from app.db import models # DB Model
from app.crud import crud_finding # Finding CRUD functions
from app.db.graph_db import Neo4jClient # Import Neo4j Client

# Import the new analyzer functions
from app.services.analyzers import s3_analyzer, rds_analyzer, iam_analyzer, ec2_analyzer, lambda_analyzer # Import individual analyzers
# Add imports for VPC and EBS analyzers assuming they exist or will be created
from app.services.analyzers import vpc_analyzer, ebs_analyzer

from app.services.remediation.iac_guidance import get_remediation_guidance
from app.services.remediation.schemas import RemediationOutputV2 # Updated to RemediationOutputV2

class SecurityAnalyzer:
    """Service for analyzing AWS resources for security issues."""

    def __init__(self):
        """Initialize the security analyzer service."""
        pass # No specific initialization needed for now

    def analyze_resources(
        self,
        db: Session, # Add db Session parameter
        db_client: Neo4jClient, # Add Neo4j client parameter
        aws_provider: AwsProvider,
        resources: Dict[str, Dict[str, List[Any]]],
        scan_id: uuid.UUID, # Expect UUID here now
    ) -> None: # Doesn't need to return findings anymore
        """
        Analyze AWS resources and save findings directly to the DB.
        """
        logger.info(f"[{scan_id}] Starting analysis of resources...")
        # Ensure all analysis functions are correctly mapped to imported functions
        analysis_functions = {
            "iam": iam_analyzer.analyze_iam,
            "s3": s3_analyzer.analyze_s3,
            "ec2": ec2_analyzer.analyze_ec2,
            "rds": rds_analyzer.analyze_rds,
            "lambda": lambda_analyzer.analyze_lambda,
            "vpc": vpc_analyzer.analyze_vpc, # Add VPC analyzer
            "ebs": ebs_analyzer.analyze_ebs, # Add EBS analyzer
        }

        account_id = aws_provider.account_id
        total_findings_created = 0

        for service, regions_data in resources.items():
            if service in analysis_functions:
                logger.debug(f"[{scan_id}] Analyzing service: {service}")
                if service == "iam":
                    iam_resources = regions_data.get("global", [])
                    # Call IAM analyzer, which returns a dict
                    iam_analysis_result = analysis_functions[service](
                        db=db, 
                        db_client=db_client, # Add db_client here
                        account_id=account_id, 
                        scan_id=scan_id, 
                        region="global", 
                        iam_resources=iam_resources, 
                        aws_provider=aws_provider, 
                        create_finding_callback=self._create_finding
                    )
                    # Extract the count from the result dict
                    findings_count = iam_analysis_result.get("findings_created", 0)
                    total_findings_created += findings_count
                    # Note: We are ignoring the "relationships_to_create" dict here
                    # because the graph_builder calls the analyzer separately.
                # Handle regional services
                else:
                    for region, regional_resources in regions_data.items():
                        # Prepare arguments once
                        args = {
                            "db": db,
                            "account_id": account_id,
                            "scan_id": scan_id,
                            "region": region,
                            "create_finding_callback": self._create_finding
                        }
                        # Add service-specific resource list OR db_client
                        if service == "s3":
                            # args["s3_resources"] = regional_resources # Old way
                            args["db_client"] = db_client # New way for S3
                        elif service == "ec2":
                            args["ec2_resources"] = regional_resources
                            args["db_client"] = db_client # Also pass for EC2 analyzer if it uses graph
                        elif service == "rds":
                            args["rds_resources"] = regional_resources
                            args["db_client"] = db_client # Also pass for RDS analyzer
                        elif service == "lambda":
                            args["lambda_resources"] = regional_resources
                            args["aws_provider"] = aws_provider 
                            args["db_client"] = db_client # Also pass for Lambda analyzer
                        elif service == "vpc":
                            args["vpc_resources"] = regional_resources 
                            args["db_client"] = db_client # Also pass for VPC analyzer
                        elif service == "ebs":
                            args["ebs_resources"] = regional_resources 
                            args["db_client"] = db_client # Also pass for EBS analyzer
                        # For IAM, db_client needs to be passed differently as it's not in the regional loop
                        # The IAM analyzer is called separately and will need db_client added to its args there.

                        # Call the correct analyzer function
                        try:
                            count = analysis_functions[service](**args)
                            total_findings_created += count
                        except Exception as e:
                            logger.error(f"[{scan_id}] Error analyzing {service} in {region}: {e}")
                            # Optionally add a finding about the analysis error itself
                            
            else:
                logger.warning(f"[{scan_id}] No analysis function found for service: {service}")

        logger.info(f"[{scan_id}] Analysis complete. Created {total_findings_created} new findings in DB.")
        # Return None

    # --- Individual Service Analyzers --- #
    # All _analyze_* methods are now removed.

    # --- Finding Creation Helper --- #
    def _create_finding(
        self,
        db: Session, # Add db Session parameter
        account_id: str, scan_id: uuid.UUID, region: str, resource_id: str, resource_type: str,
        title: str, description: str, severity: FindingSeverity, category: FindingCategory,
        compliance_standards: Optional[List[str]] = None,
        remediation_steps: Optional[List[str]] = None,
        details: Optional[Dict[str, Any]] = None # Added details parameter
    ) -> models.Finding: # Return the persisted DB model
        """Helper to create a Finding DB model object and save it, including the details dict."""
        db_finding = models.Finding(
            scan_id=scan_id,
            account_id=account_id,
            region=region,
            resource_id=resource_id,
            resource_type=resource_type,
            title=title,
            description=description,
            severity=severity,
            category=category,
            compliance_standards=compliance_standards or [],
            remediation_steps=remediation_steps or [],
            details=details # Pass details to the model
        )
        return crud_finding.create_finding(db=db, finding=db_finding)


    # --- DB-backed Finding Management --- #

    def get_finding(self, db: Session, finding_id: uuid.UUID) -> Optional[models.Finding]:
        """Get finding by ID from DB."""
        return crud_finding.get_finding(db=db, finding_id=finding_id)

    def list_findings(
        self,
        db: Session, # Add db Session parameter
        skip: int = 0,
        limit: int = 1000,
        account_id: Optional[str] = None,
        scan_id: Optional[uuid.UUID] = None,
        severity: Optional[FindingSeverity] = None,
        category: Optional[FindingCategory] = None,
        region: Optional[str] = None,
        resource_id: Optional[str] = None,
        resource_type: Optional[str] = None,
    ) -> List[models.Finding]:
        """List findings from DB, optionally filtered."""
        return crud_finding.list_findings(
            db=db, skip=skip, limit=limit,
            account_id=account_id, scan_id=scan_id,
            severity=severity, category=category,
            region=region, resource_id=resource_id, resource_type=resource_type
        )

    # --- Remediation Generation (Now uses imported function) ---
    
    def get_remediation(self, db: Session, finding_id: uuid.UUID) -> Optional[Dict[str, Any]]:
        """Retrieves remediation steps and structured guidance for a finding."""
        logger.debug(f"Fetching remediation for finding ID: {finding_id}")
        finding_model_instance = crud_finding.get_finding(db, finding_id=finding_id)
        if not finding_model_instance:
            logger.warning(f"Finding {finding_id} not found when fetching remediation.")
            return None

        # Get the structured V2 guidance model (or None if guidance func fails or not found)
        # The type hint for get_remediation_guidance should ideally be updated to RemediationOutputV2
        # in iac_guidance.py if all guidance functions now conform to it.
        guidance_v2_object: Optional[RemediationOutputV2] = get_remediation_guidance(finding_model_instance)

        # The API response structure is defined by FindingRemediation in app/api/v1/schemas.py
        # It expects a 'guidance' field that will hold our RemediationOutputV2 object.
        remediation_response = {
            "finding_id": str(finding_model_instance.id),
            "steps": finding_model_instance.remediation_steps or [], # Basic steps from DB Finding
            "guidance": guidance_v2_object # Assign the Pydantic model directly; FastAPI handles serialization
        }
        
        # Log the structure being returned for debugging Pydantic validation issues
        if guidance_v2_object:
            logger.debug(f"SecurityAnalyzer returning guidance: {guidance_v2_object.model_dump_json(indent=2)}")
        else:
            logger.debug(f"SecurityAnalyzer returning no specific guidance object for finding {finding_id}")

        return remediation_response

    # _generate_iac_snippet method is removed.
