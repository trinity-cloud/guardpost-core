import os
import json
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from loguru import logger

from app.api.deps import get_current_user, get_db, get_graph_db
from app.db import models
from app.services.remediation.schemas import RemediationOutputV2, ImpactAnalysis, RiskScore
from app.api.v1 import schemas
from app.crud import crud_finding
from app.services.remediation.llm_guidance import generate_llm_remediation, ANTHROPIC_API_KEY, initialize_claude_client
from app.services.security_analyzer import SecurityAnalyzer

router = APIRouter()

# Instantiate analyzer (or use dependency injection if preferred)
# For simplicity here, we create an instance.
# If Analyzer had dependencies (like AWS provider), injection would be better.
security_analyzer = SecurityAnalyzer()

# Placeholder functions for components to be built in Phase 2, returning Nones for now
async def get_resource_node_details(graph_db: Any, resource_type: str, resource_id: str) -> Optional[Dict[str, Any]]:
    logger.debug(f"Placeholder: Fetching resource node details for {resource_type} {resource_id}")
    return None

async def get_resource_graph_impact(graph_db: Any, resource_type: str, resource_id: str) -> Optional[ImpactAnalysis]:
    logger.debug(f"Placeholder: Fetching resource graph impact for {resource_type} {resource_id}")
    return None

async def calculate_risk_score(finding: models.Finding, impact_data: Optional[ImpactAnalysis], resource_details: Optional[Dict[str, Any]]) -> Optional[RiskScore]:
    logger.debug(f"Placeholder: Calculating risk score for finding {finding.id}")
    return None

@router.get("/", response_model=List[schemas.Finding])
async def list_findings(
    account_id: Optional[str] = Query(None, description="Filter by AWS Account ID"),
    scan_id: Optional[UUID] = Query(None, description="Filter by Scan ID"),
    severity: Optional[schemas.FindingSeverity] = Query(None, description="Filter by severity level"),
    category: Optional[schemas.FindingCategory] = Query(None, description="Filter by finding category"),
    region: Optional[str] = Query(None, description="Filter by AWS Region"),
    resource_id: Optional[str] = Query(None, description="Filter by specific Resource ID (e.g., bucket name, instance ID)"),
    resource_type: Optional[str] = Query(None, description="Filter findings by AWS resource type (e.g., AWS::S3::Bucket)"),
    skip: int = Query(0, description="Number of records to skip for pagination"),
    limit: int = Query(100, description="Maximum number of records to return"),
    db: Session = Depends(get_db),
    current_user: str = Depends(get_current_user),
) -> Any:
    """
    List findings from DB, optionally filtered by various criteria.
    """
    logger.debug(
        f"Listing findings with filters: account_id={account_id}, scan_id={scan_id}, "
        f"severity={severity}, category={category}, region={region}, resource_id={resource_id}, "
        f"resource_type={resource_type}, skip={skip}, limit={limit}"
    )
    findings = crud_finding.list_findings(
        db=db,
        account_id=account_id,
        scan_id=scan_id,
        severity=severity,
        category=category,
        region=region,
        resource_id=resource_id,
        resource_type=resource_type,
        skip=skip,
        limit=limit,
    )
    logger.debug(f"Found {len(findings)} findings matching criteria.")
    return findings


@router.get("/{finding_id}", response_model=schemas.Finding)
async def get_finding(
    finding_id: UUID,
    db: Session = Depends(get_db),
    current_user: str = Depends(get_current_user),
) -> Any:
    """
    Get finding details by ID from DB.
    """
    finding = crud_finding.get_finding(db=db, finding_id=finding_id)
    if not finding:
        logger.warning(f"Finding ID {finding_id} not found in database.")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )
    
    return finding


@router.get("/{finding_id}/remediation", response_model=RemediationOutputV2)
async def get_finding_remediation(
    finding_id: UUID,
    db: Session = Depends(get_db),
    graph_db: Any = Depends(get_graph_db),
    current_user: str = Depends(get_current_user),
) -> RemediationOutputV2:
    """
    Get enhanced remediation guidance for a specific finding, using LLM if enabled.
    """
    finding = crud_finding.get_finding(db=db, finding_id=finding_id)
    if not finding:
        logger.warning(f"Finding ID {finding_id} not found for remediation.")
        raise HTTPException(status_code=404, detail="Finding not found")

    # 1. Check for cached LLM-enhanced guidance
    if finding.llm_remediation_output:
        try:
            logger.info(f"Returning cached LLM remediation for finding {finding_id}")
            # Assuming llm_remediation_output is stored as a JSON string or dict
            if isinstance(finding.llm_remediation_output, str):
                cached_data = json.loads(finding.llm_remediation_output)
            else: # Assuming it's already a dict/JSON compatible
                cached_data = finding.llm_remediation_output
            return RemediationOutputV2(**cached_data)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse cached LLM remediation for finding {finding_id}: {e}. Will attempt to regenerate.")
        except Exception as e: # Catch other potential Pydantic validation errors etc.
             logger.error(f"Error loading cached LLM remediation for finding {finding_id}: {e}. Will attempt to regenerate.")


    # 2. Get base rule-based remediation guidance
    #    The plan implies get_base_remediation returns RemediationOutputV2.
    #    Let's assume security_analyzer.get_remediation() can be adapted or a new function is made.
    #    For now, we'll call it and expect a dict that can be a base for RemediationOutputV2 or parts of it.
    base_remediation_data: Optional[Dict[str, Any]] = security_analyzer.get_remediation(db=db, finding_id=finding_id)
    
    if base_remediation_data is None: # security_analyzer.get_remediation might return None if finding not found or no rules
        base_remediation_data = {} # Ensure it's a dict for generate_llm_remediation
        logger.warning(f"No base rule-based remediation found for finding {finding_id}. Proceeding with minimal data for LLM.")


    # 3. Fetch additional context (placeholders for now, to be implemented in Phase 2)
    resource_node_details: Optional[Dict[str, Any]] = await get_resource_node_details(graph_db, finding.resource_type, finding.resource_id)
    impact_analysis_data: Optional[ImpactAnalysis] = await get_resource_graph_impact(graph_db, finding.resource_type, finding.resource_id)
    risk_score_data: Optional[RiskScore] = await calculate_risk_score(finding, impact_analysis_data, resource_node_details)

    use_llm = os.getenv("ENABLE_LLM_REMEDIATION", "true").lower() == "true"
    final_remediation_output: RemediationOutputV2

    claude_client_initialized = initialize_claude_client() is not None # Check if client can be initialized

    if use_llm and ANTHROPIC_API_KEY and claude_client_initialized:
        try:
            logger.info(f"Generating LLM remediation for finding {finding_id}")
            # Ensure base_remediation_data is a dict, even if it was a Pydantic model before
            base_guidance_dict = base_remediation_data.model_dump() if hasattr(base_remediation_data, 'model_dump') else base_remediation_data

            llm_generated_output = generate_llm_remediation(
                finding=finding,
                base_guidance=base_guidance_dict if base_guidance_dict else {},
                impact_data=impact_analysis_data,
                risk_score=risk_score_data,
                resource_details=resource_node_details
            )
            
            # Store the LLM-generated output in the database
            try:
                finding.llm_remediation_output = llm_generated_output.model_dump() # Store as dict/JSON
                db.add(finding)
                db.commit()
                db.refresh(finding)
                logger.info(f"Successfully cached LLM remediation for finding {finding_id}")
            except Exception as e:
                db.rollback()
                logger.error(f"Failed to cache LLM remediation for finding {finding_id}: {e}")
            
            final_remediation_output = llm_generated_output

        except Exception as e:
            logger.error(f"LLM remediation generation failed for finding {finding_id}: {e}. Falling back to rule-based guidance.")
            # Fallback: use base_remediation_data, ensuring it's RemediationOutputV2
            # The create_fallback_remediation in llm_guidance.py can be used if base_remediation_data is insufficient
            if base_remediation_data and isinstance(base_remediation_data, dict) and base_remediation_data.get("schema_version") == "2.0":
                 # If base_remediation_data was already a V2 schema, use it.
                 final_remediation_output = RemediationOutputV2(**base_remediation_data)
            else: # Create a minimal one or use the fallback from llm_guidance
                 from app.services.remediation.llm_guidance import create_fallback_remediation
                 final_remediation_output = create_fallback_remediation(finding, base_remediation_data if base_remediation_data else {}, impact_analysis_data, risk_score_data)
            
            # Ensure risk and impact are added even to fallback
            if final_remediation_output:
                final_remediation_output.risk_score = risk_score_data
                final_remediation_output.impact_analysis = impact_analysis_data
    else:
        logger.info(f"LLM remediation is disabled or API key not set for finding {finding_id}. Using rule-based guidance.")
        if base_remediation_data and isinstance(base_remediation_data, dict) and base_remediation_data.get("schema_version") == "2.0":
            final_remediation_output = RemediationOutputV2(**base_remediation_data)
        else:
            from app.services.remediation.llm_guidance import create_fallback_remediation
            final_remediation_output = create_fallback_remediation(finding, base_remediation_data if base_remediation_data else {}, impact_analysis_data, risk_score_data)

        if not final_remediation_output: # Should not happen if create_fallback_remediation works
             logger.error(f"Rule-based remediation guidance is missing or failed to create for finding {finding_id}.")
             raise HTTPException(status_code=500, detail="Core remediation guidance missing.")
        
        final_remediation_output.risk_score = risk_score_data
        final_remediation_output.impact_analysis = impact_analysis_data

    # Ensure finding_id is set, as per plan
    if final_remediation_output:
        final_remediation_output.finding_id = str(finding.id) 
    else: # Ultimate fallback if everything else failed
        logger.error(f"Failed to generate any remediation output for finding {finding_id}")
        raise HTTPException(status_code=500, detail="Failed to generate any remediation guidance.")

    return final_remediation_output
