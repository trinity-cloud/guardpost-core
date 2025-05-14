from typing import Optional, Dict, Any

from loguru import logger

from app.db import models # Import the Finding DB model
from app.api.v1.schemas import FindingSeverity # Import Severity Enum
from .schemas import RiskScore, ImpactAnalysis # Import V2 Schemas

# Mapping from FindingSeverity Enum to a base numerical score (0-100 range)
SEVERITY_BASE_MAP = {
    FindingSeverity.CRITICAL: 90.0,
    FindingSeverity.HIGH: 70.0,
    FindingSeverity.MEDIUM: 40.0,
    FindingSeverity.LOW: 10.0,
    FindingSeverity.INFORMATIONAL: 0.0, # Or handle separately
}

# Default factors (can be adjusted based on context)
DEFAULT_EXPOSURE_FACTOR = 1.0
DEFAULT_IMPACT_FACTOR = 1.0
DEFAULT_CONFIDENCE = 0.8 # Initial confidence level

def calculate_risk_score(
    finding: models.Finding,
    impact_data: Optional[ImpactAnalysis] = None,
    # Add other contextual data if needed, e.g., resource properties map
    resource_properties: Optional[Dict[str, Any]] = None
) -> Optional[RiskScore]:
    """
    Calculates a risk score for a given finding based on its severity,
    potential impact (blast radius), and exposure.

    Args:
        finding: The Finding database model object.
        impact_data: Optional ImpactAnalysis data (from graph context/blast radius).
        resource_properties: Optional dictionary of the resource's properties (e.g., for public access flags).

    Returns:
        A RiskScore object or None if scoring is not applicable.
    """
    if finding.severity == FindingSeverity.INFORMATIONAL:
        logger.trace(f"Skipping risk score calculation for INFORMATIONAL finding {finding.id}")
        return None # Informational findings typically don't need a risk score

    # 1. Base Severity Score
    severity_base = SEVERITY_BASE_MAP.get(finding.severity, 10.0) # Default to LOW if enum missing?

    # 2. Exposure Factor (Example: Check for public accessibility)
    exposure_factor = DEFAULT_EXPOSURE_FACTOR
    # TODO: Enhance this logic based on resource_properties or specific finding types
    # Example:
    # if resource_properties and resource_properties.get('PubliclyAccessible') is True:
    #     exposure_factor = 1.5 # Increase factor for public resources
    # elif 'public' in finding.title.lower() or 'public' in finding.description.lower():
    #     exposure_factor = 1.2 # Increase slightly if finding title suggests public exposure

    # 3. Impact Factor (Example: Use blast_radius_score)
    impact_factor = DEFAULT_IMPACT_FACTOR
    if impact_data and impact_data.blast_radius_score is not None:
        # Scale the blast radius score (0-1000) to a multiplier (e.g., 1.0 to 2.0)
        # Simple linear scaling example: 1.0 + (blast_radius_score / 1000.0)
        scaled_impact = 1.0 + (min(impact_data.blast_radius_score, 1000.0) / 1000.0)
        impact_factor = max(DEFAULT_IMPACT_FACTOR, scaled_impact) # Ensure it doesn't decrease score
        logger.trace(f"Finding {finding.id}: Blast radius score {impact_data.blast_radius_score} -> Impact factor {impact_factor:.2f}")

    # 4. Combine factors
    # Simple multiplication - adjust formula as needed
    raw_score = severity_base * exposure_factor * impact_factor

    # 5. Normalize/Cap Score (e.g., 0-100)
    normalized_score = max(0.0, min(100.0, raw_score))

    # 6. Confidence Level
    # TODO: Adjust confidence based on how factors were derived (e.g., lower if blast radius missing)
    confidence = DEFAULT_CONFIDENCE
    if not impact_data or impact_data.blast_radius_score is None:
        confidence *= 0.9 # Slightly reduce confidence if impact data is missing

    risk_score_obj = RiskScore(
        score=round(normalized_score, 1),
        severity_base=severity_base,
        exposure_factor=round(exposure_factor, 2),
        impact_factor=round(impact_factor, 2),
        confidence=round(confidence, 2)
    )
    logger.debug(f"Calculated risk score for finding {finding.id}: {risk_score_obj.model_dump_json()}")
    return risk_score_obj 