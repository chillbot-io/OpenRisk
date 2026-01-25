"""
OpenLabels Scoring Engine.

Computes risk scores from normalized entity counts and exposure context.

Formula:
    content_score = Σ(weight × (1 + ln(count)) × confidence)
    content_score *= co_occurrence_multiplier
    final_score = min(100, content_score × exposure_multiplier)
"""

from typing import List, Dict, Optional
from dataclasses import dataclass
import math

from ..adapters.base import NormalizedInput, Entity


# Exposure multipliers
EXPOSURE_MULTIPLIERS = {
    "PRIVATE": 1.0,
    "INTERNAL": 1.3,
    "OVER_EXPOSED": 1.8,
    "PUBLIC": 2.5,
}

# Co-occurrence multipliers (when certain entity combinations appear together)
CO_OCCURRENCE_RULES = {
    "hipaa_phi": {
        "requires": ["direct_identifier", "health_info"],
        "multiplier": 2.0,
    },
    "identity_theft": {
        "requires": ["direct_identifier", "financial"],
        "multiplier": 1.8,
    },
    "credential_exposure": {
        "requires": ["credential", "pii"],
        "multiplier": 2.0,
    },
    "reidentification": {
        "requires_count": {"quasi_identifier": 3},
        "multiplier": 1.5,
    },
    "bulk_quasi_id": {
        "requires_count": {"quasi_identifier": 4},
        "multiplier": 1.7,
    },
    "minor_data": {
        "requires": ["direct_identifier", "minor_indicator"],
        "multiplier": 1.8,
    },
    "classified_data": {
        "requires": ["classification_marking"],
        "multiplier": 2.5,
    },
    "biometric_pii": {
        "requires": ["biometric", "direct_identifier"],
        "multiplier": 2.2,
    },
    "genetic_data": {
        "requires": ["genetic"],
        "multiplier": 2.0,
    },
}


@dataclass
class ScoringResult:
    """Result of scoring a file/object."""
    score: int                      # 0-100 risk score
    tier: str                       # CRITICAL, HIGH, MEDIUM, LOW, MINIMAL
    content_score: float            # Pre-exposure score
    exposure_multiplier: float      # Applied exposure multiplier
    co_occurrence_multiplier: float # Applied co-occurrence multiplier
    co_occurrence_rules: List[str]  # Which rules triggered
    entities: List[Entity]          # Detected entities
    exposure: str                   # Exposure level


def score(input: NormalizedInput) -> ScoringResult:
    """
    Compute risk score from normalized input.

    Args:
        input: Normalized entities and context from adapter

    Returns:
        ScoringResult with score, tier, and breakdown
    """
    # TODO: Implement scoring algorithm
    raise NotImplementedError("Scoring engine not yet implemented")


def _compute_content_score(entities: List[Entity]) -> float:
    """Compute base content score from entities."""
    total = 0.0
    for entity in entities:
        # weight × (1 + ln(count)) × confidence
        count_factor = 1 + math.log(max(1, entity.count))
        total += entity.weight * count_factor * entity.confidence
    return total


def _get_co_occurrence_multiplier(entities: List[Entity]) -> tuple[float, List[str]]:
    """Check co-occurrence rules and return multiplier."""
    # TODO: Implement co-occurrence detection
    return 1.0, []


def _score_to_tier(score: int) -> str:
    """Convert numeric score to risk tier."""
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    elif score >= 20:
        return "LOW"
    else:
        return "MINIMAL"
