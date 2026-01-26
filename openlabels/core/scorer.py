"""
OpenLabels Scoring Engine.

Computes risk scores from detected entities and exposure context.

Formula:
    content_score = Σ(weight × WEIGHT_SCALE × (1 + ln(count)) × confidence)
    content_score *= co_occurrence_multiplier
    final_score = min(100, content_score × exposure_multiplier)

Weights are sourced from registry.py (1-10 scale) and scaled for scoring.
"""

from typing import List, Dict, Set, Tuple
from dataclasses import dataclass
from enum import Enum
import math

from .registry import get_weight as registry_get_weight, get_category as registry_get_category


class RiskTier(Enum):
    """Risk tier classification."""
    MINIMAL = "MINIMAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# =============================================================================
# CALIBRATED PARAMETERS (January 2026)
# =============================================================================

# Scale factor: converts registry weights (1-10) to scoring weights
# Calibrated so single SSN (weight=10) at PRIVATE = Medium tier (~40)
WEIGHT_SCALE = 4.0

# Co-occurrence rules: (required_categories, multiplier, rule_name)
# Categories from registry: direct_identifier, health_info, financial, credential, etc.
CO_OCCURRENCE_RULES: List[Tuple[Set[str], float, str]] = [
    # HIPAA: Direct ID + Health data
    ({'direct_identifier', 'health_info'}, 2.0, 'hipaa_phi'),
    # Identity theft: Direct ID + Financial
    ({'direct_identifier', 'financial'}, 1.8, 'identity_theft'),
    # Credentials always risky
    ({'credential'}, 1.5, 'credential_exposure'),
    # Personal + Health (even without direct ID)
    ({'quasi_identifier', 'health_info'}, 1.5, 'phi_without_id'),
    # Contact + Health
    ({'contact', 'health_info'}, 1.4, 'phi_with_contact'),
    # Full identity package
    ({'direct_identifier', 'quasi_identifier', 'financial'}, 2.2, 'full_identity'),
    # Classified data
    ({'classification_marking'}, 2.5, 'classified_data'),
]

# Tier thresholds
TIER_THRESHOLDS = {
    'critical': 80,
    'high': 55,
    'medium': 31,
    'low': 11,
}

# Exposure multipliers
EXPOSURE_MULTIPLIERS = {
    'PRIVATE': 1.0,
    'INTERNAL': 1.2,
    'ORG_WIDE': 1.8,
    'PUBLIC': 2.5,
}


# =============================================================================
# SCORING IMPLEMENTATION
# =============================================================================

@dataclass
class ScoringResult:
    """Complete scoring result."""
    score: int                        # Final risk score (0-100)
    tier: RiskTier                    # Risk tier
    content_score: float              # Pre-exposure score
    exposure_multiplier: float        # Applied exposure multiplier
    co_occurrence_multiplier: float   # Applied co-occurrence multiplier
    co_occurrence_rules: List[str]    # Which rules triggered
    categories: Set[str]              # Entity categories present
    exposure: str                     # Exposure level

    def to_dict(self) -> dict:
        return {
            'score': self.score,
            'tier': self.tier.value,
            'content_score': self.content_score,
            'exposure_multiplier': self.exposure_multiplier,
            'co_occurrence_multiplier': self.co_occurrence_multiplier,
            'co_occurrence_rules': self.co_occurrence_rules,
            'categories': list(self.categories),
            'exposure': self.exposure,
        }


def get_entity_weight(entity_type: str) -> float:
    """Get calibrated weight for an entity type."""
    # Registry uses 1-10 scale, we scale up for scoring formula
    raw_weight = registry_get_weight(entity_type.upper())
    return raw_weight * WEIGHT_SCALE


def get_categories(entities: Dict[str, int]) -> Set[str]:
    """Get set of categories present in entities."""
    categories = set()
    for entity_type in entities:
        cat = registry_get_category(entity_type.upper())
        if cat and cat != "unknown":
            categories.add(cat)
    return categories


def get_co_occurrence_multiplier(
    entities: Dict[str, int]
) -> Tuple[float, List[str]]:
    """Get the highest applicable co-occurrence multiplier and triggered rules."""
    if not entities:
        return 1.0, []

    categories = get_categories(entities)
    max_mult = 1.0
    triggered_rules = []

    for required_cats, mult, rule_name in CO_OCCURRENCE_RULES:
        if required_cats.issubset(categories):
            if mult > max_mult:
                max_mult = mult
                triggered_rules = [rule_name]
            elif mult == max_mult:
                triggered_rules.append(rule_name)

    return max_mult, triggered_rules


def calculate_content_score(
    entities: Dict[str, int],
    confidence: float = 0.90,
) -> float:
    """
    Calculate content sensitivity score from detected entities.

    Args:
        entities: Dict of {entity_type: count}
        confidence: Average detection confidence (0.0-1.0)

    Returns:
        Content score (0-100 scale, before exposure adjustment)
    """
    if not entities:
        return 0.0

    base_score = 0.0
    for entity_type, count in entities.items():
        weight = get_entity_weight(entity_type)
        # Log aggregation: diminishing returns for more instances
        aggregation = 1 + math.log(max(1, count))
        entity_score = weight * aggregation * confidence
        base_score += entity_score

    # Apply co-occurrence multiplier
    multiplier, _ = get_co_occurrence_multiplier(entities)
    adjusted_score = base_score * multiplier

    # Cap at 100
    return min(100.0, adjusted_score)


def score_to_tier(score: float) -> RiskTier:
    """Map score to risk tier."""
    if score >= TIER_THRESHOLDS['critical']:
        return RiskTier.CRITICAL
    elif score >= TIER_THRESHOLDS['high']:
        return RiskTier.HIGH
    elif score >= TIER_THRESHOLDS['medium']:
        return RiskTier.MEDIUM
    elif score >= TIER_THRESHOLDS['low']:
        return RiskTier.LOW
    else:
        return RiskTier.MINIMAL


def score(
    entities: Dict[str, int],
    exposure: str = 'PRIVATE',
    confidence: float = 0.90,
) -> ScoringResult:
    """
    Calculate risk score from detected entities and exposure context.

    This is the main scoring function used by OpenLabels.

    Args:
        entities: Dict of {entity_type: count} from detection
        exposure: Exposure level (PRIVATE, INTERNAL, ORG_WIDE, PUBLIC)
        confidence: Average detection confidence

    Returns:
        ScoringResult with score, tier, and breakdown

    Example:
        >>> result = score({'ssn': 1, 'diagnosis': 1}, exposure='PUBLIC')
        >>> print(f"Risk: {result.score} ({result.tier.value})")
        Risk: 100 (CRITICAL)
    """
    # Calculate content score
    content_score = calculate_content_score(entities, confidence)

    # Get co-occurrence info
    co_mult, co_rules = get_co_occurrence_multiplier(entities)

    # Apply exposure multiplier
    exp_mult = EXPOSURE_MULTIPLIERS.get(exposure.upper(), 1.0)
    final_score = min(100.0, content_score * exp_mult)

    # Determine tier
    tier = score_to_tier(final_score)

    return ScoringResult(
        score=int(round(final_score)),
        tier=tier,
        content_score=round(content_score, 1),
        exposure_multiplier=exp_mult,
        co_occurrence_multiplier=co_mult,
        co_occurrence_rules=co_rules,
        categories=get_categories(entities),
        exposure=exposure.upper(),
    )


# =============================================================================
# TESTING
# =============================================================================

if __name__ == '__main__':
    # Test cases - using canonical uppercase entity types
    tests = [
        ({}, 'PRIVATE', 'Empty'),
        ({'SSN': 1}, 'PRIVATE', 'Single SSN (private)'),
        ({'SSN': 1}, 'PUBLIC', 'Single SSN (public)'),
        ({'SSN': 1, 'DIAGNOSIS': 1}, 'PRIVATE', 'HIPAA combo'),
        ({'API_KEY': 1}, 'PRIVATE', 'API key'),
        ({'EMAIL': 1, 'PHONE': 1}, 'PRIVATE', 'Contact info'),
    ]

    print("OpenLabels Scorer Test")
    print("=" * 60)

    for entities, exposure, desc in tests:
        result = score(entities, exposure)
        print(f"\n{desc}")
        print(f"  Entities: {entities}")
        print(f"  Exposure: {exposure}")
        print(f"  Score: {result.score} → {result.tier.value}")
        if result.co_occurrence_rules:
            print(f"  Rules: {result.co_occurrence_rules}")
