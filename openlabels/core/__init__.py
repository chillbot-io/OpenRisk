"""
OpenLabels Core.

Scoring engine, entity registry, and common types.
"""

from .types import Span, DetectionResult
from .registry import get_weight, get_category, normalize_type, ENTITY_REGISTRY
from .scorer import score, ScoringResult

__all__ = [
    # Types
    "Span",
    "DetectionResult",
    # Registry
    "get_weight",
    "get_category",
    "normalize_type",
    "ENTITY_REGISTRY",
    # Scoring
    "score",
    "ScoringResult",
]
