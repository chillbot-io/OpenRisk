"""
OpenLabels Core.

Scoring engine and entity registry.
The scoring standard, independent of any scanner.
"""

from .registry import get_weight, get_category, normalize_type, ENTITY_REGISTRY
from .scorer import score, ScoringResult

__all__ = [
    # Registry
    "get_weight",
    "get_category",
    "normalize_type",
    "ENTITY_REGISTRY",
    # Scoring
    "score",
    "ScoringResult",
]
