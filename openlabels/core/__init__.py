"""
OpenLabels Core.

Scoring engine, entity registry, and label primitives.
The scoring standard, independent of any scanner.
"""

from .registry import get_weight, get_category, normalize_type, ENTITY_REGISTRY
from .scorer import score, ScoringResult
from .labels import (
    # Label ID and hashing
    generate_label_id,
    compute_content_hash,
    compute_content_hash_file,
    compute_value_hash,
    # Data model
    Label,
    LabelSet,
    VirtualLabelPointer,
    # Utilities
    labels_from_detection,
    is_valid_label_id,
    is_valid_content_hash,
    is_valid_value_hash,
)

__all__ = [
    # Registry
    "get_weight",
    "get_category",
    "normalize_type",
    "ENTITY_REGISTRY",
    # Scoring
    "score",
    "ScoringResult",
    # Labels
    "generate_label_id",
    "compute_content_hash",
    "compute_content_hash_file",
    "compute_value_hash",
    "Label",
    "LabelSet",
    "VirtualLabelPointer",
    "labels_from_detection",
    "is_valid_label_id",
    "is_valid_content_hash",
    "is_valid_value_hash",
]
