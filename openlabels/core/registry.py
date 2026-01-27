"""
OpenLabels Entity Registry.

Canonical entity types with weights, categories, and vendor mappings.
This is the single source of truth for entity classification.

Adapters MUST use normalize_type() to convert vendor-specific types.
Scorer MUST use get_weight() to look up entity weights.

Entity count: ~303 types per openlabels-entity-registry-v1.md

NOTE: This module is a facade that re-exports from:
  - weights.py: ENTITY_WEIGHTS, ENTITY_CATEGORIES, DEFAULT_WEIGHT
  - vendors.py: VENDOR_ALIASES
"""

from typing import Optional

# Import data structures from split modules
from .weights import (
    ENTITY_WEIGHTS,
    ENTITY_CATEGORIES,
    DEFAULT_WEIGHT,
)
from .vendors import VENDOR_ALIASES


# =============================================================================
# PUBLIC API
# =============================================================================

def get_weight(entity_type: str) -> int:
    """
    Get weight for an entity type.

    Args:
        entity_type: Canonical entity type (e.g., "SSN", "CREDIT_CARD")

    Returns:
        Weight from 1-10, or DEFAULT_WEIGHT if unknown
    """
    return ENTITY_WEIGHTS.get(entity_type, DEFAULT_WEIGHT)


def get_category(entity_type: str) -> str:
    """
    Get category for an entity type.

    Args:
        entity_type: Canonical entity type

    Returns:
        Category string, or "unknown" if not categorized
    """
    return ENTITY_CATEGORIES.get(entity_type, "unknown")


def normalize_type(vendor_type: str, source: Optional[str] = None) -> str:
    """
    Normalize a vendor-specific entity type to canonical OpenLabels type.

    Args:
        vendor_type: Entity type from Macie, DLP, Purview, or scanner
        source: Optional source hint (unused, for logging)

    Returns:
        Canonical OpenLabels entity type
    """
    # Already canonical?
    if vendor_type in ENTITY_WEIGHTS:
        return vendor_type

    # Check vendor aliases
    if vendor_type in VENDOR_ALIASES:
        return VENDOR_ALIASES[vendor_type]

    # Unknown - pass through as-is
    return vendor_type


def is_known_type(entity_type: str) -> bool:
    """Check if an entity type is in the registry."""
    return entity_type in ENTITY_WEIGHTS or entity_type in VENDOR_ALIASES


# Re-export for backward compatibility
__all__ = [
    "ENTITY_WEIGHTS",
    "ENTITY_CATEGORIES",
    "VENDOR_ALIASES",
    "DEFAULT_WEIGHT",
    "get_weight",
    "get_category",
    "normalize_type",
    "is_known_type",
]
