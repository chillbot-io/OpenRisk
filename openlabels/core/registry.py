"""
OpenLabels Entity Registry.

Canonical entity types with weights, categories, and co-occurrence mappings.
This is the source of truth for entity classification.

See docs/openlabels-entity-registry-v1.md for the full specification.
"""

from typing import Dict, List
from dataclasses import dataclass


@dataclass
class EntityDefinition:
    """Definition of an entity type."""
    type: str           # Canonical name (e.g., "SSN")
    weight: int         # Risk weight 1-10
    category: str       # Category for co-occurrence rules
    aliases: List[str]  # Alternative names from various scanners


# Entity categories for co-occurrence rules
CATEGORIES = {
    "direct_identifier": "Directly identifies an individual",
    "quasi_identifier": "Could identify when combined with others",
    "health_info": "Protected health information",
    "financial": "Financial account information",
    "credential": "Authentication credentials",
    "government": "Government-issued identifiers",
    "biometric": "Biometric data",
    "genetic": "Genetic information",
    "contact": "Contact information",
    "classification_marking": "Security classification markings",
    "minor_indicator": "Indicates data about a minor",
}


# Canonical entity registry
# TODO: Load from docs/openlabels-entity-registry-v1.md or separate JSON
ENTITY_REGISTRY: Dict[str, EntityDefinition] = {
    # Direct Identifiers (weight 8-10)
    "SSN": EntityDefinition(
        type="SSN",
        weight=10,
        category="direct_identifier",
        aliases=["USA_SOCIAL_SECURITY_NUMBER", "US_SOCIAL_SECURITY_NUMBER", "U.S. Social Security Number (SSN)"],
    ),
    "PASSPORT": EntityDefinition(
        type="PASSPORT",
        weight=9,
        category="direct_identifier",
        aliases=["USA_PASSPORT_NUMBER", "US_PASSPORT", "U.S. Passport Number"],
    ),
    "DRIVERS_LICENSE": EntityDefinition(
        type="DRIVERS_LICENSE",
        weight=8,
        category="direct_identifier",
        aliases=["USA_DRIVERS_LICENSE", "US_DRIVERS_LICENSE_NUMBER", "U.S. Driver's License Number"],
    ),

    # Financial (weight 7-9)
    "CREDIT_CARD": EntityDefinition(
        type="CREDIT_CARD",
        weight=8,
        category="financial",
        aliases=["CREDIT_CARD_NUMBER", "Credit Card Number"],
    ),
    "BANK_ACCOUNT": EntityDefinition(
        type="BANK_ACCOUNT",
        weight=7,
        category="financial",
        aliases=["BANK_ACCOUNT_NUMBER", "U.S. Bank Account Number"],
    ),

    # Credentials (weight 9-10)
    "AWS_ACCESS_KEY": EntityDefinition(
        type="AWS_ACCESS_KEY",
        weight=10,
        category="credential",
        aliases=["AWS_CREDENTIALS"],
    ),

    # Contact (weight 4-5)
    "EMAIL": EntityDefinition(
        type="EMAIL",
        weight=5,
        category="contact",
        aliases=["EMAIL_ADDRESS", "Email"],
    ),
    "PHONE": EntityDefinition(
        type="PHONE",
        weight=4,
        category="contact",
        aliases=["PHONE_NUMBER", "Phone Number"],
    ),

    # TODO: Load full registry (300+ entity types) from spec
}


def get_weight(entity_type: str) -> int:
    """Get weight for an entity type."""
    if entity_type in ENTITY_REGISTRY:
        return ENTITY_REGISTRY[entity_type].weight
    return 5  # Default weight for unknown types


def get_category(entity_type: str) -> str:
    """Get category for an entity type."""
    if entity_type in ENTITY_REGISTRY:
        return ENTITY_REGISTRY[entity_type].category
    return "unknown"


def normalize_type(vendor_type: str) -> str:
    """
    Normalize a vendor-specific entity type to canonical OpenLabels type.

    Args:
        vendor_type: Entity type from Macie, DLP, Purview, etc.

    Returns:
        Canonical OpenLabels entity type
    """
    # Check if it's already canonical
    if vendor_type in ENTITY_REGISTRY:
        return vendor_type

    # Search aliases
    for canonical, definition in ENTITY_REGISTRY.items():
        if vendor_type in definition.aliases:
            return canonical

    # Unknown type, return as-is
    return vendor_type
