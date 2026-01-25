"""
AWS Macie + S3 metadata adapter.

Converts Macie findings and S3 object metadata to OpenLabels normalized format.
"""

from typing import Dict, Any
from .base import Adapter, Entity, NormalizedContext, NormalizedInput


# Entity type mapping: Macie -> OpenLabels canonical types
ENTITY_MAP = {
    "AWS_CREDENTIALS": "AWS_ACCESS_KEY",
    "CREDIT_CARD_NUMBER": "CREDIT_CARD",
    "USA_SOCIAL_SECURITY_NUMBER": "SSN",
    "USA_PASSPORT_NUMBER": "PASSPORT",
    "USA_DRIVERS_LICENSE": "DRIVERS_LICENSE",
    "EMAIL_ADDRESS": "EMAIL",
    "NAME": "NAME",
    "PHONE_NUMBER": "PHONE",
    "ADDRESS": "ADDRESS",
    "DATE_OF_BIRTH": "DOB",
    "BANK_ACCOUNT_NUMBER": "BANK_ACCOUNT",
    "USA_INDIVIDUAL_TAX_IDENTIFICATION_NUMBER": "ITIN",
    "USA_EMPLOYER_IDENTIFICATION_NUMBER": "EIN",
    # TODO: Complete mapping for all Macie entity types
}


class MacieAdapter:
    """AWS Macie + S3 metadata adapter."""

    def extract(
        self,
        findings: Dict[str, Any],
        s3_metadata: Dict[str, Any],
    ) -> NormalizedInput:
        """
        Convert Macie findings + S3 metadata to normalized format.

        Args:
            findings: Macie findings JSON
            s3_metadata: S3 object/bucket metadata

        Returns:
            NormalizedInput ready for scoring
        """
        # TODO: Implement
        raise NotImplementedError("Macie adapter not yet implemented")

    def _severity_to_confidence(self, severity: str) -> float:
        """Map Macie severity to confidence score."""
        return {
            "High": 0.95,
            "Medium": 0.80,
            "Low": 0.65,
        }.get(severity, 0.75)

    def _normalize_s3_context(self, meta: Dict[str, Any]) -> NormalizedContext:
        """Convert S3 metadata to normalized context."""
        # TODO: Implement ACL -> exposure mapping
        raise NotImplementedError()
