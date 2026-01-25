"""
GCP DLP + GCS metadata adapter.

Converts GCP DLP inspection results and GCS object metadata to OpenLabels normalized format.
"""

from typing import Dict, Any
from .base import Adapter, Entity, NormalizedContext, NormalizedInput


# Entity type mapping: GCP DLP -> OpenLabels canonical types
ENTITY_MAP = {
    "CREDIT_CARD_NUMBER": "CREDIT_CARD",
    "US_SOCIAL_SECURITY_NUMBER": "SSN",
    "EMAIL_ADDRESS": "EMAIL",
    "PHONE_NUMBER": "PHONE",
    "PERSON_NAME": "NAME",
    "STREET_ADDRESS": "ADDRESS",
    "DATE_OF_BIRTH": "DOB",
    "US_PASSPORT": "PASSPORT",
    "US_DRIVERS_LICENSE_NUMBER": "DRIVERS_LICENSE",
    "US_BANK_ROUTING_MICR": "BANK_ROUTING",
    "US_INDIVIDUAL_TAXPAYER_IDENTIFICATION_NUMBER": "ITIN",
    "US_EMPLOYER_IDENTIFICATION_NUMBER": "EIN",
    "GCP_CREDENTIALS": "GCP_CREDENTIALS",
    # TODO: Complete mapping for all DLP infoTypes
}


class DLPAdapter:
    """GCP DLP + GCS metadata adapter."""

    def extract(
        self,
        findings: Dict[str, Any],
        gcs_metadata: Dict[str, Any],
    ) -> NormalizedInput:
        """
        Convert DLP findings + GCS metadata to normalized format.

        Args:
            findings: DLP inspection results JSON
            gcs_metadata: GCS object/bucket metadata

        Returns:
            NormalizedInput ready for scoring
        """
        # TODO: Implement
        raise NotImplementedError("GCP DLP adapter not yet implemented")

    def _likelihood_to_confidence(self, likelihood: str) -> float:
        """Map DLP likelihood to confidence score."""
        return {
            "VERY_LIKELY": 0.95,
            "LIKELY": 0.85,
            "POSSIBLE": 0.70,
            "UNLIKELY": 0.50,
            "VERY_UNLIKELY": 0.30,
        }.get(likelihood, 0.75)

    def _normalize_gcs_context(self, meta: Dict[str, Any]) -> NormalizedContext:
        """Convert GCS metadata to normalized context."""
        # TODO: Implement IAM -> exposure mapping
        raise NotImplementedError()
