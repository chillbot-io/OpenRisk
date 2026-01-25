"""
Azure Purview + Blob metadata adapter.

Converts Purview classifications and Azure Blob metadata to OpenLabels normalized format.
"""

from typing import Dict, Any
from .base import Adapter, Entity, NormalizedContext, NormalizedInput


# Entity type mapping: Purview -> OpenLabels canonical types
ENTITY_MAP = {
    "Credit Card Number": "CREDIT_CARD",
    "U.S. Social Security Number (SSN)": "SSN",
    "Email": "EMAIL",
    "Phone Number": "PHONE",
    "Person's Name": "NAME",
    "Address": "ADDRESS",
    "Date of Birth": "DOB",
    "U.S. Passport Number": "PASSPORT",
    "U.S. Driver's License Number": "DRIVERS_LICENSE",
    "U.S. Bank Account Number": "BANK_ACCOUNT",
    "Azure Storage Account Key": "AZURE_STORAGE_KEY",
    "Azure SQL Connection String": "AZURE_SQL_CONNECTION",
    # TODO: Complete mapping for all Purview classification types
}


class PurviewAdapter:
    """Azure Purview + Blob metadata adapter."""

    def extract(
        self,
        classifications: Dict[str, Any],
        blob_metadata: Dict[str, Any],
    ) -> NormalizedInput:
        """
        Convert Purview classifications + Blob metadata to normalized format.

        Args:
            classifications: Purview classifications JSON
            blob_metadata: Blob/container metadata

        Returns:
            NormalizedInput ready for scoring
        """
        # TODO: Implement
        raise NotImplementedError("Purview adapter not yet implemented")

    def _normalize_blob_context(self, meta: Dict[str, Any]) -> NormalizedContext:
        """Convert Blob metadata to normalized context."""
        # TODO: Implement access tier -> exposure mapping
        raise NotImplementedError()
