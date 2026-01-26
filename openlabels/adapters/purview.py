"""
Azure Purview + Blob metadata adapter.

Converts Purview classifications and Azure Blob metadata to OpenLabels normalized format.

Usage:
    >>> from openlabels.adapters.purview import PurviewAdapter
    >>> adapter = PurviewAdapter()
    >>> normalized = adapter.extract(purview_classifications, blob_metadata)
    >>> result = score(normalized.entities, normalized.context.exposure)
"""

from typing import Dict, Any, List, Optional

from .base import (
    Entity, NormalizedContext, NormalizedInput,
    ExposureLevel, calculate_staleness_days, is_archive,
)

# Entity type mapping: Purview classification -> OpenLabels canonical types
ENTITY_MAP = {
    # US Identifiers
    "U.S. Social Security Number (SSN)": "SSN",
    "U.S. / U.K. Passport Number": "PASSPORT",
    "U.S. Driver's License Number": "DRIVERS_LICENSE",
    "U.S. Individual Taxpayer Identification Number (ITIN)": "ITIN",

    # Financial
    "Credit Card Number": "CREDIT_CARD",
    "U.S. Bank Account Number": "BANK_ACCOUNT",
    "International Banking Account Number (IBAN)": "IBAN",
    "SWIFT Code": "SWIFT",
    "ABA Routing Number": "BANK_ROUTING",

    # Contact
    "Email": "EMAIL",
    "Phone Number": "PHONE",
    "Person's Name": "NAME",
    "All Full Names": "NAME",
    "Address": "ADDRESS",
    "Physical Addresses": "ADDRESS",

    # Dates
    "Date of Birth": "DOB",
    "EU Date of Birth": "DOB",

    # Health
    "U.S. Health Insurance Claim Number (HICN)": "HICN",
    "Drug Enforcement Agency (DEA) Number": "DEA",
    "National Provider Index (NPI)": "NPI",

    # Credentials/Secrets
    "Azure Storage Account Key": "AZURE_STORAGE_KEY",
    "Azure SQL Connection String": "AZURE_SQL_CONNECTION",
    "Azure Service Bus Connection String": "AZURE_SERVICE_BUS_KEY",
    "Azure Cosmos DB Connection String": "AZURE_COSMOS_KEY",
    "Azure DocumentDB Auth Key": "AZURE_DOCDB_KEY",
    "Azure IoT Hub Connection String": "AZURE_IOT_KEY",
    "Azure Redis Cache Connection String": "AZURE_REDIS_KEY",
    "Azure Shared Access Signature": "AZURE_SAS",
    "Password": "PASSWORD",
    "Generic Secret": "SECRET",
    "Http Authorization Header": "AUTH_HEADER",

    # International
    "Canada Social Insurance Number": "SIN_CA",
    "Canada Health Service Number": "HEALTH_NUMBER_CA",
    "U.K. National Insurance Number (NINO)": "NINO_UK",
    "U.K. National Health Service Number": "NHS_UK",
    "France National ID Card (CNI)": "CNI_FR",
    "France Social Security Number (INSEE)": "INSEE_FR",
    "Germany Identity Card Number": "PERSONALAUSWEIS_DE",
    "Germany Driver's License Number": "DRIVERS_LICENSE_DE",
    "Italy Fiscal Code": "CODICE_FISCALE_IT",
    "Spain DNI": "DNI_ES",
    "Spain Social Security Number": "SSN_ES",
    "Brazil CPF Number": "CPF_BR",
    "Brazil Legal Entity Number (CNPJ)": "CNPJ_BR",
    "Japan My Number": "MY_NUMBER_JP",
    "Japan Residence Card Number": "RESIDENCE_CARD_JP",
    "China Resident Identity Card Number": "RESIDENT_ID_CN",
    "India Unique Identification (Aadhaar)": "AADHAAR_IN",
    "India Permanent Account Number (PAN)": "PAN_IN",
    "Australia Tax File Number": "TFN_AU",
    "Australia Medicare Number": "MEDICARE_AU",
    "Australia Business Number": "ABN_AU",
    "New Zealand Ministry of Health Number": "NHI_NZ",
    "South Africa Identification Number": "ID_ZA",

    # Network
    "IP Address": "IP_ADDRESS",
    "IPv4 Address": "IP_ADDRESS",
    "IPv6 Address": "IP_ADDRESS",
    "MAC Address": "MAC_ADDRESS",
    "URL": "URL",
}

class PurviewAdapter:
    """
    Azure Purview + Blob metadata adapter.

    Converts Purview classifications to normalized entities and Azure Blob
    metadata to normalized context for risk scoring.
    """

    def extract(
        self,
        classifications: Dict[str, Any],
        blob_metadata: Dict[str, Any],
    ) -> NormalizedInput:
        """
        Convert Purview classifications + Blob metadata to normalized format.

        Args:
            classifications: Purview classifications JSON
                Expected structure:
                {
                    "classifications": [
                        {
                            "typeName": "MICROSOFT.PERSONAL.US.SOCIAL_SECURITY_NUMBER",
                            "attributes": {"confidence": 0.95, "count": 5}
                        }
                    ]
                }
                OR
                {
                    "scanResult": {
                        "classifications": [
                            {"classificationName": "Credit Card Number", "count": 3}
                        ]
                    }
                }
            blob_metadata: Azure Blob/container metadata
                Expected structure:
                {
                    "container": "my-container",
                    "name": "path/to/file.csv",
                    "properties": {
                        "content_length": 1024,
                        "last_modified": "2024-01-15T10:30:00Z",
                        "content_type": "text/csv",
                        "blob_tier": "Hot"
                    },
                    "access_level": "private",  # private, blob, container
                    "encryption": {"key_source": "Microsoft.Storage"},
                    "versioning_enabled": true,
                    "soft_delete_enabled": true
                }

        Returns:
            NormalizedInput ready for scoring
        """
        entities = self._extract_entities(classifications)
        context = self._normalize_blob_context(blob_metadata)
        return NormalizedInput(entities=entities, context=context)

    def _extract_entities(self, classifications: Dict[str, Any]) -> List[Entity]:
        """Extract entities from Purview classifications."""
        seen_types: Dict[str, Dict] = {}

        # Handle multiple classification formats
        class_list = classifications.get("classifications", [])
        if not class_list and "scanResult" in classifications:
            class_list = classifications.get("scanResult", {}).get("classifications", [])

        for classification in class_list:
            # Get classification name (different formats)
            purview_type = (
                classification.get("classificationName") or
                classification.get("typeName", "UNKNOWN")
            )

            # Normalize Purview internal type names
            purview_type = self._normalize_type_name(purview_type)

            # Get count and confidence
            attrs = classification.get("attributes", {})
            count = classification.get("count", attrs.get("count", 1))
            confidence = attrs.get("confidence", 0.85)

            # Map to canonical type
            entity_type = ENTITY_MAP.get(purview_type, purview_type)

            # Aggregate by type
            if entity_type in seen_types:
                seen_types[entity_type]["count"] += count
                seen_types[entity_type]["confidence"] = max(
                    seen_types[entity_type]["confidence"], confidence
                )
            else:
                seen_types[entity_type] = {
                    "count": count,
                    "confidence": confidence,
                }

        return [
            Entity(
                type=etype,
                count=data["count"],
                confidence=data["confidence"],
                source="purview",
            )
            for etype, data in seen_types.items()
        ]

    def _normalize_type_name(self, type_name: str) -> str:
        """Normalize Purview internal type names to display names."""
        # Handle MICROSOFT.PERSONAL.* format
        if type_name.startswith("MICROSOFT."):
            # Convert MICROSOFT.PERSONAL.US.SOCIAL_SECURITY_NUMBER
            # to "U.S. Social Security Number (SSN)"
            mapping = {
                "MICROSOFT.PERSONAL.US.SOCIAL_SECURITY_NUMBER": "U.S. Social Security Number (SSN)",
                "MICROSOFT.FINANCIAL.CREDIT_CARD_NUMBER": "Credit Card Number",
                "MICROSOFT.PERSONAL.EMAIL": "Email",
                "MICROSOFT.PERSONAL.PHONE_NUMBER": "Phone Number",
                "MICROSOFT.PERSONAL.NAME": "Person's Name",
                "MICROSOFT.PERSONAL.DATE_OF_BIRTH": "Date of Birth",
                "MICROSOFT.PERSONAL.ADDRESS": "Address",
                "MICROSOFT.PERSONAL.IPADDRESS": "IP Address",
            }
            return mapping.get(type_name, type_name)
        return type_name

    def _normalize_blob_context(self, meta: Dict[str, Any]) -> NormalizedContext:
        """Convert Azure Blob metadata to normalized context."""
        # Determine exposure from access level
        exposure = self._determine_exposure(meta)

        # Get properties
        props = meta.get("properties", {})

        # Normalize encryption
        encryption = self._normalize_encryption(meta.get("encryption"))

        # Calculate staleness
        last_modified = props.get("last_modified")
        staleness = calculate_staleness_days(last_modified)

        return NormalizedContext(
            # Exposure
            exposure=exposure.name,
            cross_account_access=meta.get("cross_tenant_access", False),
            anonymous_access=(exposure == ExposureLevel.PUBLIC),

            # Protection
            encryption=encryption,
            versioning=meta.get("versioning_enabled", False),
            access_logging=meta.get("analytics_logging", {}).get("read", False),
            retention_policy=meta.get("soft_delete_enabled", False),

            # Staleness
            last_modified=last_modified,
            last_accessed=props.get("last_accessed"),
            staleness_days=staleness,

            # Classification
            has_classification=True,
            classification_source="purview",

            # File info
            path=f"azure://{meta.get('container', '')}/{meta.get('name', '')}",
            owner=meta.get("owner"),
            size_bytes=props.get("content_length", 0),
            file_type=props.get("content_type", ""),
            is_archive=is_archive(meta.get("name", "")),
        )

    def _determine_exposure(self, meta: Dict[str, Any]) -> ExposureLevel:
        """Determine exposure from Azure Blob access level."""
        access_level = meta.get("access_level", "private").lower()

        # Container-level access = public
        if access_level == "container":
            return ExposureLevel.PUBLIC

        # Blob-level access = semi-public
        if access_level == "blob":
            return ExposureLevel.ORG_WIDE

        # Check for SAS tokens that allow public access
        if meta.get("has_public_sas", False):
            return ExposureLevel.PUBLIC

        # Check network rules
        network_rules = meta.get("network_rules", {})
        if network_rules.get("default_action") == "Allow":
            return ExposureLevel.ORG_WIDE

        return ExposureLevel.PRIVATE

    def _normalize_encryption(self, encryption: Optional[Dict]) -> str:
        """Normalize Azure Blob encryption."""
        if not encryption:
            return "platform"  # Azure has default encryption

        key_source = encryption.get("key_source", "")
        if "keyvault" in key_source.lower() or key_source == "Microsoft.KeyVault":
            return "customer_managed"

        return "platform"


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def from_purview_scan(scan_result: Dict[str, Any], blob_meta: Dict[str, Any]) -> NormalizedInput:
    """Convert Purview scan result to normalized input."""
    adapter = PurviewAdapter()
    return adapter.extract(scan_result, blob_meta)
