"""
GCP DLP + GCS metadata adapter.

Converts GCP DLP inspection results and GCS object metadata to OpenLabels normalized format.

Usage:
    >>> from openlabels.adapters.dlp import DLPAdapter
    >>> adapter = DLPAdapter()
    >>> normalized = adapter.extract(dlp_findings, gcs_metadata)
    >>> result = score(normalized.entities, normalized.context.exposure)
"""

from typing import Dict, Any, List, Optional

from .base import (
    Entity, NormalizedContext, NormalizedInput,
    ExposureLevel, calculate_staleness_days,
)

# Entity type mapping: GCP DLP infoType -> OpenLabels canonical types
ENTITY_MAP = {
    # US Identifiers
    "US_SOCIAL_SECURITY_NUMBER": "SSN",
    "US_PASSPORT": "PASSPORT",
    "US_DRIVERS_LICENSE_NUMBER": "DRIVERS_LICENSE",
    "US_INDIVIDUAL_TAXPAYER_IDENTIFICATION_NUMBER": "ITIN",
    "US_EMPLOYER_IDENTIFICATION_NUMBER": "EIN",
    "US_HEALTHCARE_NPI": "NPI",
    "US_DEA_NUMBER": "DEA",

    # Financial
    "CREDIT_CARD_NUMBER": "CREDIT_CARD",
    "CREDIT_CARD_TRACK_NUMBER": "CREDIT_CARD",
    "US_BANK_ROUTING_MICR": "BANK_ROUTING",
    "IBAN_CODE": "IBAN",
    "SWIFT_CODE": "SWIFT",
    "FINANCIAL_ACCOUNT_NUMBER": "BANK_ACCOUNT",

    # Contact
    "EMAIL_ADDRESS": "EMAIL",
    "PHONE_NUMBER": "PHONE",
    "PERSON_NAME": "NAME",
    "FIRST_NAME": "NAME",
    "LAST_NAME": "NAME",
    "STREET_ADDRESS": "ADDRESS",

    # Dates
    "DATE_OF_BIRTH": "DOB",
    "DATE": "DATE",
    "TIME": "TIME",

    # Health
    "US_MEDICARE_BENEFICIARY_ID_NUMBER": "MBI",

    # Credentials
    "GCP_CREDENTIALS": "GCP_CREDENTIALS",
    "AWS_CREDENTIALS": "AWS_ACCESS_KEY",
    "AZURE_AUTH_TOKEN": "AZURE_AUTH_TOKEN",
    "AUTH_TOKEN": "AUTH_TOKEN",
    "ENCRYPTION_KEY": "ENCRYPTION_KEY",
    "PASSWORD": "PASSWORD",
    "XSRF_TOKEN": "XSRF_TOKEN",
    "HTTP_COOKIE": "HTTP_COOKIE",
    "JSON_WEB_TOKEN": "JWT",

    # International
    "CANADA_SOCIAL_INSURANCE_NUMBER": "SIN_CA",
    "CANADA_BC_PHN": "HEALTH_NUMBER_CA",
    "CANADA_OHIP": "HEALTH_NUMBER_CA",
    "CANADA_PASSPORT": "PASSPORT_CA",
    "UK_NATIONAL_INSURANCE_NUMBER": "NINO_UK",
    "UK_NHS_NUMBER": "NHS_UK",
    "UK_PASSPORT": "PASSPORT_UK",
    "UK_TAXPAYER_REFERENCE": "UTR_UK",
    "FRANCE_CNI": "CNI_FR",
    "FRANCE_NIR": "INSEE_FR",
    "FRANCE_PASSPORT": "PASSPORT_FR",
    "GERMANY_IDENTITY_CARD_NUMBER": "PERSONALAUSWEIS_DE",
    "GERMANY_PASSPORT": "PASSPORT_DE",
    "ITALY_FISCAL_CODE": "CODICE_FISCALE_IT",
    "SPAIN_DNI_NUMBER": "DNI_ES",
    "SPAIN_NIE_NUMBER": "NIE_ES",
    "BRAZIL_CPF_NUMBER": "CPF_BR",
    "JAPAN_MY_NUMBER": "MY_NUMBER_JP",
    "CHINA_RESIDENT_ID_NUMBER": "RESIDENT_ID_CN",
    "INDIA_AADHAAR_INDIVIDUAL": "AADHAAR_IN",
    "INDIA_PAN_INDIVIDUAL": "PAN_IN",
    "AUSTRALIA_TAX_FILE_NUMBER": "TFN_AU",
    "AUSTRALIA_MEDICARE_NUMBER": "MEDICARE_AU",
    "MEXICO_CURP_NUMBER": "CURP_MX",

    # Network/Technical
    "IP_ADDRESS": "IP_ADDRESS",
    "MAC_ADDRESS": "MAC_ADDRESS",
    "IMEI_HARDWARE_ID": "IMEI",
    "URL": "URL",
    "DOMAIN_NAME": "DOMAIN",

    # Vehicle
    "VEHICLE_IDENTIFICATION_NUMBER": "VIN",

    # Generic
    "AGE": "AGE",
    "GENDER": "GENDER",
    "ETHNIC_GROUP": "ETHNICITY",
    "LOCATION": "LOCATION",
}

# Entity weights
ENTITY_WEIGHTS = {
    "SSN": 10, "CREDIT_CARD": 10, "PASSPORT": 9, "DRIVERS_LICENSE": 8,
    "BANK_ACCOUNT": 8, "IBAN": 8, "GCP_CREDENTIALS": 10, "AWS_ACCESS_KEY": 10,
    "PASSWORD": 10, "JWT": 9, "EMAIL": 3, "PHONE": 3, "NAME": 4,
    "ADDRESS": 5, "DOB": 6, "NPI": 6, "DEA": 7, "MBI": 7, "AADHAAR_IN": 10,
}

DEFAULT_WEIGHT = 5


class DLPAdapter:
    """
    GCP DLP + GCS metadata adapter.

    Converts DLP inspection results to normalized entities and GCS bucket/object
    metadata to normalized context for risk scoring.
    """

    def extract(
        self,
        findings: Dict[str, Any],
        gcs_metadata: Dict[str, Any],
    ) -> NormalizedInput:
        """
        Convert DLP findings + GCS metadata to normalized format.

        Args:
            findings: DLP inspection results JSON
                Expected structure:
                {
                    "result": {
                        "findings": [
                            {
                                "infoType": {"name": "US_SOCIAL_SECURITY_NUMBER"},
                                "likelihood": "VERY_LIKELY",
                                "location": {...},
                                "quote": "..."
                            }
                        ]
                    }
                }
            gcs_metadata: GCS object/bucket metadata
                Expected structure:
                {
                    "bucket": "my-bucket",
                    "name": "path/to/file.csv",
                    "size": 1024,
                    "updated": "2024-01-15T10:30:00Z",
                    "contentType": "text/csv",
                    "iam_policy": {
                        "bindings": [
                            {"role": "roles/storage.objectViewer", "members": ["allUsers"]}
                        ]
                    },
                    "encryption": {"defaultKmsKeyName": "..."},
                    "versioning": {"enabled": true},
                    "logging": {"logBucket": "..."},
                    "retentionPolicy": {...}
                }

        Returns:
            NormalizedInput ready for scoring
        """
        entities = self._extract_entities(findings)
        context = self._normalize_gcs_context(gcs_metadata)
        return NormalizedInput(entities=entities, context=context)

    def _extract_entities(self, findings: Dict[str, Any]) -> List[Entity]:
        """Extract entities from DLP findings."""
        seen_types: Dict[str, Dict] = {}

        # Handle both direct findings array and nested result.findings
        findings_list = findings.get("findings", [])
        if not findings_list and "result" in findings:
            findings_list = findings.get("result", {}).get("findings", [])

        for finding in findings_list:
            info_type = finding.get("infoType", {})
            dlp_type = info_type.get("name", "UNKNOWN")
            likelihood = finding.get("likelihood", "POSSIBLE")

            # Map to canonical type
            entity_type = ENTITY_MAP.get(dlp_type, dlp_type)
            confidence = self._likelihood_to_confidence(likelihood)
            weight = ENTITY_WEIGHTS.get(entity_type, DEFAULT_WEIGHT)

            # Aggregate by type (DLP reports each occurrence separately)
            if entity_type in seen_types:
                seen_types[entity_type]["count"] += 1
                seen_types[entity_type]["confidence"] = max(
                    seen_types[entity_type]["confidence"], confidence
                )
            else:
                seen_types[entity_type] = {
                    "count": 1,
                    "confidence": confidence,
                    "weight": weight,
                }

        return [
            Entity(
                type=etype,
                count=data["count"],
                confidence=data["confidence"],
                weight=data["weight"],
                source="dlp",
            )
            for etype, data in seen_types.items()
        ]

    def _likelihood_to_confidence(self, likelihood: str) -> float:
        """Map DLP likelihood to confidence score."""
        return {
            "VERY_LIKELY": 0.95,
            "LIKELY": 0.85,
            "POSSIBLE": 0.70,
            "UNLIKELY": 0.50,
            "VERY_UNLIKELY": 0.30,
            "LIKELIHOOD_UNSPECIFIED": 0.60,
        }.get(likelihood, 0.70)

    def _normalize_gcs_context(self, meta: Dict[str, Any]) -> NormalizedContext:
        """Convert GCS metadata to normalized context."""
        # Determine exposure from IAM policy
        exposure = self._determine_exposure(meta)

        # Normalize encryption
        encryption = self._normalize_encryption(meta.get("encryption"))

        # Calculate staleness
        last_modified = meta.get("updated") or meta.get("timeCreated")
        staleness = calculate_staleness_days(last_modified)

        return NormalizedContext(
            # Exposure
            exposure=exposure.name,
            cross_account_access=self._has_cross_project_access(meta),
            anonymous_access=(exposure == ExposureLevel.PUBLIC),

            # Protection
            encryption=encryption,
            versioning=meta.get("versioning", {}).get("enabled", False),
            access_logging=meta.get("logging", {}).get("logBucket") is not None,
            retention_policy=meta.get("retentionPolicy") is not None,

            # Staleness
            last_modified=last_modified,
            last_accessed=None,  # GCS doesn't track this
            staleness_days=staleness,

            # Classification
            has_classification=True,
            classification_source="dlp",

            # File info
            path=f"gs://{meta.get('bucket', '')}/{meta.get('name', '')}",
            owner=meta.get("owner", {}).get("entity") if isinstance(meta.get("owner"), dict) else meta.get("owner"),
            size_bytes=int(meta.get("size", 0)),
            file_type=meta.get("contentType", ""),
            is_archive=self._is_archive(meta.get("name", "")),
        )

    def _determine_exposure(self, meta: Dict[str, Any]) -> ExposureLevel:
        """Determine exposure from GCS IAM policy."""
        iam_policy = meta.get("iam_policy", {})
        bindings = iam_policy.get("bindings", [])

        for binding in bindings:
            members = binding.get("members", [])
            if "allUsers" in members:
                return ExposureLevel.PUBLIC
            if "allAuthenticatedUsers" in members:
                return ExposureLevel.ORG_WIDE

        # Check for uniform bucket-level access
        if meta.get("iamConfiguration", {}).get("publicAccessPrevention") == "enforced":
            return ExposureLevel.PRIVATE

        # Check ACL if present
        acl = meta.get("acl", [])
        for entry in acl:
            entity = entry.get("entity", "")
            if entity == "allUsers":
                return ExposureLevel.PUBLIC
            if entity == "allAuthenticatedUsers":
                return ExposureLevel.ORG_WIDE

        return ExposureLevel.PRIVATE

    def _has_cross_project_access(self, meta: Dict[str, Any]) -> bool:
        """Check if IAM policy grants cross-project access."""
        iam_policy = meta.get("iam_policy", {})
        bindings = iam_policy.get("bindings", [])
        bucket_project = meta.get("projectNumber", "")

        for binding in bindings:
            for member in binding.get("members", []):
                # Check for service accounts from other projects
                if "serviceAccount:" in member and bucket_project:
                    # Extract project from service account
                    if f"@{bucket_project}" not in member:
                        return True
        return False

    def _normalize_encryption(self, encryption: Optional[Dict]) -> str:
        """Normalize GCS encryption."""
        if not encryption:
            return "platform"  # GCS has default encryption
        if encryption.get("defaultKmsKeyName"):
            return "customer_managed"
        return "platform"

    def _is_archive(self, name: str) -> bool:
        """Check if file is an archive."""
        archive_exts = {'.zip', '.tar', '.gz', '.tgz', '.tar.gz', '.7z', '.rar', '.bz2'}
        return any(name.lower().endswith(ext) for ext in archive_exts)


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def from_dlp_inspect_result(result: Dict[str, Any], gcs_meta: Dict[str, Any]) -> NormalizedInput:
    """Convert DLP inspection result to normalized input."""
    adapter = DLPAdapter()
    return adapter.extract(result, gcs_meta)
