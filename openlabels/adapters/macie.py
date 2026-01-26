"""
AWS Macie + S3 metadata adapter.

Converts Macie findings and S3 object metadata to OpenLabels normalized format.

Usage:
    >>> from openlabels.adapters.macie import MacieAdapter
    >>> adapter = MacieAdapter()
    >>> normalized = adapter.extract(macie_findings, s3_metadata)
    >>> # Feed to scorer
    >>> result = score(normalized.entities, normalized.context.exposure)
"""

from typing import Dict, Any, List, Optional

from .base import (
    Entity, NormalizedContext, NormalizedInput,
    ExposureLevel, calculate_staleness_days,
)

# Entity type mapping: Macie -> OpenLabels canonical types
ENTITY_MAP = {
    # Credentials
    "AWS_CREDENTIALS": "AWS_ACCESS_KEY",
    "OPENSSH_PRIVATE_KEY": "PRIVATE_KEY",
    "PGP_PRIVATE_KEY": "PRIVATE_KEY",
    "PKCS": "PRIVATE_KEY",

    # Financial
    "CREDIT_CARD_NUMBER": "CREDIT_CARD",
    "BANK_ACCOUNT_NUMBER": "BANK_ACCOUNT",

    # US Identifiers
    "USA_SOCIAL_SECURITY_NUMBER": "SSN",
    "USA_PASSPORT_NUMBER": "PASSPORT",
    "USA_DRIVERS_LICENSE": "DRIVERS_LICENSE",
    "USA_INDIVIDUAL_TAX_IDENTIFICATION_NUMBER": "ITIN",
    "USA_EMPLOYER_IDENTIFICATION_NUMBER": "EIN",
    "USA_HEALTH_INSURANCE_CLAIM_NUMBER": "HICN",
    "USA_MEDICARE_BENEFICIARY_IDENTIFIER": "MBI",
    "USA_NATIONAL_PROVIDER_IDENTIFIER": "NPI",
    "USA_DRUG_ENFORCEMENT_AGENCY_NUMBER": "DEA",
    "USA_NATIONAL_DRUG_CODE": "NDC",

    # Contact info
    "EMAIL_ADDRESS": "EMAIL",
    "PHONE_NUMBER": "PHONE",
    "ADDRESS": "ADDRESS",
    "NAME": "NAME",

    # Dates
    "DATE_OF_BIRTH": "DOB",

    # Vehicle
    "VEHICLE_IDENTIFICATION_NUMBER": "VIN",

    # International
    "CA_SOCIAL_INSURANCE_NUMBER": "SIN_CA",
    "CA_HEALTH_NUMBER": "HEALTH_NUMBER_CA",
    "UK_NATIONAL_INSURANCE_NUMBER": "NINO_UK",
    "UK_NATIONAL_HEALTH_SERVICE_NUMBER": "NHS_UK",
    "UK_UNIQUE_TAXPAYER_REFERENCE": "UTR_UK",
    "FRANCE_NATIONAL_IDENTIFICATION_NUMBER": "INSEE_FR",
    "GERMANY_NATIONAL_IDENTIFICATION_NUMBER": "PERSONALAUSWEIS_DE",
    "ITALY_NATIONAL_IDENTIFICATION_NUMBER": "CODICE_FISCALE_IT",
    "SPAIN_NATIONAL_IDENTIFICATION_NUMBER": "DNI_ES",
    "BRAZIL_CPF_NUMBER": "CPF_BR",
}

# Entity weights (from registry, subset for quick lookup)
ENTITY_WEIGHTS = {
    "SSN": 10,
    "CREDIT_CARD": 10,
    "PASSPORT": 9,
    "DRIVERS_LICENSE": 8,
    "BANK_ACCOUNT": 8,
    "AWS_ACCESS_KEY": 10,
    "PRIVATE_KEY": 10,
    "EMAIL": 3,
    "PHONE": 3,
    "NAME": 4,
    "ADDRESS": 5,
    "DOB": 6,
    "NPI": 6,
    "DEA": 7,
    "MBI": 7,
    "HICN": 7,
    "VIN": 5,
}

DEFAULT_WEIGHT = 5


class MacieAdapter:
    """
    AWS Macie + S3 metadata adapter.

    Converts Macie findings to normalized entities and S3 bucket/object
    metadata to normalized context for risk scoring.
    """

    def extract(
        self,
        findings: Dict[str, Any],
        s3_metadata: Dict[str, Any],
    ) -> NormalizedInput:
        """
        Convert Macie findings + S3 metadata to normalized format.

        Args:
            findings: Macie findings JSON (from GetFindings API or S3 event)
                Expected structure:
                {
                    "findings": [
                        {
                            "type": "SensitiveData:S3Object/Personal",
                            "severity": {"score": 3},
                            "classificationDetails": {
                                "result": {
                                    "sensitiveData": [
                                        {
                                            "category": "PERSONAL_INFORMATION",
                                            "detections": [
                                                {"type": "USA_SOCIAL_SECURITY_NUMBER", "count": 5}
                                            ]
                                        }
                                    ]
                                }
                            }
                        }
                    ]
                }
            s3_metadata: S3 object/bucket metadata
                Expected structure:
                {
                    "bucket": "my-bucket",
                    "key": "path/to/file.csv",
                    "size": 1024,
                    "last_modified": "2024-01-15T10:30:00Z",
                    "content_type": "text/csv",
                    "acl": "private",
                    "public_access_block": True,
                    "encryption": "AES256" | "aws:kms" | None,
                    "versioning": "Enabled" | "Suspended" | None,
                    "logging_enabled": True | False,
                    "cross_account": False,
                    "owner": "123456789012"
                }

        Returns:
            NormalizedInput ready for scoring
        """
        entities = self._extract_entities(findings)
        context = self._normalize_s3_context(s3_metadata)
        return NormalizedInput(entities=entities, context=context)

    def _extract_entities(self, findings: Dict[str, Any]) -> List[Entity]:
        """Extract entities from Macie findings."""
        entities = []
        seen_types: Dict[str, Entity] = {}

        for finding in findings.get("findings", []):
            severity = finding.get("severity", {})
            severity_score = severity.get("score", 2) if isinstance(severity, dict) else 2

            # Get classification details
            class_details = finding.get("classificationDetails", {})
            result = class_details.get("result", {})
            sensitive_data = result.get("sensitiveData", [])

            for category_data in sensitive_data:
                detections = category_data.get("detections", [])

                for detection in detections:
                    macie_type = detection.get("type", "UNKNOWN")
                    count = detection.get("count", 1)

                    # Map to canonical type
                    entity_type = ENTITY_MAP.get(macie_type, macie_type)
                    confidence = self._severity_to_confidence(severity_score)
                    weight = ENTITY_WEIGHTS.get(entity_type, DEFAULT_WEIGHT)

                    # Aggregate by type
                    if entity_type in seen_types:
                        existing = seen_types[entity_type]
                        seen_types[entity_type] = Entity(
                            type=entity_type,
                            count=existing.count + count,
                            confidence=max(existing.confidence, confidence),
                            weight=weight,
                            source="macie",
                        )
                    else:
                        seen_types[entity_type] = Entity(
                            type=entity_type,
                            count=count,
                            confidence=confidence,
                            weight=weight,
                            source="macie",
                        )

        return list(seen_types.values())

    def _severity_to_confidence(self, severity_score: int) -> float:
        """
        Map Macie severity score to confidence.

        Macie severity scores: 1 (Low) to 4 (High)
        """
        return {
            1: 0.65,  # Low
            2: 0.75,  # Medium
            3: 0.85,  # High
            4: 0.95,  # Critical
        }.get(severity_score, 0.75)

    def _normalize_s3_context(self, meta: Dict[str, Any]) -> NormalizedContext:
        """Convert S3 metadata to normalized context."""
        # Determine exposure level
        exposure = self._determine_exposure(meta)

        # Normalize encryption
        encryption = self._normalize_encryption(meta.get("encryption"))

        # Calculate staleness
        last_modified = meta.get("last_modified")
        staleness = calculate_staleness_days(last_modified)

        return NormalizedContext(
            # Exposure
            exposure=exposure.name,
            cross_account_access=meta.get("cross_account", False),
            anonymous_access=(exposure == ExposureLevel.PUBLIC),

            # Protection
            encryption=encryption,
            versioning=(meta.get("versioning") == "Enabled"),
            access_logging=meta.get("logging_enabled", False),
            retention_policy=meta.get("object_lock", False),

            # Staleness
            last_modified=last_modified,
            last_accessed=meta.get("last_accessed"),
            staleness_days=staleness,

            # Classification
            has_classification=True,
            classification_source="macie",

            # File info
            path=f"s3://{meta.get('bucket', '')}/{meta.get('key', '')}",
            owner=meta.get("owner"),
            size_bytes=meta.get("size", 0),
            file_type=meta.get("content_type", ""),
            is_archive=self._is_archive(meta.get("key", "")),
        )

    def _determine_exposure(self, meta: Dict[str, Any]) -> ExposureLevel:
        """Determine exposure level from S3 ACL and public access settings."""
        # Check public access block first
        public_block = meta.get("public_access_block", True)
        if public_block is False or public_block == "False":
            acl = meta.get("acl", "private").lower()

            if "public-read" in acl or "public-read-write" in acl:
                return ExposureLevel.PUBLIC

            if "authenticated-read" in acl:
                return ExposureLevel.ORG_WIDE

        # Check bucket policy for public access
        if meta.get("bucket_policy_public", False):
            return ExposureLevel.PUBLIC

        # Check for cross-account access
        if meta.get("cross_account", False):
            return ExposureLevel.ORG_WIDE

        # Check ACL grants
        acl = meta.get("acl", "private").lower()
        if acl == "private" or acl == "bucket-owner-full-control":
            return ExposureLevel.PRIVATE

        return ExposureLevel.INTERNAL

    def _normalize_encryption(self, enc: Optional[str]) -> str:
        """Normalize S3 encryption to standard format."""
        if not enc:
            return "none"
        enc_lower = enc.lower()
        if "aws:kms" in enc_lower or "kms" in enc_lower:
            return "customer_managed"
        if "aes256" in enc_lower or "sse-s3" in enc_lower:
            return "platform"
        return "platform"

    def _is_archive(self, key: str) -> bool:
        """Check if file is an archive based on extension."""
        archive_exts = {'.zip', '.tar', '.gz', '.tgz', '.tar.gz', '.7z', '.rar', '.bz2'}
        key_lower = key.lower()
        return any(key_lower.endswith(ext) for ext in archive_exts)


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def from_macie_finding(finding: Dict[str, Any], s3_meta: Dict[str, Any]) -> NormalizedInput:
    """
    Convert a single Macie finding to normalized input.

    Args:
        finding: Single Macie finding dict
        s3_meta: S3 metadata dict

    Returns:
        NormalizedInput
    """
    adapter = MacieAdapter()
    return adapter.extract({"findings": [finding]}, s3_meta)


def from_macie_job_result(job_result: Dict[str, Any]) -> List[NormalizedInput]:
    """
    Convert Macie job results to list of normalized inputs.

    Args:
        job_result: Macie classification job result

    Returns:
        List of NormalizedInput, one per affected object
    """
    adapter = MacieAdapter()
    results = []

    for finding in job_result.get("findings", []):
        # Extract S3 location from finding
        resources = finding.get("resourcesAffected", {})
        s3_object = resources.get("s3Object", {})
        s3_bucket = resources.get("s3Bucket", {})

        s3_meta = {
            "bucket": s3_bucket.get("name", ""),
            "key": s3_object.get("key", ""),
            "size": s3_object.get("size", 0),
            "last_modified": s3_object.get("lastModified"),
            "public_access_block": s3_bucket.get("publicAccess", {}).get("effectivePermission") != "PUBLIC",
            "encryption": s3_object.get("serverSideEncryption", {}).get("encryptionType"),
            "owner": s3_bucket.get("owner", {}).get("id"),
        }

        normalized = adapter.extract({"findings": [finding]}, s3_meta)
        results.append(normalized)

    return results
