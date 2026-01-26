"""
OpenLabels Adapter Protocol.

All adapters implement this interface and produce normalized output
that can be fed into the scoring engine.
"""

from typing import Protocol, List, Any, Optional, Tuple, Dict
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class ExposureLevel(Enum):
    """
    Normalized exposure levels across all platforms.

    PERMISSION MAPPING BY PLATFORM:

    ┌─────────────┬──────────────────────────────────────────────────────────────┐
    │ Level       │ Description                                                  │
    ├─────────────┼──────────────────────────────────────────────────────────────┤
    │ PRIVATE (0) │ Only owner or explicitly named principals                    │
    │ INTERNAL(1) │ Same organization/tenant, requires authentication            │
    │ ORG_WIDE(2) │ Overly broad access (all authenticated, large groups)        │
    │ PUBLIC (3)  │ Anonymous access, no authentication required                 │
    └─────────────┴──────────────────────────────────────────────────────────────┘

    AWS S3 PERMISSIONS → EXPOSURE LEVEL:
    ┌────────────────────────────────────────────┬─────────────┐
    │ S3 Permission                              │ Level       │
    ├────────────────────────────────────────────┼─────────────┤
    │ ACL: private                               │ PRIVATE     │
    │ ACL: bucket-owner-full-control             │ PRIVATE     │
    │ ACL: bucket-owner-read                     │ PRIVATE     │
    │ ACL: aws-exec-read                         │ INTERNAL    │
    │ ACL: log-delivery-write                    │ INTERNAL    │
    │ ACL: authenticated-read                    │ ORG_WIDE    │
    │ ACL: public-read                           │ PUBLIC      │
    │ ACL: public-read-write                     │ PUBLIC      │
    │ Policy: Principal="*" (no Condition)       │ PUBLIC      │
    │ Policy: Principal="*" + aws:SourceArn      │ INTERNAL    │
    │ Cross-account access                       │ ORG_WIDE    │
    │ Website hosting enabled                    │ PUBLIC      │
    │ Public Access Block: all enabled           │ blocks→PRIV │
    └────────────────────────────────────────────┴─────────────┘

    GCP GCS PERMISSIONS → EXPOSURE LEVEL:
    ┌────────────────────────────────────────────┬─────────────┐
    │ GCS Permission                             │ Level       │
    ├────────────────────────────────────────────┼─────────────┤
    │ IAM: specific user/serviceAccount          │ PRIVATE     │
    │ IAM: projectViewer/Editor/Owner            │ INTERNAL    │
    │ IAM: group:*@domain.com                    │ INTERNAL    │
    │ IAM: domain:domain.com                     │ INTERNAL    │
    │ IAM: allAuthenticatedUsers                 │ ORG_WIDE    │
    │ IAM: allUsers                              │ PUBLIC      │
    │ ACL entity: user-* / group-*               │ PRIVATE     │
    │ ACL entity: project-*                      │ INTERNAL    │
    │ ACL entity: allAuthenticatedUsers          │ ORG_WIDE    │
    │ ACL entity: allUsers                       │ PUBLIC      │
    │ Cross-project service account access       │ ORG_WIDE    │
    │ publicAccessPrevention: enforced           │ blocks→PRIV │
    └────────────────────────────────────────────┴─────────────┘

    AZURE BLOB PERMISSIONS → EXPOSURE LEVEL:
    ┌────────────────────────────────────────────┬─────────────┐
    │ Azure Blob Permission                      │ Level       │
    ├────────────────────────────────────────────┼─────────────┤
    │ access_level: private                      │ PRIVATE     │
    │ RBAC: specific user/service principal      │ PRIVATE     │
    │ RBAC: Owner/Contributor (resource scope)   │ INTERNAL    │
    │ access_level: blob (blob-level anonymous)  │ ORG_WIDE    │
    │ SAS token: limited scope + expiry          │ INTERNAL    │
    │ SAS token: broad scope / no expiry         │ ORG_WIDE    │
    │ access_level: container                    │ PUBLIC      │
    │ SAS token: publicly shared                 │ PUBLIC      │
    │ Cross-tenant access                        │ ORG_WIDE    │
    │ Network rules: default=Allow               │ ORG_WIDE    │
    │ Network rules: default=Deny + VNet rules   │ INTERNAL    │
    │ Private endpoint only                      │ PRIVATE     │
    └────────────────────────────────────────────┴─────────────┘

    NTFS (WINDOWS) PERMISSIONS → EXPOSURE LEVEL:
    ┌────────────────────────────────────────────┬─────────────┐
    │ NTFS Permission                            │ Level       │
    ├────────────────────────────────────────────┼─────────────┤
    │ Owner only                                 │ PRIVATE     │
    │ Specific user/group ACE                    │ PRIVATE     │
    │ CREATOR OWNER                              │ PRIVATE     │
    │ Domain Admins                              │ INTERNAL    │
    │ Domain Users                               │ INTERNAL    │
    │ Authenticated Users (domain)               │ INTERNAL    │
    │ BUILTIN\\Users                             │ ORG_WIDE    │
    │ Everyone (authenticated context)           │ ORG_WIDE    │
    │ Anonymous Logon                            │ PUBLIC      │
    │ Everyone (+ anonymous enabled)             │ PUBLIC      │
    │ NULL SID                                   │ PUBLIC      │
    │ Network share: Everyone Full Control       │ PUBLIC      │
    │ Inherited broad permissions                │ ORG_WIDE    │
    └────────────────────────────────────────────┴─────────────┘

    NFS PERMISSIONS → EXPOSURE LEVEL:
    ┌────────────────────────────────────────────┬─────────────┐
    │ NFS Permission                             │ Level       │
    ├────────────────────────────────────────────┼─────────────┤
    │ root_squash + specific UID/GID             │ PRIVATE     │
    │ Single host export (/path host)            │ PRIVATE     │
    │ Kerberos auth (sec=krb5/krb5i/krb5p)       │ INTERNAL    │
    │ Subnet export (/path 10.0.0.0/24)          │ INTERNAL    │
    │ all_squash + anonuid mapping               │ INTERNAL    │
    │ Large subnet (/16 or broader)              │ ORG_WIDE    │
    │ no_root_squash                             │ ORG_WIDE    │
    │ sec=sys (AUTH_SYS, UID trust)              │ ORG_WIDE    │
    │ Export: * (all hosts)                      │ PUBLIC      │
    │ insecure option (non-privileged ports)     │ PUBLIC      │
    │ World-readable (mode 755/644) + * export   │ PUBLIC      │
    │ no_auth_nlm                                │ PUBLIC      │
    └────────────────────────────────────────────┴─────────────┘

    M365 (SHAREPOINT/ONEDRIVE) PERMISSIONS → EXPOSURE LEVEL:
    ┌────────────────────────────────────────────┬─────────────┐
    │ M365 Permission                            │ Level       │
    ├────────────────────────────────────────────┼─────────────┤
    │ Specific users (direct permission)         │ PRIVATE     │
    │ "Only people with existing access"         │ PRIVATE     │
    │ Private channel membership                 │ PRIVATE     │
    │ Security group (scoped)                    │ INTERNAL    │
    │ "People in your organization" link         │ INTERNAL    │
    │ M365 Group / Team membership               │ INTERNAL    │
    │ Site collection scoped                     │ INTERNAL    │
    │ "People in <org> with the link"            │ ORG_WIDE    │
    │ "Anyone in org" (all employees)            │ ORG_WIDE    │
    │ External sharing: specific guests          │ ORG_WIDE    │
    │ External sharing: existing guests          │ ORG_WIDE    │
    │ "Anyone with the link" (sign-in req)       │ ORG_WIDE    │
    │ "Anyone with the link" (no sign-in)        │ PUBLIC      │
    │ Anonymous guest links                      │ PUBLIC      │
    │ Public site / Public CDN                   │ PUBLIC      │
    │ Forms: anyone can respond                  │ PUBLIC      │
    └────────────────────────────────────────────┴─────────────┘
    """
    PRIVATE = 0       # Only owner/specific principals
    INTERNAL = 1      # Same org/tenant
    ORG_WIDE = 2      # Too broad (authenticated users, large groups)
    PUBLIC = 3        # Anyone, anonymous


@dataclass
class Entity:
    """A detected entity with metadata."""
    type: str                       # Canonical entity type (e.g., "SSN", "CREDIT_CARD")
    count: int                      # Number of occurrences
    confidence: float               # Detection confidence (0.0-1.0)
    source: str                     # Which adapter detected this
    positions: List[Tuple[int, int]] = field(default_factory=list)  # [(start, end), ...]


@dataclass
class NormalizedContext:
    """
    Normalized file/object context across all platforms.

    Used by the scoring engine to apply exposure multipliers and
    additional context adjustments to the risk score.
    """
    # Exposure factors
    exposure: str                   # PRIVATE, INTERNAL, ORG_WIDE, PUBLIC
    cross_account_access: bool = False    # Access from other accounts/tenants
    anonymous_access: bool = False        # Anonymous/public access

    # Protection factors
    encryption: str = "none"        # none, platform, customer_managed
    versioning: bool = False        # Object versioning enabled
    access_logging: bool = False    # Access logging enabled
    retention_policy: bool = False  # Retention/immutability policy

    # Staleness
    last_modified: Optional[str] = None   # ISO timestamp
    last_accessed: Optional[str] = None   # ISO timestamp (if available)
    staleness_days: int = 0               # Days since last modified

    # Classification source
    has_classification: bool = False      # Has external classification
    classification_source: str = "none"   # macie, dlp, purview, scanner, none

    # File info
    path: str = ""                  # File path or object key
    owner: Optional[str] = None     # Owner identifier
    size_bytes: int = 0             # File size
    file_type: str = ""             # MIME type or extension
    is_archive: bool = False        # Whether this is a compressed archive


@dataclass
class NormalizedInput:
    """Standard input to the OpenLabels scorer."""
    entities: List[Entity]
    context: NormalizedContext


class Adapter(Protocol):
    """
    All adapters implement this interface.

    Adapters extract entities and context from various sources:
    - Cloud DLP services (Macie, GCP DLP, Purview)
    - Local scanners
    - Other classification tools (Presidio, etc.)
    """

    def extract(self, source: Any, metadata: Any) -> NormalizedInput:
        """
        Extract entities and context from a source.

        Args:
            source: The detection results (findings, classifications, etc.)
            metadata: Platform-specific metadata (S3, GCS, Blob, filesystem)

        Returns:
            NormalizedInput ready for scoring
        """
        ...


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def calculate_staleness_days(last_modified: Optional[str]) -> int:
    """Calculate days since last modification."""
    if not last_modified:
        return 0
    try:
        if isinstance(last_modified, str):
            # Parse ISO format
            if 'T' in last_modified:
                dt = datetime.fromisoformat(last_modified.replace('Z', '+00:00'))
            else:
                dt = datetime.fromisoformat(last_modified)
        else:
            dt = last_modified
        delta = datetime.now(dt.tzinfo) - dt
        return max(0, delta.days)
    except Exception:
        return 0


ARCHIVE_EXTENSIONS = frozenset({'.zip', '.tar', '.gz', '.tgz', '.tar.gz', '.7z', '.rar', '.bz2'})


def is_archive(filename: str) -> bool:
    """Check if file is an archive based on extension."""
    filename_lower = filename.lower()
    return any(filename_lower.endswith(ext) for ext in ARCHIVE_EXTENSIONS)


class EntityAggregator:
    """
    Utility for aggregating detected entities by type.

    Handles the common pattern across all adapters:
    - Aggregate counts (sum)
    - Aggregate confidence (max)
    - Track positions (optional)
    - Convert to List[Entity]

    Usage:
        >>> agg = EntityAggregator(source="macie")
        >>> agg.add("SSN", count=5, confidence=0.95)
        >>> agg.add("SSN", count=3, confidence=0.85)  # Aggregates with existing
        >>> agg.add("EMAIL", count=2, confidence=0.90)
        >>> entities = agg.to_entities()
        >>> # Returns [Entity(type="SSN", count=8, confidence=0.95, source="macie"), ...]
    """

    def __init__(self, source: str):
        """
        Initialize aggregator.

        Args:
            source: Source identifier for entities (e.g., "macie", "dlp", "nfs")
        """
        self.source = source
        self._data: Dict[str, Dict[str, Any]] = {}

    def add(
        self,
        entity_type: str,
        count: int = 1,
        confidence: float = 0.8,
        positions: Optional[List[Tuple[int, int]]] = None,
    ) -> None:
        """
        Add an entity detection to the aggregator.

        Args:
            entity_type: Canonical entity type (should already be normalized)
            count: Number of occurrences to add
            confidence: Detection confidence (0.0-1.0)
            positions: Optional list of (start, end) positions
        """
        if not entity_type:
            return

        if entity_type not in self._data:
            self._data[entity_type] = {
                "count": 0,
                "confidence": 0.0,
                "positions": [],
            }

        self._data[entity_type]["count"] += count
        self._data[entity_type]["confidence"] = max(
            self._data[entity_type]["confidence"], confidence
        )
        if positions:
            self._data[entity_type]["positions"].extend(positions)

    def to_entities(self) -> List[Entity]:
        """
        Convert aggregated data to list of Entity objects.

        Returns:
            List of Entity objects, one per unique entity type
        """
        return [
            Entity(
                type=entity_type,
                count=data["count"],
                confidence=data["confidence"],
                source=self.source,
                positions=data["positions"],
            )
            for entity_type, data in self._data.items()
        ]

    def __len__(self) -> int:
        """Return number of unique entity types."""
        return len(self._data)
