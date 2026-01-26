"""
OpenLabels Adapter Protocol.

All adapters implement this interface and produce normalized output
that can be fed into the scoring engine.
"""

from typing import Protocol, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class ExposureLevel(Enum):
    """Normalized exposure levels across all platforms."""
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


def exposure_from_string(exposure: str) -> ExposureLevel:
    """Convert string exposure to enum."""
    mapping = {
        'PRIVATE': ExposureLevel.PRIVATE,
        'INTERNAL': ExposureLevel.INTERNAL,
        'ORG_WIDE': ExposureLevel.ORG_WIDE,
        'OVER_EXPOSED': ExposureLevel.ORG_WIDE,  # Alias
        'PUBLIC': ExposureLevel.PUBLIC,
    }
    return mapping.get(exposure.upper(), ExposureLevel.PRIVATE)


ARCHIVE_EXTENSIONS = frozenset({'.zip', '.tar', '.gz', '.tgz', '.tar.gz', '.7z', '.rar', '.bz2'})


def is_archive(filename: str) -> bool:
    """Check if file is an archive based on extension."""
    filename_lower = filename.lower()
    return any(filename_lower.endswith(ext) for ext in ARCHIVE_EXTENSIONS)
