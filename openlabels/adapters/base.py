"""
OpenLabels Adapter Protocol.

All adapters implement this interface and produce normalized output
that can be fed into the scoring engine.
"""

from typing import Protocol, List, Any, Optional
from dataclasses import dataclass


@dataclass
class Entity:
    """A detected entity with metadata."""
    type: str           # Canonical entity type (e.g., "SSN", "CREDIT_CARD")
    count: int          # Number of occurrences
    confidence: float   # Detection confidence (0.0-1.0)
    weight: int         # Risk weight from registry (1-10)
    source: str         # Which adapter detected this


@dataclass
class NormalizedContext:
    """Normalized file/object context across all platforms."""
    exposure: str           # PRIVATE, INTERNAL, ORG_WIDE, PUBLIC
    encryption: str         # none, platform, customer_managed
    owner: Optional[str]    # Owner identifier
    path: str               # File path or object key
    size_bytes: int         # File size
    last_modified: str      # ISO timestamp
    file_type: str          # MIME type or extension
    is_archive: bool        # Whether this is a compressed archive


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
