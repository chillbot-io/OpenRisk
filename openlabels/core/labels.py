"""
OpenLabels Label Primitives.

Core functions for label ID generation, content hashing, and value hashing.

Per the OpenLabels Specification v1.0:
- labelID: Immutable identifier assigned when a file is first labeled
- content_hash: SHA-256 of file content, truncated to 12 hex chars
- value_hash: SHA-256 of normalized entity value, truncated to 6 hex chars
"""

import hashlib
import secrets
import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

from ..adapters.scanner.constants import FILE_READ_CHUNK_SIZE


# =============================================================================
# LABEL ID
# =============================================================================

def generate_label_id() -> str:
    """
    Generate a new immutable label ID.

    Format: ol_ + 12 random hex characters (48 bits)
    Example: ol_7f3a9b2c4d5e

    Properties:
    - Unique within a tenant
    - Should be globally unique (collision probability negligible)
    - Never changes for the lifetime of the labeled file
    """
    return "ol_" + secrets.token_hex(6)


def is_valid_label_id(label_id: str) -> bool:
    """Check if a string is a valid label ID format."""
    return bool(re.match(r'^ol_[a-f0-9]{12}$', label_id))


# =============================================================================
# CONTENT HASH
# =============================================================================

def compute_content_hash(content: bytes) -> str:
    """
    Compute content hash for version tracking.

    Algorithm: SHA-256 truncated to first 12 hex characters
    Example: e3b0c44298fc

    The content hash changes when file content changes, enabling
    version tracking while the labelID remains constant.

    Args:
        content: File content as bytes

    Returns:
        12-character lowercase hex string
    """
    digest = hashlib.sha256(content).hexdigest()
    return digest[:12].lower()


def compute_content_hash_file(path: str) -> str:
    """
    Compute content hash from a file path.

    Args:
        path: Path to the file

    Returns:
        12-character lowercase hex string
    """
    sha256 = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(FILE_READ_CHUNK_SIZE), b''):
            sha256.update(chunk)
    return sha256.hexdigest()[:12].lower()


def is_valid_content_hash(hash_str: str) -> bool:
    """Check if a string is a valid content hash format."""
    return bool(re.match(r'^[a-f0-9]{12}$', hash_str))


# =============================================================================
# VALUE HASH
# =============================================================================

# Normalization rules by entity type
VALUE_NORMALIZERS = {
    'SSN': lambda v: re.sub(r'[-\s]', '', v),  # Remove hyphens and spaces
    'CREDIT_CARD': lambda v: re.sub(r'[-\s]', '', v),
    'PHONE': lambda v: re.sub(r'[^\d+]', '', v),  # Keep only digits and +
    'IBAN': lambda v: re.sub(r'\s', '', v).upper(),
    'EMAIL': lambda v: v.strip().lower(),
}


def normalize_value(value: str, entity_type: str) -> str:
    """
    Normalize a value before hashing.

    Normalization ensures the same logical value produces the same hash
    regardless of formatting differences (spaces, hyphens, case).

    Args:
        value: The detected sensitive value
        entity_type: The entity type (SSN, CREDIT_CARD, etc.)

    Returns:
        Normalized string
    """
    # Strip whitespace from all values
    value = value.strip()

    # Apply type-specific normalization if available
    normalizer = VALUE_NORMALIZERS.get(entity_type.upper())
    if normalizer:
        value = normalizer(value)

    return value


def compute_value_hash(value: str, entity_type: str = '') -> str:
    """
    Compute value hash for cross-system correlation.

    Algorithm: SHA-256 of normalized UTF-8 bytes, truncated to 6 hex chars
    Example: 15e2b0

    The value hash enables correlation of the same sensitive value
    across different systems without exposing the actual value.

    Note: This is NOT encryption. High-value targets can be brute-forced.

    Args:
        value: The detected sensitive value
        entity_type: Optional entity type for normalization

    Returns:
        6-character lowercase hex string
    """
    normalized = normalize_value(value, entity_type)
    value_bytes = normalized.encode('utf-8')
    digest = hashlib.sha256(value_bytes).hexdigest()
    return digest[:6].lower()


def is_valid_value_hash(hash_str: str) -> bool:
    """Check if a string is a valid value hash format."""
    return bool(re.match(r'^[a-f0-9]{6}$', hash_str))


# =============================================================================
# LABEL DATA MODEL
# =============================================================================

@dataclass
class Label:
    """
    A single detected entity label.

    Per the spec, this uses compact field names for serialization:
    - t: entity type
    - c: confidence
    - d: detector type
    - h: value hash
    - n: count (optional, default 1)
    - x: extensions (optional)
    """
    type: str                           # Entity type (e.g., "SSN")
    confidence: float                   # Detection confidence (0.0-1.0)
    detector: str                       # Detector type: checksum, pattern, ml, structured
    value_hash: str                     # 6-char value hash
    count: int = 1                      # Occurrence count
    extensions: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to compact JSON format per spec."""
        d = {
            't': self.type,
            'c': round(self.confidence, 2),
            'd': self.detector,
            'h': self.value_hash,
        }
        if self.count > 1:
            d['n'] = self.count
        if self.extensions:
            d['x'] = self.extensions
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'Label':
        """Deserialize from compact JSON format."""
        return cls(
            type=d['t'],
            confidence=d['c'],
            detector=d['d'],
            value_hash=d['h'],
            count=d.get('n', 1),
            extensions=d.get('x'),
        )


@dataclass
class LabelSet:
    """
    A collection of labels for a single file/data unit.

    This is the core portable data structure that travels with files
    (embedded) or is stored in the index (virtual).
    """
    version: int                        # Spec version, must be 1
    label_id: str                       # Immutable label ID
    content_hash: str                   # Content hash for this version
    labels: List[Label]                 # Array of Label objects
    source: str                         # Source generator:version
    timestamp: int                      # Unix timestamp
    extensions: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        """Validate fields after initialization."""
        if self.version != 1:
            raise ValueError(f"Unsupported version: {self.version}")
        if not is_valid_label_id(self.label_id):
            raise ValueError(f"Invalid label ID format: {self.label_id}")
        if not is_valid_content_hash(self.content_hash):
            raise ValueError(f"Invalid content hash format: {self.content_hash}")

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to compact JSON format per spec."""
        d = {
            'v': self.version,
            'id': self.label_id,
            'hash': self.content_hash,
            'labels': [label.to_dict() for label in self.labels],
            'src': self.source,
            'ts': self.timestamp,
        }
        if self.extensions:
            d['x'] = self.extensions
        return d

    def to_json(self, compact: bool = True) -> str:
        """Serialize to JSON string."""
        import json
        if compact:
            return json.dumps(self.to_dict(), separators=(',', ':'))
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'LabelSet':
        """Deserialize from JSON dict."""
        return cls(
            version=d['v'],
            label_id=d['id'],
            content_hash=d['hash'],
            labels=[Label.from_dict(l) for l in d['labels']],
            source=d['src'],
            timestamp=d['ts'],
            extensions=d.get('x'),
        )

    @classmethod
    def from_json(cls, json_str: str) -> 'LabelSet':
        """Deserialize from JSON string."""
        import json
        return cls.from_dict(json.loads(json_str))

    @classmethod
    def create(
        cls,
        labels: List[Label],
        content: bytes,
        source: str = 'openlabels:1.0.0',
        label_id: Optional[str] = None,
    ) -> 'LabelSet':
        """
        Create a new LabelSet from detection results.

        Args:
            labels: List of detected Label objects
            content: File content bytes (for hash computation)
            source: Generator identifier (e.g., "openlabels:1.0.0")
            label_id: Optional existing label ID (for re-scans)

        Returns:
            New LabelSet instance
        """
        import time

        return cls(
            version=1,
            label_id=label_id or generate_label_id(),
            content_hash=compute_content_hash(content),
            labels=labels,
            source=source,
            timestamp=int(time.time()),
        )


# =============================================================================
# VIRTUAL LABEL POINTER
# =============================================================================

@dataclass
class VirtualLabelPointer:
    """
    A pointer stored in extended attributes for virtual labels.

    Format: labelID:content_hash
    Example: ol_7f3a9b2c4d5e:e3b0c44298fc
    """
    label_id: str
    content_hash: str

    def to_string(self) -> str:
        """Serialize to xattr value format."""
        return f"{self.label_id}:{self.content_hash}"

    @classmethod
    def from_string(cls, value: str) -> 'VirtualLabelPointer':
        """Parse from xattr value format."""
        parts = value.strip().split(':')
        if len(parts) != 2:
            raise ValueError(f"Invalid virtual label format: {value}")
        return cls(label_id=parts[0], content_hash=parts[1])

    def __str__(self) -> str:
        return self.to_string()


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def labels_from_detection(
    entity_counts: Dict[str, int],
    spans: List[Any],
    detector_type: str = 'pattern',
) -> List[Label]:
    """
    Convert scanner detection results to Label objects.

    Args:
        entity_counts: Dict of {entity_type: count}
        spans: List of detection spans with entity_type, text, confidence
        detector_type: Default detector type if not in span

    Returns:
        List of Label objects
    """
    # Group spans by entity type to compute value hashes and confidences
    type_data: Dict[str, Dict] = {}

    for span in spans:
        etype = span.entity_type
        if etype not in type_data:
            type_data[etype] = {
                'values': [],
                'confidences': [],
                'detector': getattr(span, 'detector', detector_type),
            }
        type_data[etype]['values'].append(span.text)
        type_data[etype]['confidences'].append(span.confidence)

    labels = []
    for etype, data in type_data.items():
        # Use the first value for hash (most common case)
        # For multiple distinct values, could create multiple labels
        primary_value = data['values'][0] if data['values'] else ''
        avg_confidence = sum(data['confidences']) / len(data['confidences'])

        labels.append(Label(
            type=etype,
            confidence=avg_confidence,
            detector=data['detector'],
            value_hash=compute_value_hash(primary_value, etype),
            count=entity_counts.get(etype, len(data['values'])),
        ))

    return labels
