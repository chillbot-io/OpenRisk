# OpenLabels Label Schema v1

**Portable Label Format for Data Sensitivity Classification**

---

**Version:** 1.0
**Status:** Draft
**Last Updated:** January 2026

---

## Overview

This document defines the portable label format for OpenLabels. Labels describe WHAT is in the data. Risk is computed separately based on exposure context.

**Core Principle: Labels are the primitive. Risk is derived.**

---

## Label JSON Format

### Compact Format (Option B)

The compact format is optimized for embedding in file metadata, trailers, and sidecars.

```json
{
  "v": 1,
  "labels": [
    {"t": "SSN", "c": 0.99, "d": "checksum", "h": "a1b2c3"},
    {"t": "NAME", "c": 0.87, "d": "pattern", "h": "d4e5f6"},
    {"t": "CREDIT_CARD", "c": 0.95, "d": "checksum", "h": "e7f8g9"}
  ],
  "src": "orscan:0.1.0",
  "ts": 1706000000
}
```

### Field Definitions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `v` | integer | Yes | Schema version (currently 1) |
| `labels` | array | Yes | Array of detected entity labels |
| `src` | string | Yes | Source generator and version |
| `ts` | integer | Yes | Unix timestamp of label generation |

### Label Object Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `t` | string | Yes | Entity type (e.g., "SSN", "NAME", "CREDIT_CARD") |
| `c` | number | Yes | Confidence score (0.0 - 1.0) |
| `d` | string | Yes | Detector type: "checksum", "pattern", "ml", "structured" |
| `h` | string | Yes | Hash of the detected value (for cross-system correlation) |
| `n` | integer | No | Count of occurrences (default: 1) |

---

## Hash Computation

The hash (`h`) field enables cross-system correlation without exposing sensitive content.

### Algorithm

```python
import hashlib

def compute_label_hash(detected_value: str, salt: str = "") -> str:
    """
    Compute a short hash for a detected value.

    Args:
        detected_value: The actual PII/PHI value detected
        salt: Optional salt for additional security

    Returns:
        First 6 characters of SHA-256 hex digest
    """
    content = (salt + detected_value).encode('utf-8')
    full_hash = hashlib.sha256(content).hexdigest()
    return full_hash[:6]
```

### Properties

- **Deterministic**: Same value always produces same hash
- **Collision-resistant**: 6 hex chars = 16M possible values
- **Cross-tenant**: When file moves, hash survives and enables correlation
- **Privacy-preserving**: Cannot reverse hash to recover original value

### Example

```python
>>> compute_label_hash("123-45-6789")
'a1b2c3'

>>> compute_label_hash("John Smith")
'd4e5f6'
```

---

## Detector Types

| Detector | Code | Description |
|----------|------|-------------|
| Checksum | `checksum` | Validated via algorithm (SSN, CC, NPI, IBAN) |
| Pattern | `pattern` | Matched via regex pattern |
| ML | `ml` | Detected by machine learning model |
| Structured | `structured` | Extracted from structured formats (JSON keys, CSV headers) |

---

## File Attachment Methods

Labels can be attached to files in three ways:

### 1. Native Metadata

For files with native metadata support, embed the label JSON directly.

| File Type | Metadata Location |
|-----------|-------------------|
| PDF | XMP metadata (`openlabels` namespace) |
| DOCX/XLSX/PPTX | Custom properties (`openlabels`) |
| JPEG/PNG/TIFF | EXIF `UserComment` or XMP |
| MP4/MOV | Metadata atoms |

### 2. Trailer Format

For text-based files, append a trailer:

```
[Original file content - unchanged]

---OPENLABEL-V1---
{"v":1,"labels":[{"t":"SSN","c":0.99,"d":"checksum","h":"a1b2c3"}],"src":"orscan:0.1.0","ts":1706000000}
---END-OPENLABEL---
```

**Supported file types:** txt, csv, tsv, json, jsonl, md, log, sql, yaml, xml, html

**Properties:**
- Original content unchanged (hash verifiable)
- Single newline before start marker
- JSON must be compact (no pretty-printing)
- End marker has no trailing newline

### 3. Sidecar Format

For binary files or when trailers are not possible, use a sidecar file:

```
/data/
├── document.pdf
├── document.pdf.openlabel.json    ← Sidecar
├── image.png
└── image.png.openlabel.json       ← Sidecar
```

**Sidecar file naming:** `{original_filename}.openlabel.json`

**Sidecar content includes file reference:**

```json
{
  "v": 1,
  "file": {
    "name": "document.pdf",
    "size": 1048576,
    "hash": "sha256:abc123..."
  },
  "labels": [
    {"t": "SSN", "c": 0.99, "d": "checksum", "h": "a1b2c3"}
  ],
  "src": "orscan:0.1.0",
  "ts": 1706000000
}
```

---

## Attachment Decision Matrix

| File Type | Primary Method | Fallback |
|-----------|----------------|----------|
| PDF | Native (XMP) | Sidecar |
| DOCX/XLSX/PPTX | Native (custom props) | Sidecar |
| Images (JPG, PNG, etc.) | Native (EXIF/XMP) | Sidecar |
| TXT, CSV, JSON, MD | Trailer | Sidecar |
| LOG, SQL, YAML, XML | Trailer | Sidecar |
| ZIP, TAR, GZ | Sidecar only | - |
| EML, MSG | Sidecar only | - |
| Binary files | Sidecar only | - |

---

## Reading Labels

### Python Implementation

```python
import json
import re

START_MARKER = b'\n---OPENLABEL-V1---\n'
END_MARKER = b'\n---END-OPENLABEL---'

def read_labels(filepath: str) -> dict | None:
    """
    Read OpenLabels from a file (trailer, sidecar, or native metadata).

    Returns:
        Label dict if found, None otherwise
    """
    path = Path(filepath)

    # Try sidecar first
    sidecar = path.parent / f"{path.name}.openlabel.json"
    if sidecar.exists():
        with open(sidecar) as f:
            return json.load(f)

    # Try trailer
    with open(filepath, 'rb') as f:
        content = f.read()

    end_pos = content.rfind(END_MARKER)
    if end_pos != -1:
        start_pos = content.rfind(START_MARKER)
        if start_pos != -1:
            tag_start = start_pos + len(START_MARKER)
            tag_json = content[tag_start:end_pos]
            return json.loads(tag_json.decode('utf-8'))

    # Try native metadata (file-type specific)
    return _read_native_metadata(filepath)
```

---

## Writing Labels

### Python Implementation

```python
def write_labels(filepath: str, labels: dict, method: str = "auto") -> None:
    """
    Write OpenLabels to a file.

    Args:
        filepath: Path to the file
        labels: Label dict to write
        method: "trailer", "sidecar", "native", or "auto"
    """
    path = Path(filepath)

    if method == "auto":
        method = _choose_method(path)

    if method == "trailer":
        _write_trailer(path, labels)
    elif method == "sidecar":
        _write_sidecar(path, labels)
    elif method == "native":
        _write_native_metadata(path, labels)


def _write_trailer(path: Path, labels: dict) -> None:
    """Append trailer to file."""
    with open(path, 'ab') as f:
        tag_json = json.dumps(labels, separators=(',', ':'))
        f.write(START_MARKER)
        f.write(tag_json.encode('utf-8'))
        f.write(END_MARKER)


def _write_sidecar(path: Path, labels: dict) -> None:
    """Write sidecar file."""
    # Add file reference
    labels_with_file = {
        **labels,
        "file": {
            "name": path.name,
            "size": path.stat().st_size,
            "hash": _compute_file_hash(path),
        }
    }

    sidecar = path.parent / f"{path.name}.openlabel.json"
    with open(sidecar, 'w') as f:
        json.dump(labels_with_file, f, indent=2)
```

---

## Validation Rules

1. `v` MUST be a positive integer
2. `labels` MUST be a non-empty array if any entities were detected
3. `t` MUST be a valid entity type from the OpenLabels registry
4. `c` MUST be a number in range [0.0, 1.0]
5. `d` MUST be one of: "checksum", "pattern", "ml", "structured"
6. `h` MUST be a 6-character hexadecimal string
7. `src` MUST follow format `generator:version`
8. `ts` MUST be a valid Unix timestamp

---

## Security Considerations

### Hash Privacy

The label hash (`h`) is designed to enable correlation without exposing content:

- **DO**: Use for cross-system deduplication
- **DO**: Use for tracking data lineage
- **DON'T**: Consider hash as encryption
- **DON'T**: Store hash → value mappings (defeats the purpose)

### Sidecar Access Control

Sidecar files contain metadata about sensitive content:

- Match sidecar permissions to original file
- Delete sidecar when original file is deleted
- Include sidecar in backup/restore procedures

### Trailer Integrity

When reading trailers:

1. Verify start and end markers are present
2. Parse JSON strictly (reject malformed)
3. Optionally verify content hash if stored
4. Treat unknown generators with caution

---

## Examples

### Example 1: Healthcare Document

```json
{
  "v": 1,
  "labels": [
    {"t": "SSN", "c": 0.99, "d": "checksum", "h": "a1b2c3"},
    {"t": "NAME", "c": 0.92, "d": "pattern", "h": "d4e5f6"},
    {"t": "DATE_DOB", "c": 0.88, "d": "pattern", "h": "g7h8i9"},
    {"t": "DIAGNOSIS", "c": 0.85, "d": "ml", "h": "j0k1l2"},
    {"t": "MRN", "c": 0.97, "d": "checksum", "h": "m3n4o5"}
  ],
  "src": "orscan:0.1.0",
  "ts": 1706000000
}
```

### Example 2: Financial Spreadsheet

```json
{
  "v": 1,
  "labels": [
    {"t": "CREDIT_CARD", "c": 0.99, "d": "checksum", "h": "p6q7r8", "n": 47},
    {"t": "BANK_ACCOUNT", "c": 0.95, "d": "pattern", "h": "s9t0u1", "n": 12},
    {"t": "NAME", "c": 0.90, "d": "pattern", "h": "v2w3x4", "n": 47},
    {"t": "EMAIL", "c": 0.99, "d": "pattern", "h": "y5z6a7", "n": 45}
  ],
  "src": "orscan:0.1.0",
  "ts": 1706000000
}
```

### Example 3: Developer Config File

```json
{
  "v": 1,
  "labels": [
    {"t": "AWS_ACCESS_KEY", "c": 0.99, "d": "pattern", "h": "b8c9d0"},
    {"t": "AWS_SECRET_KEY", "c": 0.99, "d": "pattern", "h": "e1f2g3"},
    {"t": "DATABASE_URL", "c": 0.95, "d": "structured", "h": "h4i5j6"}
  ],
  "src": "orscan:0.1.0",
  "ts": 1706000000
}
```

---

## JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://openlabels.dev/schema/v1/label.json",
  "title": "OpenLabels Label",
  "type": "object",
  "required": ["v", "labels", "src", "ts"],
  "properties": {
    "v": {
      "type": "integer",
      "minimum": 1,
      "description": "Schema version"
    },
    "labels": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["t", "c", "d", "h"],
        "properties": {
          "t": {
            "type": "string",
            "description": "Entity type"
          },
          "c": {
            "type": "number",
            "minimum": 0,
            "maximum": 1,
            "description": "Confidence score"
          },
          "d": {
            "type": "string",
            "enum": ["checksum", "pattern", "ml", "structured"],
            "description": "Detector type"
          },
          "h": {
            "type": "string",
            "pattern": "^[a-f0-9]{6}$",
            "description": "Value hash for correlation"
          },
          "n": {
            "type": "integer",
            "minimum": 1,
            "description": "Occurrence count"
          }
        }
      }
    },
    "src": {
      "type": "string",
      "pattern": "^[a-z0-9-]+:[0-9.]+$",
      "description": "Source generator:version"
    },
    "ts": {
      "type": "integer",
      "description": "Unix timestamp"
    },
    "file": {
      "type": "object",
      "description": "File reference (sidecar only)",
      "properties": {
        "name": {"type": "string"},
        "size": {"type": "integer"},
        "hash": {"type": "string"}
      }
    }
  }
}
```

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01 | Initial specification |

---

**Labels are the primitive. Risk is derived.**
