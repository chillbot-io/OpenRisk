# OpenLabels Specification

**Version:** 1.0.0-draft
**Status:** Draft
**Document ID:** OL-SPEC-001
**Last Updated:** January 2026

---

## Abstract

This document defines OpenLabels, a portable format for data sensitivity labels. OpenLabels enables interoperable labeling of sensitive data across platforms, tools, and organizational boundaries. Labels describe WHAT sensitive data is present; risk is computed separately based on exposure context.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology](#2-terminology)
3. [Data Model](#3-data-model)
4. [Serialization](#4-serialization)
5. [Transport](#5-transport)
6. [Algorithms](#6-algorithms)
7. [Conformance](#7-conformance)
8. [Security Considerations](#8-security-considerations)
9. [IANA Considerations](#9-iana-considerations)
10. [References](#10-references)
11. [Appendix A: JSON Schema](#appendix-a-json-schema)
12. [Appendix B: Entity Type Registry](#appendix-b-entity-type-registry)
13. [Appendix C: Examples](#appendix-c-examples)

---

## 1. Introduction

### 1.1 Purpose

OpenLabels defines a standard format for describing sensitive data detected within files or data streams. The format is designed to be:

- **Portable**: Labels travel with data across systems
- **Interoperable**: Multiple implementations can read/write labels
- **Minimal**: Compact representation suitable for embedding
- **Extensible**: New entity types can be registered

### 1.2 Design Principles

```
LABELS ARE THE PRIMITIVE. RISK IS DERIVED.
```

OpenLabels separates two concerns:

1. **Labels**: Describe what sensitive data is present (portable, travels with data)
2. **Risk**: Computed locally from labels plus exposure context (not portable)

This separation enables cross-system correlation while respecting that risk depends on context.

### 1.3 Scope

This specification defines:

- The Label data model
- JSON serialization format
- Transport mechanisms (trailer, sidecar, native metadata)
- Hash computation algorithm
- Conformance requirements

This specification does NOT define:

- Detection algorithms (how labels are produced)
- Risk scoring formulas (how risk is computed from labels)
- Index storage formats (implementation-specific)

---

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://tools.ietf.org/html/rfc2119).

| Term | Definition |
|------|------------|
| **Label** | A single detected entity with type, confidence, detector, and hash |
| **Label Set** | A collection of labels for a single file or data unit |
| **Entity Type** | The category of sensitive data (e.g., "SSN", "CREDIT_CARD") |
| **Confidence** | A score from 0.0 to 1.0 indicating detection certainty |
| **Detector** | The method used to detect the entity (checksum, pattern, ml, structured) |
| **Label Hash** | A truncated hash of the detected value for correlation |
| **Trailer** | Label data appended to a file |
| **Sidecar** | Label data stored in an adjacent file |
| **Reader** | An implementation that parses Label Sets |
| **Writer** | An implementation that produces Label Sets |

---

## 3. Data Model

### 3.1 Label Set

A Label Set is the top-level structure containing all labels for a data unit.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `v` | integer | REQUIRED | Specification version. MUST be `1` for this version. |
| `labels` | array | REQUIRED | Array of Label objects. MAY be empty. |
| `src` | string | REQUIRED | Source identifier. Format: `generator:version`. |
| `ts` | integer | REQUIRED | Unix timestamp (seconds since epoch) when labels were generated. |
| `file` | object | OPTIONAL | File reference. REQUIRED for sidecars. See Section 3.3. |
| `x` | object | OPTIONAL | Extension data. See Section 3.4. |

### 3.2 Label

A Label describes a single detected sensitive entity.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `t` | string | REQUIRED | Entity type. MUST be a registered type (Appendix B) or prefixed with `x-`. |
| `c` | number | REQUIRED | Confidence score. MUST be in range [0.0, 1.0]. |
| `d` | string | REQUIRED | Detector type. MUST be one of: `checksum`, `pattern`, `ml`, `structured`. |
| `h` | string | REQUIRED | Label hash. MUST be exactly 6 lowercase hexadecimal characters. |
| `n` | integer | OPTIONAL | Occurrence count. MUST be >= 1. Default is 1. |
| `x` | object | OPTIONAL | Extension data. See Section 3.4. |

### 3.3 File Reference

For sidecar transport, a file reference links the Label Set to its source file.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | REQUIRED | Original filename (basename only, no path). |
| `size` | integer | REQUIRED | File size in bytes. |
| `hash` | string | OPTIONAL | File content hash. Format: `algorithm:hexdigest`. |

### 3.4 Extensions

Implementations MAY include additional data in the `x` field at the Label Set or Label level.

- Extension field names SHOULD use reverse domain notation (e.g., `com.example.custom`)
- Readers MUST ignore unrecognized extension fields
- Writers MUST NOT require extensions for basic interoperability

### 3.5 Detector Types

| Value | Description | Typical Confidence |
|-------|-------------|-------------------|
| `checksum` | Validated via checksum algorithm (Luhn, SSN, etc.) | 0.95 - 1.00 |
| `pattern` | Matched via regular expression | 0.70 - 0.95 |
| `ml` | Detected by machine learning model | 0.60 - 0.95 |
| `structured` | Extracted from structured data (JSON keys, headers) | 0.80 - 1.00 |

---

## 4. Serialization

### 4.1 JSON Format

Label Sets MUST be serialized as JSON conforming to [RFC 8259](https://tools.ietf.org/html/rfc8259).

### 4.2 Encoding

- JSON text MUST be encoded as UTF-8
- Writers MUST NOT include a byte order mark (BOM)
- Writers SHOULD use compact serialization (no unnecessary whitespace)

### 4.3 Numeric Precision

- Confidence values (`c`) SHOULD be serialized with at most 2 decimal places
- Implementations MUST accept confidence values with any decimal precision

### 4.4 Field Order

Field order is not significant. Readers MUST accept fields in any order.

### 4.5 Unknown Fields

Readers MUST ignore unrecognized fields without error. This enables forward compatibility.

---

## 5. Transport

Labels can be attached to files via three mechanisms.

### 5.1 Trailer Format

Trailers append label data to the end of a file.

#### 5.1.1 Structure

```
FILE = CONTENT || START_MARKER || LABEL_JSON || END_MARKER
```

Where:

| Component | Value | Bytes |
|-----------|-------|-------|
| CONTENT | Original file content | Variable |
| START_MARKER | `\n---OPENLABEL-V1---\n` | 21 |
| LABEL_JSON | Compact JSON Label Set | Variable |
| END_MARKER | `\n---END-OPENLABEL---` | 21 |

#### 5.1.2 Byte Sequences

```
START_MARKER (hex): 0A 2D 2D 2D 4F 50 45 4E 4C 41 42 45 4C 2D 56 31 2D 2D 2D 0A
END_MARKER (hex):   0A 2D 2D 2D 45 4E 44 2D 4F 50 45 4E 4C 41 42 45 4C 2D 2D 2D
```

#### 5.1.3 Requirements

- LABEL_JSON MUST be compact (no newlines within JSON)
- LABEL_JSON MUST be valid UTF-8
- Writers MUST NOT modify CONTENT
- The END_MARKER MUST NOT be followed by additional data

#### 5.1.4 Reading Trailers

To extract labels from a trailer:

1. Search backward from end of file for END_MARKER
2. If not found, file has no trailer
3. Search backward from END_MARKER position for START_MARKER
4. Extract bytes between START_MARKER and END_MARKER
5. Parse as JSON Label Set

#### 5.1.5 Applicable File Types

Trailers are RECOMMENDED for text-based files:

- Plain text: `.txt`, `.log`, `.md`
- Data files: `.csv`, `.tsv`, `.json`, `.jsonl`
- Config files: `.yaml`, `.yml`, `.xml`, `.ini`
- Source code: `.py`, `.js`, `.java`, `.go`, etc.
- Query files: `.sql`

Trailers MUST NOT be used for:

- Binary files (images, PDFs, executables)
- Archives (`.zip`, `.tar`, `.gz`)
- Files where appending changes semantics

### 5.2 Sidecar Format

Sidecars store labels in an adjacent file.

#### 5.2.1 Naming Convention

For a file named `example.pdf`, the sidecar MUST be named `example.pdf.openlabel.json`.

```
/data/
├── document.pdf
├── document.pdf.openlabel.json    ← Sidecar
├── image.png
└── image.png.openlabel.json       ← Sidecar
```

#### 5.2.2 Requirements

- Sidecar MUST contain a valid Label Set JSON
- Sidecar MUST include the `file` field (Section 3.3)
- Sidecar SHOULD be in the same directory as the source file
- Sidecar permissions SHOULD match the source file

#### 5.2.3 Applicable File Types

Sidecars are RECOMMENDED for:

- Binary files: images, PDFs, videos
- Archives: `.zip`, `.tar`, `.gz`, `.7z`
- Email: `.eml`, `.msg`
- Files where trailers are not possible

### 5.3 Native Metadata

Labels MAY be embedded in native file metadata.

#### 5.3.1 PDF Files

- Store in XMP metadata
- Namespace: `http://openlabels.dev/ns/1.0/`
- Property: `openlabels:data`
- Value: Compact JSON Label Set

#### 5.3.2 Office Documents (DOCX, XLSX, PPTX)

- Store in Custom Properties
- Property name: `openlabels`
- Value: Compact JSON Label Set

#### 5.3.3 Images (JPEG, PNG, TIFF)

- Store in XMP metadata (preferred) or EXIF UserComment
- Same namespace and property as PDF

#### 5.3.4 Requirements

- Native metadata MUST NOT alter the visual/functional content
- If native metadata exceeds size limits, use sidecar instead

### 5.4 Transport Priority

When reading labels, implementations SHOULD check in order:

1. Sidecar (if exists)
2. Native metadata (if supported)
3. Trailer (if applicable file type)

This allows sidecars to override embedded labels when needed.

---

## 6. Algorithms

### 6.1 Label Hash Computation

The label hash enables cross-system correlation without exposing sensitive values.

#### 6.1.1 Algorithm

```
INPUT: value (string) - the detected sensitive value
OUTPUT: hash (string) - 6 character lowercase hexadecimal string

PROCEDURE:
  1. Encode value as UTF-8 bytes
  2. Compute SHA-256 digest of bytes
  3. Encode digest as lowercase hexadecimal
  4. Return first 6 characters
```

#### 6.1.2 Pseudocode

```python
def compute_label_hash(value: str) -> str:
    value_bytes = value.encode('utf-8')
    digest = sha256(value_bytes)
    hex_digest = digest.hexdigest().lower()
    return hex_digest[:6]
```

#### 6.1.3 Normalization

Before hashing, values SHOULD be normalized:

- Remove leading/trailing whitespace
- For SSNs: Remove hyphens (e.g., "123-45-6789" → "123456789")
- For credit cards: Remove spaces and hyphens
- For phone numbers: Digits only

Implementations MUST document their normalization rules.

#### 6.1.4 Properties

- **Deterministic**: Same input always produces same hash
- **Collision space**: 16,777,216 possible values (24 bits)
- **Non-reversible**: Cannot recover value from hash

#### 6.1.5 Examples

| Input | SHA-256 (first 12 hex) | Label Hash |
|-------|------------------------|------------|
| `123456789` | `15e2b0d3c338...` | `15e2b0` |
| `John Smith` | `ef61a579c907...` | `ef61a5` |
| `4111111111111111` | `9f86d081884c...` | `9f86d0` |

### 6.2 Label Merging (Informative)

When combining labels from multiple sources, implementations SHOULD use conservative union:

- For same entity type, take maximum count
- For same entity type, take maximum confidence
- Include entity if ANY source detected it

This is informative guidance, not a normative requirement.

---

## 7. Conformance

### 7.1 Conformance Levels

| Level | Requirements |
|-------|--------------|
| **Reader** | Parse Label Sets, extract from transport mechanisms |
| **Writer** | Produce valid Label Sets, write to transport mechanisms |
| **Full** | Reader + Writer |

### 7.2 Reader Conformance

A conforming OpenLabels Reader:

1. MUST parse any valid Label Set JSON (Section 3, 4)
2. MUST extract labels from trailers (Section 5.1)
3. MUST extract labels from sidecars (Section 5.2)
4. MUST ignore unknown fields without error (Section 4.5)
5. MUST accept `v` value of `1`
6. MUST validate `h` field is 6 hexadecimal characters
7. MUST validate `c` field is in range [0.0, 1.0]
8. SHOULD extract labels from native metadata (Section 5.3)
9. SHOULD verify file hash when `file.hash` is present

### 7.3 Writer Conformance

A conforming OpenLabels Writer:

1. MUST produce JSON conforming to Section 3 and 4
2. MUST set `v` field to `1`
3. MUST compute hashes per Section 6.1
4. MUST use compact JSON for trailers (no internal newlines)
5. MUST include `file` field when writing sidecars
6. MUST use registered entity types OR prefix custom types with `x-`
7. SHOULD use detector type that reflects actual detection method
8. SHOULD set confidence based on detection certainty

### 7.4 Conformance Testing

Implementations SHOULD pass the OpenLabels Conformance Test Suite (published separately).

---

## 8. Security Considerations

### 8.1 Label Hash Privacy

The label hash is NOT encryption. It provides:

- **Correlation**: Match same values across systems
- **Pseudonymity**: Cannot directly read the value

It does NOT provide:

- **Secrecy**: High-value targets can be brute-forced
- **Encryption**: Hash is deterministic, not random

Implementations SHOULD NOT rely on hash secrecy for security.

### 8.2 Information Disclosure

Label Sets reveal metadata about file contents:

- Entity types present
- Approximate counts
- Detection confidence

This metadata may itself be sensitive. Implementations SHOULD apply appropriate access controls to Label Sets.

### 8.3 Trailer Injection

Malicious actors could append fake trailers. Mitigations:

1. Verify `file.hash` matches actual content
2. Verify `src` is a trusted generator
3. Use signed labels (extension, not in base spec)

### 8.4 Index Security

Label indexes aggregate sensitive metadata. Per the OpenLabels Constitution:

- Indexes MUST NOT leave the user's tenant
- Indexes SHOULD be protected at rest
- Indexes SHOULD have appropriate access controls

### 8.5 Sidecar Synchronization

Sidecars can become stale if source files change. Implementations SHOULD:

- Verify `file.size` matches
- Verify `file.hash` if present
- Regenerate labels if source changed

---

## 9. IANA Considerations

### 9.1 Media Type Registration

This specification registers the following media type:

```
Type name: application
Subtype name: openlabels+json
Required parameters: none
Optional parameters: none
Encoding considerations: UTF-8
Security considerations: See Section 8
Interoperability considerations: See Section 7
Published specification: This document
Applications that use this media type: Data classification tools
File extension: .openlabel.json
```

### 9.2 Entity Type Registry

The OpenLabels Entity Type Registry is maintained at:

```
https://openlabels.dev/registry/entity-types
```

New entity types may be registered via the process defined in the registry documentation.

---

## 10. References

### 10.1 Normative References

- [RFC 2119] Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.
- [RFC 8259] Bray, T., Ed., "The JavaScript Object Notation (JSON) Data Interchange Format", STD 90, RFC 8259, December 2017.
- [FIPS 180-4] "Secure Hash Standard (SHS)", FIPS PUB 180-4, August 2015.

### 10.2 Informative References

- OpenLabels Constitution v3
- OpenLabels Entity Registry v1
- OpenLabels Architecture v2

---

## Appendix A: JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://openlabels.dev/schema/v1/labelset.json",
  "title": "OpenLabels Label Set",
  "type": "object",
  "required": ["v", "labels", "src", "ts"],
  "properties": {
    "v": {
      "type": "integer",
      "const": 1,
      "description": "Specification version"
    },
    "labels": {
      "type": "array",
      "items": { "$ref": "#/$defs/label" },
      "description": "Array of labels"
    },
    "src": {
      "type": "string",
      "pattern": "^[a-z0-9_-]+:[0-9a-z.-]+$",
      "description": "Source generator:version"
    },
    "ts": {
      "type": "integer",
      "minimum": 0,
      "description": "Unix timestamp"
    },
    "file": {
      "$ref": "#/$defs/fileRef",
      "description": "File reference (required for sidecars)"
    },
    "x": {
      "type": "object",
      "description": "Extension data"
    }
  },
  "$defs": {
    "label": {
      "type": "object",
      "required": ["t", "c", "d", "h"],
      "properties": {
        "t": {
          "type": "string",
          "minLength": 1,
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
          "description": "Label hash"
        },
        "n": {
          "type": "integer",
          "minimum": 1,
          "description": "Occurrence count"
        },
        "x": {
          "type": "object",
          "description": "Extension data"
        }
      }
    },
    "fileRef": {
      "type": "object",
      "required": ["name", "size"],
      "properties": {
        "name": {
          "type": "string",
          "minLength": 1,
          "description": "Filename"
        },
        "size": {
          "type": "integer",
          "minimum": 0,
          "description": "File size in bytes"
        },
        "hash": {
          "type": "string",
          "pattern": "^(sha256|sha384|sha512):[a-f0-9]+$",
          "description": "Content hash"
        }
      }
    }
  }
}
```

---

## Appendix B: Entity Type Registry

The following entity types are registered in v1.0:

### B.1 Direct Identifiers

| Type | Description | Category |
|------|-------------|----------|
| `SSN` | US Social Security Number | direct_id |
| `PASSPORT` | Passport number | direct_id |
| `DRIVER_LICENSE` | Driver's license number | direct_id |
| `NATIONAL_ID` | National identification number | direct_id |

### B.2 Financial

| Type | Description | Category |
|------|-------------|----------|
| `CREDIT_CARD` | Credit/debit card number | financial |
| `BANK_ACCOUNT` | Bank account number | financial |
| `IBAN` | International Bank Account Number | financial |
| `SWIFT` | SWIFT/BIC code | financial |
| `ROUTING_NUMBER` | Bank routing number | financial |

### B.3 Contact Information

| Type | Description | Category |
|------|-------------|----------|
| `EMAIL` | Email address | contact |
| `PHONE` | Phone number | contact |
| `ADDRESS` | Physical address | contact |

### B.4 Personal Information

| Type | Description | Category |
|------|-------------|----------|
| `NAME` | Person name | pii |
| `DATE_DOB` | Date of birth | pii |
| `AGE` | Age | pii |
| `GENDER` | Gender | pii |

### B.5 Healthcare

| Type | Description | Category |
|------|-------------|----------|
| `MRN` | Medical Record Number | health |
| `NPI` | National Provider Identifier | health |
| `DEA` | DEA Number | health |
| `DIAGNOSIS` | Medical diagnosis | health |
| `MEDICATION` | Medication name | health |

### B.6 Credentials

| Type | Description | Category |
|------|-------------|----------|
| `AWS_ACCESS_KEY` | AWS access key ID | credential |
| `AWS_SECRET_KEY` | AWS secret access key | credential |
| `API_KEY` | Generic API key | credential |
| `PASSWORD` | Password | credential |
| `PRIVATE_KEY` | Cryptographic private key | credential |

### B.7 Network

| Type | Description | Category |
|------|-------------|----------|
| `IP_ADDRESS` | IP address (v4 or v6) | network |
| `MAC_ADDRESS` | MAC address | network |
| `URL` | URL with potential PII | network |

See the full registry at https://openlabels.dev/registry for 300+ types.

---

## Appendix C: Examples

### C.1 Minimal Label Set

```json
{"v":1,"labels":[],"src":"orscan:1.0.0","ts":1706140800}
```

### C.2 Healthcare Document

```json
{
  "v": 1,
  "labels": [
    {"t": "SSN", "c": 0.99, "d": "checksum", "h": "15e2b0"},
    {"t": "NAME", "c": 0.92, "d": "pattern", "h": "ef61a5"},
    {"t": "DATE_DOB", "c": 0.88, "d": "pattern", "h": "7c4a8d"},
    {"t": "MRN", "c": 0.97, "d": "checksum", "h": "2c6ee2"},
    {"t": "DIAGNOSIS", "c": 0.85, "d": "ml", "h": "8d969e"}
  ],
  "src": "orscan:1.0.0",
  "ts": 1706140800
}
```

### C.3 File with Trailer

Original file content:
```
Patient: John Smith
SSN: 123-45-6789
DOB: 01/15/1980
```

File with trailer:
```
Patient: John Smith
SSN: 123-45-6789
DOB: 01/15/1980

---OPENLABEL-V1---
{"v":1,"labels":[{"t":"NAME","c":0.92,"d":"pattern","h":"ef61a5"},{"t":"SSN","c":0.99,"d":"checksum","h":"15e2b0"},{"t":"DATE_DOB","c":0.88,"d":"pattern","h":"7c4a8d"}],"src":"orscan:1.0.0","ts":1706140800}
---END-OPENLABEL---
```

### C.4 Sidecar File

For `report.pdf`, sidecar `report.pdf.openlabel.json`:

```json
{
  "v": 1,
  "file": {
    "name": "report.pdf",
    "size": 1048576,
    "hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  },
  "labels": [
    {"t": "CREDIT_CARD", "c": 0.99, "d": "checksum", "h": "9f86d0", "n": 47},
    {"t": "NAME", "c": 0.90, "d": "pattern", "h": "ef61a5", "n": 47}
  ],
  "src": "orscan:1.0.0",
  "ts": 1706140800
}
```

### C.5 With Extensions

```json
{
  "v": 1,
  "labels": [
    {
      "t": "SSN",
      "c": 0.99,
      "d": "checksum",
      "h": "15e2b0",
      "x": {
        "com.example.redacted": true,
        "com.example.page": 3
      }
    }
  ],
  "src": "orscan:1.0.0",
  "ts": 1706140800,
  "x": {
    "com.example.scan_duration_ms": 1250,
    "com.example.ocr_used": true
  }
}
```

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0-draft | 2026-01 | Initial draft |

---

## Authors

OpenLabels Community

---

## License

This specification is released under CC BY 4.0.

---

**Labels are the primitive. Risk is derived.**
