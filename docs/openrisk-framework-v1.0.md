# OpenRisk Framework 1.0

**A Universal Standard for Data Sensitivity Risk Scoring**

---

**Version:** 1.0
**Status:** Official
**License:** Apache 2.0 (code), CC BY 4.0 (specification)
**Last Updated:** January 2026

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Problem Statement](#2-problem-statement)
3. [The OpenRisk Solution](#3-the-openrisk-solution)
4. [Core Value Proposition](#4-core-value-proposition)
5. [System Architecture](#5-system-architecture)
6. [Tag Schema Specification](#6-tag-schema-specification)
7. [Scoring Algorithm](#7-scoring-algorithm)
8. [Entity Taxonomy](#8-entity-taxonomy)
9. [Adapters](#9-adapters)
10. [Normalizers](#10-normalizers)
11. [Scanner Adapter](#11-scanner-adapter)
12. [Scan Triggers](#12-scan-triggers)
13. [Trailer & Sidecar Formats](#13-trailer--sidecar-formats)
14. [CLI & Query Language](#14-cli--query-language)
15. [Agent (On-Prem)](#15-agent-on-prem)
16. [SDK Reference](#16-sdk-reference)
17. [Security Considerations](#17-security-considerations)
18. [Conformance](#18-conformance)
19. [Governance](#19-governance)
20. [Appendices](#20-appendices)

---

## 1. Executive Summary

OpenRisk is a universal, portable standard for expressing data sensitivity risk. It solves a fundamental problem in data security: when files move between systems, their classification metadata is lost.

### The Core Insight

```
Macie tells you WHAT's in your data.
OpenRisk tells you HOW RISKY that data actually is, given WHERE it lives.
```

An SSN in a private, encrypted bucket ≠ an SSN in a public, unencrypted bucket.

**Same content, different risk. Only OpenRisk captures this.**

### What OpenRisk Provides

| Component | Description |
|-----------|-------------|
| **Tag Schema** | JSON structure for risk scores with transparent scoring factors |
| **Scoring Algorithm** | Deterministic, reproducible formula: content × exposure = risk |
| **Entity Taxonomy** | 300+ sensitive data types with standardized weights |
| **Adapters** | Bridges for Macie, DLP, Purview, and custom scanners |
| **Normalizers** | Cross-platform metadata translation (S3, GCS, Azure, NTFS, POSIX) |
| **CLI** | Risk-aware data management with quarantine, find, move commands |
| **SDK** | Python SDK for reading, writing, and scoring |

### What OpenRisk Is NOT

- **Not a scanner** (though it includes one as an adapter)
- **Not a replacement for Macie/DLP/Purview** (it consumes their output)
- **Not just another label** (it quantifies risk with context)

---

## 2. Problem Statement

### 2.1 The Multi-Cloud Classification Problem

Every major platform has data classification:
- AWS Macie scans S3 buckets
- Microsoft Purview labels documents
- Google Cloud DLP inspects GCP data
- Open source tools like Presidio detect PII

**None of them interoperate.**

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        DATA LIFECYCLE                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   Created in        Stored in         Processed in      Archived in     │
│   Office 365   →    AWS S3       →    Databricks   →    Azure Blob     │
│                                                                          │
│   Purview           Macie             Custom            ???              │
│   classifies        re-scans          detection         No scanning     │
│                                                                          │
│   Classification lost at each transition                                │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Consequences

**Redundant Compute Costs**: Organizations scan the same data repeatedly across systems.

**Inconsistent Risk Assessments**: Different tools have different capabilities. Tool A finds 5 SSNs; Tool B finds 7. Reconciliation requires manual effort.

**Audit and Compliance Gaps**: Regulations like HIPAA, GDPR, and CCPA require knowing where sensitive data resides. Fragmented metadata makes unified inventory difficult.

**No Context Awareness**: Existing tools tell you *what* data exists but not *how risky* it is given its exposure, encryption, and access patterns.

### 2.3 The Gap in Existing Standards

| Standard | What It Does | Why It's Not Enough |
|----------|--------------|---------------------|
| STIX/TAXII | Threat intelligence exchange | Describes threats, not data sensitivity |
| FAIR | Enterprise risk quantification | Scenario-level, not file-level |
| TLP | Sharing restrictions | Qualitative only (RED/AMBER/GREEN) |
| NIST 800-122 | PII protection guidance | Qualitative, implementation-dependent |
| ISO 27001 | Security management systems | No specific classification scheme |

**None provides portable, quantitative, machine-readable data sensitivity scores.**

---

## 3. The OpenRisk Solution

### 3.1 Design Philosophy

OpenRisk combines **content sensitivity** (what entities are present) with **exposure context** (how it's stored and who can access it) into a single **portable 0-100 risk score**.

```
Risk = Content × Exposure
```

### 3.2 Design Principles

1. **Portability**: Risk scores travel with data across system boundaries
2. **Universality**: Categories transcend specific regulations
3. **Determinism**: Same inputs always produce same scores
4. **Extensibility**: Community-driven entity registry
5. **Transparency**: Scores are fully explainable
6. **Context Awareness**: Exposure and metadata always contribute to risk

### 3.3 The Formula

```python
# Content score from detected entities
content_score = Σ(weight × (1 + ln(count)) × confidence)
content_score *= co_occurrence_multiplier

# Exposure multiplier from context
exposure_multiplier = f(exposure_level, encryption, staleness, etc.)

# Final score
final_score = min(100, content_score × exposure_multiplier)
```

---

## 4. Core Value Proposition

| Need | Solution |
|------|----------|
| Cross-platform comparison | Same score formula everywhere |
| Content + Context risk | Only OpenRisk combines both |
| Already have Macie/DLP | Use vendor adapter → get portable score |
| Want more granularity | Add scanner adapter → standardized detection |
| Want portability | Scanner works anywhere (on-prem, any cloud) |
| Want defense in depth | Run multiple adapters → conservative union |
| Actionable remediation | CLI with quarantine, move, delete based on risk |

---

## 5. System Architecture

### 5.1 High-Level Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              INPUT LAYER                                    │
└─────────────────────────────────────────────────────────────────────────────┘
        │                                                    │
        ▼                                                    ▼
┌─────────────────┐                               ┌─────────────────────┐
│  Cloud Storage  │                               │   Local / On-Prem   │
│  + Vendor DLP   │                               │   File Systems      │
└────────┬────────┘                               └──────────┬──────────┘
         │                                                   │
         ▼                                                   ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              ADAPTERS                                       │
│                     (all produce normalized entities + context)             │
│                                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐│
│  │   Macie     │  │   GCP DLP   │  │   Purview   │  │      Scanner        ││
│  │   Adapter   │  │   Adapter   │  │   Adapter   │  │      Adapter        ││
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘│
│         │                │                │                     │          │
│         └────────────────┴────────────────┴─────────────────────┘          │
│                                    │                                        │
│                                    ▼                                        │
│                        ┌─────────────────────┐                             │
│                        │  Normalized Format  │                             │
│                        │  • Entities[]       │                             │
│                        │  • Context{}        │                             │
│                        └──────────┬──────────┘                             │
└───────────────────────────────────┼─────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              OPENRISK CORE                                  │
│                                                                             │
│    ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐        │
│    │   Merger     │───►│    Scorer    │───►│   Output Generator   │        │
│    │              │    │              │    │                      │        │
│    │ • Union      │    │ • Content    │    │ • Score 0-100        │        │
│    │ • Dedupe     │    │ • Exposure   │    │ • Risk level         │        │
│    │ • Max conf   │    │ • Combined   │    │ • Entity summary     │        │
│    └──────────────┘    └──────────────┘    └──────────────────────┘        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              OUTPUT                                         │
│                                                                             │
│    Score: 73                                                                │
│    Level: HIGH                                                              │
│    Entities: [SSN (3), EMAIL (12), CREDIT_CARD (1)]                        │
│    Exposure: PUBLIC                                                         │
│    Triggers: [public_access, no_encryption]                                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Processing Flow

```
┌──────────────────┐
│   Object/File    │
└────────┬─────────┘
         │
         ▼
┌────────────────────────────────┐
│  1. Normalize metadata         │
│  (exposure, encryption, age)   │
└────────────────┬───────────────┘
                 │
                 ▼
┌────────────────────────────────┐
│  2. Has labels/classification? │
└────────────────┬───────────────┘
                 │
   ┌─────────────┴─────────────┐
   ▼                           ▼
  YES                          NO
   │                           │
   ▼                           ▼
┌─────────────┐       ┌─────────────────┐
│ Check scan  │       │ MUST scan       │
│ triggers    │       │ (no other data) │
└──────┬──────┘       └────────┬────────┘
       │                       │
 ┌─────┴─────┐                 │
 ▼           ▼                 │
SCAN       TRUST               │
ANYWAY     LABELS              │
 │           │                 │
 └───────────┴─────────────────┘
                 │
                 ▼
┌────────────────────────────────┐
│  3. Merge entities, calculate  │
│  score with exposure multiplier│
└────────────────────────────────┘
```

---

## 6. Tag Schema Specification

### 6.1 Complete Schema

```json
{
  "openrisk": {
    "version": "1.0",
    "score": 74,
    "tier": "High",
    "content_hash": "sha256:3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b",
    "content_length": 1048576,
    "factors": {
      "entities": [
        {
          "type": "ssn",
          "category": "direct_identifier.national_id",
          "count": 47,
          "confidence_avg": 0.94,
          "weight": 9
        },
        {
          "type": "diagnosis",
          "category": "health.diagnosis",
          "count": 23,
          "confidence_avg": 0.87,
          "weight": 8
        }
      ],
      "exposure": "PUBLIC",
      "exposure_multiplier": 2.5,
      "co_occurrence_rules": ["direct_id + health"],
      "co_occurrence_multiplier": 2.0,
      "raw_score": 29.6,
      "filtered": []
    },
    "context": {
      "encryption": "none",
      "versioning": false,
      "access_logging": false,
      "staleness_days": 547,
      "classification_source": "macie+scanner"
    },
    "scoring": {
      "algorithm": "openrisk-v1.0-standard",
      "confidence_threshold": 0.8,
      "mode": "strict"
    },
    "provenance": {
      "generator": "openrisk-sdk/1.0.0",
      "generator_org": "openrisk",
      "generated_at": "2026-01-24T14:32:00Z",
      "adapters_used": ["macie", "scanner"],
      "scan_duration_ms": 1247
    },
    "signature": null
  }
}
```

### 6.2 Field Definitions

#### Core Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | string | Yes | Specification version (e.g., "1.0") |
| `score` | integer | Yes | Normalized risk score, 0-100 |
| `tier` | string | Yes | Risk tier: Critical, High, Medium, Low, Minimal |
| `content_hash` | string | Yes | Hash of original content |
| `content_length` | integer | Yes | Original content length in bytes |

#### Factors Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `entities` | array | Yes | List of detected entity types |
| `exposure` | string | Yes | PRIVATE, INTERNAL, OVER_EXPOSED, PUBLIC |
| `exposure_multiplier` | number | Yes | Applied multiplier from exposure |
| `co_occurrence_rules` | array | No | Triggered co-occurrence rules |
| `co_occurrence_multiplier` | number | No | Applied multiplier (default: 1.0) |
| `raw_score` | number | No | Pre-multiplier score for debugging |
| `filtered` | array | No | Detections excluded from scoring |

#### Entity Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Entity type identifier (e.g., "ssn") |
| `category` | string | Yes | Hierarchical category |
| `count` | integer | Yes | Number of instances detected |
| `confidence_avg` | number | Yes | Average confidence score, 0.0-1.0 |
| `weight` | integer | Yes | Entity weight used in scoring, 1-10 |

### 6.3 Validation Rules

1. `version` MUST match pattern `^\d+\.\d+$`
2. `score` MUST be an integer in range [0, 100]
3. `tier` MUST be one of: "Critical", "High", "Medium", "Low", "Minimal"
4. `content_hash` MUST match pattern `^(sha256|sha384|sha512):[a-f0-9]+$`
5. `content_length` MUST be a non-negative integer
6. `entities` MUST contain at least one entity if `score` > 0
7. `confidence_avg` MUST be in range [0.0, 1.0]
8. `weight` MUST be an integer in range [1, 10]
9. `generated_at` MUST be a valid ISO 8601 timestamp
10. `exposure` MUST be one of: PRIVATE, INTERNAL, OVER_EXPOSED, PUBLIC

---

## 7. Scoring Algorithm

### 7.1 Algorithm Identifier

The current algorithm is identified as `openrisk-v1.0-standard`.

### 7.2 Complete Formula

```python
from math import log
from enum import Enum

class ExposureLevel(Enum):
    PRIVATE = 0
    INTERNAL = 1
    OVER_EXPOSED = 2
    PUBLIC = 3

# Exposure multipliers
EXPOSURE_MULTIPLIERS = {
    ExposureLevel.PRIVATE: 1.0,
    ExposureLevel.INTERNAL: 1.2,
    ExposureLevel.OVER_EXPOSED: 1.8,
    ExposureLevel.PUBLIC: 2.5,
}

def calculate_score(entities, context):
    """
    OpenRisk scoring algorithm.

    Formula:
        content_score = Σ(weight × (1 + ln(count)) × confidence)
        content_score *= co_occurrence_multiplier
        exposure_multiplier = f(context)
        final_score = min(100, content_score × exposure_multiplier)
    """

    # Step 1: Calculate content score
    content_score = 0.0
    for entity in entities:
        weight = entity.weight
        count_factor = 1 + log(max(entity.count, 1))
        contribution = weight * count_factor * entity.confidence
        content_score += contribution

    # Step 2: Apply co-occurrence multipliers
    co_mult, rules = check_co_occurrence(entities)
    content_score *= co_mult

    # Step 3: Calculate exposure multiplier
    exposure_mult = EXPOSURE_MULTIPLIERS[context.exposure]

    # Additional context adjustments
    if context.encryption == "none":
        exposure_mult *= 1.3
    if not context.access_logging:
        exposure_mult *= 1.1
    if context.staleness_days > 365:
        exposure_mult *= 1.2
    if context.cross_account_access:
        exposure_mult *= 1.3

    # Step 4: Calculate final score
    final_score = min(100, int(content_score * exposure_mult))

    return final_score
```

### 7.3 Co-occurrence Rules

| Rule Name | Condition | Multiplier | Rationale |
|-----------|-----------|------------|-----------|
| `hipaa_phi` | direct_id + health | 2.0 | HIPAA PHI combination |
| `identity_theft` | direct_id + financial | 1.8 | Financial fraud risk |
| `credential_exposure` | credential + any PII | 2.0 | Access + identity risk |
| `reidentification` | 3+ quasi-identifiers | 1.5 | Sweeney re-identification |
| `bulk_quasi_id` | 4+ quasi-identifiers | 1.7 | High re-identification probability |
| `minor_data` | direct_id + minor indicator | 1.8 | COPPA considerations |
| `classified_data` | classification markers | 2.5 | Government/military |
| `biometric_pii` | biometric + direct_id | 2.2 | BIPA considerations |
| `genetic_data` | genetic identifiers | 2.0 | GINA considerations |

### 7.4 Tier Thresholds

| Tier | Score Range | Interpretation |
|------|-------------|----------------|
| Critical | 90-100 | Immediate action required |
| High | 70-89 | Significant risk; restricted handling |
| Medium | 50-69 | Moderate risk; standard controls |
| Low | 25-49 | Limited risk; basic controls |
| Minimal | 0-24 | Negligible sensitivity |

---

## 8. Entity Taxonomy

### 8.1 Category Hierarchy

```
sensitive_data
├── direct_identifier (weight: 8-10)
│   ├── national_id (ssn, sin, aadhaar, nino, cpf, etc.)
│   ├── financial (credit_card, bank_account)
│   ├── government (passport, drivers_license)
│   └── biometric (fingerprint, face_geometry, iris_scan)
│
├── health (weight: 5-8)
│   ├── identifier (mrn, health_plan_id, npi)
│   ├── diagnosis (icd_code, condition)
│   ├── treatment (procedure, medication, lab_result)
│   └── provider (physician, facility)
│
├── financial (weight: 5-7)
│   ├── account (iban, routing_number, swift_bic)
│   ├── transaction (amount, merchant)
│   └── investment (cusip, isin)
│
├── contact (weight: 3-5)
│   ├── electronic (email, ip_address, mac_address)
│   ├── phone (phone, fax)
│   └── physical (address, postal_code)
│
├── demographic (weight: 2-6)
│   ├── name (full_name, first_name, last_name)
│   ├── personal (date_of_birth, age, gender)
│   └── sensitive (race_ethnicity, religion, sexual_orientation)
│
├── credential (weight: 7-10)
│   ├── authentication (password, pin, security_answer)
│   ├── api_key (aws_access_key, api_token, jwt)
│   └── certificate (private_key, certificate)
│
├── quasi_identifier (weight: 2-3)
│   └── (date_of_birth, gender, postal_code, age, race_ethnicity)
│
└── legal (weight: 5-7)
    ├── case (case_number, docket)
    └── privilege (attorney_client, work_product)
```

### 8.2 Entity Registry

The complete entity registry includes 300+ types across 20 categories. Key examples:

| Entity Type | Category | Weight | Description |
|-------------|----------|--------|-------------|
| `ssn` | direct_identifier.national_id | 9 | US Social Security Number |
| `credit_card` | direct_identifier.financial | 8 | Credit/debit card number |
| `diagnosis` | health.diagnosis | 8 | Medical diagnosis or condition |
| `mrn` | health.identifier | 7 | Medical Record Number |
| `email` | contact.electronic | 4 | Email address |
| `password` | credential.authentication | 9 | Password or passphrase |
| `aws_access_key` | credential.api_key | 9 | AWS access key ID |
| `private_key` | credential.certificate | 9 | Private key material |

See `openrisk-entity-registry-v1.md` for the complete registry.

---

## 9. Adapters

### 9.1 Adapter Interface

All adapters implement the same interface and produce normalized output:

```python
from typing import Protocol, List
from dataclasses import dataclass

class ExposureLevel(Enum):
    PRIVATE = 0
    INTERNAL = 1
    OVER_EXPOSED = 2
    PUBLIC = 3

@dataclass
class Entity:
    type: str
    count: int
    confidence: float
    weight: int
    source: str

@dataclass
class NormalizedContext:
    exposure: ExposureLevel
    encryption: str
    versioning: bool
    access_logging: bool
    staleness_days: int
    has_classification: bool
    classification_source: str

@dataclass
class NormalizedInput:
    entities: List[Entity]
    context: NormalizedContext

class Adapter(Protocol):
    def extract(self, source: Any, metadata: Any) -> NormalizedInput:
        ...
```

### 9.2 Macie Adapter

```python
class MacieAdapter:
    ENTITY_MAP = {
        "AWS_CREDENTIALS": "AWS_ACCESS_KEY",
        "CREDIT_CARD_NUMBER": "CREDIT_CARD",
        "USA_SOCIAL_SECURITY_NUMBER": "SSN",
        "USA_PASSPORT_NUMBER": "PASSPORT",
        # ... complete mapping
    }

    def extract(self, findings: dict, s3_metadata: dict) -> NormalizedInput:
        entities = []
        for finding in findings.get("findings", []):
            entity_type = self.ENTITY_MAP.get(finding["type"])
            if entity_type:
                entities.append(Entity(
                    type=entity_type,
                    count=finding.get("count", 1),
                    confidence=self._severity_to_confidence(finding["severity"]),
                    weight=ENTITY_REGISTRY[entity_type]["weight"],
                    source="macie",
                ))

        context = self._normalize_s3_context(s3_metadata)
        return NormalizedInput(entities=entities, context=context)
```

### 9.3 GCP DLP Adapter

```python
class DLPAdapter:
    ENTITY_MAP = {
        "CREDIT_CARD_NUMBER": "CREDIT_CARD",
        "US_SOCIAL_SECURITY_NUMBER": "SSN",
        "EMAIL_ADDRESS": "EMAIL",
        # ... complete mapping
    }

    def _likelihood_to_confidence(self, likelihood: str) -> float:
        return {
            "VERY_LIKELY": 0.95,
            "LIKELY": 0.85,
            "POSSIBLE": 0.70,
            "UNLIKELY": 0.50,
            "VERY_UNLIKELY": 0.30,
        }.get(likelihood, 0.70)
```

### 9.4 Purview Adapter

```python
class PurviewAdapter:
    ENTITY_MAP = {
        "Credit Card Number": "CREDIT_CARD",
        "U.S. Social Security Number (SSN)": "SSN",
        "Email": "EMAIL",
        # ... complete mapping
    }
```

---

## 10. Normalizers

### 10.1 Permission Normalization

Maps platform-specific permissions to universal exposure levels:

```python
class MetadataNormalizer:
    PERMISSION_MAP = {
        # AWS S3
        "private": ExposureLevel.PRIVATE,
        "authenticated-read": ExposureLevel.OVER_EXPOSED,
        "public-read": ExposureLevel.PUBLIC,

        # GCP GCS
        "allUsers": ExposureLevel.PUBLIC,
        "allAuthenticatedUsers": ExposureLevel.OVER_EXPOSED,

        # Azure Blob
        "None": ExposureLevel.PRIVATE,
        "Blob": ExposureLevel.PUBLIC,
        "Container": ExposureLevel.PUBLIC,

        # NTFS / Windows
        "Authenticated Users": ExposureLevel.OVER_EXPOSED,
        "Everyone": ExposureLevel.PUBLIC,
        "Domain Users": ExposureLevel.INTERNAL,
        "BUILTIN\\Users": ExposureLevel.OVER_EXPOSED,

        # POSIX / Linux
        "o+r": ExposureLevel.PUBLIC,
        "g+r": ExposureLevel.INTERNAL,

        # SharePoint
        "Anyone with link": ExposureLevel.PUBLIC,
        "People in org with link": ExposureLevel.INTERNAL,
        "Specific people": ExposureLevel.PRIVATE,
    }
```

### 10.2 Entity Type Normalization

Maps vendor entity types to canonical OpenRisk types:

```python
class EntityNormalizer:
    MAPPINGS = {
        # Macie
        "AWS_CREDENTIALS": "AWS_ACCESS_KEY",
        "USA_SOCIAL_SECURITY_NUMBER": "SSN",

        # GCP DLP
        "US_SOCIAL_SECURITY_NUMBER": "SSN",
        "PERSON_NAME": "NAME",

        # Purview
        "U.S. Social Security Number (SSN)": "SSN",

        # Presidio
        "US_SSN": "SSN",
    }
```

---

## 11. Scanner Adapter

The scanner is an adapter like any other. It produces the same normalized output but analyzes raw content rather than consuming external findings.

### 11.1 Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           SCANNER ADAPTER                                   │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    Content Input                                     │   │
│  └──────────────────────────────┬──────────────────────────────────────┘   │
│                                 │                                           │
│                                 ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    File Type Detection                               │   │
│  │    Archive? → Expand    Image/PDF? → Queue OCR    Text? → Direct    │   │
│  └──────────────────────────────┬──────────────────────────────────────┘   │
│                                 │                                           │
│                                 ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    Detector Orchestrator                             │   │
│  │                                                                      │   │
│  │    ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │   │
│  │    │   Checksum   │  │   Patterns   │  │   Secrets    │             │   │
│  │    │  Detector    │  │  Detector    │  │  Detector    │             │   │
│  │    └──────────────┘  └──────────────┘  └──────────────┘             │   │
│  │                                                                      │   │
│  │    ┌──────────────────────────────────────────────────────────┐     │   │
│  │    │               ML Detectors (Optional)                     │     │   │
│  │    │    PHI-BERT, PII-BERT - lazy-loaded from HuggingFace     │     │   │
│  │    └──────────────────────────────────────────────────────────┘     │   │
│  └──────────────────────────────┬──────────────────────────────────────┘   │
│                                 │                                           │
│                                 ▼                                           │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    Normalized Output                                 │   │
│  │    NormalizedInput(entities=[...], context={...})                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 11.2 OCR Worker

RapidOCR-based text extraction (always-on, lazy-loaded):

```python
class OCRWorker:
    def __init__(self):
        self._ocr = None  # Lazy-loaded

    @property
    def ocr(self):
        if self._ocr is None:
            from rapidocr_onnxruntime import RapidOCR
            self._ocr = RapidOCR()
        return self._ocr

    def extract(self, content: bytes, file_type: str) -> str:
        if file_type == "pdf":
            return self._extract_pdf(content)
        else:
            return self._extract_image(content)
```

---

## 12. Scan Triggers

When to activate the scanner even if labels exist:

```python
class ScanTrigger(Enum):
    NO_LABELS = "no_labels"
    PUBLIC_ACCESS = "public_access"
    OVER_EXPOSED = "over_exposed"
    NO_ENCRYPTION = "no_encryption"
    STALE_DATA = "stale_data"
    LOW_CONFIDENCE_HIGH_RISK = "low_conf_high_risk"

def should_scan(entities, context) -> Tuple[bool, List[ScanTrigger]]:
    triggers = []

    if not entities or not context.has_classification:
        triggers.append(ScanTrigger.NO_LABELS)

    if context.exposure == ExposureLevel.PUBLIC:
        triggers.append(ScanTrigger.PUBLIC_ACCESS)
    elif context.exposure == ExposureLevel.OVER_EXPOSED:
        triggers.append(ScanTrigger.OVER_EXPOSED)

    if context.encryption == "none":
        triggers.append(ScanTrigger.NO_ENCRYPTION)

    if context.staleness_days > 365:
        triggers.append(ScanTrigger.STALE_DATA)

    for entity in entities:
        if entity.weight >= 8 and entity.confidence < 0.80:
            triggers.append(ScanTrigger.LOW_CONFIDENCE_HIGH_RISK)
            break

    return len(triggers) > 0, triggers
```

### Decision Matrix

| Scenario | Scan? | Reason |
|----------|-------|--------|
| No labels | Yes | Nothing to go on |
| Labels exist, private, high confidence | No | Trust external tool |
| Labels exist, **public** | Yes | Exposure too high to trust |
| Labels exist, **no encryption** | Yes | Protection gap |
| Labels exist, **stale >1yr** | Yes | Verify still accurate |
| SSN @ 0.65 confidence | Yes | High risk + uncertain |
| EMAIL @ 0.65 confidence | No | Low risk |
| CREDIT_CARD @ 0.90 confidence | No | High confidence |

---

## 13. Trailer & Sidecar Formats

### 13.1 Trailer Format

```
[Original file content - unchanged]
\n---OPENRISK-TAG-V1---\n
{"openrisk":{"version":"1.0","score":74,...}}
\n---END-OPENRISK-TAG---
```

**Properties:**
- Original content unchanged (hash verifiable)
- Works on any file type (CSV, JSON, TXT, logs)
- `content_length` field enables extraction of original

### 13.2 Sidecar Format

For binary files or when trailers are undesirable:

```
/data/
├── document.pdf
├── document.pdf.openrisk.json    ← Sidecar
├── image.png
└── image.png.openrisk.json       ← Sidecar
```

### 13.3 When to Use Each

| Scenario | Recommendation |
|----------|----------------|
| Text files (CSV, JSON, TXT) | Trailer preferred |
| Binary files (images, PDFs) | Sidecar required |
| Read-only files | Sidecar required |
| Version-controlled files | Sidecar preferred |
| Archives (ZIP, TAR) | Sidecar required |

---

## 14. CLI & Query Language

### 14.1 Commands

```bash
# Scan and score
openrisk scan <path>
openrisk scan s3://bucket/prefix
openrisk scan gs://bucket/prefix

# Find with filters
openrisk find <path> --where "<filter>"

# Actions
openrisk quarantine <path> --where "<filter>" --to <dest>
openrisk move <path> --where "<filter>" --to <dest>
openrisk delete <path> --where "<filter>" --confirm
openrisk encrypt <path> --where "<filter>" --key <kms-key>

# Reporting
openrisk report <path> --format json|csv|html
openrisk heatmap <path>
```

### 14.2 Filter Grammar

```
<filter>     := <condition> (AND|OR <condition>)*
<condition>  := <field> <operator> <value>
             | has(<entity_type>)
             | missing(<field>)

<field>      := score | exposure | encryption | last_accessed
             | last_modified | size | entity_count | source

<operator>   := = | != | > | < | >= | <= | contains | matches

<value>      := <number> | <duration> | <enum> | <string>
<duration>   := <number>(d|w|m|y)  # days, weeks, months, years
```

### 14.3 Examples

```bash
# Quarantine high-risk stale data
openrisk quarantine s3://prod-bucket \
  --where "score > 75 AND last_accessed > 5y" \
  --to s3://quarantine-bucket

# Find public SSNs
openrisk find s3://data-lake \
  --where "exposure = public AND has(SSN)"

# Complex query
openrisk find . --where "
  score > 75
  AND exposure >= over_exposed
  AND last_accessed > 1y
  AND (has(SSN) OR has(CREDIT_CARD))
  AND encryption = none
"
```

---

## 15. Agent (On-Prem)

For local/on-prem file systems:

```python
class OpenRiskAgent:
    def __init__(self, scanner: ScannerAdapter):
        self.scanner = scanner
        self.is_windows = platform.system() == "Windows"

    def scan_path(self, path: str) -> ScoringResult:
        context = self.collect_metadata(path)

        with open(path, "rb") as f:
            content = f.read()

        input = self.scanner.extract(content, {"name": os.path.basename(path)})
        input.context = context

        return RiskScorer().score(input)

    def _get_posix_exposure(self, mode: int) -> ExposureLevel:
        if mode & stat.S_IROTH:
            return ExposureLevel.PUBLIC
        if mode & stat.S_IRGRP:
            return ExposureLevel.INTERNAL
        return ExposureLevel.PRIVATE

    def _get_ntfs_exposure(self, path: str) -> ExposureLevel:
        # Check for Everyone, Authenticated Users, etc.
        # Returns appropriate ExposureLevel
        ...
```

---

## 16. SDK Reference

### 16.1 Installation

```bash
pip install openrisk
```

### 16.2 Basic Usage

```python
from openrisk import RiskScorer

scorer = RiskScorer()
scorer.add_detection("ssn", count=3, confidence=0.94)
scorer.add_detection("diagnosis", count=5, confidence=0.87)

tag = scorer.generate(
    content_hash="sha256:abc123...",
    content_length=1048576,
    generator="my-scanner/1.0"
)

print(tag.score)  # 74
print(tag.tier)   # "High"
```

### 16.3 Using Adapters

```python
from openrisk import Client
from openrisk.adapters import macie, scanner

client = Client()

# Score with Macie findings
result = client.score(
    adapters=[macie.extract(findings, s3_metadata)]
)

# Defense in depth (conservative union)
result = client.score(
    adapters=[
        macie.extract(findings, s3_metadata),
        scanner.extract(file_content, file_metadata)
    ]
)
```

### 16.4 Programmatic Filtering

```python
from openrisk import Client, Filter

client = Client()

high_risk_stale = Filter(
    score__gt=75,
    last_accessed__gt="5y",
    exposure__gte="over_exposed"
)

for obj in client.find("s3://bucket", where=high_risk_stale):
    print(f"{obj.path}: {obj.score}")

# Quarantine
client.quarantine(
    source="s3://prod",
    dest="s3://quarantine",
    where=Filter(score__gt=80, exposure="public"),
)
```

---

## 17. Security Considerations

### 17.1 Tag Authenticity

Optional signature field for verifying authenticity:

```json
{
  "openrisk": {
    ...
    "signature": "ed25519:base64-encoded-signature"
  }
}
```

### 17.2 Information Disclosure

OpenRisk tags reveal metadata about file contents:
- Entity types present
- Approximate counts
- Overall sensitivity level

Consider whether this metadata should be protected.

### 17.3 Trailer Injection Mitigations

1. **Verify content_hash**: Fake trailers can't produce valid hashes
2. **Verify signatures**: If signatures are used, validate them
3. **Trust boundaries**: Only trust tags from known generators

### 17.4 Resource Limits

Implementations SHOULD limit:
- Maximum tag size: 1 MB
- Maximum entities count: 10,000
- Trailer search timeout: 5 seconds

---

## 18. Conformance

### 18.1 Conformance Levels

| Level | Requirements |
|-------|--------------|
| **Reader** | Parse valid tags, extract from trailers/sidecars, verify hash |
| **Writer** | Generate valid tags, use standard scoring algorithm |
| **Full** | Reader + Writer + Trailer support + Exposure scoring |

### 18.2 Reader Requirements

A conforming reader MUST:
1. Parse any valid OpenRisk tag JSON
2. Extract tags from trailers and sidecars
3. Verify content_hash when requested
4. Handle unknown fields gracefully

### 18.3 Writer Requirements

A conforming writer MUST:
1. Generate valid JSON per schema
2. Use the standard scoring algorithm including exposure multipliers
3. Use only registered entity types in strict mode
4. Compute accurate content_hash and content_length
5. Include exposure context in scoring

---

## 19. Governance

### 19.1 Specification Versioning

- **Major version** (1.0, 2.0): Breaking changes
- **Minor version** (1.1, 1.2): New entities, non-breaking additions
- **Patch version** (1.0.1): Documentation corrections, bug fixes

### 19.2 Entity Registry Contributions

1. **Proposal**: Open issue with entity details and justification
2. **Discussion**: Community review (minimum 14 days)
3. **Pull Request**: Submit registry entry with documentation
4. **Approval**: Requires two maintainer approvals
5. **Release**: Included in next minor version

### 19.3 Licensing

- **Specification**: Creative Commons Attribution 4.0 (CC BY 4.0)
- **Reference SDK**: Apache License 2.0
- **Entity Registry**: Creative Commons Zero (CC0)

---

## 20. Appendices

### Appendix A: JSON Schema

See `openrisk-architecture-v2.md` for the complete JSON schema.

### Appendix B: Complete Entity Registry

See `openrisk-entity-registry-v1.md` for all 300+ entity types.

### Appendix C: Scoring Examples

#### Example 1: Healthcare Data (High Risk)

**Detections:**
- 47 SSNs (confidence 0.94)
- 23 diagnoses (confidence 0.87)

**Context:**
- Exposure: PUBLIC
- Encryption: none

**Calculation:**
```
SSN:       9 × 0.94 × (1 + ln(47)) = 9 × 0.94 × 4.85 = 41.0
Diagnosis: 8 × 0.87 × (1 + ln(23)) = 8 × 0.87 × 4.14 = 28.8

Raw content score: 69.8
Co-occurrence multiplier (direct_id + health): 2.0
Content score: 69.8 × 2.0 = 139.6

Exposure multiplier (PUBLIC): 2.5
Additional (no encryption): × 1.3 = 3.25

Final: min(100, 139.6 × 3.25) = 100

Tier: "Critical"
```

#### Example 2: Contact List (Low Risk)

**Detections:**
- 156 emails (confidence 0.99)
- 89 phones (confidence 0.91)

**Context:**
- Exposure: PRIVATE
- Encryption: platform

**Calculation:**
```
Email: 4 × 0.99 × (1 + ln(156)) = 4 × 0.99 × 6.05 = 24.0
Phone: 4 × 0.91 × (1 + ln(89)) = 4 × 0.91 × 5.49 = 20.0

Raw content score: 44.0
No co-occurrence rules triggered

Exposure multiplier (PRIVATE): 1.0

Final: min(100, 44.0 × 1.0) = 44

Tier: "Low"
```

---

## References

1. IBM Security. "Cost of a Data Breach Report 2024-2025." Ponemon Institute.
2. Sweeney, L. "Simple Demographics Often Identify People Uniquely." Carnegie Mellon, 2000.
3. OASIS. "STIX/TAXII Version 2.1." 2021.
4. The Open Group. "Open FAIR Body of Knowledge." 2025.
5. NIST. "SP 800-122: Guide to Protecting PII." 2010.

---

**End of OpenRisk Framework 1.0**

*This document is the authoritative reference for OpenRisk. All implementations should conform to this specification.*
