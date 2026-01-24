# OpenRisk Specification

**A Portable Standard for Data Sensitivity Scoring**

---

**Version:** 0.2  
**Status:** Draft  
**Authors:** Ben (scrubIQ)  
**License:** Apache 2.0  
**Last Updated:** January 2026

---

## Abstract

OpenRisk is an open standard for expressing, transporting, and verifying data sensitivity risk scores. It provides a vendor-neutral format for describing what sensitive data exists within a file, document, or data asset—enabling risk metadata to travel with data as it moves between systems, platforms, and organizations.

The standard defines:

1. **Tag Schema** — A JSON structure representing risk scores with full transparency into scoring factors
2. **Scoring Algorithm** — A deterministic, reproducible formula for computing 0-100 risk scores
3. **Entity Taxonomy** — A hierarchical classification of sensitive data types with standardized weights
4. **Trailer Format** — A universal method for attaching metadata to any file type
5. **Integration Patterns** — Adapters enabling any classification tool to output OpenRisk-compliant tags

OpenRisk does not prescribe how sensitive data should be detected—only how detection results should be expressed. This separation allows organizations to use their preferred detection tools while gaining interoperability through a common output format.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Problem Statement](#2-problem-statement)
3. [Design Principles](#3-design-principles)
4. [Tag Schema Specification](#4-tag-schema-specification)
5. [Scoring Algorithm](#5-scoring-algorithm)
6. [Entity Taxonomy](#6-entity-taxonomy)
7. [Trailer Format](#7-trailer-format)
8. [Sidecar Format](#8-sidecar-format)
9. [Content Integrity](#9-content-integrity)
10. [Integration Patterns](#10-integration-patterns)
11. [SDK Reference](#11-sdk-reference)
12. [CLI Reference](#12-cli-reference)
13. [Security Considerations](#13-security-considerations)
14. [Conformance](#14-conformance)
15. [Future Work](#15-future-work)
16. [Appendices](#16-appendices)

---

## 1. Introduction

### 1.1 Background

Every major platform has data classification capabilities:

- **AWS Macie** scans S3 buckets for sensitive data
- **Microsoft Purview** applies sensitivity labels to Office documents
- **Google Cloud DLP** inspects data across GCP services
- **Open source tools** like Presidio detect PII in text

Each tool produces valuable insights about data sensitivity. However, these insights are siloed within their respective ecosystems. When a file classified by AWS Macie is downloaded and uploaded to Azure Blob Storage, its classification is lost. When a document labeled in Microsoft Purview is exported to a data lake, the sensitivity context disappears.

This fragmentation creates significant operational challenges:

- **Redundant scanning**: The same file is scanned multiple times as it moves between systems
- **Inconsistent policies**: Different tools may classify the same data differently
- **Lost context**: Risk assessments don't travel with the data they describe
- **Audit gaps**: No unified view of data sensitivity across heterogeneous environments

### 1.2 The OpenRisk Solution

OpenRisk addresses these challenges by defining a portable, vendor-neutral format for data sensitivity metadata. Rather than replacing existing classification tools, OpenRisk provides a common output format that any tool can produce.

The key innovation is the **trailer format**—a method for appending metadata to any file type without modifying the original content. Inspired by ID3 tags (which solved metadata portability for audio files in 1996), OpenRisk trailers enable risk scores to travel with data across system boundaries.

### 1.3 Scope

OpenRisk specifies:

- **What to express**: Risk scores, detected entities, confidence levels, scoring factors
- **How to express it**: JSON schema, field definitions, validation rules
- **Where to store it**: Trailer format, sidecar files, or external registries
- **How to verify it**: Content hashing for integrity verification

OpenRisk does not specify:

- **How to detect sensitive data**: Detection is tool-specific
- **What policies to enforce**: Policy decisions remain with organizations
- **How to remediate risks**: Remediation is out of scope

### 1.4 Terminology

| Term | Definition |
|------|------------|
| **Tag** | An OpenRisk JSON structure describing a data asset's sensitivity |
| **Entity** | A detected instance of sensitive data (e.g., an SSN, email address) |
| **Entity Type** | A category of sensitive data (e.g., "ssn", "credit_card") |
| **Score** | A normalized 0-100 value representing overall sensitivity risk |
| **Tier** | A human-readable risk level (Critical, High, Medium, Low, Minimal) |
| **Trailer** | OpenRisk metadata appended to a file |
| **Sidecar** | A separate file containing OpenRisk metadata |
| **Generator** | The tool that produced the OpenRisk tag |

---

## 2. Problem Statement

### 2.1 The Multi-Cloud Classification Problem

Modern organizations operate across multiple cloud providers, on-premises systems, and SaaS applications. Data flows continuously between these environments:

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

Each transition represents a classification boundary. Metadata from the source system is typically not preserved in the destination.

### 2.2 Consequences

**Redundant Compute Costs**

Organizations scan the same data repeatedly. A 1TB dataset scanned by Macie, then re-scanned by Purview, then re-scanned by a custom tool represents 3TB of scanning costs—plus the compute time for ML inference on each scan.

**Inconsistent Risk Assessments**

Different tools have different capabilities and thresholds. Tool A might report 5 SSNs with high confidence; Tool B might report 7 SSNs with varying confidence. Without a common format, reconciling these assessments requires manual effort.

**Audit and Compliance Gaps**

Regulations like HIPAA, GDPR, and CCPA require organizations to know where sensitive data resides. When classification metadata is fragmented across tools, producing a unified inventory becomes a significant undertaking.

**Delayed Incident Response**

When a data breach occurs, responders need to quickly assess what sensitive data was exposed. If classification metadata is unavailable or inconsistent, this assessment takes longer—increasing potential harm.

### 2.3 Why Existing Solutions Fall Short

**Vendor Lock-in**

Proprietary classification formats (Purview labels, Macie findings) are designed for their respective ecosystems. Exporting this metadata for use elsewhere requires custom integration work.

**No File-Level Portability**

Existing solutions store classification metadata in databases or APIs, separate from the files themselves. When files move, metadata doesn't follow automatically.

**Schema Incompatibility**

Each tool defines its own entity types, confidence scales, and output formats. "US_SSN" in Presidio is "US_SOCIAL_SECURITY_NUMBER" in Macie is "Social Security Number" in Purview. Mapping between these requires ongoing maintenance.

### 2.4 The Opportunity

A successful standard would:

1. **Travel with data**: Metadata attached to files, not stored separately
2. **Be tool-agnostic**: Any scanner can output it, any system can read it
3. **Provide transparency**: Scores are reproducible from documented inputs
4. **Enable interoperability**: Common entity taxonomy across tools
5. **Preserve integrity**: Verify that content hasn't changed since classification

---

## 3. Design Principles

OpenRisk is guided by the following principles:

### 3.1 Portability Over Features

The primary goal is enabling metadata to travel with data. Features that would complicate portability are deferred or excluded.

### 3.2 Transparency Over Opacity

Every OpenRisk score can be traced back to its inputs. The scoring algorithm is fully documented. Organizations can verify scores independently.

### 3.3 Simplicity Over Completeness

The specification covers common use cases well rather than attempting to address every edge case. Extensions are possible but not required.

### 3.4 Detection-Agnostic

OpenRisk does not mandate how sensitive data should be detected. Organizations may use commercial tools, open source libraries, custom models, or manual review. The standard only specifies how to express results.

### 3.5 Backward Compatible Evolution

Future versions will maintain backward compatibility. A tag valid in v0.2 will remain valid in v1.0.

### 3.6 Open Governance

The specification, reference implementation, and entity taxonomy are open source under Apache 2.0. Community contributions are welcome through standard open source processes.

---

## 4. Tag Schema Specification

### 4.1 Overview

An OpenRisk tag is a JSON object containing metadata about a data asset's sensitivity. Tags may be embedded in files (via trailer), stored in sidecar files, or maintained in external registries.

### 4.2 Complete Schema

```json
{
  "openrisk": {
    "version": "0.2",
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
        },
        {
          "type": "phone",
          "category": "contact.phone",
          "count": 89,
          "confidence_avg": 0.91,
          "weight": 4
        }
      ],
      "co_occurrence_rules": ["direct_id + health"],
      "co_occurrence_multiplier": 1.5,
      "raw_score": 67.3,
      "filtered": [
        {
          "type": "date",
          "count": 234,
          "confidence_avg": 0.72,
          "reason": "below_threshold"
        }
      ]
    },
    "scoring": {
      "algorithm": "openrisk-v0.2-standard",
      "confidence_threshold": 0.8,
      "mode": "strict"
    },
    "provenance": {
      "generator": "openrisk-scan/0.1.0",
      "generator_org": "scrubiq",
      "generated_at": "2026-01-24T14:32:00Z",
      "source_tool": "phi-bert-v1.2",
      "scan_duration_ms": 1247
    },
    "signature": null
  }
}
```

### 4.3 Field Definitions

#### 4.3.1 Root Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `openrisk` | object | Yes | Container for all OpenRisk metadata |

#### 4.3.2 Core Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | string | Yes | Specification version (e.g., "0.2") |
| `score` | integer | Yes | Normalized risk score, 0-100 |
| `tier` | string | Yes | Risk tier: "Critical", "High", "Medium", "Low", "Minimal" |
| `content_hash` | string | Yes | Hash of original content (format: "algorithm:hexdigest") |
| `content_length` | integer | Yes | Original content length in bytes |

#### 4.3.3 Factors Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `entities` | array | Yes | List of detected entity types (see 4.3.4) |
| `co_occurrence_rules` | array | No | List of triggered co-occurrence rule names |
| `co_occurrence_multiplier` | number | No | Applied multiplier from co-occurrence rules (default: 1.0) |
| `raw_score` | number | No | Pre-normalization score for debugging |
| `filtered` | array | No | Detections excluded from scoring (see 4.3.5) |

#### 4.3.4 Entity Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Entity type identifier (see Section 6) |
| `category` | string | Yes | Hierarchical category (e.g., "direct_identifier.national_id") |
| `count` | integer | Yes | Number of instances detected |
| `confidence_avg` | number | Yes | Average confidence score, 0.0-1.0 |
| `weight` | integer | Yes | Entity weight used in scoring, 1-10 |

#### 4.3.5 Filtered Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Entity type identifier |
| `count` | integer | Yes | Number of instances detected |
| `confidence_avg` | number | Yes | Average confidence score |
| `reason` | string | Yes | Reason for filtering (e.g., "below_threshold", "allowlisted") |

#### 4.3.6 Scoring Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `algorithm` | string | Yes | Scoring algorithm identifier |
| `confidence_threshold` | number | Yes | Minimum confidence for inclusion (0.0-1.0) |
| `mode` | string | Yes | "strict" (standard weights only) or "relaxed" (custom weights allowed) |

#### 4.3.7 Provenance Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `generator` | string | Yes | Tool that generated the tag (format: "name/version") |
| `generator_org` | string | No | Organization that produced the generator |
| `generated_at` | string | Yes | ISO 8601 timestamp of tag generation |
| `source_tool` | string | No | Underlying detection tool if different from generator |
| `scan_duration_ms` | integer | No | Time taken to scan content in milliseconds |

#### 4.3.8 Signature Field

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `signature` | string | No | Cryptographic signature for authenticity (format: "algorithm:base64") |

### 4.4 Validation Rules

1. `version` MUST match pattern `^\d+\.\d+$`
2. `score` MUST be an integer in range [0, 100]
3. `tier` MUST be one of: "Critical", "High", "Medium", "Low", "Minimal"
4. `content_hash` MUST match pattern `^(sha256|sha384|sha512):[a-f0-9]+$`
5. `content_length` MUST be a non-negative integer
6. `entities` MUST contain at least one entity if `score` > 0
7. `confidence_avg` MUST be in range [0.0, 1.0]
8. `weight` MUST be an integer in range [1, 10]
9. `generated_at` MUST be a valid ISO 8601 timestamp

### 4.5 Minimal Valid Tag

The smallest valid OpenRisk tag:

```json
{
  "openrisk": {
    "version": "0.2",
    "score": 0,
    "tier": "Minimal",
    "content_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "content_length": 0,
    "factors": {
      "entities": []
    },
    "scoring": {
      "algorithm": "openrisk-v0.2-standard",
      "confidence_threshold": 0.8,
      "mode": "strict"
    },
    "provenance": {
      "generator": "openrisk-scan/0.1.0",
      "generated_at": "2026-01-24T14:32:00Z"
    }
  }
}
```

---

## 5. Scoring Algorithm

### 5.1 Overview

The OpenRisk scoring algorithm converts a list of entity detections into a single 0-100 score. The algorithm is deterministic: given the same inputs, it always produces the same output.

### 5.2 Algorithm Identifier

The current algorithm is identified as `openrisk-v0.2-standard`. Future versions may introduce alternative algorithms, but this identifier ensures reproducibility.

### 5.3 Inputs

The scoring algorithm requires:

1. **Entity detections**: List of (type, count, confidence) tuples
2. **Entity weights**: Mapping of entity types to weights (1-10)
3. **Confidence threshold**: Minimum confidence for inclusion (default: 0.8)
4. **Co-occurrence rules**: Rules that apply multipliers when certain entity types appear together

### 5.4 Algorithm Steps

#### Step 1: Filter by Confidence

Remove detections below the confidence threshold:

```python
filtered_entities = [
    e for e in entities 
    if e.confidence_avg >= confidence_threshold
]
```

Record filtered detections in `factors.filtered` for transparency.

#### Step 2: Compute Base Score

For each entity type, compute its contribution:

```python
base_score = 0
for entity in filtered_entities:
    weight = get_weight(entity.type)  # 1-10
    count_factor = min(log2(entity.count + 1), 5)  # Diminishing returns
    confidence_factor = entity.confidence_avg
    
    contribution = weight * count_factor * confidence_factor
    base_score += contribution
```

The logarithmic count factor provides diminishing returns: finding 1000 SSNs is worse than finding 10, but not 100x worse.

#### Step 3: Apply Co-occurrence Multipliers

Certain combinations of entity types indicate elevated risk. For example, SSNs appearing alongside medical diagnoses suggests healthcare data subject to HIPAA.

```python
multiplier = 1.0
triggered_rules = []

for rule in co_occurrence_rules:
    if rule.matches(filtered_entities):
        multiplier = max(multiplier, rule.multiplier)
        triggered_rules.append(rule.name)

adjusted_score = base_score * multiplier
```

#### Step 4: Normalize to 0-100

```python
# Normalize using sigmoid-like function
# Calibrated so typical scores fall in useful range
normalized = 100 * (1 - exp(-adjusted_score / 50))
score = round(min(normalized, 100))
```

#### Step 5: Assign Tier

```python
if score >= 86:
    tier = "Critical"
elif score >= 61:
    tier = "High"
elif score >= 31:
    tier = "Medium"
elif score >= 11:
    tier = "Low"
else:
    tier = "Minimal"
```

### 5.5 Co-occurrence Rules

The following co-occurrence rules are defined in v0.2:

| Rule Name | Condition | Multiplier | Rationale |
|-----------|-----------|------------|-----------|
| `direct_id + health` | SSN/MRN + diagnosis/treatment | 1.5 | HIPAA protected combination |
| `direct_id + financial` | SSN + credit_card/bank_account | 1.4 | Identity theft risk |
| `direct_id + minor` | Any direct_id + age < 18 indicator | 1.5 | COPPA considerations |
| `health + contact` | diagnosis + address/phone | 1.3 | Healthcare contact tracing |
| `bulk_pii` | 5+ distinct PII types | 1.3 | Comprehensive profile risk |

### 5.6 Tier Thresholds

| Tier | Score Range | Interpretation |
|------|-------------|----------------|
| Critical | 86-100 | Immediate action required; highest protection level |
| High | 61-85 | Significant risk; restricted handling required |
| Medium | 31-60 | Moderate risk; standard protection controls |
| Low | 11-30 | Limited risk; basic controls sufficient |
| Minimal | 0-10 | Negligible sensitivity |

### 5.7 Reference Implementation

```python
import math
from typing import List, Tuple
from dataclasses import dataclass

@dataclass
class EntityDetection:
    type: str
    count: int
    confidence_avg: float

class RiskScorer:
    VERSION = "0.2"
    ALGORITHM = "openrisk-v0.2-standard"
    
    CO_OCCURRENCE_RULES = [
        {
            "name": "direct_id + health",
            "requires": [
                {"categories": ["direct_identifier"]},
                {"categories": ["health"]},
            ],
            "multiplier": 1.5,
        },
        {
            "name": "direct_id + financial",
            "requires": [
                {"categories": ["direct_identifier"]},
                {"types": ["credit_card", "bank_account"]},
            ],
            "multiplier": 1.4,
        },
        {
            "name": "bulk_pii",
            "min_distinct_types": 5,
            "multiplier": 1.3,
        },
    ]
    
    TIER_THRESHOLDS = [
        (86, "Critical"),
        (61, "High"),
        (31, "Medium"),
        (11, "Low"),
        (0, "Minimal"),
    ]
    
    def __init__(self, confidence_threshold: float = 0.8):
        self.confidence_threshold = confidence_threshold
        self.detections: List[EntityDetection] = []
        self.filtered: List[dict] = []
    
    def add_detection(
        self, 
        entity_type: str, 
        count: int = 1, 
        confidence: float = 1.0
    ):
        """Add a detection to the scorer."""
        if confidence < self.confidence_threshold:
            self.filtered.append({
                "type": entity_type,
                "count": count,
                "confidence_avg": confidence,
                "reason": "below_threshold"
            })
            return
        
        # Aggregate by type
        for det in self.detections:
            if det.type == entity_type:
                # Update running average
                total_count = det.count + count
                det.confidence_avg = (
                    det.confidence_avg * det.count + 
                    confidence * count
                ) / total_count
                det.count = total_count
                return
        
        self.detections.append(EntityDetection(
            type=entity_type,
            count=count,
            confidence_avg=confidence
        ))
    
    def calculate_score(self) -> Tuple[int, float, List[str], float]:
        """
        Calculate the risk score.
        
        Returns:
            (score, raw_score, triggered_rules, multiplier)
        """
        if not self.detections:
            return (0, 0.0, [], 1.0)
        
        # Step 2: Compute base score
        base_score = 0.0
        for det in self.detections:
            weight = get_entity_weight(det.type)
            count_factor = min(math.log2(det.count + 1), 5)
            contribution = weight * count_factor * det.confidence_avg
            base_score += contribution
        
        # Step 3: Apply co-occurrence multipliers
        multiplier, triggered_rules = self._check_co_occurrence()
        adjusted_score = base_score * multiplier
        
        # Step 4: Normalize to 0-100
        normalized = 100 * (1 - math.exp(-adjusted_score / 50))
        score = round(min(normalized, 100))
        
        return (score, base_score, triggered_rules, multiplier)
    
    def _check_co_occurrence(self) -> Tuple[float, List[str]]:
        """Check co-occurrence rules and return max multiplier."""
        multiplier = 1.0
        triggered = []
        
        categories_present = set()
        types_present = set()
        
        for det in self.detections:
            types_present.add(det.type)
            category = get_entity_category(det.type)
            # Add all parent categories
            parts = category.split(".")
            for i in range(len(parts)):
                categories_present.add(".".join(parts[:i+1]))
        
        for rule in self.CO_OCCURRENCE_RULES:
            if "requires" in rule:
                if self._rule_matches(rule, categories_present, types_present):
                    if rule["multiplier"] > multiplier:
                        multiplier = rule["multiplier"]
                        triggered.append(rule["name"])
            
            if "min_distinct_types" in rule:
                if len(types_present) >= rule["min_distinct_types"]:
                    if rule["multiplier"] > multiplier:
                        multiplier = rule["multiplier"]
                        triggered.append(rule["name"])
        
        return (multiplier, triggered)
    
    def _rule_matches(
        self, 
        rule: dict, 
        categories: set, 
        types: set
    ) -> bool:
        """Check if a co-occurrence rule matches."""
        for requirement in rule["requires"]:
            matched = False
            
            if "categories" in requirement:
                for cat in requirement["categories"]:
                    if cat in categories:
                        matched = True
                        break
            
            if "types" in requirement:
                for t in requirement["types"]:
                    if t in types:
                        matched = True
                        break
            
            if not matched:
                return False
        
        return True
    
    def score_to_tier(self, score: int) -> str:
        """Convert score to tier name."""
        for threshold, tier in self.TIER_THRESHOLDS:
            if score >= threshold:
                return tier
        return "Minimal"
    
    def generate(
        self,
        content_hash: str,
        content_length: int,
        generator: str = "openrisk-sdk/0.1.0",
    ) -> dict:
        """Generate a complete OpenRisk tag."""
        score, raw_score, triggered_rules, multiplier = self.calculate_score()
        tier = self.score_to_tier(score)
        
        return {
            "openrisk": {
                "version": self.VERSION,
                "score": score,
                "tier": tier,
                "content_hash": content_hash,
                "content_length": content_length,
                "factors": {
                    "entities": [
                        {
                            "type": d.type,
                            "category": get_entity_category(d.type),
                            "count": d.count,
                            "confidence_avg": round(d.confidence_avg, 3),
                            "weight": get_entity_weight(d.type),
                        }
                        for d in self.detections
                    ],
                    "co_occurrence_rules": triggered_rules,
                    "co_occurrence_multiplier": multiplier,
                    "raw_score": round(raw_score, 2),
                    "filtered": self.filtered,
                },
                "scoring": {
                    "algorithm": self.ALGORITHM,
                    "confidence_threshold": self.confidence_threshold,
                    "mode": "strict",
                },
                "provenance": {
                    "generator": generator,
                    "generated_at": datetime.utcnow().isoformat() + "Z",
                },
            }
        }
```

---

## 6. Entity Taxonomy

### 6.1 Overview

The entity taxonomy defines all sensitive data types recognized by OpenRisk. Each entity type has:

- **Identifier**: Lowercase, underscore-separated name (e.g., "ssn", "credit_card")
- **Category**: Hierarchical classification (e.g., "direct_identifier.national_id")
- **Weight**: Default scoring weight (1-10)
- **Aliases**: Alternative names that resolve to this type

### 6.2 Category Hierarchy

```
sensitive_data
├── direct_identifier
│   ├── national_id (ssn, sin, aadhaar, etc.)
│   ├── financial (credit_card, bank_account, etc.)
│   ├── government (passport, drivers_license, etc.)
│   └── biometric (fingerprint, face_encoding, etc.)
├── health
│   ├── identifier (mrn, health_plan_id, npi, etc.)
│   ├── diagnosis (icd_code, condition, etc.)
│   ├── treatment (procedure, medication, etc.)
│   └── provider (physician, facility, etc.)
├── contact
│   ├── electronic (email, ip_address, etc.)
│   ├── phone (phone, fax, etc.)
│   └── physical (address, postal_code, etc.)
├── demographic
│   ├── name (full_name, first_name, etc.)
│   ├── personal (date_of_birth, age, gender, etc.)
│   └── employment (employer, job_title, etc.)
├── financial
│   ├── account (iban, routing_number, etc.)
│   ├── transaction (amount, merchant, etc.)
│   └── investment (cusip, isin, etc.)
├── credential
│   ├── authentication (password, pin, etc.)
│   ├── api_key (aws_key, stripe_key, etc.)
│   └── certificate (private_key, certificate, etc.)
└── legal
    ├── case (case_number, docket, etc.)
    └── privilege (attorney_client, work_product, etc.)
```

### 6.3 Entity Type Reference

#### 6.3.1 Direct Identifiers (Weight: 8-10)

| Type | Category | Weight | Description |
|------|----------|--------|-------------|
| `ssn` | direct_identifier.national_id | 9 | US Social Security Number |
| `sin` | direct_identifier.national_id | 9 | Canadian Social Insurance Number |
| `aadhaar` | direct_identifier.national_id | 9 | Indian Aadhaar Number |
| `nino` | direct_identifier.national_id | 9 | UK National Insurance Number |
| `credit_card` | direct_identifier.financial | 8 | Credit/debit card number |
| `bank_account` | direct_identifier.financial | 8 | Bank account number |
| `passport` | direct_identifier.government | 8 | Passport number |
| `drivers_license` | direct_identifier.government | 8 | Driver's license number |
| `tax_id` | direct_identifier.national_id | 9 | Tax identification number (EIN, ITIN) |

#### 6.3.2 Healthcare (Weight: 6-8)

| Type | Category | Weight | Description |
|------|----------|--------|-------------|
| `mrn` | health.identifier | 7 | Medical Record Number |
| `health_plan_id` | health.identifier | 7 | Health insurance beneficiary ID |
| `npi` | health.identifier | 6 | National Provider Identifier |
| `dea_number` | health.identifier | 6 | DEA registration number |
| `diagnosis` | health.diagnosis | 8 | Medical diagnosis or condition |
| `icd_code` | health.diagnosis | 8 | ICD-10 diagnosis code |
| `medication` | health.treatment | 7 | Prescription drug name |
| `procedure` | health.treatment | 7 | Medical procedure |
| `lab_result` | health.treatment | 7 | Laboratory test result |

#### 6.3.3 Contact Information (Weight: 3-5)

| Type | Category | Weight | Description |
|------|----------|--------|-------------|
| `email` | contact.electronic | 4 | Email address |
| `phone` | contact.phone | 4 | Phone number |
| `fax` | contact.phone | 4 | Fax number |
| `address` | contact.physical | 5 | Street address |
| `postal_code` | contact.physical | 3 | ZIP/postal code |
| `ip_address` | contact.electronic | 4 | IP address |
| `mac_address` | contact.electronic | 4 | MAC address |
| `url` | contact.electronic | 3 | Personal URL/website |

#### 6.3.4 Demographics (Weight: 3-6)

| Type | Category | Weight | Description |
|------|----------|--------|-------------|
| `full_name` | demographic.name | 5 | Full name |
| `first_name` | demographic.name | 3 | First/given name |
| `last_name` | demographic.name | 3 | Last/family name |
| `date_of_birth` | demographic.personal | 6 | Date of birth |
| `age` | demographic.personal | 4 | Age |
| `gender` | demographic.personal | 3 | Gender |
| `race_ethnicity` | demographic.personal | 5 | Race or ethnicity |
| `religion` | demographic.personal | 5 | Religious affiliation |
| `sexual_orientation` | demographic.personal | 6 | Sexual orientation |

#### 6.3.5 Credentials (Weight: 7-9)

| Type | Category | Weight | Description |
|------|----------|--------|-------------|
| `password` | credential.authentication | 9 | Password or passphrase |
| `pin` | credential.authentication | 8 | PIN code |
| `security_question` | credential.authentication | 7 | Security question answer |
| `aws_access_key` | credential.api_key | 9 | AWS access key ID |
| `aws_secret_key` | credential.api_key | 9 | AWS secret access key |
| `api_key` | credential.api_key | 8 | Generic API key |
| `private_key` | credential.certificate | 9 | Private key material |
| `jwt_token` | credential.api_key | 7 | JSON Web Token |

### 6.4 Aliases

Common alternative names resolve to standard types:

```yaml
aliases:
  # SSN variations
  social_security: ssn
  social_security_number: ssn
  us_ssn: ssn
  
  # Credit card variations
  cc: credit_card
  card_number: credit_card
  pan: credit_card
  
  # Healthcare
  medical_record: mrn
  medical_record_number: mrn
  health_insurance_id: health_plan_id
  
  # Contact
  phone_number: phone
  telephone: phone
  mobile: phone
  email_address: email
  street_address: address
  mailing_address: address
  zip_code: postal_code
  
  # Names
  name: full_name
  given_name: first_name
  surname: last_name
  family_name: last_name
  
  # Dates
  dob: date_of_birth
  birthdate: date_of_birth
  birthday: date_of_birth
```

### 6.5 Strict vs Relaxed Mode

In **strict mode** (default), only entity types present in the official registry are accepted. This ensures consistency across implementations.

In **relaxed mode**, custom entity types are allowed. Custom types:
- MUST use the prefix `custom_` (e.g., "custom_employee_badge")
- MUST specify a weight explicitly
- SHOULD specify a category

```python
# Strict mode (default)
scorer = RiskScorer(mode="strict")
scorer.add_detection("custom_field", count=1)  # Raises UnknownEntityError

# Relaxed mode
scorer = RiskScorer(mode="relaxed")
scorer.add_detection("custom_employee_badge", count=1, weight=5)  # OK
```

---

## 7. Trailer Format

### 7.1 Overview

The trailer format enables attaching OpenRisk metadata to any file type without modifying the original content. This is inspired by ID3 tags for MP3 files.

### 7.2 Structure

```
[Original file content - unchanged]
[Newline]
---OPENRISK-TAG-V1---
[Newline]
{OpenRisk tag JSON, compact, single line}
[Newline]
---END-OPENRISK-TAG---
```

### 7.3 Markers

| Marker | Bytes | Purpose |
|--------|-------|---------|
| Start marker | `\n---OPENRISK-TAG-V1---\n` | Signals beginning of trailer |
| End marker | `\n---END-OPENRISK-TAG---` | Signals end of trailer |

The markers are designed to be:
- Human-readable when viewing file in text editor
- Unlikely to appear in normal file content
- Easy to locate when reading from end of file

### 7.4 Content Requirements

1. Tag JSON MUST be compact (no pretty-printing, no newlines within JSON)
2. Tag JSON MUST be valid UTF-8
3. `content_hash` MUST be computed on original content (excluding trailer)
4. `content_length` MUST equal original content length (excluding trailer)

### 7.5 Writing Trailers

```python
import hashlib
import json

START_MARKER = b'\n---OPENRISK-TAG-V1---\n'
END_MARKER = b'\n---END-OPENRISK-TAG---'

def write_trailer(filepath: str, tag: dict) -> None:
    """Append OpenRisk trailer to file."""
    # Read original content
    with open(filepath, 'rb') as f:
        original = f.read()
    
    # Verify hash matches
    actual_hash = "sha256:" + hashlib.sha256(original).hexdigest()
    if tag["openrisk"]["content_hash"] != actual_hash:
        raise ValueError("Content hash mismatch")
    
    # Verify length matches
    if tag["openrisk"]["content_length"] != len(original):
        raise ValueError("Content length mismatch")
    
    # Build trailer
    tag_json = json.dumps(tag, separators=(',', ':'))
    trailer = START_MARKER + tag_json.encode('utf-8') + END_MARKER
    
    # Write original + trailer
    with open(filepath, 'wb') as f:
        f.write(original)
        f.write(trailer)
```

### 7.6 Reading Trailers

```python
def read_trailer(filepath: str) -> tuple[bytes, dict | None]:
    """
    Read file and extract OpenRisk trailer if present.
    
    Returns:
        (original_content, tag_dict or None)
    """
    with open(filepath, 'rb') as f:
        content = f.read()
    
    # Search for markers from end (more efficient for large files)
    end_pos = content.rfind(END_MARKER)
    if end_pos == -1:
        return content, None
    
    start_pos = content.rfind(START_MARKER)
    if start_pos == -1:
        return content, None
    
    # Extract JSON
    tag_start = start_pos + len(START_MARKER)
    tag_json = content[tag_start:end_pos]
    
    try:
        tag = json.loads(tag_json.decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return content, None
    
    # Extract original using content_length
    content_length = tag['openrisk']['content_length']
    original = content[:content_length]
    
    # Verify integrity
    actual_hash = "sha256:" + hashlib.sha256(original).hexdigest()
    expected_hash = tag['openrisk']['content_hash']
    
    if actual_hash != expected_hash:
        # Content modified after tagging
        return content, None
    
    return original, tag
```

### 7.7 Stripping Trailers

```python
def strip_trailer(
    input_path: str, 
    output_path: str = None
) -> dict | None:
    """
    Remove trailer and write clean file.
    
    Returns:
        Extracted tag, or None if no trailer
    """
    original, tag = read_trailer(input_path)
    
    if tag is None:
        return None
    
    output_path = output_path or input_path
    with open(output_path, 'wb') as f:
        f.write(original)
    
    return tag
```

### 7.8 Compatibility Considerations

**File types where trailers work well:**
- Text files (CSV, JSON, TXT, log files, source code)
- Delimiter-separated data
- Line-oriented formats

**File types where trailers may cause issues:**
- Binary formats with strict structure (executables, images)
- Formats that validate checksums (some archives)
- Formats where trailing data is parsed (some JSON parsers)

For binary formats, consider using sidecar files (Section 8) instead.

---

## 8. Sidecar Format

### 8.1 Overview

Sidecar files provide an alternative to trailers for cases where modifying the original file is undesirable or problematic.

### 8.2 Naming Convention

For a file `document.csv`, the sidecar file is `document.csv.openrisk.json`.

```
/data/
├── document.csv
├── document.csv.openrisk.json    ← Sidecar
├── report.pdf
└── report.pdf.openrisk.json      ← Sidecar
```

### 8.3 Sidecar Content

The sidecar contains the same JSON structure as would appear in a trailer:

```json
{
  "openrisk": {
    "version": "0.2",
    "score": 74,
    "tier": "High",
    "content_hash": "sha256:3a7bd3e2360a3d29...",
    ...
  }
}
```

### 8.4 When to Use Sidecars

| Scenario | Recommendation |
|----------|----------------|
| Text files (CSV, JSON, TXT) | Trailer preferred |
| Binary files (images, executables) | Sidecar required |
| Read-only files | Sidecar required |
| Shared files (multiple users) | Sidecar preferred |
| Version-controlled files | Sidecar preferred |
| Archives (ZIP, TAR) | Sidecar required |

### 8.5 Sidecar Synchronization

Sidecars can become stale if the original file is modified. Consumers SHOULD verify `content_hash` before trusting sidecar data:

```python
def read_sidecar(filepath: str) -> dict | None:
    """Read and validate sidecar file."""
    sidecar_path = filepath + ".openrisk.json"
    
    if not os.path.exists(sidecar_path):
        return None
    
    with open(sidecar_path) as f:
        tag = json.load(f)
    
    # Verify content hash
    with open(filepath, 'rb') as f:
        actual_hash = "sha256:" + hashlib.sha256(f.read()).hexdigest()
    
    expected_hash = tag['openrisk']['content_hash']
    
    if actual_hash != expected_hash:
        # File modified since tagging - sidecar is stale
        return None
    
    return tag
```

---

## 9. Content Integrity

### 9.1 Hash Algorithm

OpenRisk uses SHA-256 as the default hash algorithm. The hash is computed on the original file content, excluding any trailer.

Format: `sha256:<64-character-hex-digest>`

Example: `sha256:3a7bd3e2360a3d29eea436fcfb7e44c735d117c42d1c1835420b6b9942dd4f1b`

### 9.2 Supported Algorithms

| Algorithm | Format Prefix | Status |
|-----------|---------------|--------|
| SHA-256 | `sha256:` | Default, required support |
| SHA-384 | `sha384:` | Optional |
| SHA-512 | `sha512:` | Optional |

MD5 and SHA-1 are explicitly not supported due to known vulnerabilities.

### 9.3 Verification Process

```python
def verify_tag(filepath: str, tag: dict) -> bool:
    """Verify tag matches current file content."""
    with open(filepath, 'rb') as f:
        content = f.read()
    
    # If file has trailer, extract original
    if content.endswith(END_MARKER):
        content_length = tag['openrisk']['content_length']
        content = content[:content_length]
    
    # Compute actual hash
    algorithm = tag['openrisk']['content_hash'].split(':')[0]
    
    if algorithm == 'sha256':
        actual = hashlib.sha256(content).hexdigest()
    elif algorithm == 'sha384':
        actual = hashlib.sha384(content).hexdigest()
    elif algorithm == 'sha512':
        actual = hashlib.sha512(content).hexdigest()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    expected = tag['openrisk']['content_hash'].split(':')[1]
    
    return actual == expected
```

### 9.4 Handling Hash Mismatches

When `content_hash` doesn't match the current file:

1. **Log the mismatch** for audit purposes
2. **Do not trust the tag** - treat as if no tag exists
3. **Optionally re-scan** the file to generate a new tag

```python
def get_valid_tag(filepath: str) -> dict | None:
    """Get tag only if content integrity is verified."""
    _, tag = read_trailer(filepath)
    
    if tag is None:
        tag = read_sidecar(filepath)
    
    if tag is None:
        return None
    
    if not verify_tag(filepath, tag):
        logger.warning(f"Hash mismatch for {filepath}, tag discarded")
        return None
    
    return tag
```

---

## 10. Integration Patterns

### 10.1 Adapter Pattern

Most organizations have existing classification tools. The adapter pattern bridges these tools to OpenRisk:

```python
# Generic adapter structure
class ToolAdapter:
    name: str
    
    # Mapping from tool's entity types to OpenRisk types
    ENTITY_MAP: dict[str, str | None]
    
    def convert(
        self, 
        results: Any,
        content_hash: str,
        content_length: int,
    ) -> OpenRiskTag:
        scorer = RiskScorer()
        
        for detection in self.extract_detections(results):
            openrisk_type = self.ENTITY_MAP.get(detection.type)
            if openrisk_type:
                scorer.add_detection(
                    openrisk_type,
                    count=detection.count,
                    confidence=detection.confidence,
                )
        
        return scorer.generate(content_hash, content_length)
```

### 10.2 AWS Macie Adapter

```python
MACIE_TO_OPENRISK = {
    # Direct identifiers
    "AWS_CREDENTIALS": "aws_access_key",
    "BANK_ACCOUNT_NUMBER": "bank_account",
    "CREDIT_CARD_NUMBER": "credit_card",
    "US_SOCIAL_SECURITY_NUMBER": "ssn",
    "US_INDIVIDUAL_TAX_IDENTIFICATION_NUMBER": "tax_id",
    "US_PASSPORT_NUMBER": "passport",
    "US_DRIVER_LICENSE": "drivers_license",
    
    # Healthcare
    "USA_HEALTH_INSURANCE_CLAIM_NUMBER": "health_plan_id",
    "USA_MEDICARE_BENEFICIARY_IDENTIFIER": "health_plan_id",
    "USA_NATIONAL_PROVIDER_IDENTIFIER": "npi",
    "USA_DEA_NUMBER": "dea_number",
    
    # Contact
    "EMAIL_ADDRESS": "email",
    "PHONE_NUMBER": "phone",
    "ADDRESS": "address",
    
    # Financial
    "IBAN_CODE": "iban",
    "SWIFT_CODE": "swift_bic",
    
    # Skip (too vague or not sensitive)
    "NAME": None,
    "DATE": None,
    "AGE": None,
    "LATITUDE_LONGITUDE": None,
}

def from_macie_findings(findings: list) -> OpenRiskTag:
    """Convert AWS Macie findings to OpenRisk tag."""
    scorer = RiskScorer()
    content_hash = None
    content_length = 0
    
    for finding in findings:
        # Extract content info from first finding
        if content_hash is None:
            resource = finding.get("resourcesAffected", {})
            s3_object = resource.get("s3Object", {})
            content_hash = "sha256:" + s3_object.get("eTag", "").replace('"', '')
            content_length = s3_object.get("size", 0)
        
        # Extract detections
        classification = finding.get("classificationDetails", {})
        result = classification.get("result", {})
        
        for sensitive_data in result.get("sensitiveData", []):
            entity_type = sensitive_data.get("category")
            openrisk_type = MACIE_TO_OPENRISK.get(entity_type)
            
            if openrisk_type:
                for detection in sensitive_data.get("detections", []):
                    scorer.add_detection(
                        openrisk_type,
                        count=detection.get("count", 1),
                        confidence=0.95,  # Macie doesn't expose confidence
                    )
    
    return scorer.generate(
        content_hash=content_hash,
        content_length=content_length,
        generator="macie-adapter/1.0",
    )
```

### 10.3 Google Cloud DLP Adapter

```python
DLP_TO_OPENRISK = {
    # Direct identifiers
    "US_SOCIAL_SECURITY_NUMBER": "ssn",
    "CREDIT_CARD_NUMBER": "credit_card",
    "US_BANK_ROUTING_MICR": "routing_number",
    "US_PASSPORT": "passport",
    "US_DRIVERS_LICENSE_NUMBER": "drivers_license",
    "US_INDIVIDUAL_TAXPAYER_IDENTIFICATION_NUMBER": "tax_id",
    "US_EMPLOYER_IDENTIFICATION_NUMBER": "tax_id",
    
    # Healthcare
    "US_HEALTHCARE_NPI": "npi",
    "US_DEA_NUMBER": "dea_number",
    "FDA_CODE": "medication",
    "ICD9_CODE": "icd_code",
    "ICD10_CODE": "icd_code",
    
    # Contact
    "EMAIL_ADDRESS": "email",
    "PHONE_NUMBER": "phone",
    "STREET_ADDRESS": "address",
    
    # Demographics
    "PERSON_NAME": "full_name",
    "DATE_OF_BIRTH": "date_of_birth",
    "AGE": "age",
    "GENDER": "gender",
    
    # Credentials
    "AUTH_TOKEN": "api_key",
    "AWS_CREDENTIALS": "aws_access_key",
    "AZURE_AUTH_TOKEN": "api_key",
    "GCP_CREDENTIALS": "api_key",
    "PASSWORD": "password",
    "ENCRYPTION_KEY": "private_key",
    
    # Skip
    "DATE": None,
    "TIME": None,
    "DOMAIN_NAME": None,
    "URL": None,
}

def from_dlp_response(response: dict, content_hash: str, content_length: int) -> OpenRiskTag:
    """Convert Google Cloud DLP response to OpenRisk tag."""
    scorer = RiskScorer()
    
    for finding in response.get("result", {}).get("findings", []):
        info_type = finding.get("infoType", {}).get("name")
        openrisk_type = DLP_TO_OPENRISK.get(info_type)
        
        if openrisk_type:
            # Map DLP likelihood to confidence
            likelihood = finding.get("likelihood", "POSSIBLE")
            confidence_map = {
                "VERY_UNLIKELY": 0.1,
                "UNLIKELY": 0.3,
                "POSSIBLE": 0.5,
                "LIKELY": 0.7,
                "VERY_LIKELY": 0.9,
            }
            confidence = confidence_map.get(likelihood, 0.5)
            
            scorer.add_detection(
                openrisk_type,
                count=1,
                confidence=confidence,
            )
    
    return scorer.generate(
        content_hash=content_hash,
        content_length=content_length,
        generator="dlp-adapter/1.0",
    )
```

### 10.4 Microsoft Presidio Adapter

```python
PRESIDIO_TO_OPENRISK = {
    # Direct identifiers
    "US_SSN": "ssn",
    "US_ITIN": "tax_id",
    "CREDIT_CARD": "credit_card",
    "US_BANK_NUMBER": "bank_account",
    "IBAN_CODE": "iban",
    "US_PASSPORT": "passport",
    "US_DRIVER_LICENSE": "drivers_license",
    
    # Healthcare
    "MEDICAL_LICENSE": "npi",
    
    # Contact
    "EMAIL_ADDRESS": "email",
    "PHONE_NUMBER": "phone",
    "IP_ADDRESS": "ip_address",
    
    # Demographics
    "PERSON": "full_name",
    
    # Credentials
    "CRYPTO": "private_key",
    "AWS_ACCESS_KEY": "aws_access_key",
    "AWS_SECRET_KEY": "aws_secret_key",
    "AZURE_AUTH_TOKEN": "api_key",
    
    # Skip (too vague)
    "LOCATION": None,
    "DATE_TIME": None,
    "NRP": None,  # Nationalities, religions, political groups
    "URL": None,
}

def from_presidio_results(
    results: list,  # List of RecognizerResult
    content_hash: str,
    content_length: int,
) -> OpenRiskTag:
    """Convert Presidio analyzer results to OpenRisk tag."""
    scorer = RiskScorer(confidence_threshold=0.7)
    
    for result in results:
        openrisk_type = PRESIDIO_TO_OPENRISK.get(result.entity_type)
        
        if openrisk_type:
            scorer.add_detection(
                openrisk_type,
                count=1,
                confidence=result.score,
            )
    
    return scorer.generate(
        content_hash=content_hash,
        content_length=content_length,
        generator="presidio-adapter/1.0",
    )
```

### 10.5 Microsoft Purview Adapter

```python
# Purview uses "Sensitive Information Types" with GUIDs
# This maps common SIT names to OpenRisk

PURVIEW_TO_OPENRISK = {
    # Direct identifiers (US)
    "U.S. Social Security Number (SSN)": "ssn",
    "U.S. / U.K. Passport Number": "passport",
    "U.S. Driver's License Number": "drivers_license",
    "U.S. Individual Taxpayer Identification Number (ITIN)": "tax_id",
    "Credit Card Number": "credit_card",
    "U.S. Bank Account Number": "bank_account",
    "ABA Routing Number": "routing_number",
    "SWIFT Code": "swift_bic",
    "International Banking Account Number (IBAN)": "iban",
    
    # Healthcare
    "U.S. DEA Number": "dea_number",
    "U.S. National Provider Identifier (NPI)": "npi",
    "International Classification of Diseases (ICD-10-CM)": "icd_code",
    "International Classification of Diseases (ICD-9-CM)": "icd_code",
    
    # Contact
    "Email Address": "email",
    "U.S. Phone Number": "phone",
    "IP Address": "ip_address",
    "Physical Address": "address",
    
    # International identifiers
    "Canada Social Insurance Number": "sin",
    "U.K. National Insurance Number (NINO)": "nino",
    "India Unique Identification (Aadhaar) Number": "aadhaar",
    "Germany Identity Card Number": "national_id",
    "France National ID Card (CNI)": "national_id",
    
    # Credentials
    "Azure Storage Account Key": "api_key",
    "Azure Service Bus Shared Access Signature": "api_key",
    "Azure AD Client Secret": "api_key",
    "AWS Secret Access Key": "aws_secret_key",
    "General Password": "password",
    
    # Skip
    "All Full Names": None,  # Too broad
    "Person's Name": None,
    "Date": None,
    "Age": None,
}

def from_purview_classification(
    classification_result: dict,
    content_hash: str,
    content_length: int,
) -> OpenRiskTag:
    """Convert Microsoft Purview classification to OpenRisk tag."""
    scorer = RiskScorer()
    
    for sit in classification_result.get("sensitiveInformationTypes", []):
        sit_name = sit.get("name")
        openrisk_type = PURVIEW_TO_OPENRISK.get(sit_name)
        
        if openrisk_type:
            confidence = sit.get("confidence", 0.85) / 100  # Purview uses 0-100
            
            scorer.add_detection(
                openrisk_type,
                count=sit.get("count", 1),
                confidence=confidence,
            )
    
    return scorer.generate(
        content_hash=content_hash,
        content_length=content_length,
        generator="purview-adapter/1.0",
    )
```

### 10.6 Building Custom Adapters

```python
"""
Template for building a custom OpenRisk adapter.

Steps:
1. Map your tool's entity types to OpenRisk types
2. Determine confidence mapping (if applicable)
3. Implement the convert() method
"""

from openrisk import RiskScorer, OpenRiskTag

class CustomToolAdapter:
    """Adapter for CustomTool → OpenRisk."""
    
    name = "custom-tool"
    
    # Map your tool's entity types to OpenRisk types
    # Use None to skip types that don't map
    ENTITY_MAP = {
        "YOUR_SSN_TYPE": "ssn",
        "YOUR_PHONE_TYPE": "phone",
        "YOUR_VAGUE_TYPE": None,  # Skip
        # Add all your tool's entity types here
    }
    
    def __init__(self, confidence_threshold: float = 0.8):
        self.confidence_threshold = confidence_threshold
    
    def convert(
        self,
        results: Any,  # Your tool's output format
        content_hash: str,
        content_length: int,
    ) -> OpenRiskTag:
        """Convert your tool's results to OpenRisk tag."""
        scorer = RiskScorer(
            confidence_threshold=self.confidence_threshold
        )
        
        # Iterate through your tool's detections
        for detection in results:
            # Map entity type
            openrisk_type = self.ENTITY_MAP.get(detection.type)
            
            if openrisk_type:
                scorer.add_detection(
                    openrisk_type,
                    count=detection.count,  # Or 1 if not available
                    confidence=detection.score,  # Or 1.0 if not available
                )
        
        return scorer.generate(
            content_hash=content_hash,
            content_length=content_length,
            generator=f"{self.name}-adapter/1.0",
        )
```

---

## 11. SDK Reference

### 11.1 Installation

```bash
pip install openrisk
```

### 11.2 Core Classes

#### RiskScorer

```python
from openrisk import RiskScorer

# Create scorer with default settings
scorer = RiskScorer()

# Create scorer with custom confidence threshold
scorer = RiskScorer(confidence_threshold=0.7)

# Create scorer in relaxed mode (allows custom entity types)
scorer = RiskScorer(mode="relaxed")

# Add detections
scorer.add_detection("ssn", count=3, confidence=0.94)
scorer.add_detection("diagnosis", count=5, confidence=0.87)
scorer.add_detection("phone", count=12, confidence=0.91)

# Generate tag
tag = scorer.generate(
    content_hash="sha256:abc123...",
    content_length=1048576,
    generator="my-scanner/1.0"
)

print(tag["openrisk"]["score"])  # 74
print(tag["openrisk"]["tier"])   # "High"
```

#### OpenRiskTag

```python
from openrisk import OpenRiskTag

# Load from JSON
tag = OpenRiskTag.from_json(json_string)

# Load from file (auto-detects trailer or sidecar)
tag = OpenRiskTag.from_file("document.csv")

# Access properties
print(tag.score)         # 74
print(tag.tier)          # "High"
print(tag.content_hash)  # "sha256:abc123..."
print(tag.entities)      # List of EntityDetection

# Serialize
json_string = tag.to_json()
compact_json = tag.to_json(compact=True)

# Validate
errors = tag.validate()
if errors:
    print(f"Invalid tag: {errors}")
```

### 11.3 Entity Registry

```python
import openrisk

# Check if entity type exists
openrisk.entity_exists("ssn")  # True
openrisk.entity_exists("foo")  # False

# Get entity details
entity = openrisk.get_entity("ssn")
print(entity.weight)    # 9
print(entity.category)  # "direct_identifier.national_id"
print(entity.aliases)   # ["social_security", "us_ssn", ...]

# Resolve alias
openrisk.resolve_alias("social_security")  # "ssn"
openrisk.resolve_alias("ssn")              # "ssn"
openrisk.resolve_alias("unknown")          # None

# List all entities
all_entities = openrisk.list_entities()

# List entities by category
health_entities = openrisk.list_entities(category="health")
```

### 11.4 Trailer Operations

```python
import openrisk

# Write trailer to file
openrisk.write_trailer("document.csv", tag)

# Read trailer from file
original_content, tag = openrisk.read_trailer("document.csv")

# Check if file has trailer
if openrisk.has_trailer("document.csv"):
    print("File has OpenRisk trailer")

# Strip trailer (restore original file)
tag = openrisk.strip_trailer("document.csv")

# Strip trailer to different file
tag = openrisk.strip_trailer("document.csv", "document_clean.csv")
```

### 11.5 Sidecar Operations

```python
import openrisk

# Write sidecar
openrisk.write_sidecar("document.pdf", tag)
# Creates: document.pdf.openrisk.json

# Read sidecar
tag = openrisk.read_sidecar("document.pdf")

# Check if sidecar exists
if openrisk.has_sidecar("document.pdf"):
    print("File has OpenRisk sidecar")
```

### 11.6 Validation

```python
import openrisk

# Validate tag structure
result = openrisk.validate_tag(tag_dict)
if not result.valid:
    for error in result.errors:
        print(f"Validation error: {error}")

# Validate tag against file content
result = openrisk.validate_tag_integrity("document.csv", tag_dict)
if not result.valid:
    print("Content hash mismatch - file was modified")
```

### 11.7 Utility Functions

```python
import openrisk

# Hash a file
content_hash = openrisk.hash_file("document.csv")
# Returns: "sha256:abc123..."

# Hash bytes
content_hash = openrisk.hash_bytes(b"file content")

# Get file size
size = openrisk.get_file_size("document.csv")
```

---

## 12. CLI Reference

### 12.1 Installation

The CLI is included with the SDK:

```bash
pip install openrisk

# Verify installation
openrisk --version
```

### 12.2 Commands

#### openrisk scan

Scan files for sensitive data and generate OpenRisk tags.

```bash
# Scan a single file
openrisk scan document.csv

# Scan a directory
openrisk scan /data/exports

# Scan recursively
openrisk scan /data --recursive

# Output to file
openrisk scan /data -r --output results.json

# Quiet mode (no TUI)
openrisk scan /data -r --quiet

# JSON output (for piping)
openrisk scan /data -r --json

# Set confidence threshold
openrisk scan /data -r --confidence 0.7

# Write trailers to scanned files
openrisk scan /data -r --write-trailer

# Write sidecars instead
openrisk scan /data -r --write-sidecar
```

#### openrisk read

Read OpenRisk tag from a file.

```bash
# Read tag (auto-detects trailer or sidecar)
openrisk read document.csv

# Output formats
openrisk read document.csv --format json     # Full JSON
openrisk read document.csv --format summary  # Human readable
openrisk read document.csv --format score    # Just "74 High"

# Read and verify integrity
openrisk read document.csv --verify
```

#### openrisk write

Write OpenRisk tag to a file.

```bash
# Write trailer
openrisk write document.csv --tag tag.json

# Write sidecar
openrisk write document.csv --tag tag.json --sidecar

# From stdin
cat tag.json | openrisk write document.csv --tag -
```

#### openrisk validate

Validate tag structure and content integrity.

```bash
# Validate tag JSON
openrisk validate tag.json

# Validate tag against file
openrisk validate tag.json --file document.csv

# Validate file with embedded tag
openrisk validate document.csv
```

#### openrisk strip

Remove trailer from file.

```bash
# Strip in place
openrisk strip document.csv

# Strip to new file
openrisk strip document.csv --output document_clean.csv

# Extract tag while stripping
openrisk strip document.csv --save-tag tag.json
```

#### openrisk entity

Entity registry operations.

```bash
# Check if entity type exists
openrisk entity check ssn           # Exit 0 if exists
openrisk entity check unknown_type  # Exit 1 if not

# Get entity details
openrisk entity info ssn

# List all entities
openrisk entity list

# List by category
openrisk entity list --category health
openrisk entity list --category direct_identifier

# Resolve alias
openrisk entity resolve social_security  # Outputs: ssn
```

#### openrisk hash

Compute content hash.

```bash
# Hash a file
openrisk hash document.csv
# Outputs: sha256:abc123...

# Specify algorithm
openrisk hash document.csv --algorithm sha512
```

---

## 13. Security Considerations

### 13.1 Tag Authenticity

OpenRisk tags can include an optional signature field for verifying authenticity:

```json
{
  "openrisk": {
    ...
    "signature": "ed25519:base64-encoded-signature"
  }
}
```

The signature is computed over the tag content (excluding the signature field itself), using the generator's private key. Consumers can verify the signature using the generator's public key.

**Note:** Signature verification is optional. Many use cases don't require authenticated tags.

### 13.2 Content Integrity

The `content_hash` field provides integrity verification:

1. Before trusting a tag, verify that `content_hash` matches the actual file
2. If the hash doesn't match, the file was modified after tagging
3. Treat hash mismatches as if no tag exists

### 13.3 Information Disclosure

OpenRisk tags reveal information about file contents:

- Entity types present in the file
- Approximate counts of each type
- Overall sensitivity level

Consider whether this metadata should be protected in your environment.

### 13.4 Trailer Injection

Malicious actors could append fake trailers to files. Mitigations:

1. **Verify content_hash**: Fake trailers can't produce valid hashes for modified content
2. **Verify signatures**: If signatures are used, validate them
3. **Trust boundaries**: Only trust tags from known/trusted generators

### 13.5 Denial of Service

Extremely large tags could impact parsing performance. Implementations SHOULD:

1. Limit maximum tag size (recommended: 1 MB)
2. Limit maximum entities count (recommended: 10,000)
3. Timeout on trailer search (recommended: 5 seconds)

---

## 14. Conformance

### 14.1 Conformance Levels

| Level | Requirements |
|-------|--------------|
| **Reader** | Can read and parse valid OpenRisk tags |
| **Writer** | Can generate valid OpenRisk tags |
| **Full** | Reader + Writer + Trailer support |

### 14.2 Reader Requirements

A conforming reader MUST:

1. Parse any valid OpenRisk tag JSON
2. Extract tags from trailers
3. Extract tags from sidecars
4. Verify content_hash when requested
5. Handle unknown fields gracefully (ignore, don't error)

### 14.3 Writer Requirements

A conforming writer MUST:

1. Generate valid JSON per schema (Section 4)
2. Use the standard scoring algorithm (Section 5)
3. Use only registered entity types in strict mode
4. Compute accurate content_hash and content_length
5. Include all required fields

### 14.4 Trailer Requirements

A conforming implementation with trailer support MUST:

1. Write trailers in the exact format specified (Section 7)
2. Read trailers from any valid position (end of file)
3. Preserve original content exactly when stripping trailers
4. Handle files without trailers gracefully

---

## 15. Future Work

### 15.1 Planned for v1.0

- **Registry API**: Standard REST API for storing/querying tags by content hash
- **Native embedding**: XMP metadata for PDF, custom properties for DOCX/XLSX
- **Incremental updates**: Tag versioning for tracking changes over time

### 15.2 Under Consideration

- **Differential privacy**: Adding noise to entity counts for privacy preservation
- **Multi-file tags**: Tags that describe datasets spanning multiple files
- **Policy language**: Standard format for expressing handling rules based on tags
- **SBOM integration**: Embedding OpenRisk in software bill of materials

### 15.3 Explicitly Out of Scope

- Detection algorithms (OpenRisk is detection-agnostic)
- Remediation workflows
- Access control / DRM
- Real-time monitoring

---

## 16. Appendices

### Appendix A: JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://openrisk.dev/schema/v0.2/tag.json",
  "title": "OpenRisk Tag",
  "type": "object",
  "required": ["openrisk"],
  "properties": {
    "openrisk": {
      "type": "object",
      "required": [
        "version",
        "score",
        "tier",
        "content_hash",
        "content_length",
        "factors",
        "scoring",
        "provenance"
      ],
      "properties": {
        "version": {
          "type": "string",
          "pattern": "^\\d+\\.\\d+$"
        },
        "score": {
          "type": "integer",
          "minimum": 0,
          "maximum": 100
        },
        "tier": {
          "type": "string",
          "enum": ["Critical", "High", "Medium", "Low", "Minimal"]
        },
        "content_hash": {
          "type": "string",
          "pattern": "^(sha256|sha384|sha512):[a-f0-9]+$"
        },
        "content_length": {
          "type": "integer",
          "minimum": 0
        },
        "factors": {
          "type": "object",
          "required": ["entities"],
          "properties": {
            "entities": {
              "type": "array",
              "items": {
                "type": "object",
                "required": ["type", "category", "count", "confidence_avg", "weight"],
                "properties": {
                  "type": {"type": "string"},
                  "category": {"type": "string"},
                  "count": {"type": "integer", "minimum": 1},
                  "confidence_avg": {"type": "number", "minimum": 0, "maximum": 1},
                  "weight": {"type": "integer", "minimum": 1, "maximum": 10}
                }
              }
            },
            "co_occurrence_rules": {
              "type": "array",
              "items": {"type": "string"}
            },
            "co_occurrence_multiplier": {
              "type": "number",
              "minimum": 1
            },
            "raw_score": {"type": "number"},
            "filtered": {
              "type": "array",
              "items": {
                "type": "object",
                "required": ["type", "count", "confidence_avg", "reason"],
                "properties": {
                  "type": {"type": "string"},
                  "count": {"type": "integer"},
                  "confidence_avg": {"type": "number"},
                  "reason": {"type": "string"}
                }
              }
            }
          }
        },
        "scoring": {
          "type": "object",
          "required": ["algorithm", "confidence_threshold", "mode"],
          "properties": {
            "algorithm": {"type": "string"},
            "confidence_threshold": {"type": "number", "minimum": 0, "maximum": 1},
            "mode": {"type": "string", "enum": ["strict", "relaxed"]}
          }
        },
        "provenance": {
          "type": "object",
          "required": ["generator", "generated_at"],
          "properties": {
            "generator": {"type": "string"},
            "generator_org": {"type": "string"},
            "generated_at": {"type": "string", "format": "date-time"},
            "source_tool": {"type": "string"},
            "scan_duration_ms": {"type": "integer"}
          }
        },
        "signature": {
          "type": ["string", "null"]
        }
      }
    }
  }
}
```

### Appendix B: Complete Entity Registry

```yaml
# openrisk-entities-v0.2.yaml

version: "0.2"

categories:
  direct_identifier:
    description: "Uniquely identifying information"
    subcategories:
      national_id: "Government-issued national identifiers"
      financial: "Financial account identifiers"
      government: "Government-issued documents"
      biometric: "Biometric identifiers"
  
  health:
    description: "Protected health information"
    subcategories:
      identifier: "Healthcare system identifiers"
      diagnosis: "Medical diagnoses and conditions"
      treatment: "Medical treatments and procedures"
      provider: "Healthcare provider information"
  
  contact:
    description: "Contact information"
    subcategories:
      electronic: "Electronic contact methods"
      phone: "Telephone numbers"
      physical: "Physical addresses"
  
  demographic:
    description: "Demographic information"
    subcategories:
      name: "Personal names"
      personal: "Personal characteristics"
      employment: "Employment information"
  
  financial:
    description: "Financial information"
    subcategories:
      account: "Account identifiers"
      transaction: "Transaction details"
      investment: "Investment identifiers"
  
  credential:
    description: "Authentication credentials"
    subcategories:
      authentication: "Passwords and PINs"
      api_key: "API keys and tokens"
      certificate: "Certificates and keys"
  
  legal:
    description: "Legal information"
    subcategories:
      case: "Case information"
      privilege: "Privileged communications"

entities:
  # Direct identifiers - National ID
  ssn:
    category: direct_identifier.national_id
    weight: 9
    description: "US Social Security Number"
    aliases: [social_security, social_security_number, us_ssn]
    patterns: ["\\d{3}-\\d{2}-\\d{4}", "\\d{9}"]
  
  sin:
    category: direct_identifier.national_id
    weight: 9
    description: "Canadian Social Insurance Number"
    aliases: [social_insurance_number, canada_sin]
  
  aadhaar:
    category: direct_identifier.national_id
    weight: 9
    description: "Indian Aadhaar Number"
    aliases: [aadhar, india_aadhaar]
  
  nino:
    category: direct_identifier.national_id
    weight: 9
    description: "UK National Insurance Number"
    aliases: [national_insurance, uk_nino]
  
  tax_id:
    category: direct_identifier.national_id
    weight: 9
    description: "Tax Identification Number"
    aliases: [tin, ein, itin, employer_id]

  # Direct identifiers - Financial
  credit_card:
    category: direct_identifier.financial
    weight: 8
    description: "Credit or debit card number"
    aliases: [cc, card_number, pan, payment_card]
  
  bank_account:
    category: direct_identifier.financial
    weight: 8
    description: "Bank account number"
    aliases: [account_number, checking_account, savings_account]
  
  # Direct identifiers - Government
  passport:
    category: direct_identifier.government
    weight: 8
    description: "Passport number"
    aliases: [passport_number]
  
  drivers_license:
    category: direct_identifier.government
    weight: 8
    description: "Driver's license number"
    aliases: [dl, driver_license, driving_license]

  # Healthcare - Identifier
  mrn:
    category: health.identifier
    weight: 7
    description: "Medical Record Number"
    aliases: [medical_record, medical_record_number]
  
  health_plan_id:
    category: health.identifier
    weight: 7
    description: "Health insurance beneficiary ID"
    aliases: [health_insurance_id, beneficiary_id, member_id]
  
  npi:
    category: health.identifier
    weight: 6
    description: "National Provider Identifier"
    aliases: [national_provider_identifier, provider_npi]
  
  dea_number:
    category: health.identifier
    weight: 6
    description: "DEA registration number"
    aliases: [dea, dea_registration]

  # Healthcare - Diagnosis
  diagnosis:
    category: health.diagnosis
    weight: 8
    description: "Medical diagnosis or condition"
    aliases: [dx, condition, medical_condition]
  
  icd_code:
    category: health.diagnosis
    weight: 8
    description: "ICD diagnosis code"
    aliases: [icd10, icd9, diagnosis_code]

  # Healthcare - Treatment
  medication:
    category: health.treatment
    weight: 7
    description: "Prescription medication"
    aliases: [drug, prescription, rx]
  
  procedure:
    category: health.treatment
    weight: 7
    description: "Medical procedure"
    aliases: [treatment, surgery, cpt_code]
  
  lab_result:
    category: health.treatment
    weight: 7
    description: "Laboratory test result"
    aliases: [test_result, lab_value]

  # Contact - Electronic
  email:
    category: contact.electronic
    weight: 4
    description: "Email address"
    aliases: [email_address, e_mail]
  
  ip_address:
    category: contact.electronic
    weight: 4
    description: "IP address"
    aliases: [ip, ip_addr]
  
  mac_address:
    category: contact.electronic
    weight: 4
    description: "MAC address"
    aliases: [mac, hardware_address]

  # Contact - Phone
  phone:
    category: contact.phone
    weight: 4
    description: "Phone number"
    aliases: [phone_number, telephone, mobile, cell]
  
  fax:
    category: contact.phone
    weight: 4
    description: "Fax number"
    aliases: [fax_number]

  # Contact - Physical
  address:
    category: contact.physical
    weight: 5
    description: "Street address"
    aliases: [street_address, mailing_address, physical_address]
  
  postal_code:
    category: contact.physical
    weight: 3
    description: "ZIP or postal code"
    aliases: [zip, zip_code, postcode]

  # Demographics - Name
  full_name:
    category: demographic.name
    weight: 5
    description: "Full name"
    aliases: [name, person_name, complete_name]
  
  first_name:
    category: demographic.name
    weight: 3
    description: "First or given name"
    aliases: [given_name, forename]
  
  last_name:
    category: demographic.name
    weight: 3
    description: "Last or family name"
    aliases: [family_name, surname]

  # Demographics - Personal
  date_of_birth:
    category: demographic.personal
    weight: 6
    description: "Date of birth"
    aliases: [dob, birthdate, birthday]
  
  age:
    category: demographic.personal
    weight: 4
    description: "Age"
    aliases: [years_old]
  
  gender:
    category: demographic.personal
    weight: 3
    description: "Gender"
    aliases: [sex]
  
  race_ethnicity:
    category: demographic.personal
    weight: 5
    description: "Race or ethnicity"
    aliases: [race, ethnicity]
  
  sexual_orientation:
    category: demographic.personal
    weight: 6
    description: "Sexual orientation"
    aliases: []
  
  religion:
    category: demographic.personal
    weight: 5
    description: "Religious affiliation"
    aliases: [religious_affiliation]

  # Financial - Account
  iban:
    category: financial.account
    weight: 7
    description: "International Bank Account Number"
    aliases: [international_bank_account]
  
  routing_number:
    category: financial.account
    weight: 6
    description: "Bank routing number"
    aliases: [aba, aba_routing, routing]
  
  swift_bic:
    category: financial.account
    weight: 6
    description: "SWIFT/BIC code"
    aliases: [swift, bic, swift_code]

  # Financial - Investment
  cusip:
    category: financial.investment
    weight: 5
    description: "CUSIP identifier"
    aliases: []
  
  isin:
    category: financial.investment
    weight: 5
    description: "ISIN identifier"
    aliases: []

  # Credentials - Authentication
  password:
    category: credential.authentication
    weight: 9
    description: "Password"
    aliases: [passwd, pwd]
  
  pin:
    category: credential.authentication
    weight: 8
    description: "PIN code"
    aliases: [pin_code]
  
  security_answer:
    category: credential.authentication
    weight: 7
    description: "Security question answer"
    aliases: [security_question_answer]

  # Credentials - API Keys
  aws_access_key:
    category: credential.api_key
    weight: 9
    description: "AWS access key ID"
    aliases: [aws_key, aws_access_key_id]
  
  aws_secret_key:
    category: credential.api_key
    weight: 9
    description: "AWS secret access key"
    aliases: [aws_secret, aws_secret_access_key]
  
  api_key:
    category: credential.api_key
    weight: 8
    description: "Generic API key"
    aliases: [apikey, api_token]
  
  jwt_token:
    category: credential.api_key
    weight: 7
    description: "JSON Web Token"
    aliases: [jwt, bearer_token]

  # Credentials - Certificate
  private_key:
    category: credential.certificate
    weight: 9
    description: "Private key material"
    aliases: [rsa_private_key, ssh_private_key]
  
  certificate:
    category: credential.certificate
    weight: 6
    description: "X.509 certificate"
    aliases: [cert, x509, ssl_cert]
```

### Appendix C: Example Tags

#### Example 1: Healthcare Data (High Risk)

```json
{
  "openrisk": {
    "version": "0.2",
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
        },
        {
          "type": "mrn",
          "category": "health.identifier",
          "count": 47,
          "confidence_avg": 0.96,
          "weight": 7
        }
      ],
      "co_occurrence_rules": ["direct_id + health"],
      "co_occurrence_multiplier": 1.5,
      "raw_score": 49.3,
      "filtered": []
    },
    "scoring": {
      "algorithm": "openrisk-v0.2-standard",
      "confidence_threshold": 0.8,
      "mode": "strict"
    },
    "provenance": {
      "generator": "openrisk-scan/0.1.0",
      "generator_org": "scrubiq",
      "generated_at": "2026-01-24T14:32:00Z",
      "source_tool": "phi-bert-v1.2",
      "scan_duration_ms": 1247
    }
  }
}
```

#### Example 2: Contact List (Low Risk)

```json
{
  "openrisk": {
    "version": "0.2",
    "score": 18,
    "tier": "Low",
    "content_hash": "sha256:e5c19f4a2d8b3c6e7f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e",
    "content_length": 24576,
    "factors": {
      "entities": [
        {
          "type": "email",
          "category": "contact.electronic",
          "count": 156,
          "confidence_avg": 0.99,
          "weight": 4
        },
        {
          "type": "phone",
          "category": "contact.phone",
          "count": 89,
          "confidence_avg": 0.91,
          "weight": 4
        },
        {
          "type": "full_name",
          "category": "demographic.name",
          "count": 156,
          "confidence_avg": 0.85,
          "weight": 5
        }
      ],
      "co_occurrence_rules": [],
      "co_occurrence_multiplier": 1.0,
      "raw_score": 18.2,
      "filtered": []
    },
    "scoring": {
      "algorithm": "openrisk-v0.2-standard",
      "confidence_threshold": 0.8,
      "mode": "strict"
    },
    "provenance": {
      "generator": "presidio-adapter/1.0",
      "generated_at": "2026-01-24T09:15:00Z"
    }
  }
}
```

#### Example 3: Clean File (Minimal Risk)

```json
{
  "openrisk": {
    "version": "0.2",
    "score": 0,
    "tier": "Minimal",
    "content_hash": "sha256:f0e1d2c3b4a5968778695a4b3c2d1e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d",
    "content_length": 8192,
    "factors": {
      "entities": [],
      "co_occurrence_rules": [],
      "co_occurrence_multiplier": 1.0,
      "raw_score": 0,
      "filtered": [
        {
          "type": "date",
          "count": 12,
          "confidence_avg": 0.65,
          "reason": "below_threshold"
        }
      ]
    },
    "scoring": {
      "algorithm": "openrisk-v0.2-standard",
      "confidence_threshold": 0.8,
      "mode": "strict"
    },
    "provenance": {
      "generator": "openrisk-scan/0.1.0",
      "generated_at": "2026-01-24T11:00:00Z",
      "scan_duration_ms": 89
    }
  }
}
```

---

## Acknowledgments

OpenRisk is inspired by:

- **ID3 tags** for demonstrating that metadata can travel with files
- **SPDX** for showing how standards can unite an ecosystem
- **The data classification community** for years of work on sensitive data detection

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 0.2 | 2026-01 | Initial public draft |

---

**End of Specification**

*For questions, contributions, or feedback, visit: https://github.com/scrubiq/openrisk*
