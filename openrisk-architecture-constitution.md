# OpenRisk Scanner: Architecture Guide & Constitution

**Version:** 0.1.0-draft  
**Last Updated:** January 24, 2026  
**Status:** Pre-implementation design document

---

## Table of Contents

1. [Constitution (Read First)](#1-constitution-read-first)
2. [Project Vision](#2-project-vision)
3. [What OpenRisk Is and Is Not](#3-what-openrisk-is-and-is-not)
4. [Architecture Overview](#4-architecture-overview)
5. [Speed Strategy](#5-speed-strategy)
6. [Package Structure](#6-package-structure)
7. [Core Components](#7-core-components)
8. [Adapters](#8-adapters)
9. [CLI & TUI Design](#9-cli--tui-design)
10. [Scope Boundaries](#10-scope-boundaries)
11. [Technical Constraints](#11-technical-constraints)
12. [Key Design Decisions](#12-key-design-decisions)
13. [Future Considerations](#13-future-considerations)

---

## 1. Constitution (Read First)

**Claude: Before making any suggestions or writing any code for this project, internalize these principles. They are the result of extensive design discussion and represent deliberate architectural choices.**

### 1.1 Core Principles

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         OPENRISK CONSTITUTION                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  1. OPENRISK IS A STANDARD, NOT A PRODUCT                               │
│     The scanner proves the standard works. The standard is the value.   │
│     Never optimize the scanner at the expense of standard clarity.      │
│                                                                          │
│  2. OPENRISK IS NOT SCRUBIQ                                             │
│     scrubIQ: Redaction for safe LLM usage. Output = sanitized text.     │
│     OpenRisk: Classification metadata. Output = risk tags.              │
│     Different products. Different purposes. Do not conflate them.       │
│                                                                          │
│  3. SPEED THROUGH INTELLIGENCE, NOT COMPUTE                             │
│     We do not have GPU budget. We achieve speed through:                │
│     - Smart file discovery (MFT parsing, fast scandir)                  │
│     - Aggressive filtering (skip non-regulated data)                    │
│     - Content deduplication (hash-based caching)                        │
│     Never suggest "just use GPU" as the primary solution.               │
│                                                                          │
│  4. THE MODELS ARE ALREADY SMALL                                        │
│     PHI-BERT and PII-BERT are ~108MB ONNX models (MiniLM-sized).       │
│     They are already quantized to INT8. No further distillation         │
│     is practical. The inference cost is physics, not engineering.       │
│                                                                          │
│  5. ADAPTERS ARE TRIVIAL BY DESIGN                                      │
│     An adapter is a label mapping + confidence threshold + RiskScorer.  │
│     If an adapter is more than ~100 lines, something is wrong.          │
│     The point is proving ANY tool can output OpenRisk tags easily.      │
│                                                                          │
│  6. CLI-FIRST, TUI VIA RICH                                             │
│     No GUI. No Electron. No web dashboard (for now).                    │
│     Rich TUI for interactive use. JSON/quiet mode for scripts/CI.       │
│                                                                          │
│  7. PROVE THE STANDARD, THEN EXPAND                                     │
│     v1 scope is deliberately tight. Resist feature creep.               │
│     The goal is: pip install openrisk, scan files, get tags.            │
│     Everything else is v2+.                                              │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Forbidden Suggestions

Do not suggest:

| Suggestion | Why It's Forbidden |
|------------|-------------------|
| "Use GPU for faster inference" | No GPU budget. Speed comes from filtering. |
| "Distill the models further" | Models are already MiniLM-sized (~108MB). |
| "Add a web dashboard" | Out of scope. TUI only for v1. |
| "Build a platform/SaaS" | OpenRisk is a standard, not a platform. |
| "Add user authentication" | Scanner is a local tool, not a service. |
| "Integrate with scrubIQ desktop" | Different products. Keep them separate. |
| "Add real-time monitoring" | Out of scope. Batch scanning only for v1. |
| "Build adapters for 20 tools" | 4-5 key adapters prove the concept. |

### 1.3 Questions to Ask Before Suggesting Changes

1. Does this help prove the OpenRisk standard works?
2. Does this make the scanner meaningfully faster without requiring GPU?
3. Is this in v1 scope, or should it be deferred?
4. Does this keep adapters simple (<100 lines)?
5. Am I conflating OpenRisk with scrubIQ?

---

## 2. Project Vision

### 2.1 The Problem

Every cloud has data classification:
- AWS Macie
- Microsoft Purview  
- Google Cloud DLP
- Open source: Presidio

**None of them interoperate.** When files move between systems, classification is lost. There is no portable standard for data sensitivity that travels with files.

### 2.2 The Solution

OpenRisk provides:

1. **Tag Schema** — JSON format for risk scores with transparent scoring factors
2. **Scoring Algorithm** — Deterministic, reproducible 0-100 scores
3. **Entity Taxonomy** — Standardized sensitive data type registry
4. **Trailer Format** — Universal metadata attachment (like ID3 for MP3s)
5. **SDK + CLI** — Reference implementation that proves it works
6. **Adapters** — Show that Macie/Purview/DLP/Presidio can output OpenRisk

### 2.3 The Play

```
Build scanner → Scanner outputs OpenRisk tags → Tags prove standard works
     ↓
Build adapters → Adapters show other tools can output OpenRisk
     ↓
Publish standard → Community adopts → OpenRisk becomes interchange format
     ↓
scrubIQ benefits → "The OpenRisk-native scanner with best PHI detection"
```

---

## 3. What OpenRisk Is and Is Not

### 3.1 OpenRisk IS

| Attribute | Description |
|-----------|-------------|
| A specification | JSON schema, scoring algorithm, entity taxonomy |
| A reference scanner | Proves the spec works on real files |
| An SDK | `pip install openrisk` for reading/writing tags |
| Adapters | Mappings from Macie/Purview/DLP/Presidio to OpenRisk |
| Open source | Apache 2.0 license |
| A portable format | Tags travel with files across systems |

### 3.2 OpenRisk IS NOT

| Attribute | Why Not |
|-----------|---------|
| A platform | No hosted service, no SaaS, no multi-tenancy |
| A product for sale | It's a standard; scrubIQ is the product |
| A replacement for scrubIQ | Different purpose (classification vs redaction) |
| An enterprise tool | No RBAC, no audit trails, no compliance features |
| A real-time monitor | Batch scanning only |
| Varonis competitor | We can't match enterprise speed/scale without budget |

### 3.3 OpenRisk vs scrubIQ

| Dimension | scrubIQ | OpenRisk Scanner |
|-----------|---------|------------------|
| **Purpose** | Make data safe for LLMs | Describe what's in data |
| **Input** | Text, files, images | Files and directories |
| **Output** | Sanitized text with tokens | Risk metadata tags (JSON) |
| **Core value** | Transformation (redaction) | Visibility (classification) |
| **User journey** | "I need to send this to ChatGPT safely" | "What sensitive data do I have?" |
| **Token store** | Yes (for restoration) | No |
| **Encryption** | Yes | No |
| **Authentication** | PIN-based | None |

**These are different products. Code may be shared (detection pipeline), but they serve different needs.**

---

## 4. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         OPENRISK SCANNER                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                │
│   │  DISCOVERY  │───►│  FILTERING  │───►│  DETECTION  │                │
│   │             │    │             │    │             │                │
│   │ • MFT parse │    │ • Extension │    │ • scrubIQ   │                │
│   │ • scandir   │    │ • Path      │    │   pipeline  │                │
│   │             │    │ • Size      │    │ • No token- │                │
│   │             │    │ • Data type │    │   ization   │                │
│   └─────────────┘    │ • Regex     │    └──────┬──────┘                │
│                      │   triage    │           │                        │
│                      └─────────────┘           ▼                        │
│                                        ┌─────────────┐                  │
│   ┌─────────────┐    ┌─────────────┐  │  SCORING    │                  │
│   │   OUTPUT    │◄───│   TAGGING   │◄─│             │                  │
│   │             │    │             │  │ • Entity    │                  │
│   │ • JSON      │    │ • OpenRisk  │  │   weights   │                  │
│   │ • Trailer   │    │   tags      │  │ • Co-occur  │                  │
│   │ • Sidecar   │    │ • Cache     │  │   rules     │                  │
│   │ • Report    │    │             │  │ • 0-100     │                  │
│   └─────────────┘    └─────────────┘  └─────────────┘                  │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Speed Strategy

### 5.1 The Constraint

- Models are already optimized (~108MB ONNX, INT8 quantized)
- CPU inference is ~100-150ms per file (physics, not engineering)
- No GPU budget for hosting
- Must be competitive enough to prove the standard

### 5.2 The Strategy: Filter Aggressively

```
100,000 files starting point

STAGE 1: Discovery (MFT/fast scandir)
├── Time: 30 seconds (not 20 minutes)
└── Output: 100,000 FileInfo objects

STAGE 2: Extension/Path Filter
├── Skip: .exe, .dll, .png, node_modules/, .git/
├── Time: Instant (in-memory filtering)
└── Output: 40,000 files remain

STAGE 3: Data Type Classification  
├── Read first 1KB, analyze headers/structure
├── Skip: Code, config, known non-regulated
├── Time: 40 seconds (1ms per file)
└── Output: 12,000 regulated files

STAGE 4: Regex Triage
├── Quick pattern scan for PII indicators
├── Flag files that need ML
├── Time: 30 seconds
└── Output: 8,000 files need ML

STAGE 5: Hash Deduplication
├── Group by content hash
├── Scan unique content only
├── Apply results to duplicates
└── Output: 6,000 unique files

STAGE 6: ML Inference
├── Parallel file reads, sequential inference
├── Time: 6,000 × 120ms = 12 minutes
└── Output: OpenRisk tags

TOTAL: ~15 minutes (vs 4+ hours naive)
```

### 5.3 Platform-Specific Optimizations

| Platform | Discovery Method | Advantage |
|----------|-----------------|-----------|
| Windows NTFS | MFT parsing | 10-30x faster than os.walk |
| Windows NTFS | USN Journal | Instant incremental updates |
| Linux ext4/XFS | Fast scandir | Already reasonably fast |
| Network shares | Standard walk + warning | User informed of slowness |

### 5.4 What "Regulated Data" Means

Files that **could** contain sensitive data based on structure/context:

| Data Type | Detection Method | Action |
|-----------|-----------------|--------|
| Healthcare data | Headers: patient, mrn, diagnosis, dob | → ML pipeline |
| Financial data | Headers: ssn, account, credit_card | → ML pipeline |
| HR data | Headers: salary, employee, ssn | → ML pipeline |
| Customer data | Headers: email, phone, address, name | → ML pipeline |
| Code | Extension: .py, .js, .java + syntax | → Skip (or secrets-only) |
| Config | Extension: .yaml, .json, .toml | → Skip (or secrets-only) |
| Binaries | Extension + magic bytes | → Skip |
| Dependencies | Path: node_modules/, .venv/ | → Skip |

---

## 6. Package Structure

```
openrisk/
├── openrisk/
│   ├── __init__.py              # Public API exports
│   │
│   ├── cli/
│   │   ├── __init__.py
│   │   ├── main.py              # Click entry point
│   │   ├── scan.py              # scan command
│   │   ├── read.py              # read command  
│   │   ├── validate.py          # validate command
│   │   └── ui.py                # Rich TUI components
│   │
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── discovery.py         # MFT parsing + fast walk
│   │   ├── filters.py           # Extension, path, size filters
│   │   ├── classifier.py        # Data type classification
│   │   ├── triage.py            # Regex pre-scan
│   │   ├── extraction.py        # Text extraction
│   │   ├── detection.py         # Wraps scrubIQ pipeline
│   │   ├── cache.py             # Content hash → result cache
│   │   └── runner.py            # Orchestrates scan pipeline
│   │
│   ├── scoring/
│   │   ├── __init__.py
│   │   ├── scorer.py            # RiskScorer class
│   │   ├── entities.py          # Entity registry + weights
│   │   ├── tag.py               # OpenRiskTag dataclass
│   │   └── rules.py             # Co-occurrence rules
│   │
│   ├── output/
│   │   ├── __init__.py
│   │   ├── trailer.py           # Trailer read/write
│   │   ├── sidecar.py           # .openrisk.json files
│   │   └── report.py            # Summary reports
│   │
│   ├── adapters/
│   │   ├── __init__.py
│   │   ├── base.py              # Adapter base class
│   │   ├── presidio.py          # Presidio adapter
│   │   ├── aws_macie.py         # AWS Macie adapter
│   │   ├── google_dlp.py        # Google Cloud DLP adapter
│   │   ├── microsoft_purview.py # Microsoft Purview adapter
│   │   └── scrubiq.py           # scrubIQ spans → OpenRisk
│   │
│   └── _vendor/                 # Vendored detection code from scrubIQ
│       ├── __init__.py
│       ├── normalizer.py
│       ├── detectors/
│       └── merger.py
│
├── models/                      # ONNX models (or HF Hub fetch)
│   ├── phi_bert_int8.onnx
│   └── pii_bert_int8.onnx
│
├── tests/
│   ├── test_scanner/
│   ├── test_scoring/
│   ├── test_adapters/
│   └── test_output/
│
├── pyproject.toml
├── README.md
└── SPEC.md                      # OpenRisk specification document
```

---

## 7. Core Components

### 7.1 RiskScorer

The heart of OpenRisk. Converts detections to scores.

```python
from openrisk import RiskScorer

scorer = RiskScorer()
scorer.add_detection("ssn", count=3, confidence=0.94)
scorer.add_detection("diagnosis", count=2, confidence=0.87)

tag = scorer.generate(
    content_hash="sha256:abc...",
    content_length=1847,
    generator="openrisk-scan/0.1"
)

print(tag.score)  # 74
print(tag.tier)   # "High"
```

### 7.2 Entity Registry

Bundled YAML defining all recognized entity types with weights.

```yaml
# openrisk/data/entities.yaml
entities:
  # Direct identifiers (highest weight)
  ssn:
    weight: 9
    category: direct_identifier.national_id
    aliases: [social_security, social_security_number]
    
  credit_card:
    weight: 8
    category: direct_identifier.financial
    aliases: [cc, card_number]
    
  # Healthcare (high weight)  
  diagnosis:
    weight: 8
    category: health.diagnosis
    aliases: [dx, icd_code]
    
  medical_record_number:
    weight: 7
    category: health.identifier
    aliases: [mrn, medical_record]
    
  # Contact info (medium weight)
  email:
    weight: 4
    category: contact.electronic
    
  phone:
    weight: 4
    category: contact.phone
```

### 7.3 OpenRiskTag

The tag structure that gets attached to files.

```python
@dataclass
class OpenRiskTag:
    version: str                    # "0.2"
    score: int                      # 0-100
    tier: str                       # Critical/High/Medium/Low/Minimal
    content_hash: str               # sha256:...
    content_length: int             # Original file size in bytes
    entities: List[EntityDetection] # Detected entities
    co_occurrence_rules: List[str]  # Triggered multiplier rules
    co_occurrence_multiplier: float # Applied multiplier
    raw_score: float                # Pre-normalization score
    filtered: List[dict]            # Below-threshold detections
    generator: str                  # "openrisk-scan/0.1"
    generated_at: datetime          # Timestamp
```

### 7.4 Trailer Format

Universal metadata attachment for any file type.

```
[Original file content - unchanged]
---OPENRISK-TAG-V1---
{"openrisk":{"version":"0.2","score":74,"tier":"High",...}}
---END-OPENRISK-TAG---
```

Key properties:
- Original content unchanged (hash verifiable)
- content_length field enables extraction of original
- Works on any file type (CSV, JSON, TXT, logs, etc.)

---

## 8. Adapters

### 8.1 Design Principle

Adapters are intentionally simple. They demonstrate that **any** classification tool can output OpenRisk with minimal effort.

An adapter is:
1. A label mapping dictionary
2. A confidence threshold
3. A call to RiskScorer

**If an adapter exceeds ~100 lines, the design is wrong.**

### 8.2 Adapter Interface

```python
# openrisk/adapters/base.py

from abc import ABC, abstractmethod
from ..scoring import OpenRiskTag

class BaseAdapter(ABC):
    """Base class for classification tool adapters."""
    
    name: str  # e.g., "presidio", "aws_macie"
    
    @abstractmethod
    def convert(
        self, 
        results: Any, 
        content_hash: str, 
        content_length: int
    ) -> OpenRiskTag:
        """Convert tool-specific results to OpenRisk tag."""
        pass
```

### 8.3 Example: Presidio Adapter

```python
# openrisk/adapters/presidio.py

from ..scoring import RiskScorer, OpenRiskTag
from .base import BaseAdapter

PRESIDIO_TO_OPENRISK = {
    "US_SSN": "ssn",
    "CREDIT_CARD": "credit_card",
    "US_BANK_NUMBER": "bank_account",
    "PHONE_NUMBER": "phone",
    "EMAIL_ADDRESS": "email",
    "US_DRIVER_LICENSE": "drivers_license",
    "US_PASSPORT": "passport",
    "IP_ADDRESS": "ip_address",
    "IBAN_CODE": "iban",
    "MEDICAL_LICENSE": "medical_license",
    # Skip overly vague types
    "PERSON": None,
    "LOCATION": None,
    "DATE_TIME": None,
    "NRP": None,
}

class PresidioAdapter(BaseAdapter):
    name = "presidio"
    
    def __init__(self, confidence_threshold: float = 0.8):
        self.confidence_threshold = confidence_threshold
    
    def convert(
        self,
        results: list,  # List of Presidio RecognizerResult
        content_hash: str,
        content_length: int,
    ) -> OpenRiskTag:
        scorer = RiskScorer()
        
        for result in results:
            if result.score < self.confidence_threshold:
                continue
                
            openrisk_type = PRESIDIO_TO_OPENRISK.get(result.entity_type)
            if openrisk_type:
                scorer.add_detection(
                    openrisk_type,
                    count=1,
                    confidence=result.score
                )
        
        return scorer.generate(
            content_hash=content_hash,
            content_length=content_length,
            generator=f"presidio-adapter/1.0"
        )
```

### 8.4 Target Adapters for v1

| Adapter | Priority | Effort | Market Coverage |
|---------|----------|--------|-----------------|
| Presidio | P0 | 2 hrs | Open source community |
| AWS Macie | P0 | 3 hrs | AWS enterprises |
| Google Cloud DLP | P1 | 3 hrs | GCP users |
| Microsoft Purview | P1 | 4 hrs | M365/Azure enterprises |
| scrubIQ (internal) | P0 | 1 hr | Dogfooding |

---

## 9. CLI & TUI Design

### 9.1 Commands

```bash
# Core scanning
openrisk scan <path>              # Scan file or directory
openrisk scan <path> --recursive  # Include subdirectories
openrisk scan <path> --output results.json

# Tag operations
openrisk read <file>              # Read tag from file
openrisk read <file> --format json|summary
openrisk write <file> --tag tag.json
openrisk write <file> --trailer   # Append trailer
openrisk write <file> --sidecar   # Create .openrisk.json

# Validation
openrisk validate <tag.json>      # Validate tag structure
openrisk entity check <type>      # Check if entity type exists
openrisk entity list              # List all entity types

# Utilities
openrisk hash <file>              # Compute content hash
openrisk strip <file>             # Remove trailer, output original
```

### 9.2 TUI Layout (Rich)

```
┌─────────────────────────────────────────────────────────────────┐
│  OPENRISK SCANNER v0.1.0                       Elapsed: 04:23   │
└─────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────┐
│  Scanning regulated files                                       │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╸ 67% │ 4,312 / 6,412    │
│                                                                 │
│  Current: /data/exports/claims_detail_2024.csv                 │
└─────────────────────────────────────────────────────────────────┘
┌─ LIVE STATS ────────────────────────────────────────────────────┐
│                                                                 │
│  Files        Discovered    47,231                              │
│               Filtered      28,412                              │
│               Regulated      6,412                              │
│               Scanned        4,312                              │
│                                                                 │
│  Risk Found   🔴 Critical        2                              │
│               🟠 High           12                              │
│               🟡 Medium         67                              │
│               🟢 Low           284                              │
│                                                                 │
│  Performance  142 files/min │ ETA: 00:14:47                    │
│               18% cache hits (784 duplicates skipped)          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 9.3 Output Modes

| Mode | Flag | Use Case |
|------|------|----------|
| Interactive TUI | (default) | Human at terminal |
| Quiet | `--quiet` | Scripts, CI/CD |
| JSON | `--json` | Machine parsing |
| JSON Lines | `--jsonl` | Streaming, piping |

---

## 10. Scope Boundaries

### 10.1 v1 Scope (Launch)

| Feature | Status | Notes |
|---------|--------|-------|
| SDK core (RiskScorer, Tag, Trailer) | ✅ In scope | Foundation |
| CLI scanner | ✅ In scope | Proves the standard |
| Rich TUI | ✅ In scope | Good UX |
| File scanning (txt, csv, json, pdf) | ✅ In scope | Common formats |
| Directory recursion | ✅ In scope | Essential |
| Extension/path filtering | ✅ In scope | Speed |
| Data type classification | ✅ In scope | Speed |
| Content hash caching | ✅ In scope | Speed |
| Presidio adapter | ✅ In scope | Key integration |
| AWS Macie adapter | ✅ In scope | Enterprise cred |
| Google DLP adapter | ✅ In scope | Coverage |
| Microsoft Purview adapter | ✅ In scope | Coverage |
| Trailer read/write | ✅ In scope | Core feature |
| Sidecar files | ✅ In scope | Alternative to trailer |
| JSON/quiet output modes | ✅ In scope | Scriptability |

### 10.2 v2 Scope (Future)

| Feature | Status | Notes |
|---------|--------|-------|
| Registry server | ⏳ Deferred | Central tag storage |
| Web dashboard | ⏳ Deferred | Visualization |
| Incremental scanning (USN journal) | ⏳ Deferred | Speed optimization |
| Image/OCR processing | ⏳ Deferred | Complexity |
| Archive scanning (zip, tar) | ⏳ Deferred | Complexity |
| Secrets detection (API keys) | ⏳ Deferred | Different threat model |
| BIZ-BERT (financial/legal) | ⏳ Deferred | Requires training |
| Multi-user / RBAC | ⏳ Deferred | Enterprise feature |
| Real-time monitoring | ⏳ Deferred | Different architecture |

### 10.3 Never Scope

| Feature | Reason |
|---------|--------|
| SaaS platform | OpenRisk is a standard, not a product |
| Varonis feature parity | Enterprise budget required |
| GPU cloud hosting | No budget pre-revenue |
| Mobile apps | Wrong form factor |
| Browser extension | Out of scope |

---

## 11. Technical Constraints

### 11.1 Model Constraints

```
PHI-BERT:
  - Size: ~108 MB (ONNX, INT8 quantized)
  - Base: MiniLM-sized (already small)
  - Inference: ~100-150ms per file on CPU
  - Further distillation: Not practical
  
PII-BERT:
  - Size: ~108 MB (ONNX, INT8 quantized)
  - Base: MiniLM-sized (already small)
  - Inference: ~100-150ms per file on CPU
  - Further distillation: Not practical
```

**These models are at the compression floor. Speed improvements come from running inference on fewer files, not faster inference.**

### 11.2 Platform Support

| Platform | Support Level | Discovery Method |
|----------|---------------|------------------|
| Windows 10/11 | Full | MFT parsing + scandir |
| Linux (ext4, XFS) | Full | Fast scandir |
| macOS | Full | Fast scandir |
| Network shares (SMB/NFS) | Degraded | Standard walk + warning |

### 11.3 Dependencies

```toml
[project]
dependencies = [
    # CLI & TUI
    "click>=8.0",
    "rich>=13.0",
    
    # ML inference  
    "onnxruntime>=1.16",
    "transformers>=4.30",    # For tokenizers only
    
    # File handling
    "chardet>=5.0",          # Encoding detection
    "python-magic>=0.4",     # MIME type detection
    
    # Text extraction
    "pdfplumber>=0.9",       # PDF text extraction
    "python-docx>=0.8",      # DOCX extraction
    "openpyxl>=3.1",         # XLSX extraction
]

[project.optional-dependencies]
windows = [
    "python-ntfs>=0.1",      # MFT parsing
]
```

---

## 12. Key Design Decisions

### 12.1 Why Trailer Format?

**Decision:** Use trailer appending (like ID3) rather than requiring native metadata support.

**Rationale:**
- Works on ANY file type (CSV, JSON, TXT, logs)
- Doesn't require format-specific embedding logic for every type
- Original content unchanged (verifiable via hash)
- Simple to implement and understand

**Trade-off:** Some systems may not expect trailers on certain file types.

### 12.2 Why Separate from scrubIQ?

**Decision:** OpenRisk scanner is a separate package, not a scrubIQ feature.

**Rationale:**
- Different purposes (classification vs redaction)
- Different outputs (tags vs sanitized text)
- Different users (security teams vs LLM users)
- Avoids confusing the scrubIQ value proposition
- Allows OpenRisk to be adopted independently

**Code sharing:** Detection pipeline code may be vendored or imported, but products remain separate.

### 12.3 Why Aggressive Filtering?

**Decision:** Skip most files before ML inference.

**Rationale:**
- ML inference is the bottleneck (~120ms per file)
- Most files don't contain regulated data
- Extension/path filtering is instant
- Header analysis is ~1ms per file
- 90% filtering = 10x faster scans

**Risk:** May miss regulated data in unexpected places.

**Mitigation:** Conservative classification (unknown → scan), configurable thresholds.

### 12.4 Why Four Adapters?

**Decision:** Build adapters for Presidio, AWS Macie, Google DLP, Microsoft Purview.

**Rationale:**
- Covers ~90% of market (open source + big 3 clouds)
- Proves the standard works with real tools
- Each adapter is ~2-4 hours of work
- "Build your own" guide enables community additions

**Not building:** Every possible tool. Documentation > code coverage.

### 12.5 Why Rich TUI Instead of Web Dashboard?

**Decision:** CLI with Rich TUI, no web interface for v1.

**Rationale:**
- Faster to build
- No additional dependencies (server, frontend framework)
- Works in SSH sessions
- Professional enough for the use case
- Web dashboard can come in v2 if needed

---

## 13. Future Considerations

### 13.1 If OpenRisk Gets Traction

**Community contributions:**
- Additional adapters
- Entity type proposals
- Language ports (Go, Rust, JavaScript)

**Registry server:**
- Central storage for tags by content hash
- Organization-wide visibility
- Would require hosting budget

**Enterprise features:**
- RBAC, audit logs
- Integration APIs
- Compliance reporting

### 13.2 If OpenRisk Becomes a Standard

**Governance:**
- Move spec to neutral foundation?
- Versioning and compatibility guarantees
- Entity registry governance

**Certification:**
- "OpenRisk compliant" scanner certification?
- Interoperability testing

### 13.3 scrubIQ Integration (Future)

Once both products are stable:
- scrubIQ could optionally output OpenRisk tags
- "This file has risk score 74 before redaction"
- Still separate products, but complementary

---

## Appendix A: Entity Type Reference

See `SPEC.md` for the complete entity taxonomy.

## Appendix B: Scoring Algorithm

See `SPEC.md` for the scoring formula and tier thresholds.

## Appendix C: Adapter Development Guide

See `docs/adapters.md` for the "Build Your Own Adapter" guide.

---

**End of Architecture Guide**

*This document should be referenced at the start of any Claude session working on OpenRisk.*
