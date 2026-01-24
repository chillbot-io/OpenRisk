# OpenRisk Constitution

**Authoritative Design Principles for OpenRisk**

---

**Version:** 2.0
**Status:** Active
**Last Updated:** January 2026

---

## Purpose

This document defines the core principles, boundaries, and design decisions for OpenRisk. It serves as the authoritative reference for contributors, maintainers, and AI assistants working on the project.

**Read this document before making any changes to OpenRisk.**

---

## Core Principles

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          OPENRISK CONSTITUTION v2                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  1. OPENRISK IS A STANDARD FOR RISK, NOT JUST LABELS                        │
│     The unique value is: Risk = Content × Exposure                           │
│     Same SSN, different context, different risk.                             │        │
│                                                                              │
│  2. THE SCANNER IS AN ADAPTER, NOT A SEPARATE PRODUCT                        │
│     Scanner produces NormalizedInput just like Macie/DLP/Purview adapters.   │
│     It lives in the same repo, uses the same interfaces.                     │
│     The scanner cannot be "un-intertwined" from the SDK.                     │
│                                                                              │
│  3. METADATA ALWAYS CONTRIBUTES TO SCORE                                     │
│     Exposure is not conditional. It's not a "bonus" or "optional factor."   │
│     Every score includes exposure multiplier. This is the core insight.      │
│     content_score × exposure_multiplier = final_score. Always.               │
│                                                                              │
│  4. ADAPTERS NORMALIZE, THEY DON'T REPLACE                                   │
│     Macie adapter normalizes Macie output to OpenRisk format.                │
│     GCP adapter normalizes GCP output to OpenRisk format.                    │
│     Scanner adapter normalizes scanner output to OpenRisk format.            │
│     All adapters produce identical Normalized structure.                │
│                                                                              │
│  5. CONSERVATIVE UNION FOR DEFENSE IN DEPTH                                  │
│     When multiple adapters run, take max confidence per entity type.         │
│     If Macie says 3 SSNs and Scanner says 5, use 5.                         │
│     Safety first. False negatives are worse than false positives.            │
│                                                                              │
│  6. SCAN TRIGGERS DEFINE WHEN TO VERIFY                                      │
│     Even with labels, scan if: public access, no encryption, stale data,     │
│     or low confidence on high-risk entities.                                 │
│     Trust but verify. Exposure changes risk calculation.                     │
│                                                                              │
│  7. PERMISSION NORMALIZATION IS UNIVERSAL                                    │
│     S3 "authenticated-read" = NTFS "Authenticated Users" = OVER_EXPOSED     │
│     GCS "allUsers" = Azure "Blob" public = POSIX "o+r" = PUBLIC             │
│     Same exposure levels across all platforms. This enables comparison.      │
│                                                                              │
│  8. OCR IS ALWAYS-ON, LAZY-LOADED                                            │
│     RapidOCR is not optional. Many file types need it.                       │
│     Load on first use, stay loaded for session.                              │
│     Priority queue based on metadata risk score.                             │
│                                                                              │
│  9. CLI ENABLES RISK-AWARE DATA MANAGEMENT                                   │
│     quarantine, find, move, delete based on risk + filters.                  │
│     "openrisk quarantine s3://bucket --where 'score > 75 AND stale > 5y'"   │
│     This is the operational value. Not just scoring, but action.             │
│                                                                              │
│  10. AGENT FOR ON-PREM EXTENDS THE MODEL                                     │
│      Collect NTFS/POSIX metadata, normalize to same exposure levels.         │
│      Same scoring, same CLI, works everywhere.                               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## What OpenRisk IS

| Attribute | Description |
|-----------|-------------|
| **A risk scoring standard** | Portable 0-100 scores that travel with data |
| **Content + Context** | Entities detected AND exposure/metadata combined |
| **Adapter-based** | All inputs (Macie, DLP, Purview, Scanner) use same interface |
| **Cross-platform** | Same scores for S3, GCS, Azure, NTFS, POSIX |
| **Actionable** | CLI for quarantine, find, move based on risk filters |
| **Open source** | Apache 2.0 license |

---

## What OpenRisk Is NOT

| Attribute | Why Not |
|-----------|---------|
| **Just a label format** | Labels without context are incomplete. Risk needs exposure. |
| **A replacement for Macie/DLP** | We consume their output via adapters |
| **A platform or SaaS** | It's a standard with reference implementation |
| **Enterprise software** | No RBAC, no multi-tenant, no audit dashboard |
| **A real-time monitor** | Batch scanning, not streaming |
| **Varonis competitor** | Different scope, different budget class |

---

## Key Design Decisions

### 1. Exposure Multipliers

**Decision:** Exposure always multiplies content score.

**Rationale:**
- An SSN in a private bucket is different risk than SSN in public bucket
- This is the unique value proposition of OpenRisk
- Without this, we're just another classification format

**Implementation:**
```python
EXPOSURE_MULTIPLIERS = {
    ExposureLevel.PRIVATE: 1.0,
    ExposureLevel.INTERNAL: 1.2,
    ExposureLevel.OVER_EXPOSED: 1.8,
    ExposureLevel.PUBLIC: 2.5,
}

final_score = min(100, content_score * exposure_multiplier)
```

### 2. Scanner as Adapter

**Decision:** Scanner is an adapter, not a separate repo.

**Rationale:**
- Scanner produces same NormalizedInput as other adapters
- Shares entity registry, scoring engine, output formats
- Cannot be "un-intertwined" - the coupling is architectural, not accidental

**Implementation:**
```
openrisk/
├── adapters/
│   ├── macie.py
│   ├── dlp.py
│   ├── purview.py
│   └── scanner/     ← Scanner IS an adapter
│       ├── adapter.py
│       ├── detectors/
│       └── ocr/
```

### 3. Conservative Union

**Decision:** When merging adapter outputs, take max confidence per entity.

**Rationale:**
- False negatives are worse than false positives for security
- If any adapter finds something, it's probably there
- Users can tune down with confidence thresholds if needed

**Implementation:**
```python
def merge(self, inputs: List[NormalizedInput]) -> NormalizedInput:
    for entity in all_entities:
        merged[key] = Entity(
            count=max(existing.count, entity.count),
            confidence=max(existing.confidence, entity.confidence),
        )
```

### 4. Scan Triggers

**Decision:** Scan even with labels if exposure/protection gaps exist.

**Triggers:**
- NO_LABELS: No classification exists
- PUBLIC_ACCESS: Public exposure is too risky to trust labels
- NO_ENCRYPTION: Protection gap warrants verification
- STALE_DATA: Old data may have drifted
- LOW_CONFIDENCE_HIGH_RISK: Uncertain on critical entities

### 5. Permission Normalization

**Decision:** All platforms map to same four exposure levels.

**Rationale:**
- Enables cross-platform risk comparison
- "Authenticated Users" on NTFS = "authenticated-read" on S3
- Universal vocabulary for exposure

### 6. OCR Always-On

**Decision:** RapidOCR is required, not optional.

**Rationale:**
- Many file types need OCR (PDF, images)
- Small model, acceptable latency
- Lazy-load on first use to avoid startup cost

---

## Scope Boundaries

### In Scope for v1

- SDK core (RiskScorer, Tag, Trailer, Sidecar)
- All adapters (Macie, DLP, Purview, Scanner)
- Normalizers (entity types, metadata/permissions)
- Scoring engine with exposure multipliers
- CLI (scan, find, quarantine, move, report)
- Agent for on-prem (NTFS, POSIX)
- Entity registry (300+ types)

### Deferred (v2+)

- Registry server (central tag storage)
- Web dashboard
- Real-time streaming
- Multi-user / RBAC
- Incremental scanning (USN journal)

### Never Scope

- SaaS platform
- Enterprise feature parity with Varonis
- GPU cloud hosting
- Mobile apps

---

## Forbidden Suggestions

Do not suggest:

| Suggestion | Why Forbidden |
|------------|---------------|
| "Make exposure optional" | Exposure is the core differentiator |
| "Separate scanner repo" | Scanner is architecturally coupled as adapter |
| "Skip OCR for speed" | Many file types require it |
| "Add web dashboard" | Out of scope for v1 |
| "Build SaaS platform" | OpenRisk is a standard, not a product |
| "Use GPU for inference" | No GPU budget; speed via filtering |
| "Per-entity confidence thresholds" | Complexity without value |

---

## Questions to Ask Before Changes

1. Does this maintain Risk = Content × Exposure?
2. Does this keep the scanner as an adapter?
3. Is this in v1 scope?
4. Does this preserve cross-platform normalization?
5. Does this enable, not hinder, the CLI actions (quarantine, find, etc.)?

---

## Architecture Summary

```
┌────────────────────────────────────────────────────────────────────────┐
│                           OPENRISK                                      │
├────────────────────────────────────────────────────────────────────────┤
│                                                                        │
│   ADAPTERS (all produce NormalizedInput)                              │
│   ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐                    │
│   │  Macie  │ │   DLP   │ │ Purview │ │ Scanner │                    │
│   └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘                    │
│        │           │           │           │                          │
│        └───────────┴───────────┴───────────┘                          │
│                          │                                             │
│                          ▼                                             │
│   ┌─────────────────────────────────────────┐                         │
│   │         NORMALIZERS                      │                         │
│   │   • Entity types → canonical             │                         │
│   │   • Permissions → exposure levels        │                         │
│   └─────────────────────┬───────────────────┘                         │
│                         │                                              │
│                         ▼                                              │
│   ┌─────────────────────────────────────────┐                         │
│   │         MERGER                           │                         │
│   │   • Conservative union                   │                         │
│   │   • Max confidence per type              │                         │
│   └─────────────────────┬───────────────────┘                         │
│                         │                                              │
│                         ▼                                              │
│   ┌─────────────────────────────────────────┐                         │
│   │         SCORER                           │                         │
│   │   • content_score = Σ(weight × log × conf)│                       │
│   │   • × co_occurrence_multiplier           │                         │
│   │   • × exposure_multiplier                │                         │
│   │   • = final_score (0-100)                │                         │
│   └─────────────────────┬───────────────────┘                         │
│                         │                                              │
│                         ▼                                              │
│   ┌─────────────────────────────────────────┐                         │
│   │         OUTPUT                           │                         │
│   │   • OpenRisk Tag (JSON)                  │                         │
│   │   • Trailer / Sidecar                    │                         │
│   │   • CLI actions (quarantine, find, etc.) │                         │
│   └─────────────────────────────────────────┘                         │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01 | Initial constitution (scanner separate) |
| 2.0 | 2026-01 | Major rewrite: scanner as adapter, exposure multipliers, scan triggers |

---

**This document is the authoritative design reference for OpenRisk.**

*All contributors and AI assistants must internalize these principles before making changes.*
