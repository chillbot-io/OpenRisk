# OpenRisk Scoring Methodology

**Technical Deep Dive for White Paper Integration**

**Version:** 0.1 Draft
**Date:** January 2026

---

## Executive Summary

This document provides a comprehensive technical analysis of the OpenRisk scoring methodology, including mathematical foundations, industry standard comparisons, and calibration guidance. The methodology produces deterministic, explainable risk scores (0-100) that quantify data sensitivity based on detected entities, their confidence levels, and contextual co-occurrence patterns.

---

## 1. Problem Statement

### 1.1 The Granularity Gap

Current data classification tools produce categorical outputs with limited granularity:

| Tool | Output Format | Granularity |
|------|---------------|-------------|
| AWS Macie | Severity 1-3 | 3 levels |
| Google Cloud DLP | HIGH / MODERATE / LOW | 3 levels |
| Microsoft Purview | Sensitivity labels | 4-5 levels |
| Presidio | Confidence 0.0-1.0 | Continuous (per-entity only) |

**The problem:** A file containing 3 SSNs and a file containing 300 SSNs may receive the same "HIGH" classification. Organizations cannot write policies like "block files with risk > 75" because no universal continuous score exists.

### 1.2 The False Positive Problem

Detection systems inevitably produce false positives. A pattern matching "123-45-6789" might be an SSN or a product SKU. Traditional categorical systems treat all detections equally, inflating risk assessments for files with ambiguous matches.

**OpenRisk solution:** Confidence-weighted scoring automatically discounts low-confidence detections:

```
contribution = weight × quantity_factor × confidence
                                          ↑
                          low confidence = low contribution
```

A false positive with 0.35 confidence contributes 37% as much as a true positive with 0.94 confidence. Risk becomes probabilistic, not binary.

---

## 2. Industry Standard Analysis

### 2.1 NIST Risk Framework

NIST SP 800-30 defines risk as:

```
Risk = Likelihood × Impact
```

This is qualitative, using scales like:
- Likelihood: Very Low, Low, Moderate, High, Very High
- Impact: Negligible, Limited, Serious, Severe, Catastrophic

**OpenRisk alignment:** Our formula operationalizes this concept with quantitative values. Entity weight represents potential impact; confidence represents likelihood of true detection.

### 2.2 FAIR (Factor Analysis of Information Risk)

FAIR quantifies risk in financial terms:

```
Risk = Loss Event Frequency × Loss Magnitude
```

FAIR is designed for enterprise-level risk scenarios (e.g., "probability of database breach × cost of breach"), not file-level classification.

**OpenRisk alignment:** We adopt the multiplicative principle but apply it at entity level. Each entity type has an inherent "impact weight"; each detection has a "likelihood" (confidence).

### 2.3 CVSS (Common Vulnerability Scoring System)

CVSS is the closest industry analog to OpenRisk. Key parallels:

| CVSS Property | OpenRisk Equivalent |
|---------------|---------------------|
| Weighted factors | Entity weights (1-10) |
| Base score calculation | Weighted sum with aggregation |
| Environmental modifiers | Co-occurrence multipliers |
| Normalization to bounded range | Sigmoid → 0-100 |
| Severity tiers | Risk tiers (Critical/High/Medium/Low/Minimal) |

CVSS uses expert-derived formulas calibrated against real-world vulnerability data. OpenRisk follows the same philosophy: expert-defined weights, deterministic formulas, bounded output.

**Key difference:** CVSS scores vulnerabilities (attack vectors). OpenRisk scores data sensitivity (privacy impact).

### 2.4 Google Cloud DLP Sensitivity Calculation

Google's Sensitive Data Protection calculates sensitivity by considering:
- Default sensitivity of each infoType
- Likelihood that sensitive infoTypes are present
- Whether data is unstructured/freeform

Data risk level combines sensitivity with access controls.

**OpenRisk enhancement:** We provide continuous 0-100 scores rather than categorical HIGH/MODERATE/LOW, enabling finer-grained policy decisions.

---

## 3. Mathematical Model

### 3.1 Model Classification

OpenRisk uses a **weighted heuristic scoring model**:

| Model Type | Characteristics | OpenRisk |
|------------|-----------------|----------|
| Machine Learning | Trained on labeled data, learned weights | ❌ |
| Statistical | Probabilistic distributions, Bayesian inference | ❌ |
| **Heuristic Scoring** | Expert-defined weights, deterministic rules | ✅ |
| Rule Engine | If-then-else logic | Partial (co-occurrence) |

**Why heuristics over ML?**

1. **Explainability:** Every score decomposes to traceable factors
2. **Reproducibility:** Same inputs = same outputs, always
3. **No training data required:** Expert judgment encoded directly
4. **Regulatory acceptance:** "Here's exactly why" beats "the model said so"

### 3.2 Core Formula

The OpenRisk score is calculated in four stages:

#### Stage 1: Entity-Level Contribution

For each detected entity type *i*:

```
entity_score_i = weight_i × aggregation_factor_i × confidence_i
```

Where:
- **weight_i** = sensitivity weight from registry (1-10)
- **aggregation_factor_i** = 1 + ln(count_i)
- **confidence_i** = average detection confidence (0.0-1.0)

#### Stage 2: Base Score

Sum all entity contributions:

```
base_score = Σ entity_score_i
```

#### Stage 3: Co-occurrence Adjustment

Apply multiplier for dangerous entity combinations:

```
adjusted_score = base_score × max(applicable_multipliers)
```

| Combination | Multiplier | Rationale |
|-------------|------------|-----------|
| direct_id + health | 2.0 | PHI under HIPAA; medical identity theft |
| direct_id + financial | 1.8 | Financial fraud risk |
| direct_id + quasi_id (3+) | 1.5 | Re-identification (Sweeney) |
| credentials + any | 2.0 | Immediate access risk |
| quasi_id (4+) alone | 1.7 | High re-identification probability |

#### Stage 4: Normalization

Cap at 100 for bounded output:

```
final_score = min(100, adjusted_score)
```

### 3.3 Aggregation Factor: Why Logarithmic?

The logarithmic aggregation factor implements **diminishing marginal risk**:

| Count | ln(count) + 1 | Interpretation |
|-------|---------------|----------------|
| 1 | 1.00 | First detection: full weight |
| 5 | 2.61 | 5 detections: 2.6× one detection |
| 10 | 3.30 | 10 detections: 3.3× one detection |
| 100 | 5.61 | 100 detections: 5.6× one detection |
| 1000 | 7.91 | 1000 detections: 7.9× one detection |

**Intuition:** The difference between 1 SSN and 10 SSNs is significant. The difference between 1000 SSNs and 1010 SSNs is negligible. Logarithmic scaling captures this.

**Alternative considered:** Square root (√count). Rejected because it compresses high counts less aggressively. For bulk data (millions of records), logarithmic provides better discrimination.

### 3.4 Confidence Weighting: Probabilistic Risk

The formula `weight × aggregation × confidence` means:

```
Risk = Sensitivity × Quantity × Probability
```

This directly implements **expected value of harm**:
- High-confidence detection of sensitive data → high score
- Low-confidence detection of sensitive data → proportionally lower score
- High-confidence detection of low-sensitivity data → moderate score

**Example:**

| Detection | Weight | Count | Confidence | Contribution |
|-----------|--------|-------|------------|--------------|
| SSN (real) | 9 | 3 | 0.94 | 9 × 2.10 × 0.94 = **17.77** |
| SSN (false positive) | 9 | 3 | 0.35 | 9 × 2.10 × 0.35 = **6.62** |

The false positive contributes 37% as much, automatically discounting uncertain detections.

### 3.5 Co-occurrence Multipliers: Contextual Risk

Individual entity types have inherent sensitivity. Combinations create emergent risks:

**SSN alone (weight 9):** Enables identity lookup, but limited exploitation.

**SSN + Diagnosis (health):** Now it's Protected Health Information (PHI) under HIPAA. Breach notification required. Penalties up to $1.5M per violation category.

**SSN + Credit Card (financial):** Enables financial fraud, synthetic identity creation, account takeover.

The co-occurrence multiplier captures this **superadditive risk**—the combination is worse than the sum of parts.

**Implementation note:** Only the highest applicable multiplier is applied (not cumulative) to prevent score explosion.

---

## 4. Comparison with Whitepaper Formula

The existing OpenRisk whitepaper (v0.1) specifies:

```
entity_score = weight × confidence × (1 + ln(count))
final_score = min(100, raw_score × co_occurrence_multiplier)
```

This is **exactly aligned** with our analysis. The formula is:
- Mathematically sound
- Industry-defensible (CVSS parallel)
- Practically calibratable

### 4.1 Optional Enhancement: Sigmoid Normalization

For more nuanced distribution across the 0-100 range, an alternative normalization uses the sigmoid function:

```
final_score = 100 × sigmoid((adjusted_score - midpoint) / scale)

where sigmoid(x) = 1 / (1 + e^(-x))
```

**Parameters:**
- **midpoint:** Raw score that maps to 50 (e.g., 40)
- **scale:** Controls curve steepness (e.g., 25)

**Trade-offs:**

| Approach | Pros | Cons |
|----------|------|------|
| Linear cap (current) | Simple, interpretable | Bulk sensitive data all scores 100 |
| Sigmoid | Full 0-100 distribution | Compresses extremes |

**Recommendation:** Start with linear cap (simpler). Consider sigmoid if score distribution is too bimodal in production.

---

## 5. Score Interpretation

### 5.1 Tier Mapping

| Tier | Score Range | Interpretation | Example Content |
|------|-------------|----------------|-----------------|
| **Critical** | 86-100 | Immediate action required | Bulk PHI with SSNs, credentials + PII |
| **High** | 61-85 | Significant risk; restricted handling | Medical records, SSN + financial |
| **Medium** | 31-60 | Moderate risk; standard controls | Multiple PII types, single SSN |
| **Low** | 11-30 | Limited risk; basic controls | Email addresses, phone numbers |
| **Minimal** | 0-10 | Negligible sensitivity | No PII, or very low-confidence |

### 5.2 Score Decomposition

Every OpenRisk score is fully explainable:

```json
{
  "score": 83,
  "tier": "High",
  "factors": {
    "entities": [
      {"type": "ssn", "weight": 9, "count": 3, "confidence_avg": 0.94, "contribution": 17.77},
      {"type": "diagnosis", "weight": 8, "count": 2, "confidence_avg": 0.87, "contribution": 11.76},
      {"type": "provider_name", "weight": 5, "count": 5, "confidence_avg": 0.92, "contribution": 12.01}
    ],
    "raw_score": 41.54,
    "co_occurrence_rules_triggered": ["direct_id + health"],
    "co_occurrence_multiplier": 2.0,
    "adjusted_score": 83.08
  }
}
```

This transparency is critical for:
- Audit compliance (explain why a file was blocked)
- Dispute resolution (identify scoring factors)
- Tuning (see which entities drive scores)

---

## 6. Combining Multiple Evidence Sources

### 6.1 The Integration Challenge

OpenRisk may receive input from multiple sources:
1. **External classifications** (Macie says "HIPAA", Purview says "Confidential")
2. **Scanner detections** (scrubIQ finds 47 SSNs with 0.94 confidence)

How should these combine?

### 6.2 Recommended Approach: Conservative Union

```python
def combine_sources(external_score, scanner_score):
    return max(external_score, scanner_score)
```

**Rationale:** In security, false negatives are worse than false positives. If ANY source identifies risk, we should respect that signal.

| Scenario | External | Scanner | Final | Reasoning |
|----------|----------|---------|-------|-----------|
| Agreement (clean) | 5 | 8 | **8** | Both say low risk |
| Agreement (risky) | 75 | 82 | **82** | Both say high risk |
| External only | 68 | 12 | **68** | External found something scanner missed |
| Scanner only | 5 | 72 | **72** | Scanner found something external missed |

### 6.3 External Labels as Score Floors

When external tools provide categorical labels without entity details:

```python
LABEL_FLOORS = {
    "HIPAA": 60,
    "PCI": 55,
    "PII": 40,
    "CONFIDENTIAL": 50,
    "PUBLIC": 0,
}

final_score = max(calculated_score, LABEL_FLOORS.get(external_label, 0))
```

This ensures external classification expertise is respected even when we can't access underlying detection details.

---

## 7. Calibration Requirements

### 7.1 Parameters to Calibrate

| Parameter | What It Controls | Calibration Method |
|-----------|------------------|-------------------|
| Entity weights | Relative sensitivity (SSN=9, email=3) | Expert judgment + regulatory input |
| Aggregation function | How count affects score | Empirical distribution analysis |
| Co-occurrence multipliers | Combination risk amplification | Regulatory requirements (HIPAA, PCI) |
| Tier thresholds | Score-to-tier boundaries | Expected score distribution |
| Confidence threshold | Minimum confidence to count | False positive tolerance |

### 7.2 Calibration Data Requirements

Ideal calibration dataset:
- **Ground truth entity annotations** (type, location, count)
- **Confidence scores** (if from scanner) or simulate at 0.90-0.95
- **Expected risk tier** (expert-labeled subset)
- **Negative examples** (known clean files)
- **Adversarial examples** (unicode tricks, partial matches)

**Available dataset (57,821 samples):**

| File | Records | Content |
|------|---------|---------|
| ai4privacy.jsonl | 2,723 | AI4Privacy with entity annotations |
| claude.jsonl | 42,340 | Claude-generated with entities |
| corpus.jsonl | 1,000 | Medical/PHI synthetic data |
| negative.jsonl | 7,543 | Negative examples (no PII) |
| template.jsonl | 4,215 | Template-based generation |

This dataset is **excellent** for calibration:
- Ground truth entity annotations ✓
- Multiple entity types ✓
- Negative samples for false positive testing ✓
- Medical/PHI data for HIPAA scenarios ✓
- Adversarial examples (unicode, homoglyph, case) ✓

---

## 8. Validation Methodology

### 8.1 Determinism Verification

**Requirement:** Same detections → same score, across implementations.

**Test:**
```python
def test_determinism():
    detections = [
        ("ssn", 3, 0.94),
        ("diagnosis", 2, 0.87),
    ]

    scores = [calculate_score(detections) for _ in range(1000)]
    assert len(set(scores)) == 1, "Score varies across runs"
```

### 8.2 Monotonicity Verification

**Requirement:** More sensitive data → higher score (never lower).

**Tests:**
- Adding entities should never decrease score
- Increasing count should never decrease score
- Increasing confidence should never decrease score
- Triggering co-occurrence rule should never decrease score

### 8.3 Boundary Verification

**Requirement:** Scores stay in [0, 100] range.

**Tests:**
- Empty input → score 0
- Extreme input (10,000 SSNs) → score 100, not overflow
- Negative confidence → rejected
- Unknown entity type → error (strict mode)

### 8.4 Distribution Verification

**Requirement:** Scores should distribute meaningfully across tiers.

**Test against calibration dataset:**
- Not all scores should cluster at 0 or 100
- Each tier should have representatives
- Clean files should score < 10
- PHI-heavy files should score > 60

---

## 9. Conclusion

The OpenRisk scoring methodology is:

1. **Mathematically sound** - Weighted heuristic model with logarithmic scaling
2. **Industry-aligned** - Parallels CVSS, operationalizes NIST/FAIR principles
3. **Practically superior** - Continuous 0-100 vs. categorical L/M/H
4. **Explainable** - Every score decomposes to traceable factors
5. **Calibratable** - Available dataset enables empirical validation

The formula balances simplicity and expressiveness:

```
score = min(100, Σ(weight × (1 + ln(count)) × confidence) × co_occurrence_multiplier)
```

This is the right math for portable, vendor-neutral data sensitivity scoring.

---

## References

1. NIST SP 800-30 Rev. 1 - Guide for Conducting Risk Assessments
2. FIRST.org - Common Vulnerability Scoring System v4.0 Specification
3. The Open Group - Open FAIR Body of Knowledge
4. Google Cloud - Sensitivity and Data Risk Levels Documentation
5. Sweeney, L. - "Simple Demographics Often Identify People Uniquely" (2000)
6. OASIS - STIX/TAXII 2.1 Specifications

---

*This document is intended for integration into the OpenRisk whitepaper. Content licensed under CC BY 4.0.*
