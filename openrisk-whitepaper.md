# OpenRisk: A Portable Standard for Data Sensitivity Risk Scoring

**Version 0.1 Draft**

**Author:** [Your Name]

**Date:** January 2026

---

## Abstract

Organizations generate and process unprecedented volumes of sensitive data, yet no portable, vendor-agnostic standard exists for expressing the risk associated with that data at the entity level. Current approaches rely on proprietary classification schemes that create vendor lock-in, regulatory-specific labels that fragment international operations, and qualitative tiers that provide insufficient granularity for automated decision-making.

This paper introduces OpenRisk, an open standard for data sensitivity risk scoring. OpenRisk provides a universal taxonomy of sensitive data categories, a deterministic scoring algorithm, and a portable JSON schema that enables risk scores to travel with data across organizational boundaries, security tools, and compliance regimes. Unlike existing frameworks that address enterprise risk (FAIR), threat intelligence (STIX/TAXII), or provide qualitative guidance (NIST SP 800-122), OpenRisk operates at the file and record level, producing machine-readable scores that can drive automated policy enforcement.

We present the complete specification, a reference implementation, integration patterns for existing classification tools, and a governance model for community-driven evolution of the standard.

---

## 1. Introduction

### 1.1 The Data Sensitivity Problem

The global average cost of a data breach reached $4.88 million in 2024, a 10% increase from the prior year and the largest spike since the pandemic. Customer personally identifiable information (PII) was involved in 46% of these breaches, with per-record costs averaging $173. Healthcare organizations faced even steeper consequences, with average breach costs of $7.42 million.

These figures reflect a fundamental challenge: organizations cannot protect what they cannot measure. While security teams have invested heavily in data discovery and classification tools, the outputs of these tools remain siloed within proprietary ecosystems. A document classified as "Highly Confidential" in Microsoft Purview cannot communicate its risk level to Varonis, BigID, or any other system without manual mapping and translation.

This fragmentation creates several critical problems:

**Vendor Lock-in.** Organizations that adopt one classification platform find themselves dependent on that vendor's ecosystem. Switching costs include not just licensing and migration but the loss of classification metadata that cannot be exported in a standardized format.

**Inconsistent Risk Assessment.** When a file moves between systems—through email, cloud storage, or partner sharing—its risk context is lost. The receiving system must re-classify from scratch, potentially reaching different conclusions based on different detection capabilities.

**Compliance Fragmentation.** Regulatory frameworks like HIPAA, GDPR, and CCPA define sensitivity differently. Organizations operating across jurisdictions must maintain multiple classification schemes that cannot be easily reconciled or compared.

**Automation Barriers.** Without standardized, machine-readable risk signals, automated policy enforcement remains primitive. Security teams cannot write rules that say "block transmission of any file with risk score above 75" because no universal score exists.

### 1.2 The Gap in Existing Standards

The security and privacy communities have developed numerous standards and frameworks, but none addresses the specific need for portable, file-level risk scoring:

**STIX/TAXII** (Structured Threat Information Expression / Trusted Automated Exchange of Intelligence Information) provides a language and transport protocol for sharing cyber threat intelligence. It excels at describing indicators of compromise, attack patterns, and threat actors. However, STIX addresses external threats rather than internal data sensitivity. A STIX object describes what an attacker might do; it does not describe the risk inherent in a data asset.

**FAIR** (Factor Analysis of Information Risk) is the only international standard for quantifying cybersecurity risk in financial terms. FAIR enables organizations to express risk as probable frequency and magnitude of loss events. While powerful for enterprise risk management, FAIR operates at the scenario and asset-class level, not the individual file or record level. It requires extensive analysis to produce a single risk figure and is designed for human decision-making rather than automated policy enforcement.

**Traffic Light Protocol (TLP)** provides a simple four-level classification (RED, AMBER, GREEN, WHITE) for sharing sensitive information. TLP indicates how widely information can be shared but does not quantify the underlying sensitivity of the data itself. Two documents marked TLP:AMBER may have vastly different risk profiles.

**NIST SP 800-122** offers guidance for protecting personally identifiable information, including a three-level impact assessment (Low, Moderate, High) based on six factors: identifiability, quantity, data field sensitivity, context of use, obligation to protect confidentiality, and access/location. While this guidance provides a sound conceptual framework, it remains qualitative and implementation-dependent. Two organizations following NIST 800-122 may reach different conclusions about the same data.

**ISO/IEC 27001** and related standards define requirements for information security management systems but do not prescribe specific data classification schemes or risk scores.

None of these standards provides what organizations increasingly need: a portable, quantitative, machine-readable expression of data sensitivity risk that can travel with the data itself.

### 1.3 Design Goals

OpenRisk addresses this gap with the following design principles:

1. **Portability.** Risk scores must be expressible in a standard format that any system can consume, regardless of what tool generated the classification.

2. **Universality.** Categories must transcend specific regulatory frameworks. A Social Security Number is sensitive whether the applicable law is HIPAA, CCPA, or neither.

3. **Determinism.** Given the same detected entities and confidence scores, any OpenRisk-compliant implementation must produce the same risk score.

4. **Extensibility.** The entity registry must support community contributions for new data types, regional identifiers, and emerging sensitive categories.

5. **Transparency.** Scores must be explainable. The schema must include not just the final score but the factors that produced it.

6. **Minimal Overhead.** Adoption must be simple. A Python SDK, CLI validator, and clear integration patterns should enable any team to emit or consume OpenRisk tags within hours.

---

## 2. Related Work

### 2.1 Data Classification Tools

The data classification market was valued at approximately $1.86 billion in 2024 and is projected to grow at a compound annual growth rate exceeding 20% through 2033. Major vendors include:

**Microsoft Purview** (formerly Microsoft Information Protection) provides sensitivity labels, auto-classification, and data loss prevention integrated across Microsoft 365. Classification is based on trainable classifiers, keyword patterns, and sensitive information types. Labels like "Highly Confidential" or "General" can trigger encryption, access controls, and retention policies.

**Varonis** focuses on data security posture management, discovering and classifying sensitive data across file shares, cloud storage, and SaaS applications. Varonis provides risk dashboards but uses proprietary scoring.

**BigID** emphasizes data intelligence and privacy compliance, using machine learning to discover, catalog, and classify sensitive data. BigID supports multiple classification frameworks but outputs remain within its ecosystem.

**Symantec (Broadcom) DLP** provides content inspection and classification across endpoints, networks, and cloud applications. Classification policies are proprietary and organization-specific.

**Google Cloud DLP** offers API-based sensitive data discovery with built-in detectors for over 150 information types. Results include likelihood scores but not standardized risk assessments.

Each of these tools provides value within its domain, but none produces classification metadata in a format that other tools can consume without translation.

### 2.2 Academic Research on Re-identification Risk

The academic literature on data privacy provides important foundations for understanding sensitivity:

**K-anonymity**, introduced by Latanya Sweeney, ensures that each individual in a dataset cannot be distinguished from at least k-1 other individuals based on quasi-identifiers. Sweeney demonstrated that 87% of the U.S. population can be uniquely identified by the combination of 5-digit ZIP code, birth date, and gender alone.

**L-diversity** extends k-anonymity to address homogeneity attacks, requiring that each equivalence class contain at least l distinct values for sensitive attributes.

**T-closeness** further strengthens privacy guarantees by requiring that the distribution of sensitive attributes within each equivalence class be close to their distribution in the overall dataset.

These concepts inform OpenRisk's treatment of quasi-identifiers and co-occurrence risks. The combination of individually innocuous data elements can create significant re-identification risk—a principle that OpenRisk captures through its co-occurrence multipliers.

### 2.3 The STIX/TAXII Model

STIX/TAXII provides a useful precedent for OpenRisk in several ways:

**Separation of content and transport.** STIX defines the data model; TAXII defines how to exchange it. OpenRisk similarly focuses on the data model, remaining agnostic to how tags are transmitted or stored.

**JSON serialization.** STIX 2.x uses JSON for machine readability and human inspectability. OpenRisk adopts the same approach.

**Community governance.** STIX evolved through the OASIS Cyber Threat Intelligence Technical Committee, with contributions from government agencies, security vendors, and researchers. OpenRisk proposes a similar open governance model.

**Extensibility.** STIX allows custom objects and extensions while maintaining core interoperability. OpenRisk achieves this through its entity registry contribution process.

The key difference: STIX describes threats; OpenRisk describes the sensitivity of the assets those threats target.

---

## 3. The OpenRisk Specification

### 3.1 Design Philosophy

OpenRisk embraces several deliberate constraints:

**Universal categories over regulatory mappings.** Rather than encoding HIPAA's 18 identifiers or GDPR's special categories, OpenRisk defines sensitivity in terms of inherent risk characteristics. A medical diagnosis is sensitive because it can cause harm if disclosed—not because HIPAA says so. This allows OpenRisk scores to be meaningful regardless of which regulations apply.

**Entity-level granularity.** OpenRisk scores derive from specific detected entities (SSN, credit card number, diagnosis code) rather than document-level heuristics. This enables precise explanation of why a file received its score.

**Strict mode by default.** To ensure cross-implementation consistency, OpenRisk defines a strict mode that prohibits custom weights or categories. Organizations may operate in relaxed mode for internal purposes, but compliance claims require strict mode.

**Confidence thresholds.** Detections below a specified confidence threshold (default 0.8) are logged but do not contribute to the score. This prevents low-confidence false positives from inflating risk assessments.

### 3.2 Category Taxonomy

OpenRisk defines a hierarchical taxonomy of sensitive data categories. Each category has an assigned weight range reflecting its inherent sensitivity. The taxonomy is versioned and locked per specification version to ensure deterministic scoring.

```
direct_identifier (weight: 9-10)
├── national_id (9)
│   ├── ssn           # U.S. Social Security Number
│   ├── aadhaar       # India Unique Identification
│   ├── pan           # India Permanent Account Number
│   ├── nino          # UK National Insurance Number
│   ├── cpf           # Brazil Cadastro de Pessoas Físicas
│   ├── passport      # Any national passport number
│   └── drivers_license
├── tax_id (8)
└── biometric (10)
    ├── fingerprint
    ├── face_geometry
    ├── iris_scan
    └── voice_print

quasi_identifier (weight: 2-3)
├── date_of_birth (2)
├── gender (2)
├── postal_code (2)
├── age (2)
└── race_ethnicity (3)

contact (weight: 3-4)
├── email (3)
├── phone (3)
├── ip_address (3)
└── physical_address (4)

health (weight: 5-8)
├── diagnosis (8)
├── medication (7)
├── procedure (7)
├── lab_result (7)
├── health_plan_id (6)
└── provider_name (5)

financial (weight: 5-7)
├── credit_card (7)
├── bank_account (7)
├── income (6)
└── routing_number (5)

credentials (weight: 9-10)
├── password (10)
├── api_key (10)
├── private_key (10)
└── auth_token (9)

legal (weight: 5-7)
├── criminal_record (7)
├── immigration_status (6)
└── lawsuit_party (5)
```

### 3.3 Entity Registry

The entity registry maps specific entity types to their categories and weights. Each entry includes:

- **type:** Canonical identifier (lowercase, underscore-separated)
- **category:** Full category path (e.g., `direct_identifier.national_id`)
- **weight:** Integer 1-10
- **description:** Human-readable explanation
- **region:** Optional geographic scope (e.g., `US`, `IN`, `*` for universal)
- **aliases:** Alternative names that resolve to this type

Example registry entry:

```yaml
ssn:
  category: direct_identifier.national_id
  weight: 9
  description: "U.S. Social Security Number (9 digits, XXX-XX-XXXX format)"
  region: US
  aliases:
    - social_security_number
    - us_ssn
```

The registry supports contributions through a pull request process. New entities must include documentation, region specification, and justification for the proposed weight.

### 3.4 Scoring Algorithm

The scoring algorithm proceeds in four stages:

**Stage 1: Entity Scoring**

For each detected entity type:

```
base_score = weight[entity_type] × confidence
aggregation_factor = 1 + ln(count)
entity_score = base_score × aggregation_factor
```

The logarithmic aggregation factor reflects diminishing marginal risk: the 100th SSN in a file adds less incremental risk than the first, but still contributes.

**Stage 2: Raw Score Calculation**

```
raw_score = Σ(entity_scores)
```

**Stage 3: Co-occurrence Multiplier**

Certain combinations of entity types present elevated risk. OpenRisk defines the following co-occurrence rules, applying only the highest applicable multiplier:

| Combination | Multiplier | Rationale |
|-------------|------------|-----------|
| direct_id + health | 2.0 | PHI under HIPAA; enables medical identity theft |
| direct_id + financial | 1.8 | Enables financial fraud |
| direct_id + quasi_id (3+) | 1.5 | Re-identification risk per Sweeney |
| credentials + any | 2.0 | Immediate access risk |
| quasi_id (4+) alone | 1.7 | High re-identification probability |

```
co_occurrence_multiplier = max(applicable_multipliers)
```

**Stage 4: Normalization**

```
final_score = min(100, raw_score × co_occurrence_multiplier)
```

The score is capped at 100 to provide a bounded range suitable for threshold-based policies.

### 3.5 Tier Mapping

For human communication and policy definition, scores map to named tiers:

| Tier | Score Range | Interpretation |
|------|-------------|----------------|
| Critical | 86-100 | Immediate action required; highest protection level |
| High | 61-85 | Significant risk; restricted handling required |
| Medium | 31-60 | Moderate risk; standard protection controls |
| Low | 11-30 | Limited risk; basic controls sufficient |
| Minimal | 0-10 | Negligible sensitivity |

### 3.6 Tag Schema

An OpenRisk tag is a JSON object attached to or associated with a file, record, or data asset:

```json
{
  "openrisk": {
    "version": "0.1",
    "score": 72,
    "tier": "High",
    "factors": {
      "entities": [
        {
          "type": "ssn",
          "category": "direct_identifier.national_id",
          "count": 3,
          "confidence_avg": 0.94
        },
        {
          "type": "diagnosis",
          "category": "health.diagnosis",
          "count": 2,
          "confidence_avg": 0.87
        }
      ],
      "co_occurrence_rules_triggered": ["direct_id + health"],
      "aggregation_factor": 2.1,
      "filtered": [
        {
          "type": "email",
          "count": 5,
          "confidence_avg": 0.72,
          "reason": "below_threshold"
        }
      ]
    },
    "scoring": {
      "algorithm": "openrisk-v0.1-standard",
      "confidence_threshold": 0.8,
      "mode": "strict"
    },
    "integrity": {
      "content_hash": "sha256:def456...",
      "tag_hash": "sha256:abc123...",
      "signature": "ed25519:..."
    },
    "generated_at": "2026-01-23T14:32:00Z",
    "generator": "supersieve/0.9.2"
  }
}
```

**Key elements:**

- **version:** Specification version for compatibility verification
- **score:** Normalized risk score (0-100)
- **tier:** Human-readable tier name
- **factors.entities:** All detected entities contributing to the score
- **factors.filtered:** Detections below threshold, logged for transparency
- **factors.co_occurrence_rules_triggered:** Which multipliers applied
- **scoring.mode:** `strict` (no customization) or `relaxed` (custom weights allowed)
- **integrity.content_hash:** Hash of the classified content
- **integrity.tag_hash:** Hash of the tag itself (excluding signature)
- **integrity.signature:** Optional cryptographic signature for authenticity

---

## 4. Reference Implementation

### 4.1 SDK Design

The OpenRisk Python SDK provides the canonical implementation:

```bash
pip install openrisk
```

**Core usage:**

```python
from openrisk import RiskScorer

scorer = RiskScorer()
scorer.add_detection("ssn", count=3, confidence=0.94)
scorer.add_detection("diagnosis", count=2, confidence=0.87)

tag = scorer.generate(content_hash="sha256:abc123...")

print(tag.score)      # 72
print(tag.tier)       # "High"
print(tag.to_json())  # Full tag structure
```

**Validation:**

```python
from openrisk import validate_tag

result = validate_tag(tag_json)
if not result.valid:
    print(result.errors)
```

**Entity registry queries:**

```python
import openrisk

openrisk.entity_exists("ssn")           # True
openrisk.get_entity("ssn")              # Full entity details
openrisk.resolve_alias("zip_code")      # "postal_code"
openrisk.list_entities(category="health")  # All health entities
```

### 4.2 CLI Tools

```bash
# Validate a tag file
openrisk validate tag.json

# Check if an entity type is valid
openrisk entity check ssn

# Batch check entity labels
cat labels.txt | openrisk entity check-batch

# List all registered entities
openrisk registry list

# Validate a classifier mapping file
openrisk mapping validate mapping.yaml
```

### 4.3 Strict Mode Enforcement

In strict mode (the default), the SDK enforces:

- Only entity types present in the bundled registry are accepted
- Weight overrides are prohibited
- Unknown entities raise `UnknownEntityError`
- Confidence values below threshold are automatically filtered

```python
scorer = RiskScorer(mode="strict")
scorer.add_detection("custom_type", count=1, confidence=0.9)
# Raises: UnknownEntityError("custom_type not in registry")
```

Organizations requiring custom entities must operate in relaxed mode or contribute their entities to the public registry.

---

## 5. Integration Patterns

### 5.1 Classifier Adapter Pattern

Most organizations have existing classification tools. The adapter pattern bridges these tools to OpenRisk:

```python
# Mapping from Presidio labels to OpenRisk entities
PRESIDIO_MAP = {
    "US_SSN": "ssn",
    "CREDIT_CARD": "credit_card",
    "IN_AADHAAR": "aadhaar",
    "PHONE_NUMBER": "phone",
    "EMAIL_ADDRESS": "email",
    "PERSON": None,  # Ignore - not in OpenRisk scope
    "LOCATION": None,
}

def presidio_to_openrisk(presidio_results):
    scorer = RiskScorer()
    
    # Aggregate by entity type
    counts = Counter()
    confidences = defaultdict(list)
    
    for result in presidio_results:
        entity = PRESIDIO_MAP.get(result.entity_type)
        if entity and result.score >= 0.8:
            counts[entity] += 1
            confidences[entity].append(result.score)
    
    for entity, count in counts.items():
        avg_conf = sum(confidences[entity]) / len(confidences[entity])
        scorer.add_detection(entity, count=count, confidence=avg_conf)
    
    return scorer.generate()
```

### 5.2 Configuration-Based Mapping

For operations teams who prefer configuration over code:

```yaml
# presidio_mapping.yaml
classifier: presidio
version: "2.2"
mappings:
  US_SSN: ssn
  US_ITIN: tax_id
  CREDIT_CARD: credit_card
  US_BANK_NUMBER: bank_account
  IN_AADHAAR: aadhaar
  PHONE_NUMBER: phone
  EMAIL_ADDRESS: email
  IP_ADDRESS: ip_address
  DATE_TIME: null        # Ignore
  PERSON: null           # Ignore
  LOCATION: null         # Ignore
```

```python
from openrisk.adapters import load_mapping

mapping = load_mapping("presidio_mapping.yaml")
tag = mapping.process(presidio_results)
```

### 5.3 Native Integration

Classification tools that integrate OpenRisk natively can emit compliant tags directly:

```python
# In a classification tool's output module
from openrisk import RiskScorer

class OpenRiskOutputAdapter:
    def __init__(self):
        self.scorer = RiskScorer()
    
    def on_detection(self, entity_type, confidence, location):
        # Map internal entity type to OpenRisk type
        openrisk_type = self.entity_map.get(entity_type)
        if openrisk_type:
            self.scorer.add_detection(
                openrisk_type,
                count=1,
                confidence=confidence
            )
    
    def finalize(self, content_hash):
        return self.scorer.generate(content_hash=content_hash)
```

---

## 6. Score Determinism and Reproducibility

### 6.1 Sources of Variance

A critical question for any scoring system: will two implementations produce the same score?

OpenRisk distinguishes between two types of variance:

**Detection variance** occurs because different classifiers have different capabilities. Presidio may detect 5 SSNs in a document while a custom regex finds 7. This variance is inherent and acceptable—OpenRisk standardizes how detections are scored, not how they are detected.

**Scoring variance** would occur if two implementations processed the same detections differently. OpenRisk eliminates this through strict mode: identical detections must produce identical scores.

### 6.2 Reproducibility Guarantee

Tags include full detection details, enabling score verification:

```python
from openrisk import recalculate

# Load a tag generated by another tool
original_tag = load_tag("their_output.json")

# Recalculate from the included detections
my_score = recalculate(
    entities=original_tag.factors.entities,
    mode="strict"
)

# Verify consistency
if my_score != original_tag.score:
    print(f"Score divergence: expected {original_tag.score}, got {my_score}")
```

If scores diverge, either:
- One implementation has a bug
- The original was not generated in strict mode
- The specification versions differ

### 6.3 Specification Statement

> OpenRisk standardizes how detected entities are scored, not how they are detected. Two compliant tools may produce different scores for the same content if their underlying classifiers detect different entities. Tags include full detection details so scores can be compared, verified, or re-derived.

---

## 7. Governance and Evolution

### 7.1 Specification Versioning

OpenRisk uses semantic versioning:

- **Major version** (1.0, 2.0): Breaking changes to the scoring algorithm, category structure, or tag schema
- **Minor version** (0.1, 0.2): New entities, new co-occurrence rules, non-breaking schema additions
- **Patch version** (0.1.1): Documentation corrections, SDK bug fixes

Tags include the specification version, enabling consumers to handle version differences appropriately.

### 7.2 Entity Registry Contributions

The entity registry is maintained in a public GitHub repository. Contributions follow this process:

1. **Proposal:** Open an issue describing the new entity, including:
   - Entity type name
   - Proposed category and weight
   - Geographic scope
   - Detection patterns or references
   - Justification for the weight assignment

2. **Discussion:** Community review and feedback (minimum 14 days)

3. **Pull Request:** Submit the registry entry with documentation

4. **Approval:** Requires approval from two maintainers

5. **Release:** Included in the next minor version

### 7.3 Governance Structure

OpenRisk governance comprises:

**Maintainers:** Individuals with commit access to the specification and reference implementation. Initial maintainers are the original authors; additional maintainers are nominated based on sustained contribution.

**Contributors:** Anyone who submits issues, pull requests, or participates in discussions.

**Adopters:** Organizations that implement or consume OpenRisk. Adopters may request representation in governance discussions.

**Technical Steering Committee (future):** As adoption grows, a formal committee may be established to guide specification evolution.

### 7.4 Licensing

- **Specification:** Creative Commons Attribution 4.0 (CC BY 4.0)
- **Reference SDK:** Apache License 2.0
- **Entity Registry:** Creative Commons Zero (CC0) / Public Domain

---

## 8. Future Work

### 8.1 Version 0.2: Provenance

The next specification version will address data provenance:

- **Origin tracking:** Where did this data come from?
- **Transformation history:** What processing has been applied?
- **Custody chain:** Which systems have handled this data?

Provenance enables risk scores to account for context—data from a trusted internal system may warrant different treatment than data from an unknown external source.

### 8.2 Regulatory Overlays

While OpenRisk deliberately avoids encoding specific regulations, overlay modules can map OpenRisk scores to regulatory requirements:

```python
from openrisk.overlays import hipaa

tag = scorer.generate()
hipaa_assessment = hipaa.assess(tag)

print(hipaa_assessment.is_phi)           # True/False
print(hipaa_assessment.required_safeguards)
print(hipaa_assessment.breach_notification_required)
```

### 8.3 ML Training Data Licensing

OpenRisk scores could inform data licensing for machine learning:

- Training data with scores above a threshold requires explicit consent
- Model cards could include aggregate risk scores of training data
- Data marketplaces could filter by OpenRisk tier

### 8.4 Real-time Streaming

Current specification addresses file-level scoring. Future work may address:

- Streaming data classification
- Aggregate risk scores for data flows
- Time-windowed risk assessment

---

## 9. Conclusion

The data classification market continues to grow as organizations recognize the imperative to understand and protect sensitive information. Yet this growth has produced a fragmented landscape where classification metadata remains locked within vendor ecosystems, unable to travel with the data it describes.

OpenRisk addresses this gap by providing what the industry lacks: a portable, vendor-agnostic, machine-readable standard for expressing data sensitivity risk. By defining a universal category taxonomy, a deterministic scoring algorithm, and a transparent tag schema, OpenRisk enables risk signals to flow across organizational and technical boundaries.

The standard is deliberately minimal. It does not attempt to replace existing classification tools, dictate detection methodologies, or encode specific regulatory requirements. Instead, it provides a common language for expressing what those tools discover—a language that any system can speak and any policy can consume.

Adoption begins with a simple proposition: emit OpenRisk tags alongside your existing classification outputs. Consume OpenRisk tags from your partners and vendors. Over time, as more tools speak this common language, the friction of data governance decreases while its effectiveness increases.

The specification, reference implementation, and governance model are available at [openrisk.dev]. We invite security practitioners, privacy engineers, classification vendors, and policy makers to review, implement, and contribute.

Data sensitivity is too important to remain siloed. OpenRisk provides the standard to set it free.

---

## Appendix A: Complete Entity Registry (v0.1)

| Entity Type | Category | Weight | Region | Description |
|------------|----------|--------|--------|-------------|
| ssn | direct_identifier.national_id | 9 | US | U.S. Social Security Number |
| aadhaar | direct_identifier.national_id | 9 | IN | India 12-digit unique ID |
| pan | direct_identifier.national_id | 9 | IN | India Permanent Account Number |
| nino | direct_identifier.national_id | 9 | GB | UK National Insurance Number |
| cpf | direct_identifier.national_id | 9 | BR | Brazil tax identification |
| passport | direct_identifier.national_id | 9 | * | Any passport number |
| drivers_license | direct_identifier.national_id | 9 | * | Any driver's license number |
| tax_id | direct_identifier.tax_id | 8 | * | Generic tax identifier |
| fingerprint | direct_identifier.biometric | 10 | * | Fingerprint data |
| face_geometry | direct_identifier.biometric | 10 | * | Facial recognition data |
| iris_scan | direct_identifier.biometric | 10 | * | Iris scan data |
| voice_print | direct_identifier.biometric | 10 | * | Voice biometric data |
| date_of_birth | quasi_identifier | 2 | * | Birth date |
| gender | quasi_identifier | 2 | * | Gender identity |
| postal_code | quasi_identifier | 2 | * | ZIP/postal code |
| age | quasi_identifier | 2 | * | Age in years |
| race_ethnicity | quasi_identifier | 3 | * | Racial/ethnic identification |
| email | contact | 3 | * | Email address |
| phone | contact | 3 | * | Phone number |
| ip_address | contact | 3 | * | IP address |
| physical_address | contact | 4 | * | Street address |
| diagnosis | health | 8 | * | Medical diagnosis (ICD code or text) |
| medication | health | 7 | * | Prescription or medication name |
| procedure | health | 7 | * | Medical procedure (CPT code or text) |
| lab_result | health | 7 | * | Laboratory test result |
| health_plan_id | health | 6 | * | Insurance/health plan identifier |
| provider_name | health | 5 | * | Healthcare provider name |
| credit_card | financial | 7 | * | Credit/debit card number |
| bank_account | financial | 7 | * | Bank account number |
| income | financial | 6 | * | Salary or income information |
| routing_number | financial | 5 | * | Bank routing number |
| password | credentials | 10 | * | Password or passphrase |
| api_key | credentials | 10 | * | API key or secret |
| private_key | credentials | 10 | * | Cryptographic private key |
| auth_token | credentials | 9 | * | Authentication token |
| criminal_record | legal | 7 | * | Criminal history information |
| immigration_status | legal | 6 | * | Immigration/visa status |
| lawsuit_party | legal | 5 | * | Party to legal proceedings |

---

## Appendix B: JSON Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$id": "https://openrisk.dev/schema/v0.1/tag.json",
  "title": "OpenRisk Tag",
  "type": "object",
  "required": ["openrisk"],
  "properties": {
    "openrisk": {
      "type": "object",
      "required": ["version", "score", "tier", "factors", "scoring", "generated_at"],
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
        "factors": {
          "type": "object",
          "required": ["entities"],
          "properties": {
            "entities": {
              "type": "array",
              "items": {
                "type": "object",
                "required": ["type", "category", "count", "confidence_avg"],
                "properties": {
                  "type": {"type": "string"},
                  "category": {"type": "string"},
                  "count": {"type": "integer", "minimum": 1},
                  "confidence_avg": {"type": "number", "minimum": 0, "maximum": 1}
                }
              }
            },
            "co_occurrence_rules_triggered": {
              "type": "array",
              "items": {"type": "string"}
            },
            "aggregation_factor": {"type": "number"},
            "filtered": {
              "type": "array",
              "items": {
                "type": "object",
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
            "confidence_threshold": {"type": "number"},
            "mode": {"type": "string", "enum": ["strict", "relaxed"]}
          }
        },
        "integrity": {
          "type": "object",
          "properties": {
            "content_hash": {"type": "string"},
            "tag_hash": {"type": "string"},
            "signature": {"type": "string"}
          }
        },
        "generated_at": {
          "type": "string",
          "format": "date-time"
        },
        "generator": {"type": "string"}
      }
    }
  }
}
```

---

## Appendix C: Scoring Examples

### Example 1: Simple PII Document

**Detections:**
- 2 email addresses (confidence 0.95)
- 1 phone number (confidence 0.88)

**Calculation:**
```
email:  3 × 0.95 × (1 + ln(2)) = 3 × 0.95 × 1.69 = 4.82
phone:  3 × 0.88 × (1 + ln(1)) = 3 × 0.88 × 1.00 = 2.64

raw_score = 4.82 + 2.64 = 7.46
co_occurrence_multiplier = 1.0 (no rules triggered)
final_score = 7.46 → 7

tier = "Minimal"
```

### Example 2: Medical Records

**Detections:**
- 3 SSNs (confidence 0.94)
- 2 diagnoses (confidence 0.87)
- 5 provider names (confidence 0.92)

**Calculation:**
```
ssn:       9 × 0.94 × (1 + ln(3)) = 9 × 0.94 × 2.10 = 17.77
diagnosis: 8 × 0.87 × (1 + ln(2)) = 8 × 0.87 × 1.69 = 11.76
provider:  5 × 0.92 × (1 + ln(5)) = 5 × 0.92 × 2.61 = 12.01

raw_score = 17.77 + 11.76 + 12.01 = 41.54
co_occurrence_multiplier = 2.0 (direct_id + health)
final_score = 41.54 × 2.0 = 83.08 → 83

tier = "High"
```

### Example 3: Credential Exposure

**Detections:**
- 1 API key (confidence 0.99)
- 1 password (confidence 0.95)

**Calculation:**
```
api_key:  10 × 0.99 × (1 + ln(1)) = 10 × 0.99 × 1.0 = 9.90
password: 10 × 0.95 × (1 + ln(1)) = 10 × 0.95 × 1.0 = 9.50

raw_score = 9.90 + 9.50 = 19.40
co_occurrence_multiplier = 2.0 (credentials + any)
final_score = 19.40 × 2.0 = 38.80 → 39

tier = "Medium"
```

---

## References

1. IBM Security. "Cost of a Data Breach Report 2024." Ponemon Institute, 2024.

2. IBM Security. "Cost of a Data Breach Report 2025." Ponemon Institute, 2025.

3. Sweeney, L. "Simple Demographics Often Identify People Uniquely." Carnegie Mellon University, Data Privacy Working Paper 3, 2000.

4. Machanavajjhala, A., Kifer, D., Gehrke, J., Venkitasubramaniam, M. "l-Diversity: Privacy Beyond k-Anonymity." ACM Transactions on Knowledge Discovery from Data, 2007.

5. OASIS Cyber Threat Intelligence Technical Committee. "STIX Version 2.1." OASIS Standard, 2021.

6. OASIS Cyber Threat Intelligence Technical Committee. "TAXII Version 2.1." OASIS Standard, 2021.

7. The Open Group. "Open FAIR Body of Knowledge." Open Group Standard, 2025.

8. National Institute of Standards and Technology. "SP 800-122: Guide to Protecting the Confidentiality of Personally Identifiable Information (PII)." 2010.

9. IMARC Group. "Data Classification Market: Global Industry Trends, Share, Size, Growth, Opportunity and Forecast 2025-2033." 2024.

10. Mordor Intelligence. "Data Loss Prevention Market Size & Share Analysis." 2025.

11. Narayanan, A., Shmatikov, V. "Robust De-anonymization of Large Sparse Datasets." IEEE Symposium on Security and Privacy, 2008.

12. Brookings Institution. "Data portability and interoperability: A primer on two policy tools for regulation of digitized industries." 2023.

---

*This document is released under Creative Commons Attribution 4.0 International (CC BY 4.0). You are free to share and adapt this material for any purpose, provided appropriate credit is given.*
