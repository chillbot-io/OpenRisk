# OpenLabels

Universal Data Risk Scoring - **Labels are the primitive, risk is derived.**

OpenLabels detects sensitive data (PII/PHI) across files and data sources, assigns portable labels, and computes context-aware risk scores.

## Installation

```bash
pip install openlabels

# With optional features
pip install openlabels[pdf,office,ocr]  # Document scanning
pip install openlabels[all]              # Everything
```

**Requirements:** Python 3.9+

## Quick Start

### CLI

```bash
# Scan a directory
openlabels scan ./data

# Find high-risk files
openlabels find ./data --where "score >= 70"

# Generate HTML report
openlabels report ./data --format html --output report.html

# Visual risk heatmap
openlabels heatmap ./data --depth 3

# Quarantine risky files
openlabels quarantine ./data ./quarantine --min-score 80
```

### Python API

```python
from openlabels import Client

client = Client()

# Score a single file
result = client.score_file("patient_records.csv")
print(f"Risk: {result.score}/100 ({result.tier})")

# Scan directory
for item in client.scan("/data", recursive=True):
    if item.score >= 70:
        print(f"High risk: {item.path}")

# Generate report
client.report("/data", format="html", output="report.html")
```

## Features

- **Multi-format detection**: CSV, PDF, DOCX, XLSX, images (with OCR), and more
- **Entity types**: SSN, credit cards, phone numbers, emails, healthcare IDs, API keys, crypto addresses, and 50+ others
- **Checksum validation**: Validates SSNs, credit cards, IBANs, CUSIPs with Luhn/mod-97 algorithms
- **Context-aware scoring**: Co-occurrence multipliers (HIPAA, identity theft) and exposure levels
- **Cloud adapters**: AWS Macie, Google Cloud DLP, Azure Purview (normalize to common format)
- **Portable labels**: Labels travel with data via embedded metadata or virtual pointers

## Risk Scoring

Scores range 0-100 with five tiers:

| Tier | Score | Example |
|------|-------|---------|
| CRITICAL | 80+ | SSN + health diagnosis + public exposure |
| HIGH | 55-79 | Multiple direct identifiers |
| MEDIUM | 31-54 | Quasi-identifiers (name, DOB) |
| LOW | 11-30 | Contact info only |
| MINIMAL | 0-10 | No sensitive data detected |

## Architecture

```
CLI / Python API
     |
Components (Scanner, Scorer, FileOps, Reporter)
     |
Core Engine (Scoring, Labels, Entity Registry)
     |
Adapters (Cloud DLP, Filesystem, Built-in Scanner)
```

## Configuration

Entity weights are defined in `openlabels/core/registry/weights.yaml`:

```yaml
direct_identifiers:
  SSN: 10
  PASSPORT: 10
  DRIVERS_LICENSE: 9

healthcare:
  MRN: 8
  DIAGNOSIS: 7
```

## Documentation

- [OpenLabels Specification](docs/openlabels-spec-v1.md)
- [Architecture Overview](docs/openlabels-architecture-v2.md)
- [Entity Registry](docs/openlabels-entity-registry-v1.md)
- [Security Policy](SECURITY.md)

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Type checking
mypy openlabels

# Linting
ruff check openlabels
```

## License

Apache-2.0
