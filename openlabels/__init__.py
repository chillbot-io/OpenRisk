"""
OpenLabels - Universal Data Risk Scoring.

Labels are the primitive. Risk is derived.

Quick Start:
    >>> from openlabels import Client
    >>> client = Client()
    >>> result = client.score_file("document.pdf")
    >>> print(f"Risk: {result.score}/100 ({result.tier})")

For cloud DLP integration:
    >>> from openlabels.adapters import MacieAdapter
    >>> adapter = MacieAdapter()
    >>> normalized = adapter.extract(macie_findings, s3_metadata)
    >>> result = client.score_from_adapters([normalized])
"""

__version__ = "0.1.0"

from .client import Client
from .core.scorer import ScoringResult

__all__ = [
    "Client",
    "ScoringResult",
    "__version__",
]
