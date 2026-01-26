"""
OpenLabels Adapters.

Adapters normalize detection results from various sources into a common format
that can be fed into the OpenLabels scoring engine.

Available adapters:
- MacieAdapter: AWS Macie + S3
- DLPAdapter: GCP DLP + GCS
- PurviewAdapter: Azure Purview + Blob

For the built-in scanner, use:
    from openlabels.adapters.scanner import Detector, detect, detect_file
"""

from .base import Adapter, Entity, NormalizedContext, NormalizedInput
from .macie import MacieAdapter
from .dlp import DLPAdapter
from .purview import PurviewAdapter

__all__ = [
    "Adapter",
    "Entity",
    "NormalizedContext",
    "NormalizedInput",
    "MacieAdapter",
    "DLPAdapter",
    "PurviewAdapter",
]
