"""
OpenLabels Adapters.

Adapters normalize detection results from various sources into a common format
that can be fed into the OpenLabels scoring engine.

Available adapters:
- MacieAdapter: AWS Macie + S3
- DLPAdapter: GCP DLP + GCS
- PurviewAdapter: Azure Purview + Blob
- PresidioAdapter: Microsoft Presidio
- ScannerAdapter: OpenLabels native scanner (in scanner/)
"""

from .base import Adapter, Entity, NormalizedContext, NormalizedInput
from .macie import MacieAdapter
from .dlp import DLPAdapter
from .purview import PurviewAdapter
from .presidio import PresidioAdapter

__all__ = [
    "Adapter",
    "Entity",
    "NormalizedContext",
    "NormalizedInput",
    "MacieAdapter",
    "DLPAdapter",
    "PurviewAdapter",
    "PresidioAdapter",
]
