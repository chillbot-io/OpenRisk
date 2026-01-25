"""
orscan pipeline modules.

Post-detection processing: normalization, merging, filtering.
"""

from .normalizer import normalize_text
from .merger import merge_spans
from .allowlist import apply_allowlist

__all__ = [
    "normalize_text",
    "merge_spans",
    "apply_allowlist",
]
