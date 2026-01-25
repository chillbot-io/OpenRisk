"""Structured document extraction for labeled documents."""

from .core import (
    extract_structured_phi,
    post_process_ocr,
    map_span_to_original,
    StructuredExtractionResult,
    DetectedLabel,
    ExtractedField,
)

__all__ = [
    "extract_structured_phi",
    "post_process_ocr",
    "map_span_to_original",
    "StructuredExtractionResult",
    "DetectedLabel",
    "ExtractedField",
]
