"""
orscan - The OpenLabels Content Scanner

A fast, accurate PII/PHI detection engine for unstructured data.
Part of the OpenLabels universal data labeling standard.

Labels are the primitive. Risk is derived.

Quick Start:
    >>> from orscan import detect
    >>> result = detect("Patient John Smith, SSN 123-45-6789")
    >>> for span in result.spans:
    ...     print(f"{span.entity_type}: {span.text}")
    NAME: John Smith
    SSN: 123-45-6789

For more control:
    >>> from orscan import Detector, Config
    >>> config = Config(min_confidence=0.8, enable_ocr=True)
    >>> detector = Detector(config)
    >>> result = detector.detect_file("document.pdf")

File Format Support (30+):
    - Text: txt, md, csv, tsv, json, jsonl, xml, yaml, log, html, rtf, sql
    - Office: pdf, docx, xlsx, pptx
    - Images (OCR): jpg, png, gif, bmp, tiff, webp
    - Email: eml, msg
    - Config: env, ini, conf
    - Archives: zip, tar, gz
"""

__version__ = "0.1.0"

from .detector import Detector, detect, detect_file
from .types import Span, DetectionResult, Tier, KNOWN_ENTITY_TYPES
from .config import Config
from .exceptions import (
    OrscanError,
    ConfigurationError,
    DetectionError,
    ProcessingError,
    FileValidationError,
)

__all__ = [
    # Version
    "__version__",
    # Main API
    "Detector",
    "detect",
    "detect_file",
    # Types
    "Span",
    "DetectionResult",
    "Tier",
    "KNOWN_ENTITY_TYPES",
    # Config
    "Config",
    # Exceptions
    "OrscanError",
    "ConfigurationError",
    "DetectionError",
    "ProcessingError",
    "FileValidationError",
]
