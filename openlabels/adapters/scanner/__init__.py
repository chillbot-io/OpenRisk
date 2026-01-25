"""
OpenLabels Scanner - PII/PHI detection engine.

Text extraction from various file formats with OCR support.
"""

from .adapter import Detector, detect, detect_file
from .config import Config
from .types import DetectionResult, Span
from .extractor import extract_text, get_extractor, ExtractionResult
from .validators import (
    validate_file,
    validate_uploaded_file,
    detect_mime_from_magic_bytes,
    infer_content_type,
    sanitize_filename,
    is_allowed_extension,
    is_allowed_mime,
)

# OCR is optional (requires numpy, onnxruntime)
OCREngine = None
_OCR_AVAILABLE = False
try:
    from .ocr import OCREngine, _OCR_AVAILABLE
except ImportError:
    pass

__all__ = [
    # Core API
    "Detector",
    "Config",
    "DetectionResult",
    "Span",
    "detect",
    "detect_file",
    # Extraction
    "extract_text",
    "get_extractor",
    "ExtractionResult",
    # Validation
    "validate_file",
    "validate_uploaded_file",
    "detect_mime_from_magic_bytes",
    "infer_content_type",
    "sanitize_filename",
    "is_allowed_extension",
    "is_allowed_mime",
    # OCR (optional)
    "OCREngine",
    "_OCR_AVAILABLE",
]
