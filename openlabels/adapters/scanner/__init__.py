"""
OpenLabels Scanner - file processing.

Text extraction from various file formats with OCR support.
"""

from .extractor import extract_text, get_extractor
from .validators import validate_file, detect_file_type
from .ocr import OCREngine

__all__ = [
    "extract_text",
    "get_extractor",
    "validate_file",
    "detect_file_type",
    "OCREngine",
]
