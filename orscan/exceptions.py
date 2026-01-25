"""
orscan Exceptions.

Exception Hierarchy:
    OrscanError (base)
    ├── ConfigurationError
    ├── DetectionError
    └── ProcessingError
        └── FileValidationError
"""

__all__ = [
    "OrscanError",
    "ConfigurationError",
    "DetectionError",
    "ProcessingError",
    "FileValidationError",
]


class OrscanError(Exception):
    """Base exception for all orscan errors."""
    pass


class ConfigurationError(OrscanError):
    """Configuration or initialization error."""
    pass


class DetectionError(OrscanError):
    """Error during PII/PHI detection."""
    pass


class ProcessingError(OrscanError):
    """Error during file/text processing."""
    pass


class FileValidationError(ProcessingError):
    """File validation failed (type, size, etc.)."""
    def __init__(self, message: str, filename: str = None):
        self.filename = filename
        super().__init__(message)
