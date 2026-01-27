"""
OpenLabels Exception Hierarchy.

Provides structured error types that enable callers to distinguish between
different failure modes and handle them appropriately.

Exception Categories:
- TransientError: May succeed on retry (network, timeout, lock contention)
- PermanentError: Will not succeed on retry (validation, not found, corruption)

Usage:
    from openlabels.core.exceptions import (
        OpenLabelsError,
        TransientError,
        PermanentError,
        DatabaseError,
        NotFoundError,
        CorruptedDataError,
        ValidationError,
    )

    try:
        label = index.get(label_id)
    except DatabaseError:
        # Retry with backoff
    except NotFoundError:
        # Handle missing data
    except CorruptedDataError:
        # Log and skip corrupted record
"""

from enum import Enum
from typing import Optional, Any


class OpenLabelsError(Exception):
    """
    Base exception for all OpenLabels errors.

    All OpenLabels exceptions inherit from this class, making it easy
    to catch any library error while still allowing specific handling.
    """

    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} (details: {self.details})"
        return self.message


# =============================================================================
# TRANSIENT ERRORS - May succeed on retry
# =============================================================================

class TransientError(OpenLabelsError):
    """
    Error that may succeed on retry.

    Examples: network issues, timeouts, lock contention, temporary
    resource unavailability.

    Callers should implement retry with exponential backoff.
    """
    pass


class DatabaseError(TransientError):
    """
    Database operation failed.

    May be due to:
    - Lock contention (SQLITE_BUSY)
    - Connection issues
    - Disk I/O errors

    Usually retryable after a short delay.
    """

    def __init__(self, message: str, operation: Optional[str] = None, **kwargs):
        super().__init__(message, kwargs)
        self.operation = operation


class NetworkError(TransientError):
    """
    Network operation failed.

    May be due to:
    - Connection timeout
    - DNS resolution failure
    - Remote service unavailable

    Usually retryable after a delay.
    """

    def __init__(self, message: str, url: Optional[str] = None, **kwargs):
        super().__init__(message, kwargs)
        self.url = url


class TimeoutError(TransientError):
    """
    Operation timed out.

    May be due to:
    - Slow processing
    - Resource contention
    - Large input size

    May be retryable with longer timeout or smaller input.
    """

    def __init__(
        self,
        message: str,
        timeout_seconds: Optional[float] = None,
        operation: Optional[str] = None,
        **kwargs
    ):
        super().__init__(message, kwargs)
        self.timeout_seconds = timeout_seconds
        self.operation = operation


class ResourceBusyError(TransientError):
    """
    Resource is temporarily busy.

    May be due to:
    - File locked by another process
    - Queue at capacity
    - Rate limiting

    Retryable after delay.
    """

    def __init__(self, message: str, resource: Optional[str] = None, **kwargs):
        super().__init__(message, kwargs)
        self.resource = resource


# =============================================================================
# PERMANENT ERRORS - Will not succeed on retry
# =============================================================================

class PermanentError(OpenLabelsError):
    """
    Error that will not succeed on retry.

    Examples: validation failures, missing resources, corrupted data,
    permission denied.

    Callers should handle the error or propagate it.
    """
    pass


class NotFoundError(PermanentError):
    """
    Requested resource was not found.

    Examples:
    - Label ID doesn't exist
    - File path doesn't exist
    - Configuration key missing

    This is a valid "not found" result, not a database error.
    """

    def __init__(
        self,
        message: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        **kwargs
    ):
        super().__init__(message, kwargs)
        self.resource_type = resource_type
        self.resource_id = resource_id


class CorruptedDataError(PermanentError):
    """
    Data is corrupted or malformed.

    Examples:
    - Invalid JSON in database
    - Schema validation failed
    - Checksum mismatch

    The corrupted record should be logged and skipped or quarantined.
    """

    def __init__(
        self,
        message: str,
        data_location: Optional[str] = None,
        expected_format: Optional[str] = None,
        **kwargs
    ):
        super().__init__(message, kwargs)
        self.data_location = data_location
        self.expected_format = expected_format


class ValidationError(PermanentError):
    """
    Input validation failed.

    Examples:
    - Invalid parameter value
    - Required field missing
    - Value out of range

    Caller should fix the input before retrying.
    """

    def __init__(
        self,
        message: str,
        field: Optional[str] = None,
        value: Any = None,
        constraint: Optional[str] = None,
        **kwargs
    ):
        super().__init__(message, kwargs)
        self.field = field
        self.value = value
        self.constraint = constraint


class PermissionDeniedError(PermanentError):
    """
    Permission denied for operation.

    Examples:
    - File not readable
    - Directory not writable
    - Insufficient privileges

    Usually requires manual intervention to fix permissions.

    Note: Named PermissionDeniedError to avoid shadowing Python's
    built-in PermissionError.
    """

    def __init__(
        self,
        message: str,
        path: Optional[str] = None,
        required_permission: Optional[str] = None,
        **kwargs
    ):
        super().__init__(message, kwargs)
        self.path = path
        self.required_permission = required_permission


class ConfigurationError(PermanentError):
    """
    Configuration is invalid or missing.

    Examples:
    - Required config not set
    - Invalid config value
    - Incompatible config combination

    Requires configuration fix before retry.
    """

    def __init__(
        self,
        message: str,
        config_key: Optional[str] = None,
        **kwargs
    ):
        super().__init__(message, kwargs)
        self.config_key = config_key


# =============================================================================
# FILE OPERATION ERRORS
# =============================================================================

class FileErrorType(Enum):
    """Classification of file operation errors."""
    PERMISSION_DENIED = "permission_denied"
    DISK_FULL = "disk_full"
    NOT_FOUND = "not_found"
    ALREADY_EXISTS = "already_exists"
    NETWORK_ERROR = "network_error"
    LOCKED = "locked"
    INVALID_PATH = "invalid_path"
    UNKNOWN = "unknown"


class FileOperationError(OpenLabelsError):
    """
    Structured error for file operations.

    Provides classification of the error type and whether it's retryable,
    enabling callers to handle different failure modes appropriately.
    """

    def __init__(
        self,
        message: str,
        path: str,
        error_type: FileErrorType,
        retryable: bool = False,
        original_error: Optional[Exception] = None,
        **kwargs
    ):
        super().__init__(message, kwargs)
        self.path = path
        self.error_type = error_type
        self.retryable = retryable
        self.original_error = original_error

    @classmethod
    def from_exception(cls, e: Exception, path: str) -> "FileOperationError":
        """
        Create FileOperationError from a standard exception.

        Classifies the error type based on the exception class and errno.
        """
        import errno

        message = str(e)

        # PermissionError
        if isinstance(e, PermissionError):
            return cls(
                message=message,
                path=path,
                error_type=FileErrorType.PERMISSION_DENIED,
                retryable=False,
                original_error=e,
            )

        # FileNotFoundError
        if isinstance(e, FileNotFoundError):
            return cls(
                message=message,
                path=path,
                error_type=FileErrorType.NOT_FOUND,
                retryable=False,
                original_error=e,
            )

        # FileExistsError
        if isinstance(e, FileExistsError):
            return cls(
                message=message,
                path=path,
                error_type=FileErrorType.ALREADY_EXISTS,
                retryable=False,
                original_error=e,
            )

        # OSError with errno
        if isinstance(e, OSError) and hasattr(e, 'errno'):
            if e.errno == errno.ENOSPC:
                return cls(
                    message=message,
                    path=path,
                    error_type=FileErrorType.DISK_FULL,
                    retryable=False,
                    original_error=e,
                )
            if e.errno in (errno.EACCES, errno.EPERM):
                return cls(
                    message=message,
                    path=path,
                    error_type=FileErrorType.PERMISSION_DENIED,
                    retryable=False,
                    original_error=e,
                )
            if e.errno in (errno.ENOENT,):
                return cls(
                    message=message,
                    path=path,
                    error_type=FileErrorType.NOT_FOUND,
                    retryable=False,
                    original_error=e,
                )
            if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                return cls(
                    message=message,
                    path=path,
                    error_type=FileErrorType.LOCKED,
                    retryable=True,
                    original_error=e,
                )

        # Network-related errors
        if isinstance(e, (ConnectionError, TimeoutError)):
            return cls(
                message=message,
                path=path,
                error_type=FileErrorType.NETWORK_ERROR,
                retryable=True,
                original_error=e,
            )

        # Unknown
        return cls(
            message=message,
            path=path,
            error_type=FileErrorType.UNKNOWN,
            retryable=False,
            original_error=e,
        )


# =============================================================================
# DETECTION ERRORS
# =============================================================================

class DetectionError(OpenLabelsError):
    """Base class for detection-related errors."""
    pass


class DetectorFailedError(DetectionError):
    """
    A detector failed during execution.

    Contains information about which detector failed and why.
    """

    def __init__(
        self,
        message: str,
        detector_name: str,
        original_error: Optional[Exception] = None,
        **kwargs
    ):
        super().__init__(message, kwargs)
        self.detector_name = detector_name
        self.original_error = original_error


class AllDetectorsFailedError(DetectionError):
    """
    All detectors failed during execution.

    This is a critical error - no detection results are available.
    """

    def __init__(
        self,
        message: str,
        failed_detectors: list,
        **kwargs
    ):
        super().__init__(message, kwargs)
        self.failed_detectors = failed_detectors


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Base
    "OpenLabelsError",
    # Transient
    "TransientError",
    "DatabaseError",
    "NetworkError",
    "TimeoutError",
    "ResourceBusyError",
    # Permanent
    "PermanentError",
    "NotFoundError",
    "CorruptedDataError",
    "ValidationError",
    "PermissionDeniedError",
    "ConfigurationError",
    # File operations
    "FileErrorType",
    "FileOperationError",
    # Detection
    "DetectionError",
    "DetectorFailedError",
    "AllDetectorsFailedError",
]
