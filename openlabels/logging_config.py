"""
OpenLabels logging configuration.

Provides structured logging with JSON output for production and
human-readable console output for development.

Usage:
    from openlabels.logging_config import setup_logging, get_audit_logger

    # In CLI main:
    setup_logging(verbose=True, log_file="/var/log/openlabels.log")

    # For audit events:
    audit = get_audit_logger()
    audit.info("file_quarantine", path="/data/file.txt", destination="/quarantine")
"""

import logging
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any, Dict


# =============================================================================
# FORMATTERS
# =============================================================================

class JSONFormatter(logging.Formatter):
    """
    JSON formatter for structured logging.

    Outputs one JSON object per line for easy parsing by log aggregators
    like Elasticsearch, Splunk, or CloudWatch.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add source location for debug/error
        if record.levelno >= logging.WARNING or record.levelno == logging.DEBUG:
            log_data["source"] = {
                "file": record.filename,
                "line": record.lineno,
                "function": record.funcName,
            }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add any extra fields passed via the `extra` parameter
        for key, value in record.__dict__.items():
            if key not in (
                "name", "msg", "args", "created", "filename", "funcName",
                "levelname", "levelno", "lineno", "module", "msecs",
                "pathname", "process", "processName", "relativeCreated",
                "stack_info", "exc_info", "exc_text", "thread", "threadName",
                "message", "taskName"
            ):
                log_data[key] = value

        return json.dumps(log_data, default=str)


class ConsoleFormatter(logging.Formatter):
    """
    Human-readable console formatter with optional colors.

    Format: LEVEL: message [logger] (for non-INFO)
    """

    COLORS = {
        "DEBUG": "\033[36m",     # Cyan
        "INFO": "\033[32m",      # Green
        "WARNING": "\033[33m",   # Yellow
        "ERROR": "\033[31m",     # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    RESET = "\033[0m"

    def __init__(self, use_colors: bool = True):
        super().__init__()
        self.use_colors = use_colors and sys.stderr.isatty()

    def format(self, record: logging.LogRecord) -> str:
        level = record.levelname
        message = record.getMessage()

        # For INFO, just show the message (clean output)
        if level == "INFO":
            return message

        # For other levels, show level prefix
        if self.use_colors:
            color = self.COLORS.get(level, "")
            return f"{color}{level}{self.RESET}: {message}"
        else:
            return f"{level}: {message}"


# =============================================================================
# AUDIT LOGGER
# =============================================================================

class AuditLogger:
    """
    Structured audit logger for security-relevant operations.

    Audit events are always logged at INFO level with structured data,
    and use a dedicated 'audit.*' logger namespace.

    Usage:
        audit = get_audit_logger()
        audit.log("file_quarantine", path="/data/file.txt", score=85)
        audit.log("scan_complete", files_scanned=100, pii_found=5)
    """

    def __init__(self, logger: logging.Logger):
        self._logger = logger

    def log(self, event: str, **kwargs: Any) -> None:
        """
        Log an audit event with structured data.

        Args:
            event: Event type (e.g., "file_quarantine", "scan_start")
            **kwargs: Additional structured data for the event
        """
        extra = {
            "audit_event": event,
            "audit_data": kwargs,
            "audit_timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._logger.info(f"AUDIT: {event}", extra=extra)

    # Convenience methods for common events
    def scan_start(self, path: str, **kwargs) -> None:
        self.log("scan_start", path=path, **kwargs)

    def scan_complete(self, path: str, files_scanned: int, **kwargs) -> None:
        self.log("scan_complete", path=path, files_scanned=files_scanned, **kwargs)

    def file_quarantine(self, source: str, destination: str, score: int, **kwargs) -> None:
        self.log("file_quarantine", source=source, destination=destination, score=score, **kwargs)

    def file_delete(self, path: str, score: int, **kwargs) -> None:
        self.log("file_delete", path=path, score=score, **kwargs)

    def file_encrypt(self, path: str, **kwargs) -> None:
        self.log("file_encrypt", path=path, **kwargs)

    def access_restrict(self, path: str, **kwargs) -> None:
        self.log("access_restrict", path=path, **kwargs)


# Module-level audit logger instance
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> AuditLogger:
    """Get the audit logger instance."""
    global _audit_logger
    if _audit_logger is None:
        logger = logging.getLogger("audit.openlabels")
        _audit_logger = AuditLogger(logger)
    return _audit_logger


# =============================================================================
# SETUP FUNCTIONS
# =============================================================================

def setup_logging(
    verbose: bool = False,
    quiet: bool = False,
    log_file: Optional[str] = None,
    json_format: bool = False,
    no_color: bool = False,
) -> None:
    """
    Configure logging for the application.

    Args:
        verbose: Enable DEBUG level logging
        quiet: Only show ERROR and above
        log_file: Path to log file (uses JSON format automatically)
        json_format: Use JSON format for console output
        no_color: Disable colors in console output

    Examples:
        # Development - human readable
        setup_logging(verbose=True)

        # Production - JSON to file
        setup_logging(log_file="/var/log/openlabels.log")

        # CI/CD - JSON to console
        setup_logging(json_format=True)
    """
    # Determine log level
    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    # Get root logger for openlabels
    root_logger = logging.getLogger("openlabels")
    root_logger.setLevel(level)

    # Clear any existing handlers
    root_logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(level)

    if json_format:
        console_handler.setFormatter(JSONFormatter())
    else:
        console_handler.setFormatter(ConsoleFormatter(use_colors=not no_color))

    root_logger.addHandler(console_handler)

    # File handler (always JSON for machine parsing)
    if log_file:
        file_path = Path(log_file)
        file_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)  # Capture everything to file
        file_handler.setFormatter(JSONFormatter())
        root_logger.addHandler(file_handler)

    # Setup audit logger (always enabled, uses same handlers)
    audit_logger = logging.getLogger("audit.openlabels")
    audit_logger.setLevel(logging.INFO)  # Audit is always at least INFO

    # Audit gets the same handlers, but we could add a separate file handler here
    # if audit trail needs to be separate

    # Suppress noisy third-party loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("boto3").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the openlabels namespace.

    Args:
        name: Logger name, typically __name__

    Returns:
        Logger instance

    Usage:
        logger = get_logger(__name__)
        logger.info("Processing file", extra={"path": "/data/file.txt"})
    """
    # If name already starts with openlabels, use as-is
    if name.startswith("openlabels"):
        return logging.getLogger(name)
    # Otherwise, add the openlabels prefix
    return logging.getLogger(f"openlabels.{name}")
