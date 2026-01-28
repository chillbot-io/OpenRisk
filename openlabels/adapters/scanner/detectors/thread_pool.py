"""Thread pool and concurrency utilities for detector orchestration.

This module contains:
- Module-level globals for backward compatibility (deprecated)
- Thread pool executor management
- Backpressure control via semaphores
- Queue depth tracking
- Runaway detection tracking

Module-level globals are deprecated for isolated operation.
When Context is provided to DetectorOrchestrator, these globals are NOT used.

SECURITY NOTE (LOW-005): Thread Timeout Limitations
    Python threads cannot be forcibly killed - only cancelled gracefully via
    Future.cancel(). When a detector times out:

    1. If the thread hasn't started yet, it can be cancelled (good)
    2. If the thread is running, cancel() has NO EFFECT (problematic)

    Runaway threads (those that can't be cancelled) will continue executing
    in the background, consuming CPU and memory. This is a fundamental Python
    limitation, not a bug in this code.

    Mitigations:
    - We track runaway thread count via get_runaway_detection_count()
    - Critical warnings are logged when runaway count exceeds threshold
    - Use detect_with_metadata() to check metadata.detectors_timed_out
    - For true isolation, consider process-based parallelism (multiprocessing)
    - Monitor and restart long-running processes if runaway count grows
"""

import atexit
import logging
import threading
import warnings
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from typing import Optional

from ..constants import MAX_DETECTOR_WORKERS, THREAD_JOIN_TIMEOUT
from .metadata import DetectionQueueFullError

logger = logging.getLogger(__name__)


# Configuration constants (deprecated - use Context instead)

# Maximum concurrent detection requests (backpressure)
# If exceeded, new requests will block until a slot is available
# DEPRECATED: Use Context.max_concurrent_detections instead
MAX_CONCURRENT_DETECTIONS = 10

# Maximum queue depth before rejecting requests (prevents unbounded memory growth)
# Set to 0 to disable queue depth limit (block indefinitely)
# DEPRECATED: Use Context.max_queue_depth instead
MAX_QUEUE_DEPTH = 50

# Maximum runaway detections before logging critical warning # Runaway detections are threads that timed out but couldn't be cancelled
# DEPRECATED: Use Context.max_runaway_detections instead
MAX_RUNAWAY_DETECTIONS = 5


# Module-level globals (deprecated - use Context instead)
# These globals are kept for backward compatibility but are deprecated.
# For isolated operation, pass a Context to DetectorOrchestrator.
# When a Context is provided, these globals are NOT used.

# Module-level thread pool for reuse
# Created lazily on first use, shared across all DetectorOrchestrator instances
# DEPRECATED: Use Context.get_executor() instead
_SHARED_EXECUTOR: Optional[ThreadPoolExecutor] = None

# Backpressure semaphore - limits concurrent detect() calls
# Prevents unbounded queue growth under high load
# DEPRECATED: Use Context.detection_slot() instead
_DETECTION_SEMAPHORE = threading.BoundedSemaphore(MAX_CONCURRENT_DETECTIONS)

# Track queue depth for monitoring
# DEPRECATED: Use Context.detection_slot() instead
_QUEUE_DEPTH = 0
_QUEUE_LOCK = threading.Lock()

# Track runaway detections # Threads that timed out but couldn't be cancelled.
# NOTE: This counter only increases, never decreases. We cannot detect when
# a runaway thread eventually terminates. The counter serves as a warning
# signal - if it grows large, the process should be restarted.
# DEPRECATED: Use Context.track_runaway_detection() instead
_RUNAWAY_DETECTIONS = 0
_RUNAWAY_LOCK = threading.Lock()

# Flag to track if we've warned about using deprecated globals
_DEPRECATED_GLOBALS_WARNING_ISSUED = False



def get_detection_queue_depth() -> int:
    """Get current number of pending detection requests."""
    with _QUEUE_LOCK:
        return _QUEUE_DEPTH


def get_runaway_detection_count() -> int:
    """
    Get count of runaway detections (Phase 3, Issue 3.4).

    Runaway detections are threads that timed out but could not be
    cancelled. They continue running in the background, consuming
    resources.
    """
    with _RUNAWAY_LOCK:
        return _RUNAWAY_DETECTIONS



def _warn_deprecated_globals():
    """Emit warning about using deprecated module-level globals."""
    global _DEPRECATED_GLOBALS_WARNING_ISSUED
    if not _DEPRECATED_GLOBALS_WARNING_ISSUED:
        _DEPRECATED_GLOBALS_WARNING_ISSUED = True
        warnings.warn(
            "DetectorOrchestrator is using deprecated module-level globals for "
            "resource management. For isolated operation, pass a Context instance "
            "to the orchestrator. This will become an error in a future version.",
            DeprecationWarning,
            stacklevel=4,
        )


def track_runaway_detection(detector_name: str) -> int:
    """
    Track a runaway detection thread (Phase 3, Issue 3.4).

    Called when a detector times out and cannot be cancelled.

    Returns:
        Current runaway detection count
    """
    global _RUNAWAY_DETECTIONS

    with _RUNAWAY_LOCK:
        _RUNAWAY_DETECTIONS += 1
        count = _RUNAWAY_DETECTIONS

    if count == 1:
        logger.warning(
            f"Detector {detector_name} timed out and could not be cancelled. "
            "Thread still running in background."
        )
    elif count % 5 == 0 or count >= MAX_RUNAWAY_DETECTIONS:
        logger.warning(
            f"Runaway detection count: {count}. "
            f"Detector {detector_name} is the latest."
        )

    if count >= MAX_RUNAWAY_DETECTIONS:
        logger.critical(
            f"CRITICAL: {count} runaway detections (max: {MAX_RUNAWAY_DETECTIONS}). "
            "System may be under adversarial input attack or has a detector bug. "
            "Consider restarting the process to reclaim resources."
        )

    return count


# Backward compatibility alias
_track_runaway_detection = track_runaway_detection


@contextmanager
def detection_slot_legacy():
    """
    DEPRECATED: Legacy context manager using module-level globals.

    Use Context.detection_slot() instead for proper isolation.

    Handles queue depth tracking and semaphore acquisition/release.
    Raises DetectionQueueFullError if queue is at capacity.
    """
    global _QUEUE_DEPTH

    _warn_deprecated_globals()

    # Check queue depth and increment
    with _QUEUE_LOCK:
        if MAX_QUEUE_DEPTH > 0 and _QUEUE_DEPTH >= MAX_QUEUE_DEPTH:
            raise DetectionQueueFullError(_QUEUE_DEPTH, MAX_QUEUE_DEPTH)
        _QUEUE_DEPTH += 1
        current_depth = _QUEUE_DEPTH

    acquired = False  # Track acquired state for safe cleanup
    try:
        _DETECTION_SEMAPHORE.acquire()
        acquired = True
        yield current_depth
    finally:
        if acquired:
            _DETECTION_SEMAPHORE.release()
        with _QUEUE_LOCK:
            _QUEUE_DEPTH = max(0, _QUEUE_DEPTH - 1)


# Backward compatibility alias
_detection_slot_legacy = detection_slot_legacy
_detection_slot = detection_slot_legacy


def get_executor_legacy() -> ThreadPoolExecutor:
    """
    DEPRECATED: Get or create the shared thread pool using module-level globals.

    Use Context.get_executor() instead for proper isolation.
    """
    global _SHARED_EXECUTOR

    _warn_deprecated_globals()

    if _SHARED_EXECUTOR is None:
        _SHARED_EXECUTOR = ThreadPoolExecutor(
            max_workers=MAX_DETECTOR_WORKERS,
            thread_name_prefix="detector_"
        )
        _register_shutdown_handler()  # For graceful shutdown
    return _SHARED_EXECUTOR


def _register_shutdown_handler():
    """Register executor shutdown with coordinator (falls back to atexit)."""
    try:
        from ....shutdown import get_shutdown_coordinator
        coordinator = get_shutdown_coordinator()
        coordinator.register(
            callback=_shutdown_executor,
            name="detection_executor",
            priority=10,  # Shutdown early (higher = earlier)
        )
        logger.debug("Registered detection executor with shutdown coordinator")
    except Exception as e:
        logger.debug(f"Could not register with shutdown coordinator: {e}")
        # Fall back to atexit
        atexit.register(_shutdown_executor)


# Backward compatibility alias
_get_executor_legacy = get_executor_legacy
_get_executor = get_executor_legacy


# Use central constant for shutdown timeout


def _shutdown_executor():
    """Shutdown executor with timeout-enforced graceful completion."""
    global _SHARED_EXECUTOR
    if _SHARED_EXECUTOR is None:
        return

    executor = _SHARED_EXECUTOR
    _SHARED_EXECUTOR = None  # Clear early to prevent double-shutdown

    logger.info(f"Shutting down detection executor (timeout: {THREAD_JOIN_TIMEOUT}s)...")
    shutdown_complete = threading.Event()

    def do_shutdown():
        try:
            executor.shutdown(wait=True, cancel_futures=False)
            shutdown_complete.set()
        except Exception as e:
            logger.warning(f"Error during executor shutdown: {e}")

    shutdown_thread = threading.Thread(target=do_shutdown, daemon=True)
    shutdown_thread.start()

    # Wait for graceful shutdown with timeout
    if shutdown_complete.wait(timeout=THREAD_JOIN_TIMEOUT):
        logger.debug("Detection executor shutdown complete")
    else:
        # Timeout - force shutdown
        logger.warning(
            f"Executor shutdown timed out after {THREAD_JOIN_TIMEOUT}s, forcing cancellation"
        )
        try:
            executor.shutdown(wait=False, cancel_futures=True)
        except Exception as e:
            logger.debug(f"Error during forced executor shutdown: {e}")


# Export all public symbols
__all__ = [
    # Configuration constants
    'MAX_CONCURRENT_DETECTIONS',
    'MAX_QUEUE_DEPTH',
    'MAX_RUNAWAY_DETECTIONS',
    # Public API
    'get_detection_queue_depth',
    'get_runaway_detection_count',
    'track_runaway_detection',
    'detection_slot_legacy',
    'get_executor_legacy',
    # Backward compatibility aliases
    '_track_runaway_detection',
    '_detection_slot_legacy',
    '_detection_slot',
    '_get_executor_legacy',
    '_get_executor',
    '_shutdown_executor',
    # Internal state (for testing)
    '_RUNAWAY_LOCK',
    '_QUEUE_LOCK',
    '_DEPRECATED_GLOBALS_WARNING_ISSUED',
]
