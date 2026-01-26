"""
OpenLabels Context.

Thread-safe context for dependency injection. Holds shared resources
like handlers, indices, and thread pools that would otherwise be globals.

Usage:
    >>> from openlabels import Context, Client
    >>>
    >>> # Default context (created automatically)
    >>> client = Client()
    >>>
    >>> # Explicit context (for testing or isolation)
    >>> ctx = Context()
    >>> client = Client(context=ctx)
    >>>
    >>> # Multiple isolated clients
    >>> ctx1 = Context()
    >>> ctx2 = Context()
    >>> client1 = Client(context=ctx1)
    >>> client2 = Client(context=ctx2)
"""

import atexit
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Optional, Any

from .adapters.scanner.constants import MAX_DETECTOR_WORKERS


@dataclass
class Context:
    """
    Thread-safe context holding shared resources.

    Each Context instance is isolated - no global state is shared.
    This enables:
    - Thread safety (each thread can have its own context)
    - Testing (inject mock resources)
    - Isolation (multiple clients don't interfere)

    Resources are created lazily on first access.
    """

    default_exposure: str = "PRIVATE"
    max_detector_workers: int = MAX_DETECTOR_WORKERS
    max_concurrent_detections: int = 10
    max_queue_depth: int = 50

    # Internal state (created lazily)
    _executor: Optional[ThreadPoolExecutor] = field(default=None, repr=False)
    _executor_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _label_index: Optional[Any] = field(default=None, repr=False)
    _index_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _virtual_handlers: dict = field(default_factory=dict, repr=False)
    _handlers_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    # Backpressure tracking
    _detection_semaphore: Optional[threading.BoundedSemaphore] = field(default=None, repr=False)
    _queue_depth: int = field(default=0, repr=False)
    _queue_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    _shutdown: bool = field(default=False, repr=False)

    def __post_init__(self):
        """Register cleanup on exit."""
        atexit.register(self.close)

    def get_executor(self) -> ThreadPoolExecutor:
        """Get or create the thread pool executor."""
        if self._shutdown:
            raise RuntimeError("Context has been closed")

        with self._executor_lock:
            if self._executor is None:
                self._executor = ThreadPoolExecutor(
                    max_workers=self.max_detector_workers,
                    thread_name_prefix="detector_"
                )
            return self._executor

    def get_detection_semaphore(self) -> threading.BoundedSemaphore:
        """Get or create the detection backpressure semaphore."""
        with self._queue_lock:
            if self._detection_semaphore is None:
                self._detection_semaphore = threading.BoundedSemaphore(
                    self.max_concurrent_detections
                )
            return self._detection_semaphore

    def get_queue_depth(self) -> int:
        """Get current detection queue depth."""
        with self._queue_lock:
            return self._queue_depth

    def increment_queue_depth(self) -> int:
        """Increment queue depth, returns new depth."""
        with self._queue_lock:
            self._queue_depth += 1
            return self._queue_depth

    def decrement_queue_depth(self) -> None:
        """Decrement queue depth."""
        with self._queue_lock:
            self._queue_depth = max(0, self._queue_depth - 1)

    def get_label_index(self):
        """Get or create the default label index."""
        with self._index_lock:
            if self._label_index is None:
                from .output.index import LabelIndex
                self._label_index = LabelIndex()
            return self._label_index

    def set_label_index(self, index) -> None:
        """Set a custom label index (for testing)."""
        with self._index_lock:
            self._label_index = index

    def get_virtual_handler(self, handler_type: str):
        """Get or create a virtual label handler by type."""
        with self._handlers_lock:
            if handler_type not in self._virtual_handlers:
                from .output.virtual import (
                    LinuxXattrHandler,
                    MacOSXattrHandler,
                    WindowsADSHandler,
                )
                import platform

                handler_map = {
                    "linux": LinuxXattrHandler,
                    "macos": MacOSXattrHandler,
                    "windows": WindowsADSHandler,
                }

                if handler_type == "auto":
                    system = platform.system().lower()
                    if system == "darwin":
                        handler_type = "macos"
                    elif system == "windows":
                        handler_type = "windows"
                    else:
                        handler_type = "linux"

                handler_class = handler_map.get(handler_type)
                if handler_class:
                    self._virtual_handlers[handler_type] = handler_class()

            return self._virtual_handlers.get(handler_type)

    def close(self) -> None:
        """Release all resources."""
        if self._shutdown:
            return

        self._shutdown = True

        with self._executor_lock:
            if self._executor is not None:
                self._executor.shutdown(wait=False)
                self._executor = None

        with self._index_lock:
            if self._label_index is not None:
                # Close index if it has a close method
                if hasattr(self._label_index, 'close'):
                    self._label_index.close()
                self._label_index = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


# Default context for simple usage
_default_context: Optional[Context] = None
_default_context_lock = threading.Lock()


def get_default_context() -> Context:
    """Get the default shared context."""
    global _default_context
    with _default_context_lock:
        if _default_context is None:
            _default_context = Context()
        return _default_context


def reset_default_context() -> None:
    """Reset the default context (mainly for testing)."""
    global _default_context
    with _default_context_lock:
        if _default_context is not None:
            _default_context.close()
            _default_context = None
