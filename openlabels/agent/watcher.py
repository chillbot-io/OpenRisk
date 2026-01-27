"""
File System Watcher.

Real-time monitoring of file system changes for continuous scanning.

Uses platform-specific APIs:
- Linux: inotify via watchdog
- macOS: FSEvents via watchdog
- Windows: ReadDirectoryChangesW via watchdog

Example:
    >>> from openlabels.agent import start_watcher
    >>>
    >>> def handle_change(event):
    ...     print(f"{event.event_type}: {event.path}")
    ...     if event.event_type in ("created", "modified"):
    ...         # Trigger scan
    ...         result = client.score_file(event.path)
    ...         if result.score >= 70:
    ...             print(f"High risk detected: {event.path}")
    >>>
    >>> watcher = start_watcher("/data", on_change=handle_change)
    >>> # ... watcher runs in background ...
    >>> watcher.stop()
"""

import logging
import threading
import queue
import time
import hashlib
from enum import Enum
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Callable, List, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)

# Try to import watchdog
_WATCHDOG_AVAILABLE = False
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    _WATCHDOG_AVAILABLE = True
except ImportError:
    Observer = None
    FileSystemEventHandler = object


class EventType(Enum):
    """File system event types."""
    CREATED = "created"
    MODIFIED = "modified"
    DELETED = "deleted"
    MOVED = "moved"
    RENAMED = "renamed"


@dataclass
class WatchEvent:
    """
    A file system change event.
    """
    event_type: EventType
    path: str
    is_directory: bool = False
    dest_path: Optional[str] = None  # For move/rename events
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat()


@dataclass
class WatcherConfig:
    """
    Configuration for the file watcher.
    """
    recursive: bool = True
    include_hidden: bool = False

    # File patterns to include (glob patterns)
    include_patterns: List[str] = field(default_factory=list)
    # File patterns to exclude
    exclude_patterns: List[str] = field(default_factory=lambda: [
        "*.tmp", "*.temp", "*.swp", "*.swo", "*~",  # Temp files
        ".git/*", ".svn/*", ".hg/*",                 # VCS
        "__pycache__/*", "*.pyc",                    # Python
        "node_modules/*",                            # Node.js
        ".DS_Store", "Thumbs.db",                    # OS files
    ])

    # Debounce settings (to avoid duplicate events)
    debounce_seconds: float = 0.5

    # Queue settings
    max_queue_size: int = 10000

    # Event types to watch
    watch_created: bool = True
    watch_modified: bool = True
    watch_deleted: bool = True
    watch_moved: bool = True

    # Phase 6.1: Queue overflow callback
    on_queue_full: Optional[Callable[[int], None]] = None
    """
    Callback when event queue overflows (Phase 6.1).

    Called with the total number of dropped events. Use this for monitoring
    and alerting when the watcher is falling behind.

    Example:
        def alert_on_overflow(dropped_count: int):
            if dropped_count % 100 == 0:
                send_alert(f"Watcher dropped {dropped_count} events")

        config = WatcherConfig(on_queue_full=alert_on_overflow)
    """


class FileWatcher:
    """
    File system watcher with debouncing and filtering.

    Uses watchdog library for cross-platform file system monitoring.
    """

    def __init__(
        self,
        path: str,
        on_change: Optional[Callable[[WatchEvent], None]] = None,
        config: Optional[WatcherConfig] = None,
    ):
        """
        Initialize watcher.

        Args:
            path: Directory to watch
            on_change: Callback function for change events
            config: Watcher configuration
        """
        if not _WATCHDOG_AVAILABLE:
            raise ImportError(
                "watchdog not installed. Run: pip install watchdog"
            )

        self.path = Path(path).resolve()
        if not self.path.is_dir():
            raise NotADirectoryError(f"Not a directory: {path}")

        self.on_change = on_change
        self.config = config or WatcherConfig()

        # Event queue and debouncing
        self._event_queue: queue.Queue = queue.Queue(maxsize=self.config.max_queue_size)
        self._pending_events: dict = {}  # path -> (event, timestamp)
        self._lock = threading.Lock()

        # Phase 6.1: Queue overflow tracking
        self._dropped_events: int = 0
        self._dropped_events_lock = threading.Lock()

        # Watchdog components
        self._observer: Optional[Observer] = None
        self._handler: Optional[_WatchdogHandler] = None

        # State
        self._running = False
        self._processor_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start watching for changes."""
        if self._running:
            return

        logger.info(f"Starting watcher for: {self.path}")

        # Create handler and observer
        self._handler = _WatchdogHandler(self._on_raw_event, self.config)
        self._observer = Observer()
        self._observer.schedule(
            self._handler,
            str(self.path),
            recursive=self.config.recursive,
        )

        # Start observer
        self._observer.start()
        self._running = True

        # Start event processor thread
        self._processor_thread = threading.Thread(
            target=self._process_events,
            daemon=True,
        )
        self._processor_thread.start()

        logger.info(f"Watcher started for: {self.path}")

    def stop(self) -> None:
        """Stop watching."""
        if not self._running:
            return

        logger.info(f"Stopping watcher for: {self.path}")

        self._running = False

        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None

        if self._processor_thread:
            self._processor_thread.join(timeout=2)
            self._processor_thread = None

        logger.info(f"Watcher stopped for: {self.path}")

    def _on_raw_event(self, event: WatchEvent) -> None:
        """Handle raw event from watchdog (with debouncing)."""
        with self._lock:
            now = time.time()
            self._pending_events[event.path] = (event, now)

    def _process_events(self) -> None:
        """Process pending events with debouncing."""
        while self._running:
            try:
                time.sleep(0.1)  # Check every 100ms

                with self._lock:
                    now = time.time()
                    to_process = []

                    # Find events that have settled (no updates in debounce period)
                    for path, (event, timestamp) in list(self._pending_events.items()):
                        if now - timestamp >= self.config.debounce_seconds:
                            to_process.append(event)
                            del self._pending_events[path]

                # Process settled events
                for event in to_process:
                    self._dispatch_event(event)

            except (KeyError, RuntimeError, TypeError) as e:
                logger.error(f"Error processing events: {e}")

    def _dispatch_event(self, event: WatchEvent) -> None:
        """Dispatch event to callback."""
        if self.on_change:
            try:
                self.on_change(event)
            except Exception as e:
                logger.error(f"Error in event callback: {e}")
                # Phase 6.1: Track callback failures as dropped events
                with self._dropped_events_lock:
                    self._dropped_events += 1
                    dropped_count = self._dropped_events

                if dropped_count == 1 or dropped_count % 100 == 0:
                    logger.error(
                        f"Callback failures - dropped {dropped_count} events. "
                        "Check callback implementation."
                    )

                if self.config.on_queue_full:
                    try:
                        self.config.on_queue_full(dropped_count)
                    except Exception as callback_error:
                        logger.error(f"Error in on_queue_full callback: {callback_error}")

    @property
    def is_running(self) -> bool:
        """Check if watcher is running."""
        return self._running

    @property
    def dropped_events(self) -> int:
        """
        Number of events dropped due to queue overflow (Phase 6.1).

        Use this for monitoring. If this number is growing, the watcher
        is falling behind and events are being lost.
        """
        with self._dropped_events_lock:
            return self._dropped_events

    def _enqueue_event(self, event: WatchEvent) -> bool:
        """
        Enqueue an event with overflow handling (Phase 6.1).

        Args:
            event: The event to enqueue

        Returns:
            True if event was queued, False if dropped due to overflow
        """
        try:
            self._event_queue.put_nowait(event)
            return True
        except queue.Full:
            with self._dropped_events_lock:
                self._dropped_events += 1
                dropped_count = self._dropped_events

            # Log at first drop and every 100 drops
            if dropped_count == 1 or dropped_count % 100 == 0:
                logger.error(
                    f"Event queue full - dropped {dropped_count} events. "
                    "Processing may be falling behind."
                )

            # Call overflow callback if configured
            if self.config.on_queue_full:
                try:
                    self.config.on_queue_full(dropped_count)
                except Exception as e:
                    logger.error(f"Error in on_queue_full callback: {e}")

            return False

    def reset_dropped_events(self) -> int:
        """
        Reset the dropped events counter and return the previous count.

        Useful for periodic monitoring that processes and clears the counter.

        Returns:
            The number of dropped events before reset
        """
        with self._dropped_events_lock:
            count = self._dropped_events
            self._dropped_events = 0
            return count

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False


class _WatchdogHandler(FileSystemEventHandler):
    """
    Internal handler for watchdog events.
    """

    def __init__(
        self,
        callback: Callable[[WatchEvent], None],
        config: WatcherConfig,
    ):
        super().__init__()
        self.callback = callback
        self.config = config

    def _should_process(self, path: str, is_directory: bool = False) -> bool:
        """Check if event should be processed based on config."""
        path_obj = Path(path)

        # Skip hidden files
        if not self.config.include_hidden:
            if any(part.startswith('.') for part in path_obj.parts):
                return False

        # Check exclude patterns
        import fnmatch
        for pattern in self.config.exclude_patterns:
            if fnmatch.fnmatch(str(path), pattern):
                return False
            if fnmatch.fnmatch(path_obj.name, pattern):
                return False

        # Check include patterns (if specified)
        if self.config.include_patterns and not is_directory:
            matched = False
            for pattern in self.config.include_patterns:
                if fnmatch.fnmatch(str(path), pattern):
                    matched = True
                    break
                if fnmatch.fnmatch(path_obj.name, pattern):
                    matched = True
                    break
            if not matched:
                return False

        return True

    def on_created(self, event):
        if not self.config.watch_created:
            return
        if not self._should_process(event.src_path, event.is_directory):
            return

        self.callback(WatchEvent(
            event_type=EventType.CREATED,
            path=event.src_path,
            is_directory=event.is_directory,
        ))

    def on_modified(self, event):
        if not self.config.watch_modified:
            return
        if not self._should_process(event.src_path, event.is_directory):
            return
        # Skip directory modifications (noisy)
        if event.is_directory:
            return

        self.callback(WatchEvent(
            event_type=EventType.MODIFIED,
            path=event.src_path,
            is_directory=event.is_directory,
        ))

    def on_deleted(self, event):
        if not self.config.watch_deleted:
            return
        if not self._should_process(event.src_path, event.is_directory):
            return

        self.callback(WatchEvent(
            event_type=EventType.DELETED,
            path=event.src_path,
            is_directory=event.is_directory,
        ))

    def on_moved(self, event):
        if not self.config.watch_moved:
            return
        if not self._should_process(event.src_path, event.is_directory):
            return

        self.callback(WatchEvent(
            event_type=EventType.MOVED,
            path=event.src_path,
            is_directory=event.is_directory,
            dest_path=event.dest_path,
        ))


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def start_watcher(
    path: str,
    on_change: Callable[[WatchEvent], None],
    recursive: bool = True,
    **kwargs,
) -> FileWatcher:
    """
    Start watching a directory for changes.

    Convenience function that creates and starts a FileWatcher.

    Args:
        path: Directory to watch
        on_change: Callback for change events
        recursive: Watch subdirectories
        **kwargs: Additional config options

    Returns:
        Started FileWatcher instance

    Example:
        >>> watcher = start_watcher("/data", lambda e: print(e.path))
        >>> # ... do work ...
        >>> watcher.stop()
    """
    config = WatcherConfig(recursive=recursive, **kwargs)
    watcher = FileWatcher(path, on_change=on_change, config=config)
    watcher.start()
    return watcher


def watch_directory(
    path: str,
    recursive: bool = True,
    timeout: Optional[float] = None,
    **kwargs,
):
    """
    Watch a directory and yield events.

    Generator-based interface for watching changes.

    Args:
        path: Directory to watch
        recursive: Watch subdirectories
        timeout: Stop after this many seconds (None = forever)
        **kwargs: Additional config options

    Yields:
        WatchEvent for each change

    Example:
        >>> for event in watch_directory("/data", timeout=60):
        ...     print(f"{event.event_type}: {event.path}")
    """
    event_queue: queue.Queue = queue.Queue()

    def on_change(event: WatchEvent):
        event_queue.put(event)

    watcher = start_watcher(path, on_change=on_change, recursive=recursive, **kwargs)

    try:
        start_time = time.time()
        while True:
            # Check timeout
            if timeout and (time.time() - start_time) >= timeout:
                break

            try:
                event = event_queue.get(timeout=0.5)
                yield event
            except queue.Empty:
                continue
    finally:
        watcher.stop()


# =============================================================================
# POLLING FALLBACK
# =============================================================================

class PollingWatcher:
    """
    Fallback watcher that uses polling instead of native events.

    Use this when watchdog is not available or on network filesystems
    where inotify/FSEvents don't work.

    Phase 6.2: Uses content hashing for small files to detect changes
    that occur within the same second (same mtime).
    """

    # Phase 6.2: Default threshold for content hashing (1 MB)
    DEFAULT_HASH_THRESHOLD = 1024 * 1024

    def __init__(
        self,
        path: str,
        on_change: Optional[Callable[[WatchEvent], None]] = None,
        interval: float = 5.0,
        recursive: bool = True,
        hash_threshold: Optional[int] = None,
        on_queue_full: Optional[Callable[[int], None]] = None,
    ):
        """
        Initialize polling watcher.

        Args:
            path: Directory to watch
            on_change: Callback for changes
            interval: Polling interval in seconds
            recursive: Watch subdirectories
            hash_threshold: Files smaller than this are content-hashed (Phase 6.2).
                          Set to 0 to disable hashing, None for default (1MB).
            on_queue_full: Callback when events are dropped (Phase 6.1)
        """
        self.path = Path(path).resolve()
        self.on_change = on_change
        self.interval = interval
        self.recursive = recursive
        self.hash_threshold = hash_threshold if hash_threshold is not None else self.DEFAULT_HASH_THRESHOLD
        self.on_queue_full = on_queue_full

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._known_files: dict = {}  # path -> (mtime, size, content_hash)

        # Phase 6.1: Dropped events tracking
        self._dropped_events: int = 0
        self._dropped_events_lock = threading.Lock()

    def start(self) -> None:
        """Start polling."""
        if self._running:
            return

        # Initial scan
        self._known_files = self._scan_directory()
        self._running = True

        self._thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._thread.start()

        logger.info(f"Polling watcher started for: {self.path}")

    def stop(self) -> None:
        """Stop polling."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=self.interval + 1)
            self._thread = None

    def _poll_loop(self) -> None:
        """
        Main polling loop.

        Phase 6.2: Uses content hashing for small files to detect changes
        that occur within the same second (same mtime/size).
        """
        while self._running:
            try:
                time.sleep(self.interval)

                current_files = self._scan_directory()

                # Find new and modified files (Phase 6.2: compare including content_hash)
                for path, file_state in current_files.items():
                    if path not in self._known_files:
                        self._dispatch(WatchEvent(
                            event_type=EventType.CREATED,
                            path=path,
                        ))
                    elif self._known_files[path] != file_state:
                        # File state changed (mtime, size, or content_hash)
                        self._dispatch(WatchEvent(
                            event_type=EventType.MODIFIED,
                            path=path,
                        ))

                # Find deleted files
                for path in self._known_files:
                    if path not in current_files:
                        self._dispatch(WatchEvent(
                            event_type=EventType.DELETED,
                            path=path,
                        ))

                self._known_files = current_files

            except OSError as e:
                logger.error(f"Polling error: {e}")

    def _scan_directory(self) -> dict:
        """
        Scan directory and return file info.

        Phase 6.2: Includes content hash for small files to detect
        changes that occur within the same second.

        Returns:
            Dict mapping path to (mtime, size, content_hash) tuple.
            content_hash is None for files larger than hash_threshold.
        """
        files = {}
        walker = self.path.rglob("*") if self.recursive else self.path.glob("*")

        for file_path in walker:
            if file_path.is_file():
                try:
                    st = file_path.stat()
                    # Phase 6.2: Include content hash for small files
                    if self.hash_threshold > 0 and st.st_size < self.hash_threshold:
                        content_hash = self._quick_hash(file_path)
                    else:
                        content_hash = None
                    files[str(file_path)] = (st.st_mtime, st.st_size, content_hash)
                except OSError:
                    pass

        return files

    def _quick_hash(self, path: Path, block_size: int = 65536) -> str:
        """
        Calculate a fast hash of a file (Phase 6.2).

        Uses first and last blocks + size for fast comparison.
        Not cryptographically secure, but good for change detection.

        Args:
            path: File to hash
            block_size: Size of blocks to read (default 64KB)

        Returns:
            Hex digest string (32 chars)
        """
        try:
            size = path.stat().st_size
            hasher = hashlib.blake2b()
            hasher.update(str(size).encode())

            with open(path, 'rb') as f:
                # Read first block
                hasher.update(f.read(block_size))

                # Read last block if file is large enough
                if size > block_size * 2:
                    f.seek(-block_size, 2)  # Seek from end
                    hasher.update(f.read(block_size))

            return hasher.hexdigest()[:32]
        except OSError:
            return ""

    def _dispatch(self, event: WatchEvent) -> None:
        """Dispatch event to callback."""
        if self.on_change:
            try:
                self.on_change(event)
            except Exception as e:
                logger.error(f"Callback error: {e}")
                # Phase 6.1: Track callback failures as dropped events
                with self._dropped_events_lock:
                    self._dropped_events += 1
                    dropped_count = self._dropped_events

                if dropped_count == 1 or dropped_count % 100 == 0:
                    logger.error(
                        f"Callback failures - dropped {dropped_count} events. "
                        "Check callback implementation."
                    )

                if self.on_queue_full:
                    try:
                        self.on_queue_full(dropped_count)
                    except Exception as callback_error:
                        logger.error(f"Error in on_queue_full callback: {callback_error}")

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def dropped_events(self) -> int:
        """
        Number of events dropped due to callback failures (Phase 6.1).

        Use this for monitoring. If this number is growing, there may be
        issues with your callback implementation.
        """
        with self._dropped_events_lock:
            return self._dropped_events

    def reset_dropped_events(self) -> int:
        """
        Reset the dropped events counter and return the previous count.

        Useful for periodic monitoring that processes and clears the counter.

        Returns:
            The number of dropped events before reset
        """
        with self._dropped_events_lock:
            count = self._dropped_events
            self._dropped_events = 0
            return count

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False
