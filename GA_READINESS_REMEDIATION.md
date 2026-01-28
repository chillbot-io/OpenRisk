# GA Readiness Remediation Plan

**Created:** 2026-01-28
**Goal:** Address all Tier 1 and Tier 2 production blockers
**Target:** Production-ready release
**Estimated Effort:** 4-5 days

---

## Current State

| Category | Issue Count | Status |
|----------|-------------|--------|
| **Tier 1: MUST FIX** | 4 (1 complete) | Blocking GA |
| **Tier 2: SHOULD FIX** | 3 | Required before GA |

### Progress
- [x] **1.1 TOCTOU Race Conditions** - COMPLETE (2026-01-28)
- [ ] 1.2 Silent Exception Handlers
- [ ] 1.3 Incomplete Shutdown
- [ ] 1.4 No Cloud Adapter Retry
- [ ] 2.1 Long Functions
- [ ] 2.2 Missing Logging
- [ ] 2.3 Hardcoded Configuration

---

## Tier 1: MUST FIX (Blocking)

### 1.1 TOCTOU Race Conditions

**Priority:** CRITICAL
**Effort:** 4-6 hours
**Risk:** Security vulnerability - symlink attacks

#### Issue Description
Time-of-check to time-of-use race conditions allow attackers to replace files with symlinks between validation and operation, enabling path traversal attacks.

#### Affected Files

| File | Lines | Issue | Fix |
|------|-------|-------|-----|
| `agent/collector.py` | 536-538 | `is_file()` before `stat()` | Use `stat()` directly, check `S_ISREG` |
| `agent/watcher.py` | ~620-640 | Same pattern in `_scan_directory` | Use `stat()` directly, check `S_ISREG` |
| `cli/commands/quarantine.py` | 48-74 | `is_symlink()` before `shutil.move()` | Atomic move with `os.rename()` fallback |
| `components/scanner.py` | (file size check) | `stat()` before `read()` | Read with size limit, handle truncation |

#### Implementation

**Pattern to replace everywhere:**
```python
# BEFORE (vulnerable)
for file_path in walker:
    if not file_path.is_file():  # TOCTOU window here
        continue
    # ... later ...
    st = file_path.stat()

# AFTER (safe)
import stat as stat_module

for file_path in walker:
    try:
        st = file_path.stat(follow_symlinks=False)
        if not stat_module.S_ISREG(st.st_mode):
            continue  # Not a regular file (could be symlink, dir, etc.)
    except OSError:
        continue  # File doesn't exist or can't be accessed
```

**Quarantine fix:**
```python
# BEFORE (vulnerable)
if source.is_symlink():
    return False, FileError.SYMLINK
# ... time passes ...
shutil.move(source, dest)

# AFTER (safe)
def _safe_move(source: Path, dest: Path) -> Tuple[bool, Optional[FileError]]:
    """Atomically move file, rejecting symlinks."""
    try:
        # Get file info without following symlinks
        st = source.lstat()
        if stat_module.S_ISLNK(st.st_mode):
            return False, FileError.SYMLINK
        if not stat_module.S_ISREG(st.st_mode):
            return False, FileError.NOT_FILE

        # Atomic rename (same filesystem) or copy+delete
        try:
            os.rename(source, dest)
        except OSError:
            # Cross-filesystem: copy then delete
            shutil.copy2(source, dest)
            os.unlink(source)
        return True, None
    except OSError as e:
        return False, FileError.from_exception(e, str(source))
```

#### Verification
- [x] Add test: create symlink, attempt to scan, verify rejection (test_toctou_security.py)
- [x] Add test: create symlink, attempt to quarantine, verify rejection (test_toctou_security.py)
- [x] Add test: race condition simulation with threading (test_toctou_security.py)

#### Status: COMPLETE (2026-01-28)

**Comprehensive codebase audit completed. 17 files fixed:**

Core Components:
- `agent/collector.py`: Uses `lstat()` before `resolve()` to detect symlinks
- `agent/watcher.py`: Uses `stat(follow_symlinks=False)` in `_scan_directory()`
- `agent/posix.py`: Uses `lstat()` instead of `exists()` + `stat()`
- `cli/commands/quarantine.py`: Uses `lstat()` and verifies inode on cross-filesystem moves
- `components/scanner.py`: Uses `stat(follow_symlinks=False)` in `scan()`, `_iter_files()`, `_build_tree_node()`
- `components/fileops.py`: Uses `lstat()` in `move()` and `delete()`

Detection Pipeline:
- `adapters/scanner/adapter.py`: Uses `lstat()` in `detect_file()`
- `adapters/scanner/validators.py`: Uses `lstat()` in all validation functions

Output & CLI:
- `output/reader.py`: Uses `lstat()` in `find_unlabeled_files()` and `find_stale_labels()`
- `cli/main.py`: Uses `lstat()` in `run_detect_dir()`
- `cli/commands/scan.py`: Uses `lstat()` helper throughout
- `cli/commands/find.py`: Uses `lstat()` helper
- `cli/commands/report.py`: Uses `lstat()` helper
- `cli/commands/heatmap.py`: Uses `lstat()` in `build_tree()`
- `cli/commands/encrypt.py`: Uses `lstat()` in `validate_file_path()`

**33 TOCTOU-specific tests added in `tests/test_toctou_security.py`**

---

### 1.2 Silent Exception Handlers

**Priority:** CRITICAL
**Effort:** 2-3 hours
**Risk:** Production bugs hidden, debugging impossible

#### Issue Description
Multiple locations catch exceptions and silently discard them, making production debugging nearly impossible.

#### Affected Files

| File | Lines | Current | Fix |
|------|-------|---------|-----|
| `output/index.py` | 257-266 | `except sqlite3.Error: pass` | Log at WARNING |
| `output/index.py` | 316-321 | `except AttributeError: pass` | Log at DEBUG |
| `adapters/scanner/temp_storage.py` | 262 | `except OSError: pass` | Log at WARNING |
| `adapters/scanner/temp_storage.py` | 265 | `except OSError: pass` | Log at WARNING |
| `context.py` | 135-138 | `logger.debug()` for critical path | Log at WARNING |
| `components/fileops.py` | 163-169 | `except OSError: pass` | Log at DEBUG |

#### Implementation

**index.py - Connection invalidation:**
```python
# BEFORE
def _invalidate_connection(self, conn_key: str, conn: sqlite3.Connection) -> None:
    try:
        conn.close()
    except sqlite3.Error:
        pass  # Silent!
    try:
        delattr(self._thread_local, conn_key)
    except AttributeError:
        pass  # Silent!

# AFTER
def _invalidate_connection(self, conn_key: str, conn: sqlite3.Connection) -> None:
    try:
        conn.close()
    except sqlite3.Error as e:
        logger.warning(f"Error closing stale database connection: {e}")
    try:
        delattr(self._thread_local, conn_key)
    except AttributeError:
        logger.debug(f"Connection key {conn_key} already removed from thread-local storage")
```

**temp_storage.py - Cleanup:**
```python
# BEFORE
def _cleanup_on_exit(self) -> None:
    try:
        shutil.rmtree(self._path)
    except OSError:
        pass

# AFTER
def _cleanup_on_exit(self) -> None:
    try:
        shutil.rmtree(self._path)
    except OSError as e:
        logger.warning(f"Failed to clean up temp directory {self._path}: {e}")
```

**context.py - Shutdown registration:**
```python
# BEFORE
except Exception as e:
    logger.debug(f"Could not register with shutdown coordinator: {e}")

# AFTER
except Exception as e:
    logger.warning(f"Could not register with shutdown coordinator: {e}. "
                   "Graceful shutdown may not work correctly.")
```

#### Verification
- [ ] `grep -r "except.*:.*pass" openlabels/` returns 0 matches
- [ ] `grep -r "except Exception:" openlabels/` - all have logging
- [ ] Run with `LOG_LEVEL=DEBUG`, verify exception paths logged

---

### 1.3 Incomplete Shutdown

**Priority:** HIGH
**Effort:** 2-3 hours
**Risk:** Data loss, orphaned tasks on exit

#### Issue Description
Thread pool executor shutdown uses `wait=False`, abandoning in-flight tasks. This can cause incomplete results or data corruption.

#### Affected Files

| File | Lines | Issue |
|------|-------|-------|
| `adapters/scanner/thread_pool.py` | 251 | `shutdown(wait=False)` |
| `context.py` | (executor cleanup) | May not wait for tasks |

#### Implementation

**thread_pool.py:**
```python
# BEFORE
def _shutdown_executor():
    """Shutdown the shared executor on process exit."""
    if _SHARED_EXECUTOR is not None:
        _SHARED_EXECUTOR.shutdown(wait=False)

# AFTER
import signal
import threading

_SHUTDOWN_TIMEOUT = 5.0  # seconds to wait for graceful shutdown

def _shutdown_executor():
    """Shutdown the shared executor on process exit."""
    global _SHARED_EXECUTOR
    if _SHARED_EXECUTOR is not None:
        logger.info("Shutting down detection executor, waiting for in-flight tasks...")
        try:
            _SHARED_EXECUTOR.shutdown(wait=True, cancel_futures=False)
            logger.debug("Detection executor shutdown complete")
        except Exception as e:
            logger.warning(f"Error during executor shutdown: {e}")
            # Force shutdown if graceful fails
            _SHARED_EXECUTOR.shutdown(wait=False, cancel_futures=True)
        finally:
            _SHARED_EXECUTOR = None
```

**Add shutdown coordinator integration:**
```python
# In context.py or thread_pool.py
def register_shutdown_handler():
    """Register executor shutdown with the shutdown coordinator."""
    try:
        from ..shutdown import get_shutdown_coordinator
        coordinator = get_shutdown_coordinator()
        coordinator.register(
            name="detection_executor",
            callback=_shutdown_executor,
            priority=10,  # Shutdown early (higher = earlier)
            timeout=_SHUTDOWN_TIMEOUT,
        )
    except Exception as e:
        logger.warning(f"Could not register executor shutdown: {e}")
        # Fall back to atexit
        import atexit
        atexit.register(_shutdown_executor)
```

#### Verification
- [ ] Add test: submit long-running task, trigger shutdown, verify completion
- [ ] Add test: verify no warnings about abandoned tasks in logs
- [ ] Manual test: Ctrl+C during scan, verify clean exit

---

### 1.4 No Cloud Adapter Retry

**Priority:** HIGH
**Effort:** 4-5 hours
**Risk:** Single transient failure blocks all operations

#### Issue Description
Cloud adapters (Macie, DLP, Purview, M365) have no retry logic or circuit breaker. A single network timeout or transient error causes complete failure.

#### Affected Files

| File | Issue |
|------|-------|
| `adapters/macie.py` | No retry on AWS API calls |
| `adapters/dlp.py` | No retry on GCP API calls |
| `adapters/purview.py` | No retry on Azure API calls |
| `adapters/m365.py` | No retry on Graph API calls |

#### Implementation

**Create retry utility module:**
```python
# openlabels/utils/retry.py
"""Retry utilities with exponential backoff."""

import logging
import time
from functools import wraps
from typing import Callable, Tuple, Type, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar('T')

# Default retry configuration
DEFAULT_MAX_RETRIES = 3
DEFAULT_BASE_DELAY = 1.0  # seconds
DEFAULT_MAX_DELAY = 30.0  # seconds
DEFAULT_EXPONENTIAL_BASE = 2

# Transient exceptions that should trigger retry
TRANSIENT_EXCEPTIONS: Tuple[Type[Exception], ...] = (
    ConnectionError,
    TimeoutError,
    OSError,  # Network-related OS errors
)


def with_retry(
    max_retries: int = DEFAULT_MAX_RETRIES,
    base_delay: float = DEFAULT_BASE_DELAY,
    max_delay: float = DEFAULT_MAX_DELAY,
    exponential_base: float = DEFAULT_EXPONENTIAL_BASE,
    retryable_exceptions: Tuple[Type[Exception], ...] = TRANSIENT_EXCEPTIONS,
):
    """Decorator for retrying functions with exponential backoff.

    Args:
        max_retries: Maximum number of retry attempts
        base_delay: Initial delay between retries in seconds
        max_delay: Maximum delay between retries
        exponential_base: Base for exponential backoff calculation
        retryable_exceptions: Exception types that trigger retry

    Example:
        @with_retry(max_retries=3)
        def fetch_from_api():
            return requests.get(url)
    """
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            last_exception = None

            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except retryable_exceptions as e:
                    last_exception = e
                    if attempt < max_retries:
                        delay = min(
                            base_delay * (exponential_base ** attempt),
                            max_delay
                        )
                        logger.warning(
                            f"{func.__name__} failed (attempt {attempt + 1}/{max_retries + 1}): {e}. "
                            f"Retrying in {delay:.1f}s..."
                        )
                        time.sleep(delay)
                    else:
                        logger.error(
                            f"{func.__name__} failed after {max_retries + 1} attempts: {e}"
                        )

            raise last_exception

        return wrapper
    return decorator


class CircuitBreaker:
    """Simple circuit breaker for protecting against cascading failures.

    States:
    - CLOSED: Normal operation, requests pass through
    - OPEN: Failing, requests rejected immediately
    - HALF_OPEN: Testing if service recovered

    Example:
        breaker = CircuitBreaker(failure_threshold=5, recovery_timeout=30)

        @breaker
        def call_external_service():
            return api.fetch()
    """

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        expected_exceptions: Tuple[Type[Exception], ...] = TRANSIENT_EXCEPTIONS,
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exceptions = expected_exceptions

        self._state = self.CLOSED
        self._failure_count = 0
        self._last_failure_time = 0.0
        self._lock = threading.Lock()

    @property
    def state(self) -> str:
        with self._lock:
            if self._state == self.OPEN:
                # Check if recovery timeout has passed
                if time.time() - self._last_failure_time >= self.recovery_timeout:
                    self._state = self.HALF_OPEN
            return self._state

    def __call__(self, func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs) -> T:
            if self.state == self.OPEN:
                raise CircuitBreakerOpenError(
                    f"Circuit breaker is open for {func.__name__}. "
                    f"Retry after {self.recovery_timeout}s."
                )

            try:
                result = func(*args, **kwargs)
                self._on_success()
                return result
            except self.expected_exceptions as e:
                self._on_failure()
                raise

        return wrapper

    def _on_success(self):
        with self._lock:
            self._failure_count = 0
            self._state = self.CLOSED

    def _on_failure(self):
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()
            if self._failure_count >= self.failure_threshold:
                self._state = self.OPEN
                logger.warning(
                    f"Circuit breaker opened after {self._failure_count} failures"
                )


class CircuitBreakerOpenError(Exception):
    """Raised when circuit breaker is open."""
    pass


# Import threading for CircuitBreaker
import threading
```

**Apply to cloud adapters:**
```python
# In adapters/macie.py
from ..utils.retry import with_retry, CircuitBreaker, TRANSIENT_EXCEPTIONS

# Add AWS-specific transient errors
try:
    from botocore.exceptions import (
        ConnectionError as BotoConnectionError,
        ReadTimeoutError,
        ConnectTimeoutError,
    )
    AWS_TRANSIENT = TRANSIENT_EXCEPTIONS + (
        BotoConnectionError,
        ReadTimeoutError,
        ConnectTimeoutError,
    )
except ImportError:
    AWS_TRANSIENT = TRANSIENT_EXCEPTIONS

_macie_breaker = CircuitBreaker(failure_threshold=5, recovery_timeout=60)

class MacieAdapter(Adapter):
    @with_retry(max_retries=3, retryable_exceptions=AWS_TRANSIENT)
    @_macie_breaker
    def _fetch_findings(self, ...):
        """Fetch findings from Macie with retry and circuit breaker."""
        # ... existing implementation ...
```

#### Verification
- [ ] Add test: mock transient failure, verify retry occurs
- [ ] Add test: mock repeated failures, verify circuit breaker opens
- [ ] Add test: verify circuit breaker recovers after timeout
- [ ] Integration test with network partition simulation

---

## Tier 2: SHOULD FIX (Before GA)

### 2.1 Long Functions

**Priority:** MEDIUM
**Effort:** 4-5 hours
**Risk:** Difficult testing, hard to debug

#### Issue Description
Several functions exceed 100 lines with multiple responsibilities, making them untestable and hard to maintain.

#### Affected Files

| File | Method | Lines | Responsibilities |
|------|--------|-------|------------------|
| `detectors/orchestrator.py` | `_detect_impl_with_metadata()` | ~150 | 10+ steps |
| `pipeline/merger.py` | `merge_spans()` | ~75 | 15 steps |
| `validators.py` | `validate_file()` | ~130 | 3-layer validation |

#### Implementation

**orchestrator.py - Split into focused methods:**

```python
# BEFORE: One 150-line method

# AFTER: Coordinator + focused methods

def _detect_impl_with_metadata(
    self,
    text: str,
    timeout: Optional[float],
    known_entities: Optional[List[Entity]],
    metadata: DetectionMetadata,
) -> Tuple[List[Span], DetectionMetadata]:
    """Main detection orchestration - coordinates the pipeline."""
    all_spans: List[Span] = []

    # Step 1: Known entity detection
    known_spans = self._detect_known_entities(text, known_entities, metadata)
    all_spans.extend(known_spans)

    # Step 2: Structured extraction + preprocessing
    processed_text, char_map = self._preprocess_text(text, metadata)

    # Step 3: Run pattern/ML detectors
    detector_spans = self._run_detectors(processed_text, timeout, metadata)

    # Step 4: Map coordinates back to original text
    mapped_spans = self._map_span_coordinates(detector_spans, char_map, text)
    all_spans.extend(mapped_spans)

    # Step 5: Post-processing (dedup, filter, enhance)
    final_spans = self._postprocess_spans(all_spans, text, metadata)

    return final_spans, metadata


def _detect_known_entities(
    self,
    text: str,
    known_entities: Optional[List[Entity]],
    metadata: DetectionMetadata,
) -> List[Span]:
    """Step 1: Detect previously-identified entities in text."""
    if not known_entities:
        return []

    spans = []
    for entity in known_entities:
        # Find all occurrences of this entity's value
        start = 0
        while True:
            idx = text.find(entity.value, start)
            if idx == -1:
                break
            spans.append(Span(
                start=idx,
                end=idx + len(entity.value),
                entity_type=entity.entity_type,
                value=entity.value,
                confidence=entity.confidence,
                source="known_entity",
            ))
            start = idx + 1

    metadata.known_entities_found = len(spans)
    return spans


def _preprocess_text(
    self,
    text: str,
    metadata: DetectionMetadata,
) -> Tuple[str, Optional[Dict[int, int]]]:
    """Step 2: Run structured extractor and OCR post-processing."""
    char_map = None
    processed_text = text

    # Structured extraction (CSV columns, JSON keys, etc.)
    if self._structured_extractor:
        try:
            processed_text, char_map = self._structured_extractor.process(text)
            metadata.structured_extraction_applied = True
        except Exception as e:
            logger.debug(f"Structured extraction failed: {e}")

    return processed_text, char_map


def _run_detectors(
    self,
    text: str,
    timeout: Optional[float],
    metadata: DetectionMetadata,
) -> List[Span]:
    """Step 3: Run pattern and ML detectors (parallel or sequential)."""
    if self._use_parallel and len(text) > self._parallel_threshold:
        return self._run_detectors_parallel(text, timeout, metadata)
    else:
        return self._run_detectors_sequential(text, timeout, metadata)


def _map_span_coordinates(
    self,
    spans: List[Span],
    char_map: Optional[Dict[int, int]],
    original_text: str,
) -> List[Span]:
    """Step 4: Map span coordinates back to original text positions."""
    if not char_map:
        return spans

    mapped = []
    for span in spans:
        new_start = char_map.get(span.start, span.start)
        new_end = char_map.get(span.end, span.end)
        mapped.append(span._replace(start=new_start, end=new_end))

    return mapped


def _postprocess_spans(
    self,
    spans: List[Span],
    text: str,
    metadata: DetectionMetadata,
) -> List[Span]:
    """Step 5: Filter, deduplicate, normalize, and enhance spans."""
    # Deduplicate overlapping spans
    spans = self._deduplicate_spans(spans)

    # Filter low-confidence matches
    spans = [s for s in spans if s.confidence >= self._min_confidence]

    # Apply context enhancement
    if self._context_enhancer:
        spans = self._context_enhancer.enhance(spans, text)

    # Normalize entity types
    spans = [self._normalize_span(s) for s in spans]

    metadata.final_span_count = len(spans)
    return spans
```

**Each method is now:**
- 15-30 lines (testable)
- Single responsibility
- Clear inputs/outputs
- Independently unit testable

#### Verification
- [ ] Add unit tests for each extracted method
- [ ] Integration test: same results as before refactoring
- [ ] Measure: test coverage of orchestrator increases to >80%

---

### 2.2 Missing Logging

**Priority:** MEDIUM
**Effort:** 2-3 hours
**Risk:** No operational visibility in production

#### Issue Description
Many detector and pipeline modules lack logging, making production debugging impossible.

#### Affected Files (No Logger)

| File | Type | Critical Operations |
|------|------|---------------------|
| `detectors/checksum.py` | Detector | Validation failures |
| `detectors/constants.py` | Constants | N/A (acceptable) |
| `detectors/secrets.py` | Detector | Pattern matches, false positives |
| `detectors/patterns/definitions.py` | Patterns | N/A (acceptable) |
| `detectors/patterns/government.py` | Patterns | N/A (acceptable) |
| `detectors/structured/*.py` | Extractors | Column detection, parsing |

#### Implementation

**Add logging to detectors:**

```python
# detectors/checksum.py - Add at top
import logging
logger = logging.getLogger(__name__)

# Add logging at key points:
def luhn_check(num: str) -> bool:
    """Luhn algorithm for credit card / NPI validation."""
    digits = [int(d) for d in num if d.isdigit()]
    if len(digits) < 2:
        logger.debug(f"Luhn check failed: too few digits ({len(digits)})")
        return False
    # ... rest of implementation ...

    result = checksum % 10 == 0
    if not result:
        logger.debug(f"Luhn check failed: checksum={checksum}")
    return result
```

**Add logging to secrets.py:**

```python
# detectors/secrets.py - Add at top
import logging
logger = logging.getLogger(__name__)

class SecretsDetector(BaseDetector):
    def detect(self, text: str) -> List[Span]:
        spans = []
        for pattern, entity_type, confidence, group_idx in SECRETS_PATTERNS:
            matches = list(pattern.finditer(text))
            if matches:
                logger.debug(f"Found {len(matches)} potential {entity_type} matches")
            # ... rest of implementation ...

        logger.debug(f"SecretsDetector found {len(spans)} entities")
        return spans
```

**Add structured logging for operations:**

```python
# Add to orchestrator.py after detection
logger.info(
    "Detection complete",
    extra={
        "text_length": len(text),
        "entities_found": len(final_spans),
        "detectors_run": len(self._detectors),
        "detectors_failed": metadata.detectors_failed,
        "duration_ms": metadata.duration_ms,
    }
)
```

#### Verification
- [ ] All detector files have `logger = logging.getLogger(__name__)`
- [ ] Key operations log at DEBUG level
- [ ] Errors log at WARNING or ERROR level
- [ ] Run with `LOG_LEVEL=DEBUG`, verify useful output

---

### 2.3 Hardcoded Configuration

**Priority:** MEDIUM
**Effort:** 3-4 hours
**Risk:** Can't tune weights without code changes

#### Issue Description
Entity weights (656 lines) are hardcoded in Python. Compliance teams can't adjust risk weights without developer involvement.

#### Affected Files

| File | Lines | Content |
|------|-------|---------|
| `core/registry/weights.py` | 656 | Hardcoded weight dictionaries |

#### Implementation

**Create weights.yaml:**

```yaml
# openlabels/core/registry/weights.yaml
# Entity weights for risk scoring (1-10 scale)
# 10 = Critical direct identifier (SSN, Passport)
# 1 = Minimal risk (public info)
#
# Weights can be overridden via:
# - Environment: OPENLABELS_WEIGHTS_FILE=/path/to/custom.yaml
# - Code: Context(weights_file="/path/to/custom.yaml")

schema_version: "1.0"

direct_identifiers:
  SSN: 10
  PASSPORT: 10
  DRIVERS_LICENSE: 7
  STATE_ID: 7
  TAX_ID: 8
  NATIONAL_ID: 9
  AADHAAR: 10
  NHS_NUMBER: 8
  MEDICARE_ID: 8
  SOCIAL_INSURANCE_NUMBER: 9

healthcare:
  MRN: 8
  HEALTH_PLAN_ID: 8
  NPI: 7
  DEA: 7
  DIAGNOSIS: 8
  DIAGNOSIS_CODE: 7
  MEDICATION: 6
  PROCEDURE: 6
  LAB_RESULT: 7
  VITAL_SIGN: 5
  ALLERGY: 6
  IMMUNIZATION: 5

financial:
  CREDIT_CARD: 9
  BANK_ACCOUNT: 8
  ROUTING_NUMBER: 6
  IBAN: 8
  SWIFT_BIC: 5
  CUSIP: 6
  ISIN: 6
  BITCOIN_ADDRESS: 7
  ETHEREUM_ADDRESS: 7

credentials:
  PASSWORD: 10
  API_KEY: 9
  AWS_ACCESS_KEY: 9
  AWS_SECRET_KEY: 10
  PRIVATE_KEY: 10
  JWT: 8
  OAUTH_TOKEN: 8
  DATABASE_URL: 9

contact:
  EMAIL: 4
  PHONE: 5
  ADDRESS: 5
  IP_ADDRESS: 3

personal:
  NAME: 4
  DATE_OF_BIRTH: 6
  AGE: 3
  GENDER: 2
  ETHNICITY: 4
  RELIGION: 4

government:
  CLASSIFICATION_LEVEL: 9
  SECURITY_MARKING: 8
  CAGE_CODE: 5
  CONTRACT_NUMBER: 4

# Default weight for unknown entity types
default: 3
```

**Update weights.py to load from YAML:**

```python
# openlabels/core/registry/weights.py
"""Entity weights loader with YAML support."""

import logging
import os
from functools import lru_cache
from pathlib import Path
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# Default weights file location
_DEFAULT_WEIGHTS_FILE = Path(__file__).parent / "weights.yaml"

# Environment variable for custom weights
_WEIGHTS_ENV_VAR = "OPENLABELS_WEIGHTS_FILE"


def _load_yaml(path: Path) -> Dict:
    """Load YAML file, with fallback for missing pyyaml."""
    try:
        import yaml
        with open(path) as f:
            return yaml.safe_load(f)
    except ImportError:
        # Fallback: parse simple YAML manually for core weights
        logger.warning("PyYAML not installed, using built-in weights only")
        return _BUILTIN_WEIGHTS


@lru_cache(maxsize=1)
def _load_weights(weights_file: Optional[str] = None) -> Dict[str, int]:
    """Load and flatten weights from YAML file."""
    # Determine which file to load
    if weights_file:
        path = Path(weights_file)
    elif os.environ.get(_WEIGHTS_ENV_VAR):
        path = Path(os.environ[_WEIGHTS_ENV_VAR])
    else:
        path = _DEFAULT_WEIGHTS_FILE

    if not path.exists():
        logger.warning(f"Weights file not found: {path}, using defaults")
        return _BUILTIN_WEIGHTS

    try:
        data = _load_yaml(path)

        # Flatten nested structure
        flat_weights: Dict[str, int] = {}
        default_weight = data.get("default", 3)

        for category, weights in data.items():
            if category in ("schema_version", "default"):
                continue
            if isinstance(weights, dict):
                for entity_type, weight in weights.items():
                    flat_weights[entity_type.upper()] = weight

        flat_weights["_DEFAULT"] = default_weight

        logger.info(f"Loaded {len(flat_weights)} entity weights from {path}")
        return flat_weights

    except Exception as e:
        logger.error(f"Failed to load weights from {path}: {e}")
        return _BUILTIN_WEIGHTS


def get_weight(entity_type: str, weights_file: Optional[str] = None) -> int:
    """Get weight for an entity type.

    Args:
        entity_type: The entity type (case-insensitive)
        weights_file: Optional path to custom weights file

    Returns:
        Weight from 1-10, or default weight if type unknown
    """
    weights = _load_weights(weights_file)
    return weights.get(entity_type.upper(), weights.get("_DEFAULT", 3))


def get_all_weights(weights_file: Optional[str] = None) -> Dict[str, int]:
    """Get all entity weights as a flat dictionary."""
    weights = _load_weights(weights_file)
    return {k: v for k, v in weights.items() if not k.startswith("_")}


def reload_weights():
    """Clear cache and reload weights from file."""
    _load_weights.cache_clear()


# Backward compatibility: expose as module-level constant
# This will use default weights on first access
def _get_entity_weights():
    return get_all_weights()

# Lazy loading for backward compatibility
class _LazyWeights(dict):
    _loaded = False

    def _ensure_loaded(self):
        if not self._loaded:
            self.update(get_all_weights())
            self._loaded = True

    def __getitem__(self, key):
        self._ensure_loaded()
        return super().__getitem__(key)

    def get(self, key, default=None):
        self._ensure_loaded()
        return super().get(key, default)

    def __contains__(self, key):
        self._ensure_loaded()
        return super().__contains__(key)

    def __iter__(self):
        self._ensure_loaded()
        return super().__iter__()

    def __len__(self):
        self._ensure_loaded()
        return super().__len__()


ENTITY_WEIGHTS = _LazyWeights()


# Builtin fallback weights (subset for when YAML unavailable)
_BUILTIN_WEIGHTS: Dict[str, int] = {
    "SSN": 10,
    "PASSPORT": 10,
    "CREDIT_CARD": 9,
    "PASSWORD": 10,
    "API_KEY": 9,
    "PRIVATE_KEY": 10,
    "MRN": 8,
    "DIAGNOSIS": 8,
    "EMAIL": 4,
    "PHONE": 5,
    "NAME": 4,
    "ADDRESS": 5,
    "_DEFAULT": 3,
}
```

#### Verification
- [ ] Test: weights load from default YAML
- [ ] Test: `OPENLABELS_WEIGHTS_FILE` env var works
- [ ] Test: missing YAML falls back to builtins
- [ ] Test: invalid YAML logs error, uses defaults
- [ ] Backward compatibility: existing code still works

---

## Implementation Order

| Day | Phase | Tasks | Hours |
|-----|-------|-------|-------|
| **Day 1** | Tier 1 Critical | TOCTOU fixes (1.1) | 4-6h |
| **Day 2** | Tier 1 Critical | Silent exceptions (1.2), Shutdown (1.3) | 4-5h |
| **Day 3** | Tier 1 High | Cloud adapter retry (1.4) | 4-5h |
| **Day 4** | Tier 2 Medium | Long functions (2.1) | 4-5h |
| **Day 5** | Tier 2 Medium | Logging (2.2), Weights YAML (2.3) | 5-6h |

**Total Estimated Effort:** 21-27 hours (~4-5 days)

---

## Verification Checklist

### After Each Fix

- [ ] All existing tests pass: `pytest tests/ -v`
- [ ] No new ruff warnings: `ruff check openlabels/`
- [ ] Type checking passes: `mypy openlabels/`

### After All Fixes

- [ ] Security scan: No TOCTOU patterns remain
- [ ] Grep check: `grep -r "except.*:.*pass" openlabels/` returns 0
- [ ] Log check: All modules have logger
- [ ] Integration test: Full scan completes successfully
- [ ] Shutdown test: Ctrl+C produces clean exit
- [ ] Retry test: Network failure triggers retry

---

## Files to Create

| File | Purpose |
|------|---------|
| `openlabels/utils/retry.py` | Retry decorator and circuit breaker |
| `openlabels/core/registry/weights.yaml` | Externalized entity weights |

## Files to Modify

| File | Changes |
|------|---------|
| `agent/collector.py` | Fix TOCTOU pattern |
| `agent/watcher.py` | Fix TOCTOU pattern |
| `cli/commands/quarantine.py` | Atomic move with symlink rejection |
| `output/index.py` | Log exception handlers |
| `adapters/scanner/temp_storage.py` | Log cleanup failures |
| `adapters/scanner/thread_pool.py` | Graceful shutdown |
| `context.py` | Upgrade exception logging |
| `detectors/orchestrator.py` | Split long function |
| `detectors/checksum.py` | Add logging |
| `detectors/secrets.py` | Add logging |
| `core/registry/weights.py` | YAML loader |
| `adapters/macie.py` | Add retry decorator |
| `adapters/dlp.py` | Add retry decorator |
| `adapters/purview.py` | Add retry decorator |
| `adapters/m365.py` | Add retry decorator |

---

## Success Criteria

| Metric | Before | After |
|--------|--------|-------|
| TOCTOU vulnerabilities | 4 | 0 |
| Silent exception handlers | 6+ | 0 |
| Functions >100 lines | 3 | 0 |
| Modules without logging | 20+ | <5 (constants only) |
| Cloud adapter retry | None | All have retry + circuit breaker |
| Weights configurable | No | Yes (YAML) |

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| Refactoring breaks detection | Comprehensive test suite, run before/after each change |
| YAML parsing failures | Fallback to builtin weights |
| Retry causes delays | Circuit breaker prevents infinite retries |
| Shutdown hangs | Timeout on executor shutdown (5s) |

---

*Plan created: 2026-01-28*
*Last updated: 2026-01-28*
