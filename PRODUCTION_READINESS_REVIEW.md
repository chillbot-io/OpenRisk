# Production Readiness Review: OpenRisk/OpenLabels

**Review Date:** 2026-01-26
**Reviewer:** Claude (Opus 4.5)
**Branch:** claude/production-readiness-review-XICGq

## Executive Summary

This application has **reasonable foundations** but contains several issues that would cause problems under concurrent use, aggressive retries, adversarial input, and unattended operation. The code shows awareness of many security concerns (e.g., path validation, ReDoS protection), but several **assumptions rather than guarantees** remain.

---

## 1. State & Side-Effect Safety

### ISSUE: Hidden global state in orchestrator.py

**Location:** `openlabels/adapters/scanner/detectors/orchestrator.py:80-88`

```python
_SHARED_EXECUTOR: Optional[ThreadPoolExecutor] = None
_DETECTION_SEMAPHORE = threading.BoundedSemaphore(MAX_CONCURRENT_DETECTIONS)
_QUEUE_DEPTH = 0
_QUEUE_LOCK = threading.Lock()
```

**Problem:** Module-level globals are shared across all contexts. Even though `Context` claims isolation, the `DetectorOrchestrator` uses a shared executor and semaphore. Multiple `Client` instances created with separate `Context` objects still share detection concurrency limits.

**Impact:** Under concurrent use, one "isolated" client's load can block another.

---

### ISSUE: Default singleton in context.py and index.py

**Location:** `openlabels/context.py:182-193`, `openlabels/output/index.py:496-508`

```python
_default_context: Optional[Context] = None
_default_index: Optional[LabelIndex] = None
```

**Problem:** `get_default_context()` and `get_default_index()` create process-wide singletons. These leak state between "isolated" uses if someone uses the default.

**Risk:** Default usage (without explicit context injection) shares executor, label index, and semaphores across the entire process.

---

### PASS: No mutable default arguments found

The codebase correctly uses `field(default_factory=...)` for mutable defaults in dataclasses.

---

### ISSUE: Request-scoped detection queue not isolated

**Location:** `openlabels/adapters/scanner/detectors/orchestrator.py:107-125`

The `_detection_slot()` context manager tracks queue depth globally. Under concurrent use, independent "requests" (scan operations) compete for the same backpressure limits.

---

### ISSUE: atexit handlers leak between contexts

**Location:** `openlabels/context.py:69`

```python
def __post_init__(self):
    atexit.register(self.close)
```

**Problem:** Every Context created registers an atexit handler. If contexts are created frequently (e.g., per-request), this creates unbounded atexit handler accumulation.

---

### ISSUE: Cloud handler singletons persist state

**Location:** `openlabels/output/virtual.py:281-289, 547-571`

```python
_handler = None
_s3_handler = None
_gcs_handler = None
_azure_handler = None
```

**Problem:** Module-level singletons for cloud handlers persist across requests/invocations.

---

## 2. Error Handling & Failure Modes

### ISSUE: Swallowed exceptions in LabelIndex

**Location:** `openlabels/output/index.py:224-226, 264-266, 330-331, 401-403`

```python
except Exception as e:
    logger.error(f"Failed to store label: {e}")
    return False
```

**Problem:** Database errors are logged and converted to `False` return values. Callers have no way to distinguish between "not found" and "database error."

**Impact:** Under aggressive retries, transient database issues silently fail without propagating actionable errors.

---

### ISSUE: Silent continuation after structured extractor failure

**Location:** `openlabels/adapters/scanner/detectors/orchestrator.py:398-402`

```python
except Exception as e:
    logger.error(f"Structured extractor failed: {e}")
    # Continue with original text
    processed_text = text
    char_map = []
```

**Problem:** If the structured extractor crashes, detection continues with potentially degraded accuracy. No indication is returned that results may be incomplete.

---

### ISSUE: Detector failures don't propagate

**Location:** `openlabels/adapters/scanner/detectors/orchestrator.py:611-612, 657-658`

```python
except Exception as e:
    logger.error(f"Detector {detector.name} failed: {e}")
```

**Problem:** Individual detector failures are logged but don't affect the overall result. A scan could return "no entities found" when actually all detectors crashed.

---

### ISSUE: Timeout handling doesn't cancel work

**Location:** `openlabels/adapters/scanner/detectors/orchestrator.py:646-656`

```python
except TimeoutError:
    cancelled = future.cancel()
    logger.warning(...)
```

**Problem:** Comment acknowledges "Python threads can't be forcibly killed." Timed-out detectors continue consuming resources in the background. Under adversarial input (e.g., crafted to cause slow regex), threads accumulate.

---

### ISSUE: File operations don't distinguish error types

**Location:** `openlabels/components/fileops.py:135-136`

```python
except Exception as e:
    errors.append({"path": result.path, "error": str(e)})
```

**Problem:** Permission errors, disk full, and network timeouts all become string errors. Retries can't know which failures are transient.

---

## 3. Trust Boundaries & Input Validation

### PASS: Path validation exists but has gaps

**Good:** `validate_path_for_subprocess()` and `validate_data_path()` provide validation.

### ISSUE: No validation on Cloud URI parsing

**Location:** `openlabels/output/virtual.py:601-620`

```python
if uri.startswith('s3://'):
    parts = uri[5:].split('/', 1)
    bucket, key = parts[0], parts[1] if len(parts) > 1 else ''
```

**Problem:** No validation that bucket/key values are safe. A crafted URI like `s3://bucket/../../etc/passwd` would pass through.

---

### ISSUE: Filter expression injection in CLI

**Location:** `openlabels/cli/filter.py:172-194`

The `_safe_regex_match` function attempts ReDoS protection but:
1. Only blocks `(a+)+` patterns, not all catastrophic backtracking
2. 500-character limit may not prevent all ReDoS
3. Timeout parameter `timeout_ms: int = 100` is **ignored** - no actual timeout enforcement

---

### ISSUE: No size limits on text input

**Location:** `openlabels/adapters/scanner/adapter.py:54-106`

The `Detector.detect(text)` method has no maximum input size check. Adversarial multi-gigabyte text would be processed.

---

### ISSUE: File content read without size check

**Location:** `openlabels/adapters/scanner/adapter.py:140`

```python
content = path.read_bytes()
```

**Problem:** Reads entire file into memory. A 10GB file would cause OOM. The config has `max_file_size` but it's not enforced here.

---

### ISSUE: Deserialization of JSON without schema validation

**Location:** `openlabels/output/index.py:261, 289`

```python
return LabelSet.from_json(row['labels_json'])
```

**Problem:** JSON from database is deserialized without schema validation. Corrupted or malicious database content could cause unexpected behavior.

---

### ISSUE: Extended attribute value not validated on read

**Location:** `openlabels/output/virtual.py:107, 196`

```python
value = xattr.getxattr(path, self.ATTR_NAME)
return value.decode('utf-8')
```

**Problem:** Validation exists for writes but not reads. A file with manually crafted xattr could inject unexpected data.

---

## 4. Concurrency, Retries & Idempotency

### ISSUE: File operations are not idempotent

**Location:** `openlabels/components/fileops.py:128`

```python
shutil.move(result.path, dest_path)
```

**Problem:** If a quarantine operation fails partway and is retried, files already moved will cause errors or double-processing.

**Impact:** Under aggressive retries, state becomes inconsistent.

---

### ISSUE: SQLite operations not wrapped in transactions

**Location:** `openlabels/output/index.py:165-221`

```python
with self._get_connection() as conn:
    conn.execute(...)
    conn.execute(...)
    conn.execute(...)
    conn.commit()
```

**Problem:** Three `execute()` calls before `commit()`. If the process crashes between them, database state is inconsistent. Also, no `BEGIN TRANSACTION` explicit call - relies on SQLite autocommit behavior.

---

### ISSUE: No protection against concurrent file modification

**Location:** `openlabels/components/scanner.py:188-224`

```python
try:
    detection_result = detect_file(path)
    # ...file could change here...
    stat = path.stat()
```

**Problem:** Between detecting content and recording metadata, the file could be modified. No file locking or content-hash verification.

---

### ISSUE: Detection queue counter could leak

**Location:** `openlabels/adapters/scanner/detectors/orchestrator.py:117-125`

```python
try:
    _DETECTION_SEMAPHORE.acquire()
    try:
        yield current_depth
    finally:
        _DETECTION_SEMAPHORE.release()
finally:
    with _QUEUE_LOCK:
        _QUEUE_DEPTH = max(0, _QUEUE_DEPTH - 1)
```

**Problem:** If an exception occurs between `acquire()` and entering the inner try block, the semaphore may not release properly (though this is a narrow window).

---

### ISSUE: Watcher event queue can fill without feedback

**Location:** `openlabels/agent/watcher.py:141`

```python
self._event_queue: queue.Queue = queue.Queue(maxsize=self.config.max_queue_size)
```

**Problem:** If the queue fills (10000 events), new events are blocked but no error is surfaced. The system silently drops events.

---

### ISSUE: Polling watcher has race condition

**Location:** `openlabels/agent/watcher.py:501-521`

The polling watcher compares old and new file states without atomicity. A file modified during the poll scan could be seen as unchanged.

---

## 5. Implicit Contracts Between Components

### ISSUE: Entity type normalization is inconsistent

**Location:** Multiple files

- `core/scorer.py:111` - `normalize_type(entity_type.upper())`
- `components/scorer.py:143` - `entity_type.lower()`
- `core/scorer.py:122` - `entity_type.upper()`

**Problem:** Entity types are normalized to uppercase in some places, lowercase in others. This could cause scoring mismatches if an adapter returns mixed-case types.

---

### ISSUE: Exposure level strings vs enum inconsistency

**Location:** Multiple files

- `adapters/base.py` defines `ExposureLevel` enum
- `context.py:47` uses `default_exposure: str = "PRIVATE"`
- `core/scorer.py:228` uses string lookup

**Problem:** Some code uses the enum, some uses strings. No enforcement that strings match valid enum values.

---

### ISSUE: Optional vs required fields ambiguous

**Location:** `openlabels/core/types.py:53-110`

```python
@dataclass
class ScanResult:
    path: str
    size_bytes: int = 0  # Optional with default
    score: int = 0       # Optional with default
    error: Optional[str] = None
```

**Problem:** Is `score=0` meaningful (minimal risk) or placeholder (not scanned)? Callers must check `error` to know, but this isn't enforced.

---

### ISSUE: Filter expression errors not validated at parse time

**Location:** `openlabels/cli/filter.py:400-404`

```python
if field not in self.FIELDS:
    # Allow unknown fields for extensibility
    pass
```

**Problem:** Invalid field names silently pass through. Typos like `scroe > 50` won't error - they'll just never match.

---

### ISSUE: No schema versioning on configuration

**Location:** `openlabels/adapters/scanner/config.py`

`Config` class has no version field. If defaults change between versions, old configs may produce unexpected behavior without warning.

---

### ISSUE: Confidence threshold has magic default

**Location:** `openlabels/core/scorer.py:154, components/scorer.py:151`

```python
def calculate_content_score(entities, confidence: float = 0.90):
# ...
if not spans:
    return 0.90  # Magic default
```

**Problem:** The 0.90 default is used inconsistently. If spans is empty but entities exist, confidence could be wrong.

---

## Summary by Checklist

| Category | Status | Critical Issues |
|----------|--------|-----------------|
| **1. State & Side-Effect Safety** | PARTIAL | Shared globals, singleton leakage |
| **2. Error Handling & Failure Modes** | PARTIAL | Swallowed exceptions, no timeout enforcement |
| **3. Trust Boundaries & Input Validation** | PARTIAL | No input size limits, ReDoS timeout not enforced |
| **4. Concurrency, Retries & Idempotency** | FAILING | Non-idempotent operations, no transaction safety |
| **5. Implicit Contracts** | PARTIAL | Inconsistent normalization, ambiguous fields |

---

## Highest Priority Fixes

1. **Add input size limits** to `Detector.detect()` and `detect_file()` - prevents OOM from adversarial input
2. **Enforce file size limit** before `path.read_bytes()` - the config has `max_file_size` but it's not used
3. **Make file operations idempotent** - use content hashes to detect already-processed files
4. **Wrap database operations in explicit transactions** - prevents corruption on crash
5. **Enforce ReDoS timeout** in filter expressions - the parameter exists but does nothing
6. **Isolate detection concurrency per Context** - move shared globals into Context instances
7. **Return structured errors** instead of boolean/None - callers need to know if errors are transient

---

## Recommendations

### Immediate (before production)

- Add `max_text_size` check in `Detector.detect()`
- Enforce `config.max_file_size` in `detect_file()` before reading
- Use explicit `BEGIN TRANSACTION` / `COMMIT` in SQLite operations
- Make quarantine/delete operations idempotent via manifest files

### Short-term

- Replace module-level globals with Context-scoped resources
- Add structured error types (`TransientError`, `PermanentError`)
- Implement actual timeout for regex matching (use multiprocessing or signal)
- Add schema validation for deserialized JSON

### Long-term

- Consider moving to async/await for better concurrency control
- Add OpenTelemetry tracing for production debugging
- Implement distributed locking for multi-instance deployments
- Add configuration schema versioning
