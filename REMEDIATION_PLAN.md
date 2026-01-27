# OpenRisk Remediation Plan: Path to 85%

**Goal:** Raise Security from 75→85 and Code Quality from 65→85
**Excludes:** Test coverage (intentionally deferred)
**Estimated Total Effort:** 3-4 days

---

## Current State

| Category | Current | Target | Gap |
|----------|---------|--------|-----|
| Security | 75/100 | 85/100 | +10 |
| Code Quality | 65/100 | 85/100 | +20 |
| Production Readiness | 85/100 | 85/100 | ✅ |

---

## PHASE 1: Security (75 → 85)

### Issue S1: Dangerous Silent Exception Handlers
**Impact:** +4 points | **Effort:** 2 hours

Three locations silently swallow exceptions that could hide production bugs:

#### S1.1: `context.py:135-136`
```python
# BEFORE (dangerous)
except Exception:
    pass  # Shutdown coordinator may not be available

# AFTER (safe)
except Exception as e:
    logger.debug(f"Shutdown coordinator not available: {e}")
```

#### S1.2: `fileops.py:141-142`
```python
# BEFORE (dangerous - loses manifest silently)
except (json.JSONDecodeError, OSError):
    pass

# AFTER (safe)
except (json.JSONDecodeError, OSError) as e:
    logger.warning(f"Could not load quarantine manifest {manifest_path}: {e}")
```

#### S1.3: `output/index.py:289-290`
```python
# BEFORE (dangerous)
def __del__(self):
    try:
        self.close()
    except Exception:
        pass

# AFTER (safe)
def __del__(self):
    try:
        self.close()
    except Exception as e:
        # Can't use logger reliably in __del__
        import sys
        print(f"LabelIndex cleanup warning: {e}", file=sys.stderr)
```

---

### Issue S2: Add Connection Health Checks
**Impact:** +3 points | **Effort:** 3 hours

SQLite connections can go stale. Add connection validation.

**File:** `output/index.py`

```python
def _validate_connection(self, conn: sqlite3.Connection) -> bool:
    """Validate connection is still usable."""
    try:
        conn.execute("SELECT 1").fetchone()
        return True
    except sqlite3.Error:
        return False

@contextmanager
def _get_connection(self):
    """Get database connection with validation."""
    if self._closed:
        raise DatabaseError("LabelIndex has been closed")

    conn = self._get_thread_connection()

    # Validate connection before use
    if not self._validate_connection(conn):
        conn_key = f"conn_{self.db_path}"
        try:
            conn.close()
        except sqlite3.Error:
            pass
        delattr(self._thread_local, conn_key)
        conn = self._get_thread_connection()

    try:
        yield conn
    except sqlite3.Error as e:
        # ... existing error handling
```

---

### Issue S3: Transaction Rollback Logging
**Impact:** +2 points | **Effort:** 30 minutes

**File:** `output/index.py:326-327`

```python
# BEFORE
except sqlite3.Error:
    pass  # Rollback failed

# AFTER
except sqlite3.Error as rollback_err:
    logger.warning(f"Transaction rollback also failed: {rollback_err}")
```

---

### Issue S4: TOCTOU Window in PollingWatcher
**Impact:** +1 point | **Effort:** 1 hour

**File:** `agent/watcher.py:675-686`

The current code does `is_file()` then `stat()` - file could change between calls.

```python
# BEFORE
for file_path in walker:
    if file_path.is_file():  # TOCTOU: file could change here
        try:
            st = file_path.stat()
            ...

# AFTER - use stat() result directly
for file_path in walker:
    try:
        st = file_path.stat()
        if not stat.S_ISREG(st.st_mode):
            continue  # Not a regular file
        ...
    except OSError:
        pass  # File doesn't exist or can't be accessed
```

---

## PHASE 2: Code Quality (65 → 85)

### Issue Q1: Extract Pattern Definitions to YAML
**Impact:** +8 points | **Effort:** 4-6 hours

**Problem:** ~1,950 lines of repetitive `add_pattern()` calls across 8 files.

**Solution:** Create `patterns.yaml` and a loader.

#### Step 1: Create pattern schema

**New file:** `openlabels/adapters/scanner/detectors/patterns/patterns.yaml`
```yaml
# Pattern definitions for PII/PHI detection
# Format: Each pattern has regex, entity_type, confidence, and optional group/flags

pii:
  phone:
    - pattern: '\((\d{3})\)\s*(\d{3})[-.]?(\d{4})'
      type: PHONE
      confidence: 0.65  # CONFIDENCE_MEDIUM
    - pattern: '\b(\d{3})[-.](\d{3})[-.](\d{4})\b'
      type: PHONE
      confidence: 0.55
    # ... more patterns

  email:
    - pattern: '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
      type: EMAIL
      confidence: 0.85

healthcare:
  mrn:
    - pattern: '(?:MRN|Medical\s+Record(?:\s+Number)?)[:\s#]+([A-Z]*-?\d{6,12}[A-Z]*)'
      type: MRN
      confidence: 0.85
      group: 1
      flags: IGNORECASE
    # ... more patterns
```

#### Step 2: Create pattern loader

**New file:** `openlabels/adapters/scanner/detectors/patterns/loader.py`
```python
"""Load pattern definitions from YAML configuration."""
import re
import yaml
from pathlib import Path
from typing import List, Tuple

# Map flag names to re constants
FLAG_MAP = {
    'IGNORECASE': re.IGNORECASE,
    'MULTILINE': re.MULTILINE,
    'DOTALL': re.DOTALL,
}

def load_patterns(yaml_path: Path = None) -> List[Tuple[re.Pattern, str, float, int]]:
    """Load all patterns from YAML file."""
    if yaml_path is None:
        yaml_path = Path(__file__).parent / "patterns.yaml"

    with open(yaml_path) as f:
        config = yaml.safe_load(f)

    patterns = []
    for category in config.values():
        for subcategory in category.values():
            for p in subcategory:
                flags = 0
                if 'flags' in p:
                    for flag_name in p['flags'].split('|'):
                        flags |= FLAG_MAP.get(flag_name.strip(), 0)

                compiled = re.compile(p['pattern'], flags)
                patterns.append((
                    compiled,
                    p['type'],
                    p['confidence'],
                    p.get('group', 0)
                ))

    return patterns
```

#### Step 3: Replace pattern files

Keep `pii.py`, `healthcare.py`, etc. but make them thin wrappers:

```python
"""PII patterns - loaded from YAML configuration."""
from .loader import load_patterns

# All patterns now loaded from patterns.yaml
PII_PATTERNS = load_patterns(category='pii')
```

**Lines removed:** ~1,700
**Lines added:** ~300 (YAML) + ~50 (loader)
**Net reduction:** ~1,350 lines

---

### Issue Q2: Split Long Orchestrator Function
**Impact:** +5 points | **Effort:** 2-3 hours

**Problem:** `_detect_impl_with_metadata()` is 150 lines with 10+ responsibilities.

**Solution:** Extract into focused helper methods.

**File:** `openlabels/adapters/scanner/detectors/orchestrator.py`

```python
# BEFORE: One 150-line method

# AFTER: Focused methods
def _detect_impl_with_metadata(self, text, timeout, known_entities, metadata):
    """Main detection orchestration."""
    all_spans = []

    # Step 1: Known entity detection
    all_spans.extend(self._detect_known_entities_step(text, known_entities))

    # Step 2: Structured extraction
    processed_text, char_map = self._structured_extraction_step(text, metadata)

    # Step 3: Run detectors
    detector_spans = self._run_detectors_step(processed_text, timeout, metadata)

    # Step 4: Map coordinates back
    mapped_spans = self._map_coordinates_step(detector_spans, char_map, text)
    all_spans.extend(mapped_spans)

    # Step 5: Post-processing pipeline
    return self._postprocess_spans(all_spans, text, metadata)

def _detect_known_entities_step(self, text, known_entities):
    """Detect previously-identified entities."""
    if not known_entities:
        return []
    spans = self._detect_known_entities(text, known_entities)
    if spans:
        logger.info(f"Known entity detection: {len(spans)} matches")
    return spans

def _structured_extraction_step(self, text, metadata):
    """Run structured extractor with OCR post-processing."""
    if not self.enable_structured:
        return text, []
    try:
        processed_text, char_map = post_process_ocr(text)
        result = extract_structured_phi(text)
        # ... handle result
        return processed_text, char_map
    except (ValueError, RuntimeError) as e:
        logger.error(f"Structured extractor failed: {e}")
        metadata.structured_extractor_failed = True
        metadata.degraded = True
        return text, []

def _run_detectors_step(self, text, timeout, metadata):
    """Run pattern/ML detectors."""
    available = self._available_detectors
    if not available:
        logger.warning("No traditional detectors available")
        return []

    if self.parallel and len(available) > 1:
        return self._detect_parallel(text, available, timeout, metadata)
    return self._detect_sequential(text, available, timeout, metadata)

def _postprocess_spans(self, spans, text, metadata):
    """Filter, dedupe, normalize, and enhance spans."""
    # Clinical context filter
    spans = self._filter_clinical_context(spans)

    # Deduplicate
    spans = self._dedupe_spans(spans)

    # Filter tracking numbers
    spans = filter_tracking_numbers(spans, text)

    # Normalize confidence
    spans = normalize_spans_confidence(spans)

    # Context enhancement
    spans = self._enhance_context(spans, text)

    # LLM verification
    spans = self._llm_verify(spans, text)

    self._log_final_results(spans)
    return spans
```

**Before:** 1 method × 150 lines = hard to test
**After:** 8 methods × ~20 lines each = easy to test

---

### Issue Q3: Externalize Weights to Config
**Impact:** +4 points | **Effort:** 1-2 hours

**Problem:** `weights.py` is 530 lines of Python dict literals.

**Solution:** Move to `weights.yaml`.

**New file:** `openlabels/core/registry/weights.yaml`
```yaml
# Entity weights for risk scoring (1-10 scale)
# 10 = Critical direct identifier
# 1 = Minimal risk

direct_identifiers:
  SSN: 10
  PASSPORT: 10
  DRIVERS_LICENSE: 7
  STATE_ID: 7
  TAX_ID: 8
  AADHAAR: 10
  NHS_NUMBER: 8
  MEDICARE_ID: 8

healthcare:
  MRN: 8
  HEALTH_PLAN_ID: 8
  NPI: 7
  DEA: 7
  DIAGNOSIS: 8
  MEDICATION: 6

# ... rest of weights
```

**Simplified `weights.py`:**
```python
"""Entity weights loader."""
import yaml
from pathlib import Path
from functools import lru_cache

@lru_cache(maxsize=1)
def _load_weights():
    yaml_path = Path(__file__).parent / "weights.yaml"
    with open(yaml_path) as f:
        return yaml.safe_load(f)

def get_weight(entity_type: str) -> int:
    """Get weight for an entity type."""
    weights = _load_weights()
    for category in weights.values():
        if entity_type in category:
            return category[entity_type]
    return 1  # Default minimal weight

# Backward compatibility - flatten all weights
def get_all_weights():
    weights = _load_weights()
    flat = {}
    for category in weights.values():
        flat.update(category)
    return flat
```

**Lines removed:** ~500
**Lines added:** ~200 (YAML) + ~30 (loader)
**Net reduction:** ~270 lines

---

### Issue Q4: Improve Exception Handler Logging
**Impact:** +3 points | **Effort:** 1 hour

Add logging to questionable exception handlers.

**Files to update:**
- `output/index.py:326-327` - Log rollback failure
- `output/index.py:332-333` - Log rollback failure
- `agent/ntfs.py:205-206` - Already logs (OK)
- `agent/posix.py:312-313` - Already logs (OK)

---

## Implementation Order

| Phase | Task | Points | Hours | Dependencies |
|-------|------|--------|-------|--------------|
| 1.1 | S1: Fix silent exceptions | +4 | 2h | None |
| 1.2 | S3: Rollback logging | +2 | 0.5h | None |
| 1.3 | S2: Connection health | +3 | 3h | None |
| 1.4 | S4: TOCTOU fix | +1 | 1h | None |
| 2.1 | Q4: Exception logging | +3 | 1h | After 1.1 |
| 2.2 | Q3: Weights to YAML | +4 | 2h | None |
| 2.3 | Q1: Patterns to YAML | +8 | 6h | None |
| 2.4 | Q2: Split orchestrator | +5 | 3h | None |

**Total:** +30 points across both categories
**Total time:** ~18.5 hours (3 days at 6h/day)

---

## Quick Wins (Do First)

These can be done in < 30 minutes each:

1. **S1.1:** Add logging to `context.py:135`
2. **S1.2:** Add logging to `fileops.py:141`
3. **S1.3:** Add stderr print to `index.py:289`
4. **S3:** Add rollback logging to `index.py`

**Time:** 2 hours total
**Points gained:** +6

---

## Verification Checklist

After each fix, verify:

- [ ] No new exceptions swallowed silently
- [ ] All error paths logged at appropriate level
- [ ] YAML files validate with `python -c "import yaml; yaml.safe_load(open('file.yaml'))"`
- [ ] Existing tests still pass
- [ ] No regressions in functionality

---

## Expected Final Scores

| Category | Before | After | Change |
|----------|--------|-------|--------|
| Security | 75 | 85 | +10 |
| Code Quality | 65 | 85 | +20 |
| **Total Improvement** | | | **+30** |

---

## Files Modified Summary

| File | Changes |
|------|---------|
| `context.py` | Add exception logging (1 line) |
| `fileops.py` | Add exception logging (1 line) |
| `output/index.py` | Add connection validation, rollback logging, `__del__` fix |
| `agent/watcher.py` | Fix TOCTOU in `_scan_directory` |
| `orchestrator.py` | Split into 8 methods |
| `weights.py` | Replace with YAML loader |
| `patterns/*.py` | Replace with YAML loader |
| **NEW:** `weights.yaml` | ~200 lines config |
| **NEW:** `patterns.yaml` | ~300 lines config |
| **NEW:** `patterns/loader.py` | ~50 lines |

**Net code change:** -1,600 lines (moved to config)
