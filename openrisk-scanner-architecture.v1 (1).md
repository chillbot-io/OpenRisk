# OpenRisk Scanner: Architecture Document

**Version:** 0.1.0-draft  
**Last Updated:** January 2026  
**Status:** Pre-implementation design document  
**Prerequisite Reading:** OpenRisk Constitution, OpenRisk Specification v0.2

---

## Table of Contents

1. [Overview](#1-overview)
2. [Design Goals](#2-design-goals)
3. [System Architecture](#3-system-architecture)
4. [Pipeline Extraction](#4-pipeline-extraction)
5. [Discovery Layer](#5-discovery-layer)
6. [Filtering Layer](#6-filtering-layer)
7. [Detection Layer](#7-detection-layer)
8. [Scoring Layer](#8-scoring-layer)
9. [Cloud Sources](#9-cloud-sources)
10. [Output Layer](#10-output-layer)
11. [CLI & TUI](#11-cli--tui)
12. [Configuration](#12-configuration)
13. [Package Structure](#13-package-structure)
14. [Data Flow](#14-data-flow)
15. [Performance Targets](#15-performance-targets)
16. [Testing Strategy](#16-testing-strategy)
17. [Implementation Phases](#17-implementation-phases)

---

## 1. Overview

### 1.1 Purpose

OpenRisk Scanner (`openrisk-scan`) is a reference implementation of the OpenRisk specification. It scans files and directories for sensitive data and outputs standardized OpenRisk tags.

The scanner serves two purposes:

1. **Prove the standard works** - Demonstrate that the OpenRisk specification can be implemented and produces useful results on real data
2. **Provide a useful tool** - Give users a free, accurate scanner for assessing data sensitivity

### 1.2 Relationship to scrubIQ

OpenRisk Scanner extracts and adapts the detection pipeline from scrubIQ, but serves a fundamentally different purpose:

| Aspect | scrubIQ | OpenRisk Scanner |
|--------|---------|------------------|
| **Purpose** | Redact data for safe LLM usage | Classify data for risk assessment |
| **Output** | Sanitized text with tokens | OpenRisk tags (JSON metadata) |
| **Token store** | Yes (for restoration) | No |
| **Encryption** | Yes | No |
| **Authentication** | PIN-based | None |
| **Coreference** | Yes (links pronouns to names) | No (not needed for counting) |
| **Safe Harbor** | Yes (date shifting, etc.) | No |

The scanner uses scrubIQ's detection capabilities but discards everything related to redaction, tokenization, and restoration.

### 1.3 Core Principle

**Speed through intelligence, not compute.**

The scanner achieves acceptable performance on CPU by being smart about what files need ML inference, not by requiring GPU acceleration.

---

## 2. Design Goals

### 2.1 Primary Goals

| Goal | Description | Measure |
|------|-------------|---------|
| **Accuracy** | Match scrubIQ's PHI/PII detection quality | >94% F1 score on test corpus |
| **Speed** | Scan 100K files in reasonable time on CPU | <30 minutes target |
| **Simplicity** | Easy to install and run | `pip install openrisk` + single command |
| **Standard compliance** | Output valid OpenRisk tags | 100% schema conformance |

### 2.2 Non-Goals

| Non-Goal | Rationale |
|----------|-----------|
| Real-time monitoring | Different architecture, out of scope |
| GUI/Dashboard | CLI + TUI is sufficient for v1 |
| Multi-user support | Local tool, not a service |
| Enterprise features | No RBAC, audit trails, etc. |
| GPU optimization | Speed comes from filtering, not compute |

### 2.3 Constraints

| Constraint | Impact |
|------------|--------|
| Models are ~108MB each (already optimized) | Cannot improve inference speed via compression |
| No GPU budget | Must achieve speed through filtering |
| Must work on Windows and Linux | Platform-specific optimizations needed |
| Detection code from scrubIQ | Must maintain compatibility with upstream |

---

## 3. System Architecture

### 3.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           OPENRISK SCANNER                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                         CLI / TUI LAYER                              │    │
│  │                                                                      │    │
│  │  • Click command parsing                                             │    │
│  │  • Rich progress display                                             │    │
│  │  • Output formatting (JSON, quiet, interactive)                      │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                      │                                       │
│                                      ▼                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                       SCANNER ORCHESTRATOR                           │    │
│  │                                                                      │    │
│  │  Coordinates pipeline stages, manages threading, reports progress    │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                      │                                       │
│         ┌────────────────────────────┼────────────────────────────┐         │
│         ▼                            ▼                            ▼         │
│  ┌─────────────┐            ┌─────────────┐            ┌─────────────┐      │
│  │  DISCOVERY  │     ──►    │  FILTERING  │     ──►    │  DETECTION  │      │
│  │   LAYER     │            │   LAYER     │            │   LAYER     │      │
│  │             │            │             │            │             │      │
│  │ • MFT parse │            │ • Extension │            │ • Text      │      │
│  │ • scandir   │            │ • Path      │            │   extract   │      │
│  │ • File info │            │ • Size      │            │ • Normalize │      │
│  │             │            │ • Data type │            │ • Detect    │      │
│  │             │            │ • Dedup     │            │ • Merge     │      │
│  └─────────────┘            └─────────────┘            └─────────────┘      │
│                                                               │              │
│         ┌─────────────────────────────────────────────────────┘              │
│         ▼                                                                    │
│  ┌─────────────┐            ┌─────────────┐                                 │
│  │   SCORING   │     ──►    │   OUTPUT    │                                 │
│  │   LAYER     │            │   LAYER     │                                 │
│  │             │            │             │                                 │
│  │ • Entity    │            │ • JSON file │                                 │
│  │   mapping   │            │ • Trailer   │                                 │
│  │ • Weight    │            │ • Stdout    │                                 │
│  │ • Co-occur  │            │ • Report    │                                 │
│  │ • Score     │            │             │                                 │
│  └─────────────┘            └─────────────┘                                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Threading Model

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          THREADING MODEL                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  MAIN THREAD                                                                 │
│  ├── CLI parsing                                                             │
│  ├── Scanner orchestration                                                   │
│  └── TUI updates (via Rich Live)                                            │
│                                                                              │
│  DISCOVERY THREAD(S)                                                         │
│  ├── MFT parsing (Windows) - single thread                                  │
│  └── Directory walking (Linux) - can parallelize by subtree                 │
│                                                                              │
│  I/O THREAD POOL (4-8 workers)                                              │
│  ├── File reading                                                            │
│  ├── Text extraction (PDF, DOCX, etc.)                                      │
│  └── Hash computation                                                        │
│                                                                              │
│  INFERENCE THREAD (single)                                                   │
│  ├── ML model inference (not thread-safe)                                   │
│  └── Pattern/checksum detection                                             │
│                                                                              │
│  WRITER THREAD (single)                                                      │
│  ├── Result caching                                                          │
│  └── Tag output                                                              │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.3 Data Flow Summary

```
Files on disk
    │
    ▼ Discovery (MFT/scandir)
FileInfo objects (path, size, mtime)
    │
    ▼ Extension filter
    │
    ▼ Path filter  
    │
    ▼ Size filter
    │
    ▼ Data type classifier
    │
    ▼ Hash + deduplication
Unique regulated files
    │
    ▼ Text extraction (parallel)
    │
    ▼ Detection pipeline (sequential)
Spans (entity detections)
    │
    ▼ Entity mapping (scrubIQ → OpenRisk)
    │
    ▼ Scoring (RiskScorer)
OpenRisk tags
    │
    ▼ Output (JSON/trailer/stdout)
Results
```

---

## 4. Pipeline Extraction

### 4.1 What to Extract from scrubIQ

The scanner needs these components from scrubIQ:

| Component | scrubIQ Location | Purpose |
|-----------|------------------|---------|
| Text normalizer | `pipeline/normalizer.py` | Unicode normalization, whitespace cleanup |
| Checksum detector | `detectors/checksum.py` | SSN, credit card, NPI validation |
| Pattern detector | `detectors/patterns.py` | Regex-based detection |
| Additional patterns | `detectors/additional_patterns.py` | AGE, EMPLOYER, HEALTH_PLAN_ID |
| ML detectors | `detectors/ml_onnx.py` | PHI-BERT, PII-BERT inference |
| Dictionary detector | `detectors/dictionaries.py` | Name/facility lookups |
| Span merger | `pipeline/merger.py` | Resolve overlapping detections |
| Orchestrator | `detectors/orchestrator.py` | Run detectors in parallel |

### 4.2 What to Exclude

| Component | Reason |
|-----------|--------|
| Token store | Not needed - no tokenization |
| Tokenizer | Not needed - no redaction |
| Restorer | Not needed - no restoration |
| Coreference | Not needed - entity counts don't need linking |
| Safe Harbor | Not needed - no date shifting |
| Encryption/crypto | Not needed - no secrets to protect |
| Auth/PIN | Not needed - local tool |
| Conversation store | Not needed - no chat interface |
| LLM client | Not needed - no LLM integration |
| File processor (full) | Need text extraction only, not OCR/image processing |
| Entity graph | Not needed - no relationship tracking |
| Gender inference | Not needed - no pronoun resolution |
| Review queue | Not needed - no human review workflow |

### 4.3 Extraction Strategy

**Approach: Vendor with adaptation**

Copy the necessary modules into the scanner package with minimal modifications. This provides:
- Independence from scrubIQ release cycle
- Ability to strip unused code paths
- Clear dependency boundary

```
openrisk/
└── _detection/              # Vendored from scrubIQ
    ├── __init__.py
    ├── normalizer.py        # From pipeline/normalizer.py
    ├── merger.py            # From pipeline/merger.py
    ├── orchestrator.py      # From detectors/orchestrator.py (simplified)
    ├── detectors/
    │   ├── __init__.py
    │   ├── base.py          # From detectors/base.py
    │   ├── checksum.py      # From detectors/checksum.py
    │   ├── patterns.py      # From detectors/patterns.py
    │   ├── ml_onnx.py       # From detectors/ml_onnx.py
    │   └── dictionaries.py  # From detectors/dictionaries.py
    └── types.py             # Span, Tier definitions
```

### 4.4 Simplified Orchestrator

The scanner's orchestrator is simpler than scrubIQ's because it doesn't need:
- Structured extraction (OCR post-processing)
- Position mapping (for visual redaction)
- Timeout handling per detector (scan is batch, not interactive)

```python
# openrisk/_detection/orchestrator.py

class DetectorOrchestrator:
    """Simplified detector orchestrator for scanning."""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self._detectors = []
        self._init_detectors()
    
    def _init_detectors(self):
        """Initialize detectors - no lazy loading needed."""
        # Always load these (fast)
        self._detectors.append(ChecksumDetector())
        self._detectors.append(PatternDetector())
        self._detectors.append(AdditionalPatternDetector())
        
        # Load ML detectors (slow but necessary)
        if self.config.models_dir:
            phi_bert = PHIBertONNXDetector(self.config.models_dir)
            if phi_bert.load():
                self._detectors.append(phi_bert)
            
            pii_bert = PIIBertONNXDetector(self.config.models_dir)
            if pii_bert.load():
                self._detectors.append(pii_bert)
        
        # Optional dictionary detector
        if self.config.enable_dictionaries:
            self._detectors.append(DictionaryDetector())
    
    def detect(self, text: str) -> List[Span]:
        """Run all detectors and return merged spans."""
        all_spans = []
        
        for detector in self._detectors:
            try:
                spans = detector.detect(text)
                all_spans.extend(spans)
            except Exception as e:
                logger.warning(f"Detector {detector.name} failed: {e}")
        
        return all_spans
```

### 4.5 Detection Pipeline Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      DETECTION PIPELINE (Extracted)                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   INPUT: Raw text from file                                                  │
│                                                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ STAGE 1: NORMALIZE                                                   │   │
│   │                                                                      │   │
│   │ • Unicode normalization (NFKC)                                       │   │
│   │ • Whitespace cleanup                                                 │   │
│   │ • OCR artifact correction (if applicable)                           │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                      │                                       │
│                                      ▼                                       │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ STAGE 2: DETECT (parallel across detector types)                    │   │
│   │                                                                      │   │
│   │  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌────────────┐  │   │
│   │  │   CHECKSUM   │ │   PATTERN    │ │   ML BERT    │ │ DICTIONARY │  │   │
│   │  │              │ │              │ │              │ │            │  │   │
│   │  │ • Luhn SSN   │ │ • Regex      │ │ • PHI-BERT   │ │ • Names    │  │   │
│   │  │ • Luhn CC    │ │ • Dates      │ │ • PII-BERT   │ │ • Facilities│  │   │
│   │  │ • NPI check  │ │ • Phones     │ │              │ │            │  │   │
│   │  │              │ │ • Addresses  │ │              │ │            │  │   │
│   │  │ TIER 1 ▲▲▲   │ │ TIER 2 ▲▲    │ │ TIER 3 ▲     │ │ TIER 4     │  │   │
│   │  └──────────────┘ └──────────────┘ └──────────────┘ └────────────┘  │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                      │                                       │
│                                      ▼                                       │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ STAGE 3: MERGE                                                       │   │
│   │                                                                      │   │
│   │ • Resolve overlapping spans (higher tier wins)                      │   │
│   │ • Deduplicate exact matches                                         │   │
│   │ • Apply confidence threshold                                        │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                      │                                       │
│                                      ▼                                       │
│                                                                              │
│   OUTPUT: List[Span] with entity_type, confidence, start, end               │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Discovery Layer

### 5.1 Purpose

The discovery layer finds all files that need to be considered for scanning. Speed here is critical - naive `os.walk()` can take 20+ minutes on large filesystems.

### 5.2 Platform-Specific Strategies

#### 5.2.1 Windows: MFT Parsing

The Master File Table (MFT) contains metadata for every file on an NTFS volume. Parsing it directly is 10-30x faster than walking directories.

```python
# openrisk/scanner/discovery.py

class MFTDiscovery:
    """Fast file discovery via NTFS MFT parsing (Windows only)."""
    
    def __init__(self, volume: str):
        self.volume = volume  # e.g., "C:"
    
    def discover(self, root: Path) -> Iterator[FileInfo]:
        """
        Yield FileInfo for all files under root.
        
        Uses MFT parsing for speed. Requires admin privileges.
        Falls back to scandir if MFT access fails.
        """
        try:
            from ntfs import MFT
            
            mft = MFT.from_volume(self.volume)
            root_str = str(root).lower()
            
            for record in mft.entries():
                if not record.is_file or record.is_deleted:
                    continue
                
                path = record.full_path
                if path.lower().startswith(root_str):
                    yield FileInfo(
                        path=Path(path),
                        size=record.data_size,
                        mtime=record.modified_time.timestamp(),
                    )
        
        except (ImportError, PermissionError, OSError) as e:
            logger.warning(f"MFT access failed ({e}), falling back to scandir")
            yield from ScandirDiscovery().discover(root)
```

#### 5.2.2 Linux/macOS: Fast Scandir

Use `os.scandir()` instead of `os.walk()` - it returns DirEntry objects with cached stat info.

```python
class ScandirDiscovery:
    """Cross-platform file discovery using os.scandir."""
    
    def discover(self, root: Path, follow_symlinks: bool = False) -> Iterator[FileInfo]:
        """
        Yield FileInfo for all files under root.
        
        Uses os.scandir for efficiency (caches stat info).
        Tracks inodes to prevent infinite loops from symlinks.
        """
        visited_inodes = set()
        
        def walk(path: Path):
            try:
                with os.scandir(path) as entries:
                    for entry in entries:
                        try:
                            # Track inodes to prevent loops
                            stat = entry.stat(follow_symlinks=follow_symlinks)
                            inode = (stat.st_dev, stat.st_ino)
                            
                            if inode in visited_inodes:
                                continue
                            visited_inodes.add(inode)
                            
                            if entry.is_file(follow_symlinks=follow_symlinks):
                                yield FileInfo(
                                    path=Path(entry.path),
                                    size=stat.st_size,
                                    mtime=stat.st_mtime,
                                )
                            elif entry.is_dir(follow_symlinks=follow_symlinks):
                                yield from walk(Path(entry.path))
                        
                        except (PermissionError, OSError) as e:
                            logger.debug(f"Cannot access {entry.path}: {e}")
            
            except (PermissionError, OSError) as e:
                logger.debug(f"Cannot access directory {path}: {e}")
        
        yield from walk(root)
```

### 5.3 FileInfo Structure

```python
@dataclass
class FileInfo:
    """Lightweight file metadata for filtering decisions."""
    path: Path
    size: int
    mtime: float
    
    # Computed lazily
    _suffix: str = None
    _content_hash: str = None
    
    @property
    def suffix(self) -> str:
        if self._suffix is None:
            self._suffix = self.path.suffix.lower()
        return self._suffix
    
    @property
    def content_hash(self) -> str:
        """Compute hash on first access (expensive)."""
        if self._content_hash is None:
            self._content_hash = compute_file_hash(self.path)
        return self._content_hash
```

### 5.4 Discovery Factory

```python
def get_discovery(root: Path) -> Discovery:
    """Get appropriate discovery strategy for platform and path."""
    
    # Check if Windows and local NTFS
    if sys.platform == "win32" and is_local_ntfs(root):
        volume = get_volume(root)  # e.g., "C:"
        return MFTDiscovery(volume)
    
    # Check if network path
    if is_network_path(root):
        logger.warning(
            f"Network path detected: {root}\n"
            "Scanning over network is significantly slower.\n"
            "Consider running the scanner on the file server."
        )
    
    return ScandirDiscovery()
```

---

## 6. Filtering Layer

### 6.1 Purpose

The filtering layer eliminates files that don't need ML inference. This is the primary source of speed gains - every file filtered is ~100ms saved.

### 6.2 Filter Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           FILTER PIPELINE                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   100,000 files from Discovery                                               │
│        │                                                                     │
│        ▼                                                                     │
│   ┌─────────────────────────────────────────┐                               │
│   │ FILTER 1: Extension (instant)           │                               │
│   │                                         │                               │
│   │ Skip: .exe .dll .so .png .jpg .mp4     │                               │
│   │       .zip .tar .gz .whl .pyc          │                               │
│   └─────────────────────────────────────────┘                               │
│        │                                                                     │
│        ▼  (~55,000 files remain)                                            │
│   ┌─────────────────────────────────────────┐                               │
│   │ FILTER 2: Path Pattern (instant)        │                               │
│   │                                         │                               │
│   │ Skip: node_modules/ .git/ __pycache__/ │                               │
│   │       .venv/ venv/ site-packages/      │                               │
│   │       .idea/ .vscode/ dist/ build/     │                               │
│   └─────────────────────────────────────────┘                               │
│        │                                                                     │
│        ▼  (~40,000 files remain)                                            │
│   ┌─────────────────────────────────────────┐                               │
│   │ FILTER 3: Size (instant)                │                               │
│   │                                         │                               │
│   │ Skip: files > 1GB (configurable)        │                               │
│   │ Flag: files > 100MB for sampling        │                               │
│   └─────────────────────────────────────────┘                               │
│        │                                                                     │
│        ▼  (~39,500 files remain)                                            │
│   ┌─────────────────────────────────────────┐                               │
│   │ FILTER 4: Data Type Classification      │                               │
│   │           (~1ms per file)               │                               │
│   │                                         │                               │
│   │ Read first 4KB, analyze structure       │                               │
│   │ Skip: CODE, CONFIG, DOCUMENTATION       │                               │
│   │ Keep: REGULATED, UNKNOWN                │                               │
│   └─────────────────────────────────────────┘                               │
│        │                                                                     │
│        ▼  (~12,000 files remain)                                            │
│   ┌─────────────────────────────────────────┐                               │
│   │ FILTER 5: Content Hash Deduplication    │                               │
│   │           (~2ms per file)               │                               │
│   │                                         │                               │
│   │ Group by hash, scan unique only         │                               │
│   │ Apply results to all duplicates         │                               │
│   └─────────────────────────────────────────┘                               │
│        │                                                                     │
│        ▼  (~8,000 unique files for ML)                                      │
│                                                                              │
│   RESULT: 92% filtered, 8% need ML inference                                │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 6.3 Extension Filter

```python
# openrisk/scanner/filters.py

# File extensions to always skip (never contain regulated data)
SKIP_EXTENSIONS = {
    # Executables/binaries
    '.exe', '.dll', '.so', '.dylib', '.bin', '.o', '.a',
    '.pyc', '.pyo', '.class', '.wasm',
    
    # Images
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg',
    '.webp', '.tiff', '.psd', '.ai', '.eps',
    
    # Audio/Video
    '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.wav',
    '.ogg', '.m4a', '.flac', '.mkv', '.webm',
    
    # Archives (scan separately if needed)
    '.zip', '.tar', '.gz', '.bz2', '.xz', '.7z', '.rar',
    '.whl', '.egg', '.jar', '.war',
    
    # Fonts
    '.ttf', '.otf', '.woff', '.woff2', '.eot',
    
    # Other binary
    '.pdf',  # Would need OCR - skip for v1
    '.doc',  # Legacy format - skip for v1 (docx is supported)
    '.xls',  # Legacy format - skip for v1 (xlsx is supported)
    '.sqlite', '.db', '.mdb',
}

# Extensions that definitely need scanning
SCAN_EXTENSIONS = {
    '.csv', '.tsv',
    '.json', '.jsonl', '.ndjson',
    '.xml',
    '.txt', '.text', '.log',
    '.yaml', '.yml',
    '.md', '.rst',
    '.html', '.htm',
    '.docx', '.xlsx',
    '.eml', '.msg',
}

def filter_by_extension(file: FileInfo) -> FilterResult:
    """Filter file by extension."""
    ext = file.suffix
    
    if ext in SKIP_EXTENSIONS:
        return FilterResult.SKIP, "binary_extension"
    
    if ext in SCAN_EXTENSIONS:
        return FilterResult.SCAN, None
    
    # Unknown extension - let data type classifier decide
    return FilterResult.UNKNOWN, None
```

### 6.4 Path Filter

```python
# Directory patterns to always skip
SKIP_PATH_PATTERNS = {
    # Dependencies
    'node_modules',
    '.venv', 'venv', 'virtualenv',
    'site-packages', 'dist-packages',
    '__pycache__',
    '.tox', '.nox',
    'vendor', 'third_party',
    
    # Version control
    '.git', '.svn', '.hg', '.bzr',
    
    # IDE/editor
    '.idea', '.vscode', '.vs',
    '.eclipse', '.settings',
    
    # Build artifacts
    'dist', 'build', 'target',
    'out', 'output', 'bin', 'obj',
    '_build', '.build',
    
    # Cache
    '.cache', '__cache__',
    '.pytest_cache', '.mypy_cache',
    '.ruff_cache', '.eslintcache',
    
    # OS
    '.Trash', '$RECYCLE.BIN',
    'System Volume Information',
}

def filter_by_path(file: FileInfo) -> FilterResult:
    """Filter file by path patterns."""
    parts = set(file.path.parts)
    
    if parts & SKIP_PATH_PATTERNS:
        return FilterResult.SKIP, "dependency_or_build"
    
    return FilterResult.UNKNOWN, None
```

### 6.5 Data Type Classifier

This is the smart filter - it reads file headers to determine if the file could contain regulated data.

```python
# openrisk/scanner/classifier.py

class DataType(Enum):
    CODE = "code"
    CONFIG = "config"
    DOCUMENTATION = "documentation"
    REGULATED = "regulated"
    UNKNOWN = "unknown"

# Header patterns that indicate regulated data
REGULATED_SIGNALS = {
    # Healthcare (HIPAA)
    'patient', 'mrn', 'medical_record', 'diagnosis', 'icd', 'cpt',
    'dob', 'date_of_birth', 'ssn', 'social_security', 'insurance',
    'provider', 'physician', 'prescription', 'medication', 'treatment',
    'hipaa', 'phi', 'health_plan', 'beneficiary',
    
    # Financial (PCI-DSS, GLBA)
    'credit_card', 'card_number', 'cvv', 'account_number', 'routing',
    'bank', 'balance', 'transaction', 'payment',
    
    # HR/Personnel
    'employee', 'salary', 'compensation', 'performance', 'termination',
    'hire_date', 'department', 'manager', 'payroll',
    
    # General PII
    'first_name', 'last_name', 'full_name', 'email', 'phone',
    'address', 'street', 'city', 'zip', 'postal',
    'birth', 'age', 'gender', 'race', 'ethnicity',
    'passport', 'driver_license', 'national_id',
}

# Header patterns that indicate non-regulated data
SAFE_SIGNALS = {
    # Code/Config
    'version', 'dependencies', 'scripts', 'config', 'settings',
    'import', 'export', 'module', 'package', 'require',
    'function', 'class', 'def', 'const', 'let', 'var',
    
    # Metrics/Telemetry (usually ok)
    'timestamp', 'duration', 'count', 'metric', 'value',
    'request_id', 'trace_id', 'span_id', 'correlation_id',
    
    # Product/Inventory (not PII)
    'product_id', 'sku', 'inventory', 'price', 'quantity',
    'category', 'brand', 'manufacturer',
}

def classify_data_type(file: FileInfo) -> DataType:
    """
    Classify file by analyzing structure and headers.
    
    Reads first 4KB to determine if file could contain regulated data.
    """
    # Quick extension-based classification
    ext = file.suffix
    
    if ext in {'.py', '.js', '.ts', '.java', '.c', '.cpp', '.go', '.rs', '.rb'}:
        return DataType.CODE
    
    if ext in {'.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf'}:
        return DataType.CONFIG
    
    if ext in {'.md', '.rst', '.txt'} and is_documentation_path(file.path):
        return DataType.DOCUMENTATION
    
    # Read header for structured files
    try:
        with open(file.path, 'r', encoding='utf-8', errors='ignore') as f:
            header = f.read(4096).lower()
    except (IOError, OSError):
        return DataType.UNKNOWN
    
    # CSV/TSV: analyze column headers
    if ext in {'.csv', '.tsv'}:
        return classify_csv_headers(header)
    
    # JSON: analyze top-level keys
    if ext in {'.json', '.jsonl', '.ndjson'}:
        return classify_json_structure(header)
    
    # XML: analyze element names
    if ext in {'.xml'}:
        return classify_xml_structure(header)
    
    # Plain text: look for patterns
    return classify_text_content(header)


def classify_csv_headers(header: str) -> DataType:
    """Classify CSV by analyzing column headers."""
    # Get first line (headers)
    first_line = header.split('\n')[0] if '\n' in header else header
    
    # Normalize and split
    headers = [h.strip().lower().replace('"', '').replace("'", '') 
               for h in first_line.split(',')]
    
    # Count signals
    regulated_hits = sum(
        1 for h in headers 
        if any(signal in h for signal in REGULATED_SIGNALS)
    )
    safe_hits = sum(
        1 for h in headers 
        if any(signal in h for signal in SAFE_SIGNALS)
    )
    
    # Decision logic
    if regulated_hits >= 2:
        return DataType.REGULATED
    if regulated_hits >= 1 and safe_hits == 0:
        return DataType.REGULATED
    if safe_hits > regulated_hits and regulated_hits == 0:
        return DataType.CONFIG  # Likely metrics or product data
    
    return DataType.UNKNOWN


def classify_json_structure(header: str) -> DataType:
    """Classify JSON by analyzing key names."""
    # Extract potential key names (simple heuristic)
    import re
    keys = re.findall(r'"([^"]+)"\s*:', header)
    keys_lower = [k.lower() for k in keys]
    
    regulated_hits = sum(
        1 for k in keys_lower 
        if any(signal in k for signal in REGULATED_SIGNALS)
    )
    safe_hits = sum(
        1 for k in keys_lower 
        if any(signal in k for signal in SAFE_SIGNALS)
    )
    
    if regulated_hits >= 2:
        return DataType.REGULATED
    if safe_hits > regulated_hits * 2:
        return DataType.CONFIG
    
    return DataType.UNKNOWN
```

### 6.6 Content Hash Deduplication

```python
# openrisk/scanner/dedup.py

def deduplicate_by_hash(
    files: List[FileInfo],
    progress_callback: Callable = None,
) -> Dict[str, List[FileInfo]]:
    """
    Group files by content hash.
    
    Returns dict mapping hash -> list of files with that hash.
    First file in each list is the "primary" to scan.
    """
    hash_groups: Dict[str, List[FileInfo]] = defaultdict(list)
    
    for i, file in enumerate(files):
        try:
            # Use quick hash (first 64KB + size) for initial grouping
            quick_hash = compute_quick_hash(file.path, file.size)
            hash_groups[quick_hash].append(file)
            
            if progress_callback:
                progress_callback(i, len(files))
        
        except (IOError, OSError) as e:
            logger.debug(f"Cannot hash {file.path}: {e}")
    
    # For groups with multiple files, verify with full hash
    verified_groups: Dict[str, List[FileInfo]] = {}
    
    for quick_hash, group in hash_groups.items():
        if len(group) == 1:
            # Only one file with this quick hash - use it directly
            full_hash = compute_full_hash(group[0].path)
            verified_groups[full_hash] = group
        else:
            # Multiple files - compute full hashes to verify
            for file in group:
                full_hash = compute_full_hash(file.path)
                if full_hash not in verified_groups:
                    verified_groups[full_hash] = []
                verified_groups[full_hash].append(file)
    
    return verified_groups


def compute_quick_hash(path: Path, size: int) -> str:
    """Quick hash using first 64KB + file size."""
    hasher = hashlib.sha256()
    hasher.update(str(size).encode())
    
    with open(path, 'rb') as f:
        chunk = f.read(65536)  # 64KB
        hasher.update(chunk)
    
    return hasher.hexdigest()[:16]  # Truncate for speed


def compute_full_hash(path: Path) -> str:
    """Full SHA-256 hash of file content."""
    hasher = hashlib.sha256()
    
    with open(path, 'rb') as f:
        while chunk := f.read(1048576):  # 1MB chunks
            hasher.update(chunk)
    
    return f"sha256:{hasher.hexdigest()}"
```

### 6.7 Filter Manager

```python
# openrisk/scanner/filter_manager.py

@dataclass
class FilterStats:
    """Statistics from filtering."""
    total_discovered: int = 0
    skipped_extension: int = 0
    skipped_path: int = 0
    skipped_size: int = 0
    skipped_data_type: int = 0
    duplicates: int = 0
    to_scan: int = 0


class FilterManager:
    """Coordinates all filtering stages."""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.stats = FilterStats()
    
    def filter(
        self, 
        files: Iterator[FileInfo],
        progress_callback: Callable = None,
    ) -> Tuple[List[FileInfo], FilterStats]:
        """
        Apply all filters and return files that need scanning.
        """
        # Stage 1 & 2: Extension and path filters (in-memory, instant)
        after_static = []
        for file in files:
            self.stats.total_discovered += 1
            
            # Extension filter
            result, reason = filter_by_extension(file)
            if result == FilterResult.SKIP:
                self.stats.skipped_extension += 1
                continue
            
            # Path filter
            result, reason = filter_by_path(file)
            if result == FilterResult.SKIP:
                self.stats.skipped_path += 1
                continue
            
            # Size filter
            if file.size > self.config.max_file_size:
                self.stats.skipped_size += 1
                continue
            
            after_static.append(file)
        
        # Stage 3: Data type classification (requires file read)
        after_classification = []
        for file in after_static:
            data_type = classify_data_type(file)
            
            if data_type in {DataType.CODE, DataType.CONFIG, DataType.DOCUMENTATION}:
                self.stats.skipped_data_type += 1
                continue
            
            after_classification.append(file)
        
        # Stage 4: Deduplication
        hash_groups = deduplicate_by_hash(after_classification, progress_callback)
        
        # Count duplicates
        for group in hash_groups.values():
            if len(group) > 1:
                self.stats.duplicates += len(group) - 1
        
        # Return primary file from each group
        to_scan = [group[0] for group in hash_groups.values()]
        self.stats.to_scan = len(to_scan)
        
        return to_scan, hash_groups, self.stats
```

---

## 7. Detection Layer

### 7.1 Purpose

The detection layer extracts text from files and runs the ML pipeline to identify sensitive entities.

### 7.2 Text Extraction

```python
# openrisk/scanner/extraction.py

class TextExtractor:
    """Extract text content from various file formats."""
    
    def extract(self, file: FileInfo) -> ExtractionResult:
        """
        Extract text from file.
        
        Returns ExtractionResult with text and metadata.
        """
        ext = file.suffix
        
        try:
            if ext in {'.txt', '.text', '.log', '.md', '.rst'}:
                return self._extract_plain_text(file)
            
            elif ext in {'.csv', '.tsv'}:
                return self._extract_csv(file)
            
            elif ext in {'.json', '.jsonl', '.ndjson'}:
                return self._extract_json(file)
            
            elif ext in {'.xml', '.html', '.htm'}:
                return self._extract_xml(file)
            
            elif ext == '.docx':
                return self._extract_docx(file)
            
            elif ext == '.xlsx':
                return self._extract_xlsx(file)
            
            else:
                # Try as plain text
                return self._extract_plain_text(file)
        
        except Exception as e:
            logger.warning(f"Extraction failed for {file.path}: {e}")
            return ExtractionResult(
                text="",
                success=False,
                error=str(e),
            )
    
    def _extract_plain_text(self, file: FileInfo) -> ExtractionResult:
        """Extract plain text with encoding detection."""
        raw = file.path.read_bytes()
        
        # Detect encoding
        if raw.startswith(b'\xef\xbb\xbf'):
            encoding = 'utf-8-sig'
        else:
            import chardet
            detected = chardet.detect(raw[:10000])
            encoding = detected['encoding'] or 'utf-8'
        
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            text = raw.decode('utf-8', errors='replace')
            encoding = 'utf-8-lossy'
        
        # Handle large files via sampling
        if len(text) > self.config.max_text_length:
            text = self._sample_large_text(text)
        
        return ExtractionResult(
            text=text,
            success=True,
            encoding=encoding,
            original_length=len(raw),
        )
    
    def _extract_csv(self, file: FileInfo) -> ExtractionResult:
        """Extract CSV as text, preserving structure."""
        # Read as text to preserve original formatting
        result = self._extract_plain_text(file)
        result.format = 'csv'
        return result
    
    def _extract_json(self, file: FileInfo) -> ExtractionResult:
        """Extract JSON, flattening values to text."""
        result = self._extract_plain_text(file)
        result.format = 'json'
        return result
    
    def _extract_docx(self, file: FileInfo) -> ExtractionResult:
        """Extract text from Word document."""
        from docx import Document
        
        doc = Document(str(file.path))
        paragraphs = [p.text for p in doc.paragraphs]
        text = '\n'.join(paragraphs)
        
        return ExtractionResult(
            text=text,
            success=True,
            format='docx',
        )
    
    def _extract_xlsx(self, file: FileInfo) -> ExtractionResult:
        """Extract text from Excel spreadsheet."""
        from openpyxl import load_workbook
        
        wb = load_workbook(str(file.path), read_only=True, data_only=True)
        texts = []
        
        for sheet in wb.worksheets:
            for row in sheet.iter_rows(values_only=True):
                row_text = ' '.join(str(cell) for cell in row if cell is not None)
                if row_text.strip():
                    texts.append(row_text)
        
        return ExtractionResult(
            text='\n'.join(texts),
            success=True,
            format='xlsx',
        )
    
    def _sample_large_text(self, text: str) -> str:
        """Sample large text to stay within limits."""
        max_len = self.config.max_text_length
        chunk_size = max_len // 4
        
        # Take beginning, two middle samples, and end
        return (
            text[:chunk_size] +
            '\n...[SAMPLED]...\n' +
            text[len(text)//3 : len(text)//3 + chunk_size] +
            '\n...[SAMPLED]...\n' +
            text[2*len(text)//3 : 2*len(text)//3 + chunk_size] +
            '\n...[SAMPLED]...\n' +
            text[-chunk_size:]
        )


@dataclass
class ExtractionResult:
    text: str
    success: bool
    format: str = 'text'
    encoding: str = None
    original_length: int = None
    error: str = None
```

### 7.3 Detection Runner

```python
# openrisk/scanner/detection.py

class DetectionRunner:
    """Runs detection pipeline on extracted text."""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.normalizer = TextNormalizer()
        self.orchestrator = DetectorOrchestrator(config)
        self.merger = SpanMerger(min_confidence=config.confidence_threshold)
    
    def detect(self, text: str) -> List[Span]:
        """
        Run full detection pipeline.
        
        Pipeline:
        1. Normalize text
        2. Run all detectors
        3. Merge overlapping spans
        4. Filter by confidence
        """
        if not text or not text.strip():
            return []
        
        # Stage 1: Normalize
        normalized = self.normalizer.normalize(text)
        
        # Stage 2: Detect
        raw_spans = self.orchestrator.detect(normalized)
        
        # Stage 3: Merge and filter
        merged = self.merger.merge(raw_spans, text=normalized)
        
        return merged
    
    def detect_file(self, file: FileInfo, extractor: TextExtractor) -> DetectionResult:
        """
        Extract text and run detection on a file.
        """
        # Extract text
        extraction = extractor.extract(file)
        
        if not extraction.success:
            return DetectionResult(
                file=file,
                spans=[],
                success=False,
                error=extraction.error,
            )
        
        # Run detection
        spans = self.detect(extraction.text)
        
        return DetectionResult(
            file=file,
            spans=spans,
            success=True,
            text_length=len(extraction.text),
            encoding=extraction.encoding,
        )


@dataclass
class DetectionResult:
    file: FileInfo
    spans: List[Span]
    success: bool
    text_length: int = 0
    encoding: str = None
    error: str = None
```

---

## 8. Scoring Layer

### 8.1 Purpose

The scoring layer converts detection spans into OpenRisk tags by mapping entity types and computing risk scores.

### 8.2 Entity Mapping

```python
# openrisk/scoring/mapping.py

# Map scrubIQ entity types to OpenRisk types
SCRUBIQ_TO_OPENRISK = {
    # Direct identifiers
    'SSN': 'ssn',
    'CREDIT_CARD': 'credit_card',
    'BANK_ACCOUNT': 'bank_account',
    'DRIVERS_LICENSE': 'drivers_license',
    'PASSPORT': 'passport',
    'NPI': 'npi',
    'DEA': 'dea_number',
    
    # Healthcare
    'MRN': 'mrn',
    'HEALTH_PLAN_ID': 'health_plan_id',
    'DIAGNOSIS': 'diagnosis',
    'MEDICATION': 'medication',
    'PROCEDURE': 'procedure',
    'LAB_RESULT': 'lab_result',
    'ICD_CODE': 'icd_code',
    
    # Contact
    'EMAIL': 'email',
    'PHONE': 'phone',
    'FAX': 'fax',
    'ADDRESS': 'address',
    'POSTAL_CODE': 'postal_code',
    'IP_ADDRESS': 'ip_address',
    
    # Demographics
    'NAME': 'full_name',
    'NAME_PATIENT': 'full_name',
    'NAME_PROVIDER': 'full_name',
    'NAME_RELATIVE': 'full_name',
    'FIRST_NAME': 'first_name',
    'LAST_NAME': 'last_name',
    'DATE_OF_BIRTH': 'date_of_birth',
    'DOB': 'date_of_birth',
    'AGE': 'age',
    'GENDER': 'gender',
    
    # Credentials
    'AWS_ACCESS_KEY': 'aws_access_key',
    'AWS_SECRET_KEY': 'aws_secret_key',
    'API_KEY': 'api_key',
    'PASSWORD': 'password',
    'PRIVATE_KEY': 'private_key',
    
    # Financial
    'IBAN': 'iban',
    'ROUTING_NUMBER': 'routing_number',
    'SWIFT_BIC': 'swift_bic',
    
    # Types to skip (not sensitive enough or too vague)
    'DATE': None,
    'TIME': None,
    'FACILITY': None,  # May reconsider
    'LOCATION': None,
    'URL': None,
    'EMPLOYER': None,  # May reconsider
}


def map_span_to_openrisk(span: Span) -> Optional[Tuple[str, float]]:
    """
    Map a scrubIQ span to OpenRisk entity type.
    
    Returns (openrisk_type, confidence) or None if type should be skipped.
    """
    openrisk_type = SCRUBIQ_TO_OPENRISK.get(span.entity_type)
    
    if openrisk_type is None:
        return None
    
    return (openrisk_type, span.confidence)
```

### 8.3 Score Calculator

```python
# openrisk/scoring/scorer.py

class RiskScorer:
    """
    OpenRisk score calculator.
    
    Implements the openrisk-v0.2-standard algorithm.
    """
    
    VERSION = "0.2"
    ALGORITHM = "openrisk-v0.2-standard"
    
    # Co-occurrence rules
    CO_OCCURRENCE_RULES = [
        {
            "name": "direct_id + health",
            "requires": [
                {"categories": ["direct_identifier"]},
                {"categories": ["health"]},
            ],
            "multiplier": 1.5,
        },
        {
            "name": "direct_id + financial",
            "requires": [
                {"categories": ["direct_identifier"]},
                {"types": ["credit_card", "bank_account", "iban"]},
            ],
            "multiplier": 1.4,
        },
        {
            "name": "bulk_pii",
            "min_distinct_types": 5,
            "multiplier": 1.3,
        },
    ]
    
    # Tier thresholds
    TIER_THRESHOLDS = [
        (86, "Critical"),
        (61, "High"),
        (31, "Medium"),
        (11, "Low"),
        (0, "Minimal"),
    ]
    
    def __init__(self, confidence_threshold: float = 0.5):
        self.confidence_threshold = confidence_threshold
        self.detections: Dict[str, EntityAggregate] = {}
        self.filtered: List[dict] = []
    
    def add_detection(
        self,
        entity_type: str,
        count: int = 1,
        confidence: float = 1.0,
    ):
        """Add a detection to the scorer."""
        if confidence < self.confidence_threshold:
            self.filtered.append({
                "type": entity_type,
                "count": count,
                "confidence_avg": confidence,
                "reason": "below_threshold"
            })
            return
        
        if entity_type not in self.detections:
            self.detections[entity_type] = EntityAggregate(
                type=entity_type,
                count=0,
                confidence_sum=0.0,
            )
        
        agg = self.detections[entity_type]
        agg.confidence_sum += confidence * count
        agg.count += count
    
    def add_from_spans(self, spans: List[Span]):
        """Add detections from scrubIQ spans."""
        for span in spans:
            mapped = map_span_to_openrisk(span)
            if mapped:
                openrisk_type, confidence = mapped
                self.add_detection(openrisk_type, count=1, confidence=confidence)
    
    def calculate_score(self) -> Tuple[int, float, List[str], float]:
        """
        Calculate risk score.
        
        Returns: (score, raw_score, triggered_rules, multiplier)
        """
        if not self.detections:
            return (0, 0.0, [], 1.0)
        
        # Compute base score
        base_score = 0.0
        for entity_type, agg in self.detections.items():
            weight = get_entity_weight(entity_type)
            confidence_avg = agg.confidence_sum / agg.count
            count_factor = min(math.log2(agg.count + 1), 5)
            
            contribution = weight * count_factor * confidence_avg
            base_score += contribution
        
        # Apply co-occurrence multipliers
        multiplier, triggered = self._check_co_occurrence()
        adjusted_score = base_score * multiplier
        
        # Normalize to 0-100
        normalized = 100 * (1 - math.exp(-adjusted_score / 50))
        score = round(min(normalized, 100))
        
        return (score, base_score, triggered, multiplier)
    
    def _check_co_occurrence(self) -> Tuple[float, List[str]]:
        """Check co-occurrence rules."""
        multiplier = 1.0
        triggered = []
        
        # Build category and type sets
        categories = set()
        types = set(self.detections.keys())
        
        for entity_type in types:
            category = get_entity_category(entity_type)
            parts = category.split('.')
            for i in range(len(parts)):
                categories.add('.'.join(parts[:i+1]))
        
        # Check rules
        for rule in self.CO_OCCURRENCE_RULES:
            if self._rule_matches(rule, categories, types):
                if rule["multiplier"] > multiplier:
                    multiplier = rule["multiplier"]
                    triggered.append(rule["name"])
        
        return (multiplier, triggered)
    
    def _rule_matches(self, rule: dict, categories: set, types: set) -> bool:
        """Check if a rule matches current detections."""
        if "requires" in rule:
            for req in rule["requires"]:
                matched = False
                if "categories" in req:
                    matched = any(c in categories for c in req["categories"])
                if "types" in req:
                    matched = matched or any(t in types for t in req["types"])
                if not matched:
                    return False
            return True
        
        if "min_distinct_types" in rule:
            return len(types) >= rule["min_distinct_types"]
        
        return False
    
    def generate(
        self,
        content_hash: str,
        content_length: int,
        generator: str = "openrisk-scan/0.1.0",
    ) -> dict:
        """Generate complete OpenRisk tag."""
        score, raw_score, triggered, multiplier = self.calculate_score()
        tier = self._score_to_tier(score)
        
        entities = []
        for entity_type, agg in self.detections.items():
            entities.append({
                "type": entity_type,
                "category": get_entity_category(entity_type),
                "count": agg.count,
                "confidence_avg": round(agg.confidence_sum / agg.count, 3),
                "weight": get_entity_weight(entity_type),
            })
        
        return {
            "openrisk": {
                "version": self.VERSION,
                "score": score,
                "tier": tier,
                "content_hash": content_hash,
                "content_length": content_length,
                "factors": {
                    "entities": entities,
                    "co_occurrence_rules": triggered,
                    "co_occurrence_multiplier": multiplier,
                    "raw_score": round(raw_score, 2),
                    "filtered": self.filtered,
                },
                "scoring": {
                    "algorithm": self.ALGORITHM,
                    "confidence_threshold": self.confidence_threshold,
                    "mode": "strict",
                },
                "provenance": {
                    "generator": generator,
                    "generated_at": datetime.utcnow().isoformat() + "Z",
                },
            }
        }
    
    def _score_to_tier(self, score: int) -> str:
        for threshold, tier in self.TIER_THRESHOLDS:
            if score >= threshold:
                return tier
        return "Minimal"


@dataclass
class EntityAggregate:
    type: str
    count: int
    confidence_sum: float
```

---

## 9. Cloud Sources

### 9.1 Source Abstraction

All sources implement the same interface:

```python
# openrisk/sources/base.py

from abc import ABC, abstractmethod
from typing import Iterator
from dataclasses import dataclass

@dataclass
class SourceFile:
    """File from any source."""
    key: str              # Unique identifier (path, S3 key, etc.)
    size: int
    mtime: float
    source: str           # "filesystem", "s3", "gcs"
    metadata: dict = None # Source-specific metadata
    
    # For local caching
    _local_path: Path = None
    _content: bytes = None


class Source(ABC):
    """Base class for file sources."""
    
    @abstractmethod
    def list_files(self, prefix: str = "") -> Iterator[SourceFile]:
        """List all files under prefix."""
        pass
    
    @abstractmethod
    def get_content(self, file: SourceFile) -> bytes:
        """Download file content."""
        pass
    
    @abstractmethod
    def get_hash(self, file: SourceFile) -> str:
        """Get content hash (may use source-provided hash)."""
        pass
    
    def supports_streaming(self) -> bool:
        """Whether source supports streaming large files."""
        return False
```

### 9.2 AWS S3 Source

```python
# openrisk/sources/s3.py

import boto3
from typing import Iterator
import hashlib

class S3Source(Source):
    """
    Scan files in an S3 bucket.
    
    Usage:
        source = S3Source(bucket="my-data-bucket", prefix="exports/")
        for file in source.list_files():
            content = source.get_content(file)
            # scan it
    
    Auth: Uses boto3 credential chain (env vars, ~/.aws/credentials, IAM role)
    """
    
    def __init__(
        self,
        bucket: str,
        prefix: str = "",
        region: str = None,
        profile: str = None,
    ):
        self.bucket = bucket
        self.prefix = prefix
        
        session_kwargs = {}
        if region:
            session_kwargs['region_name'] = region
        if profile:
            session_kwargs['profile_name'] = profile
        
        session = boto3.Session(**session_kwargs)
        self.s3 = session.client('s3')
    
    def list_files(self, prefix: str = None) -> Iterator[SourceFile]:
        """List all objects in bucket under prefix."""
        prefix = prefix or self.prefix
        paginator = self.s3.get_paginator('list_objects_v2')
        
        for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
            for obj in page.get('Contents', []):
                # Skip "directories" (keys ending in /)
                if obj['Key'].endswith('/'):
                    continue
                
                yield SourceFile(
                    key=obj['Key'],
                    size=obj['Size'],
                    mtime=obj['LastModified'].timestamp(),
                    source="s3",
                    metadata={
                        'bucket': self.bucket,
                        'etag': obj['ETag'].strip('"'),
                        'storage_class': obj.get('StorageClass', 'STANDARD'),
                    }
                )
    
    def get_content(self, file: SourceFile) -> bytes:
        """Download object content."""
        response = self.s3.get_object(Bucket=self.bucket, Key=file.key)
        return response['Body'].read()
    
    def get_hash(self, file: SourceFile) -> str:
        """
        Get content hash.
        
        Note: S3 ETag is MD5 for single-part uploads, but not for multipart.
        We compute SHA-256 ourselves for consistency.
        """
        content = self.get_content(file)
        return f"sha256:{hashlib.sha256(content).hexdigest()}"
    
    def get_hash_from_etag(self, file: SourceFile) -> str:
        """
        Use ETag for deduplication (fast but not SHA-256).
        Only works for single-part uploads.
        """
        etag = file.metadata.get('etag', '')
        if '-' not in etag:  # Single-part upload
            return f"md5:{etag}"
        return None  # Multipart, need to compute
    
    def supports_streaming(self) -> bool:
        return True
    
    def stream_content(self, file: SourceFile, chunk_size: int = 8192) -> Iterator[bytes]:
        """Stream large files in chunks."""
        response = self.s3.get_object(Bucket=self.bucket, Key=file.key)
        for chunk in response['Body'].iter_chunks(chunk_size):
            yield chunk


# CLI integration
def scan_s3_bucket(
    bucket: str,
    prefix: str = "",
    output: Path = None,
    **scan_kwargs,
) -> dict:
    """
    Scan an S3 bucket.
    
    CLI:
        openrisk scan s3://my-bucket/prefix/ -o results.json
    """
    source = S3Source(bucket=bucket, prefix=prefix)
    scanner = Scanner(config=ScanConfig(**scan_kwargs))
    
    results = {}
    for source_file in source.list_files():
        # Apply filters
        if not scanner.should_scan(source_file):
            continue
        
        # Download and scan
        content = source.get_content(source_file)
        tag = scanner.scan_bytes(content, filename=source_file.key)
        results[source_file.key] = tag
    
    if output:
        write_json_results(results, output)
    
    return results
```

### 9.3 Google Cloud Storage Source

```python
# openrisk/sources/gcs.py

from google.cloud import storage
from typing import Iterator
import hashlib

class GCSSource(Source):
    """
    Scan files in a Google Cloud Storage bucket.
    
    Usage:
        source = GCSSource(bucket="my-data-bucket", prefix="exports/")
        for file in source.list_files():
            content = source.get_content(file)
            # scan it
    
    Auth: Uses Application Default Credentials
          (GOOGLE_APPLICATION_CREDENTIALS env var, gcloud auth, or GCE metadata)
    """
    
    def __init__(
        self,
        bucket: str,
        prefix: str = "",
        project: str = None,
    ):
        self.client = storage.Client(project=project)
        self.bucket_obj = self.client.bucket(bucket)
        self.bucket = bucket
        self.prefix = prefix
    
    def list_files(self, prefix: str = None) -> Iterator[SourceFile]:
        """List all blobs in bucket under prefix."""
        prefix = prefix or self.prefix
        
        for blob in self.client.list_blobs(self.bucket, prefix=prefix):
            # Skip "directories"
            if blob.name.endswith('/'):
                continue
            
            yield SourceFile(
                key=blob.name,
                size=blob.size,
                mtime=blob.updated.timestamp() if blob.updated else 0,
                source="gcs",
                metadata={
                    'bucket': self.bucket,
                    'md5_hash': blob.md5_hash,          # Base64-encoded MD5
                    'crc32c': blob.crc32c,              # Base64-encoded CRC32C
                    'storage_class': blob.storage_class,
                    'content_type': blob.content_type,
                }
            )
    
    def get_content(self, file: SourceFile) -> bytes:
        """Download blob content."""
        blob = self.bucket_obj.blob(file.key)
        return blob.download_as_bytes()
    
    def get_hash(self, file: SourceFile) -> str:
        """Compute SHA-256 hash."""
        content = self.get_content(file)
        return f"sha256:{hashlib.sha256(content).hexdigest()}"
    
    def get_hash_from_metadata(self, file: SourceFile) -> str:
        """Use GCS-provided MD5 for deduplication."""
        md5_b64 = file.metadata.get('md5_hash')
        if md5_b64:
            import base64
            md5_hex = base64.b64decode(md5_b64).hex()
            return f"md5:{md5_hex}"
        return None
    
    def supports_streaming(self) -> bool:
        return True
    
    def stream_content(self, file: SourceFile, chunk_size: int = 8192) -> Iterator[bytes]:
        """Stream large files in chunks."""
        blob = self.bucket_obj.blob(file.key)
        with blob.open('rb') as f:
            while chunk := f.read(chunk_size):
                yield chunk


# CLI integration
def scan_gcs_bucket(
    bucket: str,
    prefix: str = "",
    output: Path = None,
    **scan_kwargs,
) -> dict:
    """
    Scan a GCS bucket.
    
    CLI:
        openrisk scan gs://my-bucket/prefix/ -o results.json
    """
    source = GCSSource(bucket=bucket, prefix=prefix)
    scanner = Scanner(config=ScanConfig(**scan_kwargs))
    
    results = {}
    for source_file in source.list_files():
        if not scanner.should_scan(source_file):
            continue
        
        content = source.get_content(source_file)
        tag = scanner.scan_bytes(content, filename=source_file.key)
        results[source_file.key] = tag
    
    if output:
        write_json_results(results, output)
    
    return results
```

### 9.4 CLI Syntax

```bash
# Local filesystem (default)
openrisk scan /path/to/files -o results.json

# AWS S3
openrisk scan s3://bucket-name/prefix/ -o results.json
openrisk scan s3://bucket-name/ --profile prod -o results.json

# Google Cloud Storage  
openrisk scan gs://bucket-name/prefix/ -o results.json
openrisk scan gs://bucket-name/ --project my-project -o results.json

# Common options work across all sources
openrisk scan s3://bucket/ --recursive --confidence 0.7 --write-trailer
```

### 9.5 Source Detection

```python
# openrisk/sources/__init__.py

def get_source(path: str, **kwargs) -> Source:
    """
    Auto-detect source type from path.
    
    Patterns:
        /path/to/dir     → FilesystemSource
        s3://bucket/key  → S3Source
        gs://bucket/key  → GCSSource
    """
    if path.startswith('s3://'):
        bucket, _, prefix = path[5:].partition('/')
        return S3Source(bucket=bucket, prefix=prefix, **kwargs)
    
    elif path.startswith('gs://'):
        bucket, _, prefix = path[5:].partition('/')
        return GCSSource(bucket=bucket, prefix=prefix, **kwargs)
    
    else:
        return FilesystemSource(root=Path(path), **kwargs)
```

### 9.6 Dependencies

```toml
[project.optional-dependencies]
s3 = [
    "boto3>=1.26",
]
gcs = [
    "google-cloud-storage>=2.0",
]
cloud = [
    "boto3>=1.26",
    "google-cloud-storage>=2.0",
]
```

Install what you need:

```bash
pip install openrisk            # Local filesystem only
pip install openrisk[s3]        # Add S3 support
pip install openrisk[gcs]       # Add GCS support
pip install openrisk[cloud]     # Add both
```

### 9.7 Future Sources (Deferred)

| Source | Complexity | When |
|--------|------------|------|
| Azure Blob Storage | Easy | v1.1 (same pattern as S3/GCS) |
| M365 (SharePoint/OneDrive) | Medium | v1.2 (Graph API, OAuth dance) |
| Google Drive | Medium | v1.2 (OAuth, weird folder model) |
| Box | Medium | v1.3 (smaller market) |
| Dropbox | Medium | v1.3 (smaller market) |

---

## 10. Output Layer

### 9.1 Purpose

The output layer writes OpenRisk tags to various destinations.

### 9.2 Output Formats

| Format | Description | Use Case |
|--------|-------------|----------|
| JSON file | Separate `.json` file with all results | Programmatic consumption |
| Trailer | Append to original files | Metadata travels with file |
| Stdout | Print to console | Piping, scripting |
| Report | Summary HTML report | Human review |

### 9.3 Trailer Writer

```python
# openrisk/output/trailer.py

START_MARKER = b'\n---OPENRISK-TAG-V1---\n'
END_MARKER = b'\n---END-OPENRISK-TAG---'


def write_trailer(filepath: Path, tag: dict) -> bool:
    """
    Append OpenRisk trailer to file.
    
    Returns True on success, False on failure.
    """
    try:
        # Read original content
        with open(filepath, 'rb') as f:
            original = f.read()
        
        # Verify hash matches
        actual_hash = compute_hash(original)
        if tag["openrisk"]["content_hash"] != actual_hash:
            logger.error(f"Hash mismatch for {filepath}")
            return False
        
        # Check if trailer already exists
        if has_trailer(original):
            logger.warning(f"File already has trailer: {filepath}")
            original = strip_trailer_bytes(original)
        
        # Build trailer
        tag_json = json.dumps(tag, separators=(',', ':'))
        trailer = START_MARKER + tag_json.encode('utf-8') + END_MARKER
        
        # Write original + trailer
        with open(filepath, 'wb') as f:
            f.write(original)
            f.write(trailer)
        
        return True
    
    except Exception as e:
        logger.error(f"Failed to write trailer to {filepath}: {e}")
        return False


def read_trailer(filepath: Path) -> Tuple[bytes, Optional[dict]]:
    """
    Read file and extract OpenRisk trailer if present.
    
    Returns (original_content, tag_dict or None).
    """
    with open(filepath, 'rb') as f:
        content = f.read()
    
    if not has_trailer(content):
        return content, None
    
    # Find markers
    end_pos = content.rfind(END_MARKER)
    start_pos = content.rfind(START_MARKER)
    
    if start_pos == -1 or end_pos == -1:
        return content, None
    
    # Extract JSON
    tag_start = start_pos + len(START_MARKER)
    tag_json = content[tag_start:end_pos]
    
    try:
        tag = json.loads(tag_json.decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return content, None
    
    # Extract original using content_length
    content_length = tag['openrisk']['content_length']
    original = content[:content_length]
    
    # Verify integrity
    actual_hash = compute_hash(original)
    if actual_hash != tag['openrisk']['content_hash']:
        logger.warning(f"Hash mismatch - file modified since tagging")
        return content, None
    
    return original, tag


def has_trailer(content: bytes) -> bool:
    """Check if content has an OpenRisk trailer."""
    return content.rstrip().endswith(END_MARKER.rstrip())


def strip_trailer_bytes(content: bytes) -> bytes:
    """Remove trailer from content bytes."""
    start_pos = content.rfind(START_MARKER)
    if start_pos == -1:
        return content
    
    # Verify there's an end marker after start
    end_pos = content.rfind(END_MARKER)
    if end_pos == -1 or end_pos < start_pos:
        return content
    
    # Try to use content_length for precision
    try:
        tag_start = start_pos + len(START_MARKER)
        tag_json = content[tag_start:end_pos]
        tag = json.loads(tag_json.decode('utf-8'))
        content_length = tag['openrisk']['content_length']
        return content[:content_length]
    except:
        # Fallback: just remove from start marker
        return content[:start_pos]


def compute_hash(content: bytes) -> str:
    """Compute SHA-256 hash."""
    return f"sha256:{hashlib.sha256(content).hexdigest()}"
```

### 9.4 JSON Output

```python
# openrisk/output/json_output.py

def write_json_results(
    results: Dict[Path, dict],
    output_path: Path,
    pretty: bool = False,
):
    """
    Write all results to a JSON file.
    """
    output = {
        "openrisk_scan": {
            "version": "0.1.0",
            "scanned_at": datetime.utcnow().isoformat() + "Z",
            "file_count": len(results),
            "files": {
                str(path): tag
                for path, tag in results.items()
            }
        }
    }
    
    with open(output_path, 'w') as f:
        if pretty:
            json.dump(output, f, indent=2)
        else:
            json.dump(output, f, separators=(',', ':'))


def write_jsonl_results(
    results: Dict[Path, dict],
    output_path: Path,
):
    """
    Write results as JSON Lines (one per file).
    """
    with open(output_path, 'w') as f:
        for path, tag in results.items():
            record = {
                "path": str(path),
                "tag": tag,
            }
            f.write(json.dumps(record, separators=(',', ':')) + '\n')
```

### 9.5 Report Generator

```python
# openrisk/output/report.py

def generate_html_report(
    results: Dict[Path, dict],
    stats: ScanStats,
    output_path: Path,
):
    """
    Generate HTML summary report.
    """
    # Count by tier
    tier_counts = Counter()
    for tag in results.values():
        tier = tag["openrisk"]["tier"]
        tier_counts[tier] += 1
    
    # Top risk files
    top_risk = sorted(
        results.items(),
        key=lambda x: x[1]["openrisk"]["score"],
        reverse=True,
    )[:20]
    
    # Entity breakdown
    entity_counts = Counter()
    for tag in results.values():
        for entity in tag["openrisk"]["factors"]["entities"]:
            entity_counts[entity["type"]] += entity["count"]
    
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>OpenRisk Scan Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 40px; }}
        .tier-critical {{ color: #dc2626; }}
        .tier-high {{ color: #ea580c; }}
        .tier-medium {{ color: #ca8a04; }}
        .tier-low {{ color: #16a34a; }}
        .tier-minimal {{ color: #6b7280; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #f3f4f6; }}
        .stat-box {{ display: inline-block; padding: 20px; margin: 10px; background: #f9fafb; border-radius: 8px; }}
        .stat-value {{ font-size: 2em; font-weight: bold; }}
    </style>
</head>
<body>
    <h1>OpenRisk Scan Report</h1>
    <p>Generated: {datetime.utcnow().isoformat()}Z</p>
    
    <h2>Summary</h2>
    <div>
        <div class="stat-box">
            <div class="stat-value">{stats.files_scanned}</div>
            <div>Files Scanned</div>
        </div>
        <div class="stat-box">
            <div class="stat-value tier-critical">{tier_counts.get('Critical', 0)}</div>
            <div>Critical</div>
        </div>
        <div class="stat-box">
            <div class="stat-value tier-high">{tier_counts.get('High', 0)}</div>
            <div>High</div>
        </div>
        <div class="stat-box">
            <div class="stat-value tier-medium">{tier_counts.get('Medium', 0)}</div>
            <div>Medium</div>
        </div>
    </div>
    
    <h2>Highest Risk Files</h2>
    <table>
        <tr><th>Score</th><th>Tier</th><th>File</th><th>Top Entities</th></tr>
        {''.join(f'''
        <tr>
            <td>{tag["openrisk"]["score"]}</td>
            <td class="tier-{tag["openrisk"]["tier"].lower()}">{tag["openrisk"]["tier"]}</td>
            <td>{path}</td>
            <td>{", ".join(e["type"] + f"({e['count']})" for e in tag["openrisk"]["factors"]["entities"][:3])}</td>
        </tr>
        ''' for path, tag in top_risk)}
    </table>
    
    <h2>Entity Types Found</h2>
    <table>
        <tr><th>Entity Type</th><th>Total Count</th></tr>
        {''.join(f"<tr><td>{entity}</td><td>{count}</td></tr>" for entity, count in entity_counts.most_common(20))}
    </table>
</body>
</html>
"""
    
    output_path.write_text(html)
```

---

## 11. CLI & TUI

### 10.1 Command Structure

```bash
# Main scan command
openrisk scan <path> [options]

# Options
  -r, --recursive           Scan directories recursively
  -o, --output FILE         Write results to JSON file
  --write-trailer           Append trailers to scanned files
  --confidence FLOAT        Minimum confidence threshold (default: 0.5)
  --max-size SIZE           Maximum file size (default: 1GB)
  --quiet                   Suppress progress output
  --json                    Output JSON to stdout
  --report FILE             Generate HTML report

# Utility commands
openrisk read <file>        Read tag from file
openrisk strip <file>       Remove trailer from file
openrisk validate <file>    Validate tag structure
openrisk hash <file>        Compute content hash
```

### 10.2 CLI Implementation

```python
# openrisk/cli/main.py

import click
from rich.console import Console

console = Console()

@click.group()
@click.version_option(version="0.1.0")
def cli():
    """OpenRisk Scanner - Data sensitivity classification."""
    pass


@cli.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('-r', '--recursive', is_flag=True, help='Scan recursively')
@click.option('-o', '--output', type=click.Path(), help='Output JSON file')
@click.option('--write-trailer', is_flag=True, help='Write trailers to files')
@click.option('--confidence', type=float, default=0.5, help='Confidence threshold')
@click.option('--max-size', type=str, default='1GB', help='Max file size')
@click.option('--quiet', is_flag=True, help='Suppress progress')
@click.option('--json', 'json_output', is_flag=True, help='JSON to stdout')
@click.option('--report', type=click.Path(), help='HTML report path')
def scan(path, recursive, output, write_trailer, confidence, max_size, quiet, json_output, report):
    """Scan files for sensitive data."""
    from .scan import run_scan
    
    config = ScanConfig(
        root=Path(path),
        recursive=recursive,
        confidence_threshold=confidence,
        max_file_size=parse_size(max_size),
        write_trailer=write_trailer,
    )
    
    if quiet or json_output:
        results = run_scan_quiet(config)
    else:
        results = run_scan_with_tui(config)
    
    if output:
        write_json_results(results, Path(output))
    
    if json_output:
        for path, tag in results.items():
            console.print_json(data={"path": str(path), "tag": tag})
    
    if report:
        generate_html_report(results, config, Path(report))


@cli.command()
@click.argument('file', type=click.Path(exists=True))
@click.option('--format', type=click.Choice(['json', 'summary']), default='summary')
def read(file, format):
    """Read OpenRisk tag from file."""
    _, tag = read_trailer(Path(file))
    
    if tag is None:
        console.print("[yellow]No OpenRisk tag found[/yellow]")
        raise SystemExit(1)
    
    if format == 'json':
        console.print_json(data=tag)
    else:
        t = tag["openrisk"]
        console.print(f"Score: {t['score']} ({t['tier']})")
        console.print(f"Entities: {len(t['factors']['entities'])}")
        for e in t['factors']['entities']:
            console.print(f"  {e['type']}: {e['count']} (conf: {e['confidence_avg']:.2f})")


@cli.command()
@click.argument('file', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output file (default: in-place)')
def strip(file, output):
    """Remove OpenRisk trailer from file."""
    original, tag = read_trailer(Path(file))
    
    if tag is None:
        console.print("[yellow]No trailer found[/yellow]")
        return
    
    output_path = Path(output) if output else Path(file)
    output_path.write_bytes(original)
    console.print(f"[green]Stripped trailer from {file}[/green]")


if __name__ == '__main__':
    cli()
```

### 10.3 TUI Implementation

```python
# openrisk/cli/tui.py

from rich.console import Console
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

console = Console()


def run_scan_with_tui(config: ScanConfig) -> Dict[Path, dict]:
    """Run scan with Rich TUI progress display."""
    
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="progress", size=6),
        Layout(name="stats", size=14),
    )
    
    # Header
    layout["header"].update(Panel(
        "[bold blue]OPENRISK SCANNER[/bold blue] v0.1.0",
        style="blue"
    ))
    
    # Stats tracking
    stats = ScanStats()
    results = {}
    
    with Live(layout, refresh_per_second=4, console=console):
        # Phase 1: Discovery
        update_progress(layout, "Discovering files...", None, stats)
        
        discovery = get_discovery(config.root)
        files = list(discovery.discover(config.root))
        stats.total_discovered = len(files)
        
        # Phase 2: Filtering
        update_progress(layout, "Filtering...", None, stats)
        
        filter_mgr = FilterManager(config)
        to_scan, hash_groups, filter_stats = filter_mgr.filter(files)
        stats.update_from_filter(filter_stats)
        
        # Phase 3: Scanning
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("{task.completed}/{task.total}"),
            TimeElapsedColumn(),
        )
        
        scan_task = progress.add_task("Scanning", total=len(to_scan))
        layout["progress"].update(Panel(progress))
        
        extractor = TextExtractor(config)
        detector = DetectionRunner(config)
        
        for file in to_scan:
            # Update current file display
            stats.current_file = file.path.name
            update_stats_panel(layout, stats)
            
            # Detect
            result = detector.detect_file(file, extractor)
            
            if result.success:
                # Score
                scorer = RiskScorer(config.confidence_threshold)
                scorer.add_from_spans(result.spans)
                tag = scorer.generate(
                    content_hash=file.content_hash,
                    content_length=file.size,
                )
                
                # Store result for this file and all duplicates
                for dup_file in hash_groups[file.content_hash]:
                    results[dup_file.path] = tag
                
                # Update stats
                tier = tag["openrisk"]["tier"]
                stats.tier_counts[tier] += len(hash_groups[file.content_hash])
                stats.files_scanned += 1
            
            progress.update(scan_task, advance=1)
        
        # Phase 4: Write trailers if requested
        if config.write_trailer:
            update_progress(layout, "Writing trailers...", None, stats)
            for path, tag in results.items():
                write_trailer(path, tag)
        
        # Final stats
        stats.complete = True
        update_stats_panel(layout, stats)
    
    # Print summary
    print_summary(stats, results)
    
    return results


def update_stats_panel(layout: Layout, stats: ScanStats):
    """Update the stats panel."""
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Label", style="dim")
    table.add_column("Value")
    
    table.add_row("Discovered", str(stats.total_discovered))
    table.add_row("Filtered", str(stats.total_filtered))
    table.add_row("To Scan", str(stats.to_scan))
    table.add_row("Scanned", str(stats.files_scanned))
    table.add_row("", "")
    table.add_row("🔴 Critical", str(stats.tier_counts.get("Critical", 0)))
    table.add_row("🟠 High", str(stats.tier_counts.get("High", 0)))
    table.add_row("🟡 Medium", str(stats.tier_counts.get("Medium", 0)))
    table.add_row("🟢 Low", str(stats.tier_counts.get("Low", 0)))
    table.add_row("", "")
    table.add_row("Current", stats.current_file[:50] if stats.current_file else "-")
    
    layout["stats"].update(Panel(table, title="Stats"))


def print_summary(stats: ScanStats, results: Dict[Path, dict]):
    """Print final summary."""
    console.print()
    console.print("[bold]═" * 60)
    console.print("[bold]SCAN COMPLETE")
    console.print("[bold]═" * 60)
    console.print()
    
    console.print(f"Files scanned:    {stats.files_scanned}")
    console.print(f"Files filtered:   {stats.total_filtered}")
    console.print()
    
    console.print("[bold]Risk Distribution:")
    console.print(f"  🔴 Critical:  {stats.tier_counts.get('Critical', 0)}")
    console.print(f"  🟠 High:      {stats.tier_counts.get('High', 0)}")
    console.print(f"  🟡 Medium:    {stats.tier_counts.get('Medium', 0)}")
    console.print(f"  🟢 Low:       {stats.tier_counts.get('Low', 0)}")
    console.print(f"  ⚪ Minimal:   {stats.tier_counts.get('Minimal', 0)}")
    console.print()
    
    # Top 5 highest risk
    if results:
        top = sorted(
            results.items(),
            key=lambda x: x[1]["openrisk"]["score"],
            reverse=True
        )[:5]
        
        if top and top[0][1]["openrisk"]["score"] > 0:
            console.print("[bold]Top Risk Files:")
            for path, tag in top:
                score = tag["openrisk"]["score"]
                tier = tag["openrisk"]["tier"]
                if score > 0:
                    console.print(f"  {score:3d}  {path}")
```

---

## 12. Configuration

### 11.1 Configuration Structure

```python
# openrisk/config.py

@dataclass
class ScanConfig:
    """Scanner configuration."""
    
    # Paths
    root: Path
    recursive: bool = True
    
    # Filtering
    max_file_size: int = 1024 * 1024 * 1024  # 1GB
    skip_extensions: Set[str] = field(default_factory=lambda: SKIP_EXTENSIONS)
    skip_paths: Set[str] = field(default_factory=lambda: SKIP_PATH_PATTERNS)
    
    # Detection
    confidence_threshold: float = 0.5
    models_dir: Optional[Path] = None
    enable_dictionaries: bool = False
    max_text_length: int = 1024 * 1024  # 1MB of text
    
    # Output
    write_trailer: bool = False
    
    # Performance
    io_workers: int = 4
    
    def __post_init__(self):
        if self.models_dir is None:
            self.models_dir = get_default_models_dir()


def get_default_models_dir() -> Path:
    """Get default models directory."""
    # Check environment variable
    if env_dir := os.environ.get('OPENRISK_MODELS_DIR'):
        return Path(env_dir)
    
    # Check ~/.openrisk/models
    home_dir = Path.home() / '.openrisk' / 'models'
    if home_dir.exists():
        return home_dir
    
    # Fallback to package directory
    return Path(__file__).parent / 'models'
```

### 11.2 Model Management

```python
# openrisk/models.py

MODELS = {
    'phi_bert': {
        'filename': 'phi_bert_int8.onnx',
        'size': 108_000_000,
        'sha256': 'abc123...',  # For verification
    },
    'pii_bert': {
        'filename': 'pii_bert_int8.onnx',
        'size': 108_000_000,
        'sha256': 'def456...',
    },
}


def ensure_models(models_dir: Path) -> bool:
    """Ensure models are downloaded and valid."""
    models_dir.mkdir(parents=True, exist_ok=True)
    
    all_present = True
    for name, info in MODELS.items():
        model_path = models_dir / info['filename']
        
        if not model_path.exists():
            console.print(f"[yellow]Model {name} not found at {model_path}[/yellow]")
            console.print(f"Download from: https://huggingface.co/scrubiq/{name}")
            all_present = False
        elif model_path.stat().st_size != info['size']:
            console.print(f"[yellow]Model {name} appears corrupted[/yellow]")
            all_present = False
    
    return all_present
```

---

## 13. Package Structure

```
openrisk/
├── openrisk/
│   ├── __init__.py              # Public API
│   │
│   ├── cli/
│   │   ├── __init__.py
│   │   ├── main.py              # Click entry points
│   │   ├── scan.py              # Scan command implementation
│   │   └── tui.py               # Rich TUI components
│   │
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── orchestrator.py      # Main scan orchestration
│   │   ├── discovery.py         # File discovery (MFT, scandir)
│   │   ├── filters.py           # Extension, path, size filters
│   │   ├── classifier.py        # Data type classification
│   │   ├── dedup.py             # Hash-based deduplication
│   │   ├── extraction.py        # Text extraction
│   │   └── detection.py         # Detection runner
│   │
│   ├── _detection/              # Vendored from scrubIQ
│   │   ├── __init__.py
│   │   ├── normalizer.py
│   │   ├── merger.py
│   │   ├── orchestrator.py
│   │   ├── types.py
│   │   └── detectors/
│   │       ├── __init__.py
│   │       ├── base.py
│   │       ├── checksum.py
│   │       ├── patterns.py
│   │       ├── additional_patterns.py
│   │       ├── ml_onnx.py
│   │       └── dictionaries.py
│   │
│   ├── scoring/
│   │   ├── __init__.py
│   │   ├── scorer.py            # RiskScorer
│   │   ├── entities.py          # Entity registry
│   │   ├── mapping.py           # scrubIQ → OpenRisk mapping
│   │   └── weights.py           # Entity weights
│   │
│   ├── output/
│   │   ├── __init__.py
│   │   ├── trailer.py           # Trailer read/write
│   │   ├── json_output.py       # JSON file output
│   │   └── report.py            # HTML report
│   │
│   ├── adapters/                # Convert other tools' output → OpenRisk
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── presidio.py
│   │   ├── aws_macie.py
│   │   ├── google_dlp.py
│   │   └── microsoft_purview.py
│   │
│   ├── sources/                  # Read raw files from storage → scan
│   │   ├── __init__.py
│   │   ├── base.py              # Source base class
│   │   ├── filesystem.py        # Local / network filesystem
│   │   ├── s3.py                # AWS S3
│   │   └── gcs.py               # Google Cloud Storage
│   │
│   ├── config.py                # Configuration
│   ├── models.py                # Model management
│   └── utils.py                 # Utilities
│
├── models/                      # ONNX models (git-ignored, downloaded)
│   ├── phi_bert_int8.onnx
│   └── pii_bert_int8.onnx
│
├── tests/
│   ├── __init__.py
│   ├── test_discovery.py
│   ├── test_filters.py
│   ├── test_classifier.py
│   ├── test_detection.py
│   ├── test_scoring.py
│   ├── test_trailer.py
│   ├── test_adapters/
│   └── fixtures/
│
├── pyproject.toml
├── README.md
├── LICENSE                      # Apache 2.0
└── SPEC.md                      # OpenRisk specification
```

---

## 14. Data Flow

### 13.1 Complete Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         COMPLETE DATA FLOW                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   USER: openrisk scan /data --recursive                                      │
│                         │                                                    │
│                         ▼                                                    │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ CLI LAYER                                                            │   │
│   │ Parse arguments → Create ScanConfig → Initialize TUI                │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                         │                                                    │
│                         ▼                                                    │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ DISCOVERY                                                            │   │
│   │                                                                      │   │
│   │ Windows: MFT.from_volume("C:") → Iterator[FileInfo]                 │   │
│   │ Linux:   scandir recursive    → Iterator[FileInfo]                  │   │
│   │                                                                      │   │
│   │ Output: 100,000 FileInfo(path, size, mtime)                         │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                         │                                                    │
│                         ▼                                                    │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ FILTER 1: Extension                                                  │   │
│   │ Skip: .exe, .dll, .png, .mp4, .zip, etc.                            │   │
│   │ 100,000 → 55,000                                                     │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                         │                                                    │
│                         ▼                                                    │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ FILTER 2: Path                                                       │   │
│   │ Skip: node_modules/, .git/, __pycache__/, etc.                      │   │
│   │ 55,000 → 40,000                                                      │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                         │                                                    │
│                         ▼                                                    │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ FILTER 3: Size                                                       │   │
│   │ Skip: files > 1GB                                                    │   │
│   │ 40,000 → 39,500                                                      │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                         │                                                    │
│                         ▼                                                    │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ FILTER 4: Data Type Classification                                   │   │
│   │ Read first 4KB → Analyze headers/structure                          │   │
│   │ Skip: CODE, CONFIG, DOCUMENTATION                                   │   │
│   │ Keep: REGULATED, UNKNOWN                                            │   │
│   │ 39,500 → 12,000                                                      │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                         │                                                    │
│                         ▼                                                    │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ FILTER 5: Deduplication                                              │   │
│   │ Group by content hash                                                │   │
│   │ Scan unique only, apply results to duplicates                       │   │
│   │ 12,000 → 8,000 unique (4,000 duplicates)                            │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                         │                                                    │
│                         ▼                                                    │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ EXTRACTION (parallel, 4-8 workers)                                   │   │
│   │                                                                      │   │
│   │ .csv/.txt → read with encoding detection                            │   │
│   │ .docx     → python-docx extraction                                  │   │
│   │ .xlsx     → openpyxl extraction                                     │   │
│   │ .json     → read as text                                            │   │
│   │                                                                      │   │
│   │ Output: 8,000 ExtractionResult(text, encoding, length)              │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                         │                                                    │
│                         ▼                                                    │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ DETECTION PIPELINE (sequential - model not thread-safe)             │   │
│   │                                                                      │   │
│   │ ┌───────────────┐                                                   │   │
│   │ │ 1. NORMALIZE  │ Unicode NFKC, whitespace cleanup                  │   │
│   │ └───────────────┘                                                   │   │
│   │         │                                                            │   │
│   │         ▼                                                            │   │
│   │ ┌───────────────────────────────────────────────────────────────┐   │   │
│   │ │ 2. DETECT (all detectors)                                      │   │   │
│   │ │                                                                │   │   │
│   │ │ Checksum: SSN (Luhn), CC (Luhn), NPI (Luhn)                   │   │   │
│   │ │ Pattern:  Regex for dates, phones, addresses, etc.            │   │   │
│   │ │ ML:       PHI-BERT (108MB), PII-BERT (108MB)                  │   │   │
│   │ │ Dict:     Name lists, facilities (optional)                   │   │   │
│   │ └───────────────────────────────────────────────────────────────┘   │   │
│   │         │                                                            │   │
│   │         ▼                                                            │   │
│   │ ┌───────────────┐                                                   │   │
│   │ │ 3. MERGE      │ Resolve overlaps, higher tier wins               │   │
│   │ └───────────────┘                                                   │   │
│   │                                                                      │   │
│   │ Output: 8,000 List[Span(type, confidence, start, end)]              │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                         │                                                    │
│                         ▼                                                    │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ SCORING                                                              │   │
│   │                                                                      │   │
│   │ 1. Map spans: scrubIQ type → OpenRisk type                          │   │
│   │ 2. Aggregate: Count by type, compute avg confidence                 │   │
│   │ 3. Score: weight × log2(count) × confidence, sum all               │   │
│   │ 4. Co-occur: Check rules, apply multiplier                          │   │
│   │ 5. Normalize: 100 × (1 - e^(-score/50))                            │   │
│   │ 6. Tier: Critical/High/Medium/Low/Minimal                           │   │
│   │                                                                      │   │
│   │ Output: 8,000 OpenRisk tags                                         │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                         │                                                    │
│                         ▼                                                    │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ EXPAND DUPLICATES                                                    │   │
│   │                                                                      │   │
│   │ Apply each tag to all files with same content hash                  │   │
│   │ 8,000 tags → 12,000 file results                                    │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                         │                                                    │
│                         ▼                                                    │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │ OUTPUT                                                               │   │
│   │                                                                      │   │
│   │ --output results.json  → Write JSON file                            │   │
│   │ --write-trailer        → Append trailer to each file                │   │
│   │ --report report.html   → Generate HTML summary                      │   │
│   │ (default)              → Print summary to console                   │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 15. Performance Targets

### 14.1 Target Performance

| Metric | Target | Notes |
|--------|--------|-------|
| Discovery (100K files, MFT) | <30 seconds | Windows NTFS |
| Discovery (100K files, scandir) | <2 minutes | Linux ext4 |
| Filtering (100K → 8K) | <2 minutes | Including data type classification |
| Extraction (8K files) | <3 minutes | Parallel, 4-8 workers |
| Detection (8K files) | <20 minutes | Sequential ML inference |
| **Total (100K files)** | **<30 minutes** | CPU only |

### 14.2 Memory Targets

| Component | Memory | Notes |
|-----------|--------|-------|
| PHI-BERT model | ~400 MB | Loaded once |
| PII-BERT model | ~400 MB | Loaded once |
| File metadata | ~100 bytes/file | 10 MB for 100K files |
| Results cache | ~500 bytes/file | 5 MB for 10K results |
| **Total working set** | **<1.5 GB** | |

### 14.3 Benchmarking

```python
# openrisk/benchmark.py

def benchmark_scan(root: Path, iterations: int = 3) -> BenchmarkResult:
    """Run benchmark scan and report timing."""
    timings = {
        'discovery': [],
        'filtering': [],
        'extraction': [],
        'detection': [],
        'scoring': [],
        'total': [],
    }
    
    for i in range(iterations):
        start = time.perf_counter()
        
        # ... run each phase with timing ...
        
    return BenchmarkResult(
        file_count=file_count,
        timings={k: statistics.mean(v) for k, v in timings.items()},
        files_per_second=file_count / statistics.mean(timings['total']),
    )
```

---

## 16. Testing Strategy

### 15.1 Test Categories

| Category | Purpose | Coverage |
|----------|---------|----------|
| Unit tests | Test individual components | Each module |
| Integration tests | Test component interactions | Pipeline flows |
| Accuracy tests | Verify detection quality | Known test corpus |
| Performance tests | Verify speed targets | Benchmark suite |
| Compatibility tests | Test platform behavior | Windows/Linux |

### 15.2 Test Fixtures

```
tests/fixtures/
├── small/                    # Quick tests
│   ├── clean.csv            # No PII
│   ├── pii_basic.csv        # Name, email, phone
│   ├── phi_basic.csv        # SSN, MRN, diagnosis
│   └── mixed.json           # Various types
├── formats/                  # Format testing
│   ├── test.docx
│   ├── test.xlsx
│   ├── utf8.csv
│   ├── latin1.csv
│   └── utf16.csv
├── edge_cases/               # Edge cases
│   ├── empty.txt
│   ├── binary_in_text.txt
│   ├── huge_line.txt
│   └── nested.json
└── accuracy/                 # Accuracy benchmarks
    ├── labeled_phi.jsonl    # Ground truth PHI
    └── labeled_pii.jsonl    # Ground truth PII
```

### 15.3 Accuracy Testing

```python
# tests/test_accuracy.py

def test_phi_detection_recall():
    """Verify PHI detection recall meets threshold."""
    ground_truth = load_labeled_data('fixtures/accuracy/labeled_phi.jsonl')
    
    tp, fn = 0, 0
    for item in ground_truth:
        spans = detector.detect(item['text'])
        detected_types = {s.entity_type for s in spans}
        
        for expected in item['entities']:
            if expected['type'] in detected_types:
                tp += 1
            else:
                fn += 1
    
    recall = tp / (tp + fn)
    assert recall >= 0.94, f"PHI recall {recall:.2%} below threshold"


def test_scoring_determinism():
    """Verify scoring is deterministic."""
    text = "Patient SSN 123-45-6789 diagnosed with diabetes"
    
    results = [
        run_full_pipeline(text)
        for _ in range(10)
    ]
    
    scores = [r['openrisk']['score'] for r in results]
    assert len(set(scores)) == 1, "Scoring not deterministic"
```

---

## 17. Implementation Phases

### 17.1 Phase 1: Core Pipeline (Week 1-2)

**Goal:** Basic scanning works end-to-end

- [ ] Vendor detection code from scrubIQ
- [ ] Implement simple scandir discovery
- [ ] Implement extension/path filters
- [ ] Implement text extraction (plain text, CSV)
- [ ] Implement RiskScorer
- [ ] Implement JSON output
- [ ] Basic CLI with progress

**Deliverable:** `openrisk scan /path --output results.json` works

### 17.2 Phase 2: Speed Optimization (Week 3)

**Goal:** Hit performance targets

- [ ] Implement MFT discovery (Windows)
- [ ] Implement data type classifier
- [ ] Implement hash deduplication
- [ ] Implement parallel extraction
- [ ] Optimize threading model

**Deliverable:** 100K files in <30 minutes on CPU

### 17.3 Phase 3: Output & Polish (Week 4)

**Goal:** Production-ready output

- [ ] Implement trailer read/write
- [ ] Implement HTML report
- [ ] Rich TUI with live stats
- [ ] DOCX/XLSX extraction
- [ ] Error handling and logging

**Deliverable:** Full CLI feature set

### 17.4 Phase 4: Cloud Sources (Week 5)

**Goal:** Scan cloud storage

- [ ] Source abstraction layer
- [ ] AWS S3 source
- [ ] Google Cloud Storage source
- [ ] CLI auto-detection (s3://, gs://)
- [ ] Optional dependencies ([s3], [gcs], [cloud])

**Deliverable:** `openrisk scan s3://bucket/` works

### 17.5 Phase 5: Adapters & Docs (Week 6)

**Goal:** Ecosystem integration

- [ ] Presidio adapter
- [ ] AWS Macie adapter
- [ ] Google DLP adapter
- [ ] Microsoft Purview adapter
- [ ] Documentation
- [ ] PyPI packaging

**Deliverable:** `pip install openrisk` ready for launch

---

## Appendix A: Dependencies

```toml
# pyproject.toml

[project]
name = "openrisk"
version = "0.1.0"
description = "Data sensitivity scanner implementing the OpenRisk standard"
requires-python = ">=3.10"
license = {text = "Apache-2.0"}

dependencies = [
    # CLI
    "click>=8.0",
    "rich>=13.0",
    
    # ML
    "onnxruntime>=1.16",
    "transformers>=4.30",
    
    # Text extraction
    "chardet>=5.0",
    "python-docx>=0.8",
    "openpyxl>=3.1",
    
    # Utilities
    "pyyaml>=6.0",
]

[project.optional-dependencies]
windows = [
    "python-ntfs>=0.1",
]

s3 = [
    "boto3>=1.26",
]

gcs = [
    "google-cloud-storage>=2.0",
]

cloud = [
    "boto3>=1.26",
    "google-cloud-storage>=2.0",
]

dev = [
    "pytest>=7.0",
    "pytest-cov>=4.0",
    "black>=23.0",
    "ruff>=0.1",
    "mypy>=1.0",
]

[project.scripts]
openrisk = "openrisk.cli.main:cli"
```

---

## Appendix B: Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `OPENRISK_MODELS_DIR` | Path to ONNX models | `~/.openrisk/models` |
| `OPENRISK_LOG_LEVEL` | Logging verbosity | `WARNING` |
| `OPENRISK_IO_WORKERS` | Parallel I/O threads | `4` |
| `OPENRISK_NO_COLOR` | Disable colored output | unset |

---

## Appendix C: Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 3 | Models not found |
| 4 | Permission denied |
| 5 | Scan failed |

---

**End of Architecture Document**
