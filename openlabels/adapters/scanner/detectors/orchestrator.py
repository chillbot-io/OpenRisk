"""Detector orchestrator - runs all detectors in parallel.

Detectors are organized by domain:
- checksum.py: Checksum-validated identifiers (SSN, CC, NPI, DEA, VIN, IBAN, ABA)
- patterns.py: PII/PHI patterns (names, dates, addresses, phones, medical IDs)
- additional_patterns.py: EMPLOYER, AGE, HEALTH_PLAN_ID patterns
- secrets.py: API keys, tokens, credentials, private keys
- financial.py: Security identifiers (CUSIP, ISIN, SWIFT) and crypto
- government.py: Classification markings, CAGE codes, contracts
- dictionaries.py: Dictionary-based detection

Concurrency Model:
    Uses ThreadPoolExecutor for parallel pattern matching across domains.
    Pattern matching is I/O-bound (regex on text) so GIL isn't a bottleneck.
"""

import atexit
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError, Future
from typing import List, Optional, Dict, Tuple
import logging

from ..types import Span, Tier, CLINICAL_CONTEXT_TYPES
from ..config import Config
from ..constants import DETECTOR_TIMEOUT, MAX_DETECTOR_WORKERS

# Maximum concurrent detection requests (backpressure)
# If exceeded, new requests will block until a slot is available
MAX_CONCURRENT_DETECTIONS = 10

# Maximum queue depth before rejecting requests (prevents unbounded memory growth)
# Set to 0 to disable queue depth limit (block indefinitely)
MAX_QUEUE_DEPTH = 50

# Maximum runaway detections before logging critical warning (Phase 3, Issue 3.4)
# Runaway detections are threads that timed out but couldn't be cancelled
MAX_RUNAWAY_DETECTIONS = 5

from dataclasses import dataclass, field as dataclass_field
from .base import BaseDetector
from .checksum import ChecksumDetector
from .patterns import PatternDetector  # patterns/ module
from .additional_patterns import AdditionalPatternDetector
from .dictionaries import DictionaryDetector
from .structured import extract_structured_phi, post_process_ocr, map_span_to_original

# Domain-specific detectors
from .secrets import SecretsDetector
from .financial import FinancialDetector
from .government import GovernmentDetector

# Pipeline imports
from ..pipeline.merger import filter_tracking_numbers
from ..pipeline.confidence import normalize_spans_confidence

# Context enhancement - optional
ContextEnhancer = None
create_enhancer = None
try:
    from .context_enhancer import ContextEnhancer, create_enhancer
except ImportError:
    pass


logger = logging.getLogger(__name__)


class DetectionQueueFullError(Exception):
    """Raised when detection queue depth exceeds maximum.

    This is a backpressure mechanism to prevent unbounded memory growth
    under high load. Callers should either retry with exponential backoff
    or return a 503 Service Unavailable response.
    """
    def __init__(self, queue_depth: int, max_depth: int):
        self.queue_depth = queue_depth
        self.max_depth = max_depth
        super().__init__(
            f"Detection queue full: {queue_depth} pending requests "
            f"(max: {max_depth}). Try again later."
        )


# Module-level thread pool for reuse
# Created lazily on first use, shared across all DetectorOrchestrator instances
_SHARED_EXECUTOR: Optional[ThreadPoolExecutor] = None

# Backpressure semaphore - limits concurrent detect() calls
# Prevents unbounded queue growth under high load
_DETECTION_SEMAPHORE = threading.BoundedSemaphore(MAX_CONCURRENT_DETECTIONS)

# Track queue depth for monitoring
_QUEUE_DEPTH = 0
_QUEUE_LOCK = threading.Lock()

# Track runaway detections (Phase 3, Issue 3.4)
# Threads that timed out but couldn't be cancelled.
# NOTE: This counter only increases, never decreases. We cannot detect when
# a runaway thread eventually terminates. The counter serves as a warning
# signal - if it grows large, the process should be restarted.
_RUNAWAY_DETECTIONS = 0
_RUNAWAY_LOCK = threading.Lock()


@dataclass
class DetectionMetadata:
    """
    Metadata about the detection process (Phase 3: Error Observability).

    Tracks:
    - Which detectors succeeded
    - Which detectors failed and why
    - Whether results are degraded
    - Warnings generated during detection

    This enables callers to understand if results may be incomplete.
    """
    detectors_run: List[str] = dataclass_field(default_factory=list)
    detectors_failed: List[str] = dataclass_field(default_factory=list)
    detectors_timed_out: List[str] = dataclass_field(default_factory=list)
    warnings: List[str] = dataclass_field(default_factory=list)
    degraded: bool = False
    all_detectors_failed: bool = False
    structured_extractor_failed: bool = False
    runaway_threads: int = 0

    def add_failure(self, detector_name: str, error: str):
        """Record a detector failure."""
        self.detectors_failed.append(detector_name)
        self.warnings.append(f"Detector {detector_name} failed: {error}")

    def add_timeout(self, detector_name: str, timeout_seconds: float, cancelled: bool):
        """Record a detector timeout."""
        self.detectors_timed_out.append(detector_name)
        status = "cancelled" if cancelled else "still running"
        self.warnings.append(
            f"Detector {detector_name} timed out after {timeout_seconds:.1f}s ({status})"
        )

    def add_success(self, detector_name: str):
        """Record a successful detector run."""
        self.detectors_run.append(detector_name)

    def finalize(self):
        """
        Finalize metadata after all detectors have run.

        Sets all_detectors_failed if no detectors succeeded.
        """
        total_attempted = len(self.detectors_run) + len(self.detectors_failed) + len(self.detectors_timed_out)
        if total_attempted > 0 and len(self.detectors_run) == 0:
            self.all_detectors_failed = True
            self.warnings.append(
                f"All {total_attempted} detectors failed - results unreliable"
            )


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


def _track_runaway_detection(detector_name: str) -> int:
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


from contextlib import contextmanager


@contextmanager
def _detection_slot():
    """
    Context manager for detection backpressure.

    Handles queue depth tracking and semaphore acquisition/release.
    Raises DetectionQueueFullError if queue is at capacity.
    """
    global _QUEUE_DEPTH

    # Check queue depth and increment
    with _QUEUE_LOCK:
        if MAX_QUEUE_DEPTH > 0 and _QUEUE_DEPTH >= MAX_QUEUE_DEPTH:
            raise DetectionQueueFullError(_QUEUE_DEPTH, MAX_QUEUE_DEPTH)
        _QUEUE_DEPTH += 1
        current_depth = _QUEUE_DEPTH

    try:
        _DETECTION_SEMAPHORE.acquire()
        try:
            yield current_depth
        finally:
            _DETECTION_SEMAPHORE.release()
    finally:
        with _QUEUE_LOCK:
            _QUEUE_DEPTH = max(0, _QUEUE_DEPTH - 1)


def _get_executor() -> ThreadPoolExecutor:
    """Get or create the shared thread pool."""
    global _SHARED_EXECUTOR
    if _SHARED_EXECUTOR is None:
        _SHARED_EXECUTOR = ThreadPoolExecutor(
            max_workers=MAX_DETECTOR_WORKERS,
            thread_name_prefix="detector_"
        )
        # Ensure cleanup on process exit
        atexit.register(_shutdown_executor)
    return _SHARED_EXECUTOR


def _shutdown_executor():
    """Shutdown the shared executor on process exit."""
    global _SHARED_EXECUTOR
    if _SHARED_EXECUTOR is not None:
        _SHARED_EXECUTOR.shutdown(wait=False)
        _SHARED_EXECUTOR = None


class DetectorOrchestrator:
    """
    Runs all detectors and combines results.

    Pipeline:
    1. Structured extractor (OCR post-processing + label-based extraction)
    2. All other detectors in parallel on processed text
    3. Combine results with structured spans getting higher tier
    4. Context enhancement (optional) - filters obvious false positives

    Detector Categories:
    - Core PII/PHI: ChecksumDetector, PatternDetector, AdditionalPatternDetector, DictionaryDetector
    - Secrets: SecretsDetector (API keys, tokens, credentials)
    - Financial: FinancialDetector (CUSIP, ISIN, crypto)
    - Government: GovernmentDetector (classification, contracts)

    Features:
    - Parallel execution via shared ThreadPoolExecutor
    - Timeout per detector (graceful degradation)
    - Failures don't affect other detectors
    - Selective detector enablement via config
    """

    def __init__(
        self,
        config: Optional[Config] = None,
        parallel: bool = True,
        enable_structured: bool = True,
        enable_secrets: bool = True,
        enable_financial: bool = True,
        enable_government: bool = True,
    ):
        """
        Initialize the detector orchestrator.

        Args:
            config: Configuration object
            parallel: Run detectors in parallel (recommended)
            enable_structured: Enable OCR post-processing and label extraction
            enable_secrets: Enable secrets detection (API keys, tokens)
            enable_financial: Enable financial identifier detection (CUSIP, crypto)
            enable_government: Enable government/classification detection
        """
        self.config = config or Config()
        self.parallel = parallel
        self.enable_structured = enable_structured

        # Get disabled detectors from config
        disabled = self.config.disabled_detectors if self.config else set()

        # Initialize core detectors (unless disabled)
        self._detectors: List[BaseDetector] = []
        
        if "checksum" not in disabled:
            self._detectors.append(ChecksumDetector())
        if "patterns" not in disabled:
            self._detectors.append(PatternDetector())
        if "additional_patterns" not in disabled:
            self._detectors.append(AdditionalPatternDetector())
        
        # Add domain-specific detectors based on configuration
        if enable_secrets and "secrets" not in disabled:
            self._detectors.append(SecretsDetector())
            logger.info("SecretsDetector enabled (API keys, tokens, credentials)")
        
        if enable_financial and "financial" not in disabled:
            self._detectors.append(FinancialDetector())
            logger.info("FinancialDetector enabled (CUSIP, ISIN, crypto)")
        
        if enable_government and "government" not in disabled:
            self._detectors.append(GovernmentDetector())
            logger.info("GovernmentDetector enabled (classification, contracts)")

        # Add dictionary detector if dictionaries exist
        if "dictionaries" not in disabled and self.config.dictionaries_dir.exists():
            self._detectors.append(DictionaryDetector(self.config.dictionaries_dir))
            logger.info(f"DictionaryDetector enabled ({self.config.dictionaries_dir})")
        
        # Cache available detectors (checked once at init, not on every detect call)
        # Detector availability doesn't change after loading
        self._available_detectors: List[BaseDetector] = [
            d for d in self._detectors if d.is_available()
        ]

        # Log detector summary
        detector_names = [d.name for d in self._detectors]
        available_names = [d.name for d in self._available_detectors]
        logger.info(
            f"DetectorOrchestrator initialized with {len(self._detectors)} detectors "
            f"({len(self._available_detectors)} available)"
        )
        logger.info(f"  All detectors: {detector_names}")
        logger.info(f"  Available detectors: {available_names}")
        unavailable = set(detector_names) - set(available_names)
        if unavailable:
            logger.warning(f"  Unavailable detectors: {unavailable}")

        # Context enhancer (optional) - filters obvious false positives
        self._context_enhancer = None
        if create_enhancer is not None:
            try:
                self._context_enhancer = create_enhancer()
                logger.info("Context Enhancer: Enabled")
            except Exception as e:
                logger.debug(f"Context Enhancer not available: {e}")

        # LLM verifier not included - detection only, no LLM calls
        self._llm_verifier = None

    @property
    def active_detector_names(self) -> List[str]:
        """Get names of available detectors."""
        return [d.name for d in self._available_detectors]

    def _detect_known_entities(
        self,
        text: str,
        known_entities: Dict[str, tuple],
    ) -> List[Span]:
        """
        Detect occurrences of known entities in text.

        This provides entity persistence across messages - if "John" was identified
        as a name in message 1, it will be detected with high confidence in message 2
        even without contextual cues.

        Args:
            text: The text to search
            known_entities: Dict from TokenStore: {token: (value, entity_type)}

        Returns:
            List of high-confidence spans for known entity matches
        """
        spans = []
        text_lower = text.lower()

        for token, (value, entity_type) in known_entities.items():
            value_lower = value.lower()

            # Search for full value and individual name parts (partial matching)
            # e.g., if we know "John Smith", also detect standalone "John" or "Smith"
            search_terms = [value_lower]
            if ' ' in value_lower:
                parts = value_lower.split()
                # Only add parts that are 2+ characters (avoid matching "J.")
                search_terms.extend(p for p in parts if len(p) >= 2)

            for search_term in search_terms:
                start = 0
                while True:
                    idx = text_lower.find(search_term, start)
                    if idx == -1:
                        break

                    end = idx + len(search_term)

                    # Check word boundaries to avoid matching "Johnson" when searching "John"
                    valid_start = idx == 0 or not text[idx - 1].isalnum()
                    valid_end = end >= len(text) or not text[end].isalnum()

                    if valid_start and valid_end:
                        # Get original case from text
                        original_text = text[idx:end]

                        # Only match if it looks like a proper noun (capitalized)
                        if original_text and original_text[0].isupper():
                            span = Span(
                                start=idx,
                                end=end,
                                text=original_text,
                                entity_type=entity_type,
                                confidence=0.98,  # Very high - we KNOW this is an entity
                                detector="known_entity",
                                tier=Tier.STRUCTURED,  # High tier to bypass context enhancement
                            )
                            spans.append(span)
                            logger.debug(
                                f"Known entity match: '{original_text}' -> {token}"
                            )

                    start = end

        return spans

    def detect(
        self,
        text: str,
        timeout: float = DETECTOR_TIMEOUT,
        known_entities: Optional[Dict[str, tuple]] = None,
    ) -> List[Span]:
        """
        Run all detectors on text.

        Args:
            text: Normalized input text
            timeout: Max seconds per detector
            known_entities: Optional dict of known entities from TokenStore.
                           Format: {token: (value, entity_type)}
                           These are detected with high confidence (0.98) for
                           entity persistence across messages.

        Returns:
            Combined spans from all detectors (may overlap), in original text coordinates

        Raises:
            DetectionQueueFullError: If queue depth exceeds MAX_QUEUE_DEPTH
        """
        if not text:
            return []

        with _detection_slot() as queue_depth:
            logger.info(f"Detection starting on text ({len(text)} chars), queue depth: {queue_depth}")
            return self._detect_impl(text, timeout, known_entities)

    def detect_with_metadata(
        self,
        text: str,
        timeout: float = DETECTOR_TIMEOUT,
        known_entities: Optional[Dict[str, tuple]] = None,
    ) -> Tuple[List[Span], DetectionMetadata]:
        """
        Run all detectors on text and return metadata about the detection process.

        This method provides visibility into detector failures and degraded state
        (Phase 3: Error Handling & Observability).

        Args:
            text: Normalized input text
            timeout: Max seconds per detector
            known_entities: Optional dict of known entities from TokenStore

        Returns:
            Tuple of (spans, metadata) where metadata contains:
            - detectors_run: List of detectors that succeeded
            - detectors_failed: List of detectors that failed
            - warnings: Warning messages
            - degraded: True if structured extractor failed
            - all_detectors_failed: True if no detectors succeeded

        Raises:
            DetectionQueueFullError: If queue depth exceeds MAX_QUEUE_DEPTH
        """
        if not text:
            return [], DetectionMetadata()

        with _detection_slot() as queue_depth:
            logger.info(f"Detection starting on text ({len(text)} chars), queue depth: {queue_depth}")
            metadata = DetectionMetadata()
            spans = self._detect_impl_with_metadata(text, timeout, known_entities, metadata)
            metadata.finalize()
            return spans, metadata

    def _detect_impl(
        self,
        text: str,
        timeout: float,
        known_entities: Optional[Dict[str, tuple]],
    ) -> List[Span]:
        """Internal detection implementation (called with semaphore held)."""
        # Delegate to the metadata-tracking version but discard metadata
        metadata = DetectionMetadata()
        return self._detect_impl_with_metadata(text, timeout, known_entities, metadata)

    def _detect_impl_with_metadata(
        self,
        text: str,
        timeout: float,
        known_entities: Optional[Dict[str, tuple]],
        metadata: DetectionMetadata,
    ) -> List[Span]:
        """
        Internal detection implementation with metadata tracking (Phase 3).

        This is the core detection logic that tracks all failures and degraded state.
        """
        all_spans: List[Span] = []
        processed_text = text
        char_map: List[int] = []  # For mapping processed positions back to original

        # Step 0: Detect known entities first (entity persistence)
        # This ensures previously-identified entities are detected with high confidence
        if known_entities:
            known_spans = self._detect_known_entities(text, known_entities)
            all_spans.extend(known_spans)
            if known_spans:
                logger.info(f"Known entity detection: {len(known_spans)} matches from entity memory")

        # Step 1: Run structured extractor first (if enabled)
        # This does OCR post-processing and label-based extraction
        if self.enable_structured:
            try:
                # Get the char_map for position mapping
                processed_text, char_map = post_process_ocr(text)

                structured_result = extract_structured_phi(text)
                all_spans.extend(structured_result.spans)

                if structured_result.spans:
                    logger.debug(
                        f"Structured extractor: {structured_result.fields_extracted} fields, "
                        f"{len(structured_result.spans)} spans"
                    )
            except (ValueError, RuntimeError) as e:
                # Track structured extractor failure (Phase 3, Issue 3.2)
                logger.error(f"Structured extractor failed: {e}")
                metadata.structured_extractor_failed = True
                metadata.degraded = True
                metadata.warnings.append(f"Structured extraction failed: {type(e).__name__}: {e}")
                # Continue with original text
                processed_text = text
                char_map = []

        # Step 2: Run all other detectors on (possibly processed) text
        # Use cached available detectors (checked once at init, not every call)
        available = self._available_detectors

        if not available:
            logger.warning("No traditional detectors available, using only structured extraction")
            metadata.warnings.append("No traditional detectors available")
            return all_spans

        if self.parallel and len(available) > 1:
            other_spans = self._detect_parallel(processed_text, available, timeout, metadata)
        else:
            other_spans = self._detect_sequential(processed_text, available, timeout, metadata)
        
        # Step 3: Map pattern/ML spans back to original text coordinates
        if char_map and processed_text != text:
            mapped_spans = []
            for span in other_spans:
                orig_start, orig_end = map_span_to_original(
                    span.start, span.end, span.text, char_map, text
                )
                # Get actual text at original position
                orig_text = text[orig_start:orig_end] if orig_start < len(text) else span.text
                
                mapped_spans.append(Span(
                    start=orig_start,
                    end=orig_end,
                    text=orig_text,
                    entity_type=span.entity_type,
                    confidence=span.confidence,
                    detector=span.detector,
                    tier=span.tier,
                ))
            all_spans.extend(mapped_spans)
        else:
            all_spans.extend(other_spans)

        # Filter clinical context types BEFORE deduplication
        # This prevents clinical types from "winning" overlap resolution and hiding PHI
        # Uses .upper() for case-insensitive matching (handles "medication" vs "MEDICATION")
        pre_clinical_count = len(all_spans)
        all_spans = [s for s in all_spans if s.entity_type.upper() not in CLINICAL_CONTEXT_TYPES]
        clinical_filtered = pre_clinical_count - len(all_spans)
        if clinical_filtered > 0:
            logger.info(f"Clinical context filter: Removed {clinical_filtered} non-PHI entities (LAB_TEST, DIAGNOSIS, etc.)")

        # Deduplicate spans (same position + text = duplicate)
        deduped = self._dedupe_spans(all_spans)

        # Filter ML false positives: carrier names/tracking numbers detected as MRN
        deduped = filter_tracking_numbers(deduped, text)

        # Normalize confidence scores across detectors (Phase 3)
        # This applies detector-specific calibration (floors for checksum, structured, etc.)
        deduped = normalize_spans_confidence(deduped)

        # Context enhancement step (fast, rule-based filtering)
        # Filters obvious FPs and adjusts confidence before LLM
        if self._context_enhancer is not None and deduped:
            pre_enhance_count = len(deduped)
            deduped = self._context_enhancer.enhance(text, deduped)
            enhanced_filtered = pre_enhance_count - len(deduped)
            if enhanced_filtered > 0:
                logger.info(f"Context Enhancer: Filtered {enhanced_filtered} obvious FPs")

        # LLM verification step (optional, filters remaining ambiguous cases)
        # Only processes spans marked needs_review=True by context enhancer
        if self._llm_verifier is not None and deduped:
            # Only send ambiguous spans to LLM (those with needs_review=True)
            needs_llm = [s for s in deduped if getattr(s, 'needs_review', False)]
            already_verified = [s for s in deduped if not getattr(s, 'needs_review', False)]

            if needs_llm:
                pre_verify_count = len(needs_llm)
                verified = self._llm_verifier.verify(text, needs_llm)
                filtered_count = pre_verify_count - len(verified)
                if filtered_count > 0:
                    logger.info(f"LLM Verifier: Filtered {filtered_count} false positives")
                deduped = already_verified + verified
            else:
                logger.debug("LLM Verifier: No spans need verification")

        # Log final results (SECURITY: never log actual PHI text)
        if deduped:
            # Log only metadata, not the actual PHI values
            final_summary = [(s.entity_type, s.detector, f"{s.confidence:.2f}") for s in deduped]
            logger.info(f"Detection complete: {len(deduped)} final spans after dedup: {final_summary}")
        else:
            logger.info("Detection complete: 0 spans detected")

        return deduped

    def detect_with_processed_text(self, text: str, timeout: float = DETECTOR_TIMEOUT) -> Tuple[List[Span], str]:
        """
        Run all detectors and return both spans and processed text.
        
        Useful when caller needs the OCR-corrected text.
        
        Returns:
            Tuple of (spans, processed_text)
        """
        if not text:
            return [], text

        all_spans: List[Span] = []
        processed_text = text
        
        # Step 1: Run structured extractor first
        if self.enable_structured:
            try:
                structured_result = extract_structured_phi(text)
                all_spans.extend(structured_result.spans)
                processed_text = structured_result.processed_text
            except (ValueError, RuntimeError) as e:
                logger.error(f"Structured extractor failed: {e}")

        # Step 2: Run all other detectors (use cached availability for performance)
        available = self._available_detectors

        if available:
            if self.parallel and len(available) > 1:
                other_spans = self._detect_parallel(processed_text, available, timeout)
            else:
                other_spans = self._detect_sequential(processed_text, available)
            all_spans.extend(other_spans)

        deduped = self._dedupe_spans(all_spans)
        # Normalize confidence scores (Phase 3)
        normalized = normalize_spans_confidence(deduped)
        return normalized, processed_text

    def _dedupe_spans(self, spans: List[Span]) -> List[Span]:
        """
        Remove duplicate spans at the same position.

        Strategy:
        1. First, group by (start, end, entity_type) and keep best per type
        2. Then, group by (start, end) and keep highest tier/confidence overall

        This ensures only ONE span per position in the output.
        """
        if not spans:
            return spans

        # Step 1: Group by (start, end, entity_type) - keep best per type
        type_seen: Dict[Tuple[int, int, str], Span] = {}

        for span in spans:
            key = (span.start, span.end, span.entity_type)

            if key not in type_seen:
                type_seen[key] = span
            else:
                existing = type_seen[key]
                # Prefer higher tier, then higher confidence
                if (span.tier.value > existing.tier.value or
                    (span.tier.value == existing.tier.value and
                     span.confidence > existing.confidence)):
                    type_seen[key] = span

        # Step 2: Group by (start, end) only - keep highest tier/confidence overall
        # This resolves conflicting entity types at the same position
        position_seen: Dict[Tuple[int, int], Span] = {}

        for span in type_seen.values():
            key = (span.start, span.end)

            if key not in position_seen:
                position_seen[key] = span
            else:
                existing = position_seen[key]
                # Prefer higher tier, then higher confidence
                if (span.tier.value > existing.tier.value or
                    (span.tier.value == existing.tier.value and
                     span.confidence > existing.confidence)):
                    position_seen[key] = span

        return list(position_seen.values())

    def _detect_sequential(
        self,
        text: str,
        detectors: List[BaseDetector],
        timeout: float,
        metadata: Optional[DetectionMetadata] = None,
    ) -> List[Span]:
        """
        Run detectors sequentially with per-detector timeout.

        Args:
            text: Text to analyze
            detectors: List of detectors to run
            timeout: Total timeout budget
            metadata: Optional metadata object to track failures (Phase 3)
        """
        all_spans = []
        executor = _get_executor()

        # Per-detector timeout (divide total timeout among detectors)
        per_detector_timeout = timeout / max(len(detectors), 1)

        for detector in detectors:
            try:
                # Use executor for timeout protection even in sequential mode
                future = executor.submit(detector.detect, text)
                spans = future.result(timeout=per_detector_timeout)
                all_spans.extend(spans)

                # Track success (Phase 3, Issue 3.3)
                if metadata:
                    metadata.add_success(detector.name)

                if spans:
                    # SECURITY: Log only metadata, not actual PHI values
                    span_summary = [(s.entity_type, f"{s.confidence:.2f}") for s in spans]
                    logger.info(f"  {detector.name}: {len(spans)} spans: {span_summary}")
                else:
                    logger.info(f"  {detector.name}: 0 spans")

            except TimeoutError:
                # Track timeout (Phase 3, Issue 3.3 & 3.4)
                cancelled = future.cancel()
                if metadata:
                    metadata.add_timeout(detector.name, per_detector_timeout, cancelled)
                    if not cancelled:
                        metadata.runaway_threads = _track_runaway_detection(detector.name)
                logger.warning(
                    f"Detector {detector.name} timed out after {per_detector_timeout:.1f}s "
                    f"(sequential mode, cancelled={cancelled})"
                )

            except Exception as e:
                # Track failure (Phase 3, Issue 3.3)
                if metadata:
                    metadata.add_failure(detector.name, str(e))
                logger.error(f"Detector {detector.name} failed: {e}")

        return all_spans

    def _detect_parallel(
        self,
        text: str,
        detectors: List[BaseDetector],
        timeout: float,
        metadata: Optional[DetectionMetadata] = None,
    ) -> List[Span]:
        """
        Run detectors in parallel with timeout.

        Args:
            text: Text to analyze
            detectors: List of detectors to run
            timeout: Timeout per detector
            metadata: Optional metadata object to track failures (Phase 3)
        """
        all_spans = []
        executor = _get_executor()

        logger.info(f"Running {len(detectors)} detectors in parallel...")

        # Submit all tasks
        futures: Dict[Future, BaseDetector] = {
            executor.submit(d.detect, text): d
            for d in detectors
        }

        # Collect results with timeout
        for future in futures:
            detector = futures[future]
            try:
                spans = future.result(timeout=timeout)
                all_spans.extend(spans)

                # Track success (Phase 3, Issue 3.3)
                if metadata:
                    metadata.add_success(detector.name)

                if spans:
                    # SECURITY: Log only metadata, not actual PHI values
                    span_summary = [(s.entity_type, f"{s.confidence:.2f}") for s in spans]
                    logger.info(f"  {detector.name}: {len(spans)} spans: {span_summary}")
                else:
                    logger.info(f"  {detector.name}: 0 spans")

            except TimeoutError:
                # Cancel the future (best effort - thread may still run)
                # Python threads can't be forcibly killed, but we can:
                # 1. Cancel if not yet started
                # 2. Log the timeout for monitoring
                # 3. Track runaway if couldn't cancel (Phase 3, Issue 3.4)
                cancelled = future.cancel()

                # Track timeout (Phase 3, Issue 3.3 & 3.4)
                if metadata:
                    metadata.add_timeout(detector.name, timeout, cancelled)
                    if not cancelled:
                        metadata.runaway_threads = _track_runaway_detection(detector.name)

                logger.warning(
                    f"Detector {detector.name} timed out after {timeout}s "
                    f"(cancelled={cancelled})"
                )

            except Exception as e:
                # Track failure (Phase 3, Issue 3.3)
                if metadata:
                    metadata.add_failure(detector.name, str(e))
                logger.error(f"Detector {detector.name} failed: {e}")

        return all_spans

    def get_detector_info(self) -> List[Dict]:
        """Get information about loaded detectors."""
        return [
            {
                "name": d.name,
                "tier": d.tier.name,
                "available": d.is_available(),
            }
            for d in self._detectors
        ]


def detect_all(
    text: str,
    config: Optional[Config] = None,
    enable_secrets: bool = True,
    enable_financial: bool = True,
    enable_government: bool = True,
) -> List[Span]:
    """
    Convenience function to detect all PHI/PII.

    Creates orchestrator, runs detection, returns spans.

    Args:
        text: Text to analyze
        config: Optional configuration
        enable_secrets: Enable API key/token detection
        enable_financial: Enable financial identifier detection
        enable_government: Enable classification/government detection

    Returns:
        List of detected spans
    """
    orchestrator = DetectorOrchestrator(
        config=config,
        enable_secrets=enable_secrets,
        enable_financial=enable_financial,
        enable_government=enable_government,
    )
    return orchestrator.detect(text)
