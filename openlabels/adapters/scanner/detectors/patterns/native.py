"""Native Rust-accelerated pattern detector.

Provides 6-8x speedup over pure Python pattern matching by using
Rust's regex crate. Releases the GIL during scanning, enabling
true parallelism with Python threads.

Falls back to pure Python if the Rust extension is not available.
"""

import logging
from typing import List

from ...types import Span, Tier
from .definitions import PATTERNS
from .false_positives import is_false_positive_name
from .validators import (
    validate_ip,
    validate_phone,
    validate_ssn_context,
)

logger = logging.getLogger(__name__)

# Try to import the Rust extension
try:
    from openlabels._rust import PatternMatcher, RawMatch, validate_luhn, is_native_available

    _NATIVE_AVAILABLE = is_native_available()
except ImportError as e:
    logger.debug(f"Rust extension not available: {e}")
    _NATIVE_AVAILABLE = False
    PatternMatcher = None
    RawMatch = None
    validate_luhn = None


class NativePatternDetector:
    """
    Pattern detector using Rust extension for 6-8x speedup.

    The Rust extension handles:
    - Pattern compilation (once, cached globally)
    - Pattern matching (releases GIL, enables true parallelism)
    - Basic validation (Luhn checksum)

    Python handles:
    - Complex validation (SSN context, name false positives)
    - Span creation and metadata
    """

    name = "pattern"
    tier = Tier.PATTERN

    _matcher: "PatternMatcher" = None
    _failed_patterns: List[tuple] = None

    def __init__(self):
        """Initialize the native pattern detector."""
        if not _NATIVE_AVAILABLE:
            raise ImportError("Rust extension not available")

        if NativePatternDetector._matcher is None:
            self._initialize_matcher()

    @classmethod
    def _initialize_matcher(cls):
        """Initialize the Rust pattern matcher."""
        # Convert PATTERNS to format Rust expects: (regex_str, entity_type, confidence, group_idx)
        patterns_for_rust = []
        cls._failed_patterns = []

        for i, (pattern, entity_type, confidence, group_idx) in enumerate(PATTERNS):
            patterns_for_rust.append((pattern.pattern, entity_type, confidence, group_idx))

        # Create the matcher (compiles patterns in Rust)
        cls._matcher = PatternMatcher(patterns_for_rust)

        logger.info(
            f"Native pattern matcher initialized: "
            f"{cls._matcher.pattern_count} patterns compiled, "
            f"{cls._matcher.failed_count} use Python fallback"
        )

        # Track which patterns failed for Python fallback
        if cls._matcher.failed_count > 0:
            for i, (pattern, entity_type, confidence, group_idx) in enumerate(PATTERNS):
                if not cls._matcher.has_pattern(i):
                    cls._failed_patterns.append((pattern, entity_type, confidence, group_idx))

    def detect(self, text: str) -> List[Span]:
        """Detect entities using Rust-accelerated matching."""
        spans = []

        # Fast path: Rust does pattern matching (releases GIL)
        raw_matches: List[RawMatch] = self._matcher.find_matches(text)

        # Process Rust matches with Python validation
        for match in raw_matches:
            if not self._validate(text, match):
                continue

            spans.append(
                Span(
                    start=match.start,
                    end=match.end,
                    text=match.text,
                    entity_type=match.entity_type,
                    confidence=match.confidence,
                    detector=self.name,
                    tier=self.tier,
                )
            )

        # Run fallback patterns (those that failed Rust compilation)
        if self._failed_patterns:
            spans.extend(self._run_fallback_patterns(text))

        return spans

    def _validate(self, text: str, match: RawMatch) -> bool:
        """Run validation that requires Python logic."""
        et = match.entity_type
        value = match.text
        start = match.start

        if et == "IP_ADDRESS":
            return validate_ip(value)

        if et in ("PHONE", "PHONE_MOBILE", "PHONE_HOME", "PHONE_WORK", "FAX"):
            return validate_phone(value)

        if et == "SSN":
            # Rust already validated format, Python checks context
            return validate_ssn_context(text, start, match.confidence)

        if et == "CREDIT_CARD":
            # Use Rust Luhn (faster than Python)
            return validate_luhn(value)

        if et in ("NAME", "NAME_PROVIDER", "NAME_PATIENT", "NAME_RELATIVE"):
            return not is_false_positive_name(value)

        return True

    def _run_fallback_patterns(self, text: str) -> List[Span]:
        """Run patterns that failed Rust compilation via Python regex."""
        spans = []

        for pattern, entity_type, confidence, group_idx in self._failed_patterns:
            for match in pattern.finditer(text):
                if group_idx > 0 and match.lastindex and group_idx <= match.lastindex:
                    value = match.group(group_idx)
                    start = match.start(group_idx)
                    end = match.end(group_idx)
                else:
                    value = match.group(0)
                    start = match.start()
                    end = match.end()

                if not value or not value.strip():
                    continue

                spans.append(
                    Span(
                        start=start,
                        end=end,
                        text=value,
                        entity_type=entity_type,
                        confidence=confidence,
                        detector=self.name,
                        tier=self.tier,
                    )
                )

        return spans


def is_native_detector_available() -> bool:
    """Check if the native detector can be used."""
    return _NATIVE_AVAILABLE
