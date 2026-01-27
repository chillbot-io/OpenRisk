"""Base detector interface."""

import re
from abc import ABC, abstractmethod
from typing import Callable, Iterator, List, Optional, Tuple, Union

from ..types import Span, Tier


class BaseDetector(ABC):
    """
    Base class for all detectors.

    Each detector:
    - Has a name and tier
    - Takes normalized text
    - Returns list of Span
    - Is independent (no shared state)
    """

    name: str = "base"
    tier: Tier = Tier.ML

    @abstractmethod
    def detect(self, text: str) -> List[Span]:
        """
        Detect PHI/PII in text.

        Args:
            text: Normalized UTF-8 text

        Returns:
            List of detected spans
        """
        pass

    def is_available(self) -> bool:
        """Check if detector is ready to use."""
        return True


# Type aliases for pattern tuples
# Standard: (pattern, entity_type, confidence, group_index)
PatternTuple = Tuple[re.Pattern, str, float, int]
# With validator: (pattern, entity_type, confidence, group_index, validator)
PatternWithValidator = Tuple[re.Pattern, str, float, int, Optional[Callable[[str], bool]]]


class BasePatternDetector(BaseDetector):
    """
    Base class for pattern-based detectors.

    Provides common detect() logic for regex pattern matching.
    Subclasses define patterns and can override hooks for validation.
    """

    # Subclasses should override these
    patterns: List[Union[PatternTuple, PatternWithValidator]] = []
    tier: Tier = Tier.PATTERN

    def get_patterns(self) -> List[Union[PatternTuple, PatternWithValidator]]:
        """
        Get patterns for this detector.

        Override this method if patterns need dynamic loading.
        Default implementation returns the class-level patterns list.
        """
        return self.patterns

    def _validate_match(self, entity_type: str, value: str) -> bool:
        """
        Validate a matched value.

        Override in subclasses for entity-specific validation.
        Return False to reject the match.

        Args:
            entity_type: The entity type (e.g., 'JWT', 'AGE')
            value: The matched text value

        Returns:
            True if valid, False to reject
        """
        return True

    def _is_false_positive(self, entity_type: str, value: str,
                            text: str, start: int) -> bool:
        """
        Check if a match is a false positive.

        Override in subclasses for context-aware false positive filtering.

        Args:
            entity_type: The entity type
            value: The matched text value
            text: The full text being scanned
            start: Start position of the match

        Returns:
            True if this is a false positive and should be skipped
        """
        return False

    def _adjust_confidence(self, entity_type: str, confidence: float,
                           value: str, has_validator: bool) -> float:
        """
        Adjust confidence score based on context.

        Override in subclasses for confidence adjustments.

        Args:
            entity_type: The entity type
            confidence: The base confidence from the pattern
            value: The matched text value
            has_validator: Whether a validator function passed

        Returns:
            Adjusted confidence score
        """
        return confidence

    def detect(self, text: str) -> List[Span]:
        """
        Detect entities using regex patterns.

        Common implementation for all pattern-based detectors.
        """
        spans = []
        seen = set()

        for pattern_tuple in self.get_patterns():
            # Unpack pattern tuple (supports both 4 and 5 element tuples)
            if len(pattern_tuple) == 5:
                pattern, entity_type, confidence, group_idx, validator = pattern_tuple
            else:
                pattern, entity_type, confidence, group_idx = pattern_tuple
                validator = None

            for match in pattern.finditer(text):
                # Extract value and position from capture group or whole match
                if group_idx > 0 and match.lastindex and group_idx <= match.lastindex:
                    value = match.group(group_idx)
                    if value is None:
                        continue
                    start = match.start(group_idx)
                    end = match.end(group_idx)
                else:
                    value = match.group(0)
                    start = match.start()
                    end = match.end()

                # Skip empty values
                if not value or not value.strip():
                    continue

                # Deduplicate by position
                key = (start, end)
                if key in seen:
                    continue

                # Run pattern-level validator if present
                if validator is not None:
                    if not validator(value):
                        continue

                # Run subclass validation hook
                if not self._validate_match(entity_type, value):
                    continue

                # Check for false positives
                if self._is_false_positive(entity_type, value, text, start):
                    continue

                seen.add(key)

                # Allow subclass to adjust confidence
                final_confidence = self._adjust_confidence(
                    entity_type, confidence, value, validator is not None
                )

                span = Span(
                    start=start,
                    end=end,
                    text=value,
                    entity_type=entity_type,
                    confidence=final_confidence,
                    detector=self.name,
                    tier=self.tier,
                )
                spans.append(span)

        return spans
