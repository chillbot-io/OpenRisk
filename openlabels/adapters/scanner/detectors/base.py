"""Base detector interface and pattern-based detector mixin.

This module provides:
- BaseDetector: Abstract base class for all detectors
- PatternBasedDetector: Base class for detectors that use regex patterns

Pattern-based detectors (secrets, government, additional_patterns) share
common logic for pattern compilation, matching, and deduplication. The
PatternBasedDetector class extracts this duplicate code.
"""

import logging
import re
from abc import ABC, abstractmethod
from typing import List, Tuple, Optional, Set, Callable

from ..types import Span, Tier

logger = logging.getLogger(__name__)


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


# Type alias for compiled pattern tuple
# (compiled_pattern, entity_type, confidence, capture_group)
CompiledPattern = Tuple[re.Pattern, str, float, int]


class PatternBasedDetector(BaseDetector):
    """
    Base class for detectors that use regex patterns.

    Provides common functionality for:
    - Pattern storage and compilation
    - Pattern matching with capture group support
    - Deduplication of overlapping matches
    - Validation hooks for specific entity types

    Subclasses should:
    1. Define a module-level pattern list
    2. Call _add() to add patterns in module scope
    3. Pass the pattern list to __init__()

    Example:
        # In secrets.py:
        SECRETS_PATTERNS = []

        def _add(pattern, entity_type, confidence, group=0, flags=0):
            SECRETS_PATTERNS.append((re.compile(pattern, flags), entity_type, confidence, group))

        _add(r'\\b(ghp_[a-zA-Z0-9]{36})\\b', 'GITHUB_TOKEN', 0.99, 1)

        class SecretsDetector(PatternBasedDetector):
            name = "secrets"
            tier = Tier.PATTERN

            def __init__(self):
                super().__init__(SECRETS_PATTERNS)
    """

    name: str = "pattern_based"
    tier: Tier = Tier.PATTERN

    def __init__(
        self,
        patterns: Optional[List[CompiledPattern]] = None,
        validators: Optional[dict] = None,
    ):
        """
        Initialize the pattern-based detector.

        Args:
            patterns: List of (compiled_pattern, entity_type, confidence, group) tuples
            validators: Optional dict mapping entity_type to validator function.
                       Validator signature: (value: str, text: str, start: int) -> bool
                       Return True to keep the match, False to filter it.
        """
        self._patterns: List[CompiledPattern] = patterns or []
        self._validators: dict = validators or {}

    def is_available(self) -> bool:
        """Check if detector has any patterns."""
        return len(self._patterns) > 0

    def add_validator(
        self,
        entity_type: str,
        validator: Callable[[str, str, int], bool],
    ) -> None:
        """
        Add a validator for a specific entity type.

        Args:
            entity_type: The entity type to validate
            validator: Function that takes (value, text, start) and returns bool
        """
        self._validators[entity_type] = validator

    def detect(self, text: str) -> List[Span]:
        """
        Detect entities using pattern matching.

        Args:
            text: Normalized input text

        Returns:
            List of detected spans, deduplicated by position
        """
        spans = []
        seen: Set[Tuple[int, int]] = set()

        for pattern, entity_type, confidence, group_idx in self._patterns:
            for match in pattern.finditer(text):
                try:
                    # Extract value and position based on capture group
                    if group_idx > 0 and match.lastindex and group_idx <= match.lastindex:
                        value = match.group(group_idx)
                        start = match.start(group_idx)
                        end = match.end(group_idx)
                    else:
                        value = match.group(0)
                        start = match.start()
                        end = match.end()

                    # Skip empty or whitespace-only matches
                    if not value or not value.strip():
                        continue

                    # Deduplicate by position
                    key = (start, end)
                    if key in seen:
                        continue
                    seen.add(key)

                    # Run entity-specific validator if present
                    if entity_type in self._validators:
                        if not self._validators[entity_type](value, text, start):
                            continue

                    # Create span
                    span = Span(
                        start=start,
                        end=end,
                        text=value,
                        entity_type=entity_type,
                        confidence=confidence,
                        detector=self.name,
                        tier=self.tier,
                    )
                    spans.append(span)

                except (IndexError, AttributeError, ValueError) as e:
                    # Skip problematic matches
                    logger.debug(f"Pattern match error for {entity_type}: {e}")
                    continue

        return spans


def create_pattern_list() -> List[CompiledPattern]:
    """
    Create an empty pattern list for a detector module.

    Returns:
        Empty list to store compiled patterns
    """
    return []


def create_pattern_adder(
    pattern_list: List[CompiledPattern],
) -> Callable[[str, str, float, int, int], None]:
    """
    Create an _add() helper function for a pattern list.

    This factory function creates a module-level _add() helper that
    compiles patterns and adds them to the pattern list.

    Args:
        pattern_list: The list to add patterns to

    Returns:
        An _add(pattern, entity_type, confidence, group=0, flags=0) function

    Example:
        SECRETS_PATTERNS = create_pattern_list()
        _add = create_pattern_adder(SECRETS_PATTERNS)

        _add(r'\\b(ghp_[a-zA-Z0-9]{36})\\b', 'GITHUB_TOKEN', 0.99, 1)
    """
    def _add(
        pattern: str,
        entity_type: str,
        confidence: float,
        group: int = 0,
        flags: int = 0,
    ) -> None:
        """Add a pattern to the list."""
        try:
            compiled = re.compile(pattern, flags)
            pattern_list.append((compiled, entity_type, confidence, group))
        except re.error as e:
            logger.warning(f"Invalid regex pattern for {entity_type}: {e}")

    return _add
