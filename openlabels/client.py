"""
OpenLabels Client.

High-level API for scoring files and objects.
"""

from typing import Dict, List, Optional, Union
from pathlib import Path

from .adapters.base import Adapter, NormalizedInput, Entity
from .core.scorer import ScoringResult, score as score_entities


class Client:
    """
    High-level OpenLabels client.

    Example usage:
        >>> from openlabels import Client
        >>>
        >>> client = Client()
        >>> result = client.score_file("sensitive_data.pdf")
        >>> print(f"Risk score: {result.score} ({result.tier.value})")

    For cloud adapters:
        >>> from openlabels.adapters import MacieAdapter
        >>>
        >>> adapter = MacieAdapter()
        >>> normalized = adapter.extract(macie_findings, s3_metadata)
        >>> result = client.score_from_adapters([normalized])
    """

    def __init__(self, default_exposure: str = "PRIVATE"):
        """
        Initialize the client.

        Args:
            default_exposure: Default exposure level when not specified.
                             One of: PRIVATE, INTERNAL, OVER_EXPOSED, PUBLIC
        """
        self.default_exposure = default_exposure.upper()

    def score_file(
        self,
        path: Union[str, Path],
        adapters: Optional[List[Adapter]] = None,
        exposure: Optional[str] = None,
    ) -> ScoringResult:
        """
        Score a local file for data risk.

        If no adapters specified, uses the built-in scanner for detection.

        Args:
            path: Path to file to scan
            adapters: Optional list of adapters to use. If None, uses scanner.
            exposure: Exposure level override (PRIVATE, INTERNAL, OVER_EXPOSED, PUBLIC).
                     If None, uses the client's default_exposure.

        Returns:
            ScoringResult with score, tier, and breakdown

        Example:
            >>> client = Client()
            >>> result = client.score_file("patient_records.csv")
            >>> print(f"Risk: {result.score} ({result.tier.value})")
            Risk: 72 (HIGH)
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        exposure = (exposure or self.default_exposure).upper()

        if adapters:
            # Use provided adapters
            inputs = []
            for adapter in adapters:
                normalized = adapter.extract(path, {"path": str(path)})
                inputs.append(normalized)
            return self.score_from_adapters(inputs, exposure=exposure)

        # Default: use built-in scanner
        from .adapters.scanner import detect_file

        detection_result = detect_file(path)

        # Convert entity counts to scorer format (lowercase keys)
        entities = self._normalize_entity_counts(detection_result.entity_counts)

        # Calculate average confidence from spans
        confidence = self._calculate_average_confidence(detection_result.spans)

        return score_entities(entities, exposure=exposure, confidence=confidence)

    def score_text(
        self,
        text: str,
        exposure: Optional[str] = None,
    ) -> ScoringResult:
        """
        Score text content for data risk.

        Args:
            text: Text to scan for sensitive data
            exposure: Exposure level (PRIVATE, INTERNAL, OVER_EXPOSED, PUBLIC)

        Returns:
            ScoringResult with score, tier, and breakdown

        Example:
            >>> client = Client()
            >>> result = client.score_text("SSN: 123-45-6789")
            >>> print(f"Risk: {result.score} ({result.tier.value})")
        """
        from .adapters.scanner import detect

        exposure = (exposure or self.default_exposure).upper()

        detection_result = detect(text)
        entities = self._normalize_entity_counts(detection_result.entity_counts)
        confidence = self._calculate_average_confidence(detection_result.spans)

        return score_entities(entities, exposure=exposure, confidence=confidence)

    def score_from_adapters(
        self,
        inputs: List[NormalizedInput],
        exposure: Optional[str] = None,
    ) -> ScoringResult:
        """
        Score from pre-extracted adapter outputs.

        Use this when you've already run adapters and have normalized inputs.
        Merges entities from multiple inputs using conservative union
        (takes max confidence per entity type).

        Args:
            inputs: List of NormalizedInput from adapters
            exposure: Exposure level override. If None, uses the highest
                     exposure level from the inputs.

        Returns:
            ScoringResult with score, tier, and breakdown

        Example:
            >>> from openlabels.adapters import MacieAdapter, DLPAdapter
            >>>
            >>> macie_input = MacieAdapter().extract(macie_findings, s3_meta)
            >>> dlp_input = DLPAdapter().extract(dlp_findings, gcs_meta)
            >>> result = client.score_from_adapters([macie_input, dlp_input])
        """
        if not inputs:
            # No inputs = no risk
            return score_entities({}, exposure=self.default_exposure)

        # Merge entities using conservative union (max confidence per type)
        merged_entities, avg_confidence = self._merge_inputs(inputs)

        # Determine exposure level
        if exposure:
            final_exposure = exposure.upper()
        else:
            # Use highest exposure from inputs
            final_exposure = self._get_highest_exposure(inputs)

        return score_entities(
            merged_entities,
            exposure=final_exposure,
            confidence=avg_confidence,
        )

    def _normalize_entity_counts(
        self,
        entity_counts: Dict[str, int],
    ) -> Dict[str, int]:
        """
        Normalize entity type names to lowercase for scorer compatibility.

        The scanner uses uppercase types (SSN, CREDIT_CARD) while the
        scorer uses lowercase (ssn, credit_card).
        """
        return {
            entity_type.lower(): count
            for entity_type, count in entity_counts.items()
        }

    def _calculate_average_confidence(self, spans) -> float:
        """Calculate average confidence from detection spans."""
        if not spans:
            return 0.90  # Default confidence

        total_confidence = sum(span.confidence for span in spans)
        return total_confidence / len(spans)

    def _merge_inputs(
        self,
        inputs: List[NormalizedInput],
    ) -> tuple[Dict[str, int], float]:
        """
        Merge entities from multiple adapter inputs.

        Uses conservative union: for each entity type, takes the maximum
        count and confidence across all inputs.

        Returns:
            Tuple of (merged_entities dict, average_confidence)
        """
        merged: Dict[str, Dict] = {}  # {type: {count, confidence, weight}}

        for inp in inputs:
            for entity in inp.entities:
                entity_type = entity.type.lower()

                if entity_type not in merged:
                    merged[entity_type] = {
                        "count": entity.count,
                        "confidence": entity.confidence,
                    }
                else:
                    # Conservative union: take max count and confidence
                    merged[entity_type]["count"] = max(
                        merged[entity_type]["count"],
                        entity.count,
                    )
                    merged[entity_type]["confidence"] = max(
                        merged[entity_type]["confidence"],
                        entity.confidence,
                    )

        # Build final entities dict and calculate average confidence
        entities = {etype: data["count"] for etype, data in merged.items()}

        if merged:
            avg_confidence = sum(
                data["confidence"] for data in merged.values()
            ) / len(merged)
        else:
            avg_confidence = 0.90

        return entities, avg_confidence

    def _get_highest_exposure(self, inputs: List[NormalizedInput]) -> str:
        """Get the highest exposure level from inputs."""
        exposure_order = ["PRIVATE", "INTERNAL", "OVER_EXPOSED", "PUBLIC"]

        highest_idx = 0
        for inp in inputs:
            exposure = inp.context.exposure.upper()
            if exposure in exposure_order:
                idx = exposure_order.index(exposure)
                highest_idx = max(highest_idx, idx)

        return exposure_order[highest_idx]
