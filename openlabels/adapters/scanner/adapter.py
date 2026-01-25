"""
OpenLabels Scanner - the core detection engine.

This is the main entry point for detecting PII/PHI in text and files.
Part of OpenLabels - where labels are the primitive, risk is derived.
"""

import time
from pathlib import Path
from typing import List, Optional, Union

from .types import DetectionResult
from .config import Config


class Detector:
    """
    Content scanner for PII/PHI detection.

    Orchestrates multiple detection engines (patterns, checksums, structured
    extraction) to find sensitive data in text or files.

    Example:
        >>> from openlabels.adapters.scanner import Detector
        >>> detector = Detector()
        >>> result = detector.detect("Patient John Smith, SSN 123-45-6789")
        >>> for span in result.spans:
        ...     print(f"{span.entity_type}: {span.text}")
        NAME: John Smith
        SSN: 123-45-6789
    """

    def __init__(self, config: Optional[Config] = None):
        """
        Initialize the detector.

        Args:
            config: Optional configuration. If not provided, uses defaults
                   or loads from environment variables.
        """
        self.config = config or Config.from_env()
        self._orchestrator = None

    @property
    def orchestrator(self):
        """Lazy-load the detector orchestrator."""
        if self._orchestrator is None:
            from .detectors.orchestrator import DetectorOrchestrator
            self._orchestrator = DetectorOrchestrator(
                config=self.config,
            )
        return self._orchestrator

    def detect(self, text: str) -> DetectionResult:
        """
        Detect PII/PHI entities in text.

        Args:
            text: The text to scan for sensitive data.

        Returns:
            DetectionResult containing all detected spans with metadata.
        """
        from .pipeline.normalizer import normalize_text
        from .pipeline.merger import merge_spans
        from .pipeline.allowlist import apply_allowlist

        start_time = time.perf_counter()

        if not text or not text.strip():
            return DetectionResult(
                text=text or "",
                spans=[],
                processing_time_ms=0.0,
                detectors_used=[],
            )

        # Step 1: Normalize text (handle encoding, whitespace, etc.)
        normalized_text = normalize_text(text)

        # Step 2: Run all detectors in parallel
        raw_spans = self.orchestrator.detect(normalized_text)

        # Step 3: Merge overlapping spans (keep highest confidence/tier)
        merged_spans = merge_spans(raw_spans, text=normalized_text)

        # Step 4: Apply allowlist to filter false positives
        filtered_spans = apply_allowlist(normalized_text, merged_spans)

        # Step 5: Filter by confidence threshold
        final_spans = [
            span for span in filtered_spans
            if span.confidence >= self.config.min_confidence
        ]

        # Sort by position
        final_spans.sort(key=lambda s: (s.start, -s.end))

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        return DetectionResult(
            text=normalized_text,
            spans=final_spans,
            processing_time_ms=elapsed_ms,
            detectors_used=self.orchestrator.active_detector_names,
        )

    def detect_file(
        self,
        path: Union[str, Path],
        extract_text_only: bool = False,
    ) -> DetectionResult:
        """
        Detect PII/PHI entities in a file.

        Supports 30+ file formats including:
        - Text: txt, md, csv, tsv, json, jsonl, xml, yaml, log, html, rtf, sql
        - Office: pdf, docx, xlsx, pptx
        - Images (OCR): jpg, png, gif, bmp, tiff, webp
        - Email: eml, msg
        - Config: env, ini, conf
        - Archives: zip, tar, gz

        Args:
            path: Path to the file to scan.
            extract_text_only: If True, only extract text without detection.

        Returns:
            DetectionResult containing detected spans and extracted text.
        """
        from .extractor import extract_text

        start_time = time.perf_counter()
        path = Path(path)

        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        # Extract text from file
        text = extract_text(path, ocr_enabled=self.config.enable_ocr)

        if extract_text_only:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            return DetectionResult(
                text=text,
                spans=[],
                processing_time_ms=elapsed_ms,
                detectors_used=[],
            )

        # Run detection on extracted text
        result = self.detect(text)

        # Update timing to include extraction
        result.processing_time_ms = (time.perf_counter() - start_time) * 1000

        return result

    def detect_batch(
        self,
        texts: List[str],
        parallel: bool = True,
    ) -> List[DetectionResult]:
        """
        Detect PII/PHI in multiple texts.

        Args:
            texts: List of texts to scan.
            parallel: If True, process texts in parallel.

        Returns:
            List of DetectionResult, one per input text.
        """
        if not parallel or len(texts) <= 1:
            return [self.detect(text) for text in texts]

        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            results = list(executor.map(self.detect, texts))

        return results


def _make_config(**kwargs) -> Config:
    """Create Config with optional overrides."""
    config = Config()
    for key, value in kwargs.items():
        if hasattr(config, key):
            setattr(config, key, value)
    return config


def detect(text: str, **config_kwargs) -> DetectionResult:
    """
    Quick detection without explicitly creating a Detector.

    Args:
        text: Text to scan for PII/PHI.
        **config_kwargs: Optional config overrides (min_confidence, etc.)

    Returns:
        DetectionResult with detected spans.

    Example:
        >>> from openlabels.adapters.scanner import detect
        >>> result = detect("Call me at 555-123-4567")
        >>> print(result.entity_counts)
        {'PHONE': 1}
    """
    return Detector(config=_make_config(**config_kwargs)).detect(text)


def detect_file(path: Union[str, Path], **config_kwargs) -> DetectionResult:
    """
    Quick file detection without explicitly creating a Detector.

    Args:
        path: Path to file to scan.
        **config_kwargs: Optional config overrides.

    Returns:
        DetectionResult with detected spans.
    """
    return Detector(config=_make_config(**config_kwargs)).detect_file(path)
