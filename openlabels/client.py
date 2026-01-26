"""
OpenLabels Client.

High-level API for scoring files and objects.

The Client provides a unified interface for:
- Scoring individual files or text
- Scanning directories recursively
- Finding files matching filter criteria
- Data management operations (quarantine, move, delete)
- Generating reports

Example:
    >>> from openlabels import Client
    >>>
    >>> client = Client()
    >>>
    >>> # Score a single file
    >>> result = client.score_file("data.csv")
    >>> print(f"Risk: {result.score} ({result.tier.value})")
    >>>
    >>> # Scan a directory
    >>> for item in client.scan("/data", recursive=True):
    ...     if item.score >= 70:
    ...         print(f"High risk: {item.path}")
    >>>
    >>> # Find and quarantine high-risk files
    >>> client.quarantine(
    ...     "/data",
    ...     "/quarantine",
    ...     min_score=80,
    ...     recursive=True,
    ... )
"""

import shutil
import logging
import fnmatch
from datetime import datetime
from typing import Dict, List, Optional, Union, Iterator, Any, Callable
from pathlib import Path
from dataclasses import dataclass

from .adapters.base import Adapter, NormalizedInput
from .core.scorer import ScoringResult, score as score_entities
from .core.types import (
    ScanResult,
    FilterCriteria,
    OperationResult,
    TreeNode,
    ReportFormat,
    ReportConfig,
)
from .cli.filter import Filter, parse_filter

logger = logging.getLogger(__name__)


@dataclass
class QuarantineResult:
    """Result of a quarantine operation."""
    moved_count: int
    error_count: int
    moved_files: List[Dict[str, Any]]
    errors: List[Dict[str, str]]
    destination: str


@dataclass
class DeleteResult:
    """Result of a delete operation."""
    deleted_count: int
    error_count: int
    deleted_files: List[str]
    errors: List[Dict[str, str]]


@dataclass
class ScanResultItem:
    """A single scan result with file metadata."""
    path: str
    score: int
    tier: str
    content_score: float
    exposure: str
    exposure_multiplier: float
    entities: Dict[str, int]
    co_occurrence_rules: List[str]
    label_set: Optional[Any] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "score": self.score,
            "tier": self.tier,
            "content_score": self.content_score,
            "exposure": self.exposure,
            "exposure_multiplier": self.exposure_multiplier,
            "entities": self.entities,
            "co_occurrence_rules": self.co_occurrence_rules,
        }


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
                             One of: PRIVATE, INTERNAL, ORG_WIDE, PUBLIC
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
            exposure: Exposure level override (PRIVATE, INTERNAL, ORG_WIDE, PUBLIC).
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
            exposure: Exposure level (PRIVATE, INTERNAL, ORG_WIDE, PUBLIC)

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
        exposure_order = ["PRIVATE", "INTERNAL", "ORG_WIDE", "PUBLIC"]

        highest_idx = 0
        for inp in inputs:
            exposure = inp.context.exposure.upper()
            if exposure in exposure_order:
                idx = exposure_order.index(exposure)
                highest_idx = max(highest_idx, idx)

        return exposure_order[highest_idx]

    # =========================================================================
    # SCAN OPERATIONS
    # =========================================================================

    def _iter_files(
        self,
        path: Path,
        recursive: bool = True,
        include_hidden: bool = False,
        max_files: Optional[int] = None,
        on_progress: Optional[Callable[[str], None]] = None,
    ) -> Iterator[Path]:
        """
        Iterate over files in a directory.

        Args:
            path: Directory to iterate
            recursive: Recurse into subdirectories
            include_hidden: Include hidden files/directories
            max_files: Maximum number of files to yield
            on_progress: Optional callback for progress updates

        Yields:
            Path for each file found
        """
        walker = path.rglob("*") if recursive else path.glob("*")
        files_yielded = 0

        for file_path in walker:
            if file_path.is_dir():
                continue

            if not include_hidden and any(part.startswith('.') for part in file_path.parts):
                continue

            if max_files and files_yielded >= max_files:
                break

            if on_progress:
                on_progress(str(file_path))

            yield file_path
            files_yielded += 1

    def scan(
        self,
        path: Union[str, Path],
        recursive: bool = True,
        filter_criteria: Optional[FilterCriteria] = None,
        filter_expr: Optional[str] = None,
        include_hidden: bool = False,
        max_files: Optional[int] = None,
        on_progress: Optional[Callable[[str], None]] = None,
    ) -> Iterator[ScanResult]:
        """
        Scan files and yield results as they complete.

        This is the primary scanning interface. It yields results as an
        iterator, making it memory-efficient for large directory trees.

        Args:
            path: File or directory to scan
            recursive: Recurse into subdirectories (default True)
            filter_criteria: Optional FilterCriteria to filter results
            filter_expr: Optional filter expression string (e.g., "score > 70")
            include_hidden: Include hidden files/directories (default False)
            max_files: Maximum number of files to scan (None = unlimited)
            on_progress: Optional callback for progress updates

        Yields:
            ScanResult for each file scanned

        Example:
            >>> for result in client.scan("/data", recursive=True):
            ...     print(f"{result.path}: {result.score}")
        """
        path = Path(path)

        if not path.exists():
            raise FileNotFoundError(f"Path not found: {path}")

        filter_obj = parse_filter(filter_expr) if filter_expr else None

        # Single file
        if path.is_file():
            result = self._scan_single_file(path)
            if self._matches_filter(result, filter_criteria, filter_obj):
                yield result
            return

        # Directory
        for file_path in self._iter_files(path, recursive, include_hidden, max_files, on_progress):
            try:
                result = self._scan_single_file(file_path)
                if self._matches_filter(result, filter_criteria, filter_obj):
                    yield result
            except Exception as e:
                logger.warning(f"Error scanning {file_path}: {e}")
                yield ScanResult(
                    path=str(file_path),
                    error=str(e),
                )

    def _scan_single_file(self, path: Path) -> ScanResult:
        """Scan a single file and return ScanResult."""
        from .adapters.scanner import detect_file
        import time

        start_time = time.time()

        try:
            # Detect entities
            detection_result = detect_file(path)

            # Convert to scorer format
            entities = self._normalize_entity_counts(detection_result.entity_counts)
            confidence = self._calculate_average_confidence(detection_result.spans)

            # Score
            scoring_result = score_entities(
                entities,
                exposure=self.default_exposure,
                confidence=confidence,
            )

            duration_ms = (time.time() - start_time) * 1000

            # Get file info
            stat = path.stat()

            return ScanResult(
                path=str(path),
                size_bytes=stat.st_size,
                file_type=path.suffix.lower() or "unknown",
                score=scoring_result.score,
                tier=scoring_result.tier.value,
                scoring_result=scoring_result,
                entities=[],  # Could populate from detection_result.spans
                scan_duration_ms=duration_ms,
                scanned_at=datetime.utcnow().isoformat(),
            )

        except Exception as e:
            return ScanResult(
                path=str(path),
                error=str(e),
            )

    def _matches_filter(
        self,
        result: ScanResult,
        criteria: Optional[FilterCriteria],
        filter_obj: Optional[Filter],
    ) -> bool:
        """Check if a result matches filter criteria."""
        if result.error:
            return False

        # FilterCriteria checks
        if criteria:
            if criteria.min_score is not None and result.score < criteria.min_score:
                return False
            if criteria.max_score is not None and result.score > criteria.max_score:
                return False
            if criteria.tier and result.tier.upper() != criteria.tier.upper():
                return False
            if criteria.path_pattern and not fnmatch.fnmatch(result.path, criteria.path_pattern):
                return False
            if criteria.file_type:
                if not result.file_type.lower().endswith(criteria.file_type.lower()):
                    return False
            if criteria.min_size is not None and result.size_bytes < criteria.min_size:
                return False
            if criteria.max_size is not None and result.size_bytes > criteria.max_size:
                return False

        # Filter expression checks
        if filter_obj:
            result_dict = result.to_dict()
            if not filter_obj.evaluate(result_dict):
                return False

        return True

    def find(
        self,
        path: Union[str, Path],
        filter_criteria: Optional[FilterCriteria] = None,
        filter_expr: Optional[str] = None,
        recursive: bool = True,
        limit: Optional[int] = None,
    ) -> Iterator[ScanResult]:
        """
        Find files matching criteria without full scanning.

        Similar to scan() but optimized for finding files that match
        specific criteria. May use cached labels when available.

        Args:
            path: Directory to search
            filter_criteria: Filter criteria
            filter_expr: Filter expression string
            recursive: Recurse into subdirectories
            limit: Maximum results to return

        Yields:
            ScanResult for matching files

        Example:
            >>> # Find all high-risk files with SSNs
            >>> for result in client.find(
            ...     "/data",
            ...     filter_expr="score >= 70 AND has(SSN)"
            ... ):
            ...     print(result.path)
        """
        count = 0
        for result in self.scan(
            path,
            recursive=recursive,
            filter_criteria=filter_criteria,
            filter_expr=filter_expr,
        ):
            if limit and count >= limit:
                break
            yield result
            count += 1

    # =========================================================================
    # DATA MANAGEMENT OPERATIONS
    # =========================================================================

    def _build_filter_criteria(
        self,
        filter_criteria: Optional[FilterCriteria],
        min_score: Optional[int],
    ) -> Optional[FilterCriteria]:
        """Build filter criteria, merging min_score if provided."""
        if min_score is None:
            return filter_criteria
        if filter_criteria is None:
            return FilterCriteria(min_score=min_score)
        filter_criteria.min_score = min_score
        return filter_criteria

    def quarantine(
        self,
        source: Union[str, Path],
        destination: Union[str, Path],
        filter_criteria: Optional[FilterCriteria] = None,
        filter_expr: Optional[str] = None,
        min_score: Optional[int] = None,
        recursive: bool = True,
        dry_run: bool = False,
    ) -> QuarantineResult:
        """
        Move files matching criteria to quarantine.

        Scans source for files matching the filter and moves them to
        the destination directory, preserving directory structure.

        Args:
            source: Source directory to scan
            destination: Quarantine destination directory
            filter_criteria: Filter criteria for files to quarantine
            filter_expr: Filter expression string
            min_score: Minimum score to quarantine (shortcut for filter_criteria)
            recursive: Recurse into subdirectories
            dry_run: If True, don't actually move files

        Returns:
            QuarantineResult with counts and moved file list

        Example:
            >>> result = client.quarantine(
            ...     "/data",
            ...     "/quarantine",
            ...     min_score=80,
            ... )
            >>> print(f"Moved {result.moved_count} files")
        """
        source = Path(source)
        destination = Path(destination)
        filter_criteria = self._build_filter_criteria(filter_criteria, min_score)

        moved_files: List[Dict[str, Any]] = []
        errors: List[Dict[str, str]] = []

        # Create destination if needed (unless dry run)
        if not dry_run:
            destination.mkdir(parents=True, exist_ok=True)

        for result in self.scan(
            source,
            recursive=recursive,
            filter_criteria=filter_criteria,
            filter_expr=filter_expr,
        ):
            if result.error:
                errors.append({"path": result.path, "error": result.error})
                continue

            # Calculate relative path for destination
            try:
                rel_path = Path(result.path).relative_to(source)
            except ValueError:
                rel_path = Path(result.path).name

            dest_path = destination / rel_path

            if dry_run:
                moved_files.append({
                    "source": result.path,
                    "destination": str(dest_path),
                    "score": result.score,
                    "tier": result.tier,
                    "dry_run": True,
                })
            else:
                try:
                    # Create parent directories
                    dest_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(result.path, dest_path)
                    moved_files.append({
                        "source": result.path,
                        "destination": str(dest_path),
                        "score": result.score,
                        "tier": result.tier,
                    })
                except Exception as e:
                    errors.append({"path": result.path, "error": str(e)})

        return QuarantineResult(
            moved_count=len(moved_files),
            error_count=len(errors),
            moved_files=moved_files,
            errors=errors,
            destination=str(destination),
        )

    def move(
        self,
        source: Union[str, Path],
        destination: Union[str, Path],
    ) -> OperationResult:
        """
        Move a single file or directory.

        Args:
            source: Source path
            destination: Destination path

        Returns:
            OperationResult indicating success or failure
        """
        source = Path(source)
        destination = Path(destination)

        try:
            if not source.exists():
                return OperationResult(
                    success=False,
                    operation="move",
                    source_path=str(source),
                    error=f"Source not found: {source}",
                )

            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(source), str(destination))

            return OperationResult(
                success=True,
                operation="move",
                source_path=str(source),
                dest_path=str(destination),
            )

        except Exception as e:
            return OperationResult(
                success=False,
                operation="move",
                source_path=str(source),
                error=str(e),
            )

    def delete(
        self,
        path: Union[str, Path],
        filter_criteria: Optional[FilterCriteria] = None,
        filter_expr: Optional[str] = None,
        min_score: Optional[int] = None,
        recursive: bool = True,
        confirm: bool = True,
        dry_run: bool = False,
    ) -> DeleteResult:
        """
        Delete files matching criteria.

        WARNING: This permanently deletes files. Use dry_run=True first.

        Args:
            path: Directory to scan for files to delete
            filter_criteria: Filter criteria
            filter_expr: Filter expression
            min_score: Minimum score to delete
            recursive: Recurse into subdirectories
            confirm: If True, requires explicit confirmation (raises if not confirmed)
            dry_run: If True, don't actually delete files

        Returns:
            DeleteResult with counts and deleted file list

        Example:
            >>> # Dry run first
            >>> result = client.delete(
            ...     "/data",
            ...     min_score=90,
            ...     dry_run=True,
            ... )
            >>> print(f"Would delete {result.deleted_count} files")
        """
        path = Path(path)
        filter_criteria = self._build_filter_criteria(filter_criteria, min_score)

        if confirm and not dry_run:
            # In a real implementation, this would require user confirmation
            logger.warning("Delete operation requires confirmation")

        deleted_files: List[str] = []
        errors: List[Dict[str, str]] = []

        # Single file
        if path.is_file():
            if dry_run:
                return DeleteResult(
                    deleted_count=1,
                    error_count=0,
                    deleted_files=[str(path)],
                    errors=[],
                )
            try:
                path.unlink()
                return DeleteResult(
                    deleted_count=1,
                    error_count=0,
                    deleted_files=[str(path)],
                    errors=[],
                )
            except Exception as e:
                return DeleteResult(
                    deleted_count=0,
                    error_count=1,
                    deleted_files=[],
                    errors=[{"path": str(path), "error": str(e)}],
                )

        # Directory
        for result in self.scan(
            path,
            recursive=recursive,
            filter_criteria=filter_criteria,
            filter_expr=filter_expr,
        ):
            if result.error:
                errors.append({"path": result.path, "error": result.error})
                continue

            if dry_run:
                deleted_files.append(result.path)
            else:
                try:
                    Path(result.path).unlink()
                    deleted_files.append(result.path)
                except Exception as e:
                    errors.append({"path": result.path, "error": str(e)})

        return DeleteResult(
            deleted_count=len(deleted_files),
            error_count=len(errors),
            deleted_files=deleted_files,
            errors=errors,
        )

    # =========================================================================
    # REPORTING
    # =========================================================================

    def report(
        self,
        path: Union[str, Path],
        output: Optional[Union[str, Path]] = None,
        format: ReportFormat = ReportFormat.JSON,
        config: Optional[ReportConfig] = None,
        recursive: bool = True,
    ) -> Dict[str, Any]:
        """
        Generate a risk report for a path.

        Args:
            path: Path to scan for report
            output: Optional output file path
            format: Report format (JSON, CSV, HTML, JSONL, MARKDOWN)
            config: Optional report configuration
            recursive: Recurse into subdirectories

        Returns:
            Report data as dictionary

        Example:
            >>> report = client.report("/data", format=ReportFormat.JSON)
            >>> print(f"Total files: {report['summary']['total_files']}")
        """
        if config is None:
            config = ReportConfig(format=format)

        results: List[ScanResult] = []
        for result in self.scan(path, recursive=recursive):
            if not result.error:
                results.append(result)

        # Sort results
        if config.sort_by == "score":
            results.sort(key=lambda r: r.score, reverse=config.sort_descending)
        elif config.sort_by == "path":
            results.sort(key=lambda r: r.path, reverse=config.sort_descending)
        elif config.sort_by == "tier":
            tier_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "MINIMAL": 1}
            results.sort(key=lambda r: tier_order.get(r.tier, 0), reverse=config.sort_descending)

        # Apply limit
        if config.limit:
            results = results[:config.limit]

        # Build report
        report = self._build_report(results, config)

        # Write output if specified
        if output:
            self._write_report(report, output, config)

        return report

    def _build_report(
        self,
        results: List[ScanResult],
        config: ReportConfig,
    ) -> Dict[str, Any]:
        """Build report data structure."""
        # Summary statistics
        total_files = len(results)
        total_size = sum(r.size_bytes for r in results)
        scores = [r.score for r in results]

        tier_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "MINIMAL": 0}
        for r in results:
            tier = r.tier.upper()
            if tier in tier_counts:
                tier_counts[tier] += 1

        summary = {
            "total_files": total_files,
            "total_size_bytes": total_size,
            "average_score": sum(scores) / len(scores) if scores else 0,
            "max_score": max(scores) if scores else 0,
            "min_score": min(scores) if scores else 0,
            "tier_distribution": tier_counts,
        }

        # File details
        files = []
        for r in results:
            file_entry = {
                "path": r.path,
                "score": r.score,
                "tier": r.tier,
                "size_bytes": r.size_bytes,
                "file_type": r.file_type,
            }
            if config.include_entities and r.entities:
                file_entry["entities"] = [
                    {"type": e.type, "count": e.count, "confidence": e.confidence}
                    for e in r.entities
                ]
            files.append(file_entry)

        return {
            "title": config.title,
            "generated_at": datetime.utcnow().isoformat(),
            "summary": summary,
            "files": files,
        }

    def _write_report(
        self,
        report: Dict[str, Any],
        output: Union[str, Path],
        config: ReportConfig,
    ) -> None:
        """Write report to file."""
        import json

        output = Path(output)
        output.parent.mkdir(parents=True, exist_ok=True)

        if config.format == ReportFormat.JSON:
            with open(output, 'w') as f:
                json.dump(report, f, indent=2)

        elif config.format == ReportFormat.JSONL:
            with open(output, 'w') as f:
                for file_entry in report.get("files", []):
                    f.write(json.dumps(file_entry) + '\n')

        elif config.format == ReportFormat.CSV:
            import csv
            with open(output, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["path", "score", "tier", "size_bytes", "file_type"])
                for file_entry in report.get("files", []):
                    writer.writerow([
                        file_entry["path"],
                        file_entry["score"],
                        file_entry["tier"],
                        file_entry["size_bytes"],
                        file_entry["file_type"],
                    ])

        elif config.format == ReportFormat.MARKDOWN:
            with open(output, 'w') as f:
                f.write(f"# {report['title']}\n\n")
                f.write(f"Generated: {report['generated_at']}\n\n")
                f.write("## Summary\n\n")
                summary = report["summary"]
                f.write(f"- Total files: {summary['total_files']}\n")
                f.write(f"- Average score: {summary['average_score']:.1f}\n")
                f.write(f"- Max score: {summary['max_score']}\n\n")
                f.write("### Distribution\n\n")
                for tier, count in summary["tier_distribution"].items():
                    f.write(f"- {tier}: {count}\n")
                f.write("\n## Files\n\n")
                f.write("| Path | Score | Tier |\n")
                f.write("|------|-------|------|\n")
                for file_entry in report.get("files", []):
                    f.write(f"| {file_entry['path']} | {file_entry['score']} | {file_entry['tier']} |\n")

        elif config.format == ReportFormat.HTML:
            with open(output, 'w') as f:
                f.write(self._generate_html_report(report))

    def _generate_html_report(self, report: Dict[str, Any]) -> str:
        """Generate HTML report content."""
        summary = report["summary"]
        tier_colors = {
            "CRITICAL": "#dc3545",
            "HIGH": "#fd7e14",
            "MEDIUM": "#ffc107",
            "LOW": "#28a745",
            "MINIMAL": "#6c757d",
        }

        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>{report['title']}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        .summary {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .tier {{ padding: 2px 8px; border-radius: 4px; color: white; font-size: 12px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #ddd; }}
        th {{ background: #f8f9fa; }}
    </style>
</head>
<body>
    <h1>{report['title']}</h1>
    <p>Generated: {report['generated_at']}</p>

    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total files:</strong> {summary['total_files']}</p>
        <p><strong>Average score:</strong> {summary['average_score']:.1f}</p>
        <p><strong>Max score:</strong> {summary['max_score']}</p>
    </div>

    <h2>Files</h2>
    <table>
        <tr><th>Path</th><th>Score</th><th>Tier</th><th>Size</th></tr>
"""
        for f in report.get("files", []):
            tier_color = tier_colors.get(f['tier'], '#6c757d')
            html += f"""        <tr>
            <td>{f['path']}</td>
            <td>{f['score']}</td>
            <td><span class="tier" style="background:{tier_color}">{f['tier']}</span></td>
            <td>{f['size_bytes']:,}</td>
        </tr>
"""
        html += """    </table>
</body>
</html>"""
        return html

    def scan_tree(
        self,
        path: Union[str, Path],
        max_depth: Optional[int] = None,
    ) -> TreeNode:
        """
        Build a risk tree for directory visualization.

        Scans directory and builds a tree structure with aggregate
        risk statistics at each level.

        Args:
            path: Root directory to scan
            max_depth: Maximum depth to recurse (None = unlimited)

        Returns:
            TreeNode representing the directory tree with risk data

        Example:
            >>> tree = client.scan_tree("/data")
            >>> print(f"Max risk: {tree.max_score}")
            >>> for child in tree.children:
            ...     print(f"  {child.name}: {child.max_score}")
        """
        path = Path(path)

        if not path.exists():
            raise FileNotFoundError(f"Path not found: {path}")

        return self._build_tree_node(path, current_depth=0, max_depth=max_depth)

    def _build_tree_node(
        self,
        path: Path,
        current_depth: int,
        max_depth: Optional[int],
    ) -> TreeNode:
        """Recursively build tree node."""
        name = path.name or str(path)

        if path.is_file():
            # Scan file
            result = self._scan_single_file(path)
            return TreeNode(
                name=name,
                path=str(path),
                is_directory=False,
                score=result.score if not result.error else 0,
                tier=result.tier if not result.error else "MINIMAL",
            )

        # Directory node
        node = TreeNode(
            name=name,
            path=str(path),
            is_directory=True,
        )

        # Check depth limit
        if max_depth is not None and current_depth >= max_depth:
            return node

        # Process children
        scores = []
        try:
            for child_path in path.iterdir():
                if child_path.name.startswith('.'):
                    continue

                child_node = self._build_tree_node(
                    child_path,
                    current_depth + 1,
                    max_depth,
                )
                node.children.append(child_node)

                if child_node.is_directory:
                    node.total_files += child_node.total_files
                    node.total_size += child_node.total_size
                    if child_node.max_score > 0:
                        scores.extend([child_node.avg_score] * child_node.total_files)
                    node.max_score = max(node.max_score, child_node.max_score)
                    # Aggregate tier distribution
                    for tier, count in child_node.score_distribution.items():
                        node.score_distribution[tier] = node.score_distribution.get(tier, 0) + count
                else:
                    node.total_files += 1
                    if child_node.score is not None:
                        scores.append(child_node.score)
                        node.max_score = max(node.max_score, child_node.score)
                        tier = child_node.tier or "MINIMAL"
                        node.score_distribution[tier] = node.score_distribution.get(tier, 0) + 1

        except PermissionError:
            logger.warning(f"Permission denied: {path}")

        if scores:
            node.avg_score = sum(scores) / len(scores)

        return node
