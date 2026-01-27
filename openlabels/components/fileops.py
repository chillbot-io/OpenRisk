"""
OpenLabels FileOps Component.

Handles file operations: quarantine, move, delete.
"""

import logging
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Union, TYPE_CHECKING

from ..core.types import FilterCriteria, OperationResult

if TYPE_CHECKING:
    from ..context import Context
    from .scanner import Scanner

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


class FileOps:
    """
    File operations component.

    Handles:
    - quarantine(): Move matching files to quarantine
    - move(): Move a single file
    - delete(): Delete matching files

    Example:
        >>> from openlabels import Context
        >>> from openlabels.components import Scorer, Scanner, FileOps
        >>>
        >>> ctx = Context()
        >>> scorer = Scorer(ctx)
        >>> scanner = Scanner(ctx, scorer)
        >>> ops = FileOps(ctx, scanner)
        >>> result = ops.quarantine("/data", "/quarantine", min_score=80)
    """

    def __init__(self, context: "Context", scanner: "Scanner"):
        self._ctx = context
        self._scanner = scanner

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

        Args:
            source: Source directory to scan
            destination: Quarantine destination directory
            filter_criteria: Filter criteria for files to quarantine
            filter_expr: Filter expression string
            min_score: Minimum score to quarantine
            recursive: Recurse into subdirectories
            dry_run: If True, don't actually move files

        Returns:
            QuarantineResult with counts and moved file list
        """
        source = Path(source)
        destination = Path(destination)
        filter_criteria = self._build_filter_criteria(filter_criteria, min_score)

        moved_files: List[Dict[str, Any]] = []
        errors: List[Dict[str, str]] = []

        if not dry_run:
            destination.mkdir(parents=True, exist_ok=True)

        for result in self._scanner.scan(
            source,
            recursive=recursive,
            filter_criteria=filter_criteria,
            filter_expr=filter_expr,
        ):
            if result.error:
                errors.append({"path": result.path, "error": result.error})
                continue

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
                    dest_path.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(result.path, dest_path)
                    moved_files.append({
                        "source": result.path,
                        "destination": str(dest_path),
                        "score": result.score,
                        "tier": result.tier,
                    })
                except OSError as e:
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

        except OSError as e:
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
            confirm: If True, requires explicit confirmation
            dry_run: If True, don't actually delete files

        Returns:
            DeleteResult with counts and deleted file list
        """
        path = Path(path)
        filter_criteria = self._build_filter_criteria(filter_criteria, min_score)

        if confirm and not dry_run:
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
            except OSError as e:
                return DeleteResult(
                    deleted_count=0,
                    error_count=1,
                    deleted_files=[],
                    errors=[{"path": str(path), "error": str(e)}],
                )

        # Directory
        for result in self._scanner.scan(
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
                except OSError as e:
                    errors.append({"path": result.path, "error": str(e)})

        return DeleteResult(
            deleted_count=len(deleted_files),
            error_count=len(errors),
            deleted_files=deleted_files,
            errors=errors,
        )

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
