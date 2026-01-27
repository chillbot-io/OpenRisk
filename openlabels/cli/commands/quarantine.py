"""
OpenLabels quarantine command.

Move local files matching filter criteria to a quarantine location.

Usage:
    openlabels quarantine <source> --where "<filter>" --to <dest>
    openlabels quarantine ./data --where "score > 75" --to ./quarantine
"""

import json
import shutil
import os
from pathlib import Path
from typing import Optional, List
from datetime import datetime

from openlabels import Client
from openlabels.cli import MAX_PREVIEW_RESULTS
from openlabels.cli.commands.find import find_matching
from openlabels.cli.output import echo, error, warn, success, dim, progress, confirm, divider
from openlabels.logging_config import get_logger, get_audit_logger

logger = get_logger(__name__)
audit = get_audit_logger()


def move_file(source: Path, dest_dir: Path, preserve_structure: bool = True, base_path: Optional[Path] = None) -> Path:
    """
    Move a file to the destination directory.

    Args:
        source: Source file path
        dest_dir: Destination directory
        preserve_structure: If True, preserve relative path structure
        base_path: Base path for computing relative structure

    Returns:
        New file path

    Raises:
        ValueError: If source is a symlink (security: prevents symlink attacks)
        FileNotFoundError: If source doesn't exist
    """
    # SECURITY FIX (CVE-READY-002): Check for symlinks before move to prevent
    # TOCTOU race conditions where an attacker replaces the file with a symlink
    # between existence check and move operation
    if source.is_symlink():
        raise ValueError(f"Refusing to move symlink (security): {source}")

    if not source.exists():
        raise FileNotFoundError(f"Source file not found: {source}")

    if preserve_structure and base_path:
        # Compute relative path from base
        try:
            rel_path = source.relative_to(base_path)
        except ValueError:
            rel_path = source.name
    else:
        rel_path = source.name

    dest_path = dest_dir / rel_path

    # Create parent directories
    dest_path.parent.mkdir(parents=True, exist_ok=True)

    # SECURITY FIX (CVE-READY-002): Use os.rename for atomic same-filesystem moves
    # when possible, falling back to shutil.move for cross-filesystem moves
    try:
        os.rename(str(source), str(dest_path))
    except OSError:
        # Cross-filesystem move, use shutil but re-verify source isn't symlink
        if source.is_symlink():
            raise ValueError(f"Refusing to move symlink (security): {source}")
        shutil.move(str(source), str(dest_path))

    return dest_path


def write_manifest(
    dest_dir: Path,
    moved_files: List[dict],
    filter_expr: str,
) -> Path:
    """Write a manifest file documenting the quarantine operation."""
    manifest = {
        "quarantine_date": datetime.now().isoformat(),
        "filter": filter_expr,
        "file_count": len(moved_files),
        "files": moved_files,
    }

    manifest_path = dest_dir / f"quarantine_manifest_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    return manifest_path


def cmd_quarantine(args) -> int:
    """Execute the quarantine command."""
    if not args.where:
        error("--where filter is required for quarantine")
        return 1

    if not args.to:
        error("--to destination is required")
        return 1

    source = Path(args.source)
    dest = Path(args.to)

    if not source.exists():
        error(f"Source not found: {source}")
        return 1

    logger.info(f"Starting quarantine operation", extra={
        "source": str(source),
        "destination": str(dest),
        "filter": args.where,
    })

    client = Client(default_exposure=args.exposure)
    extensions = args.extensions.split(",") if args.extensions else None

    # Find matching files
    matches = list(find_matching(
        source,
        client,
        filter_expr=args.where,
        recursive=args.recursive,
        exposure=args.exposure,
        extensions=extensions,
    ))

    if not matches:
        echo("No files match the filter criteria")
        logger.info("No files matched filter criteria")
        return 0

    logger.info(f"Found {len(matches)} files matching filter")

    # Dry run - just show what would be moved
    if args.dry_run:
        echo(f"Would quarantine [bold]{len(matches)}[/bold] files to {dest}:\n")
        for result in matches[:MAX_PREVIEW_RESULTS]:
            dim(f"  {result.path} (score: {result.score})")
        if len(matches) > MAX_PREVIEW_RESULTS:
            dim(f"  ... and {len(matches) - MAX_PREVIEW_RESULTS} more")
        return 0

    # Confirm if not forced
    if not args.force:
        echo(f"About to quarantine [bold]{len(matches)}[/bold] files to {dest}")
        echo(f"Filter: {args.where}")
        echo("")
        for result in matches[:5]:
            dim(f"  {result.path} (score: {result.score})")
        if len(matches) > 5:
            dim(f"  ... and {len(matches) - 5} more")
        echo("")

        if not confirm("Proceed?"):
            echo("Aborted")
            logger.info("Quarantine aborted by user")
            return 1

    # Create destination directory
    dest.mkdir(parents=True, exist_ok=True)

    # Move files
    moved_files = []
    errors = []
    base_path = source if source.is_dir() else source.parent

    with progress("Quarantining files", total=len(matches)) as p:
        for i, result in enumerate(matches):
            try:
                source_path = Path(result.path)
                new_path = move_file(
                    source_path,
                    dest,
                    preserve_structure=args.preserve_structure,
                    base_path=base_path,
                )

                moved_files.append({
                    "original_path": result.path,
                    "new_path": str(new_path),
                    "score": result.score,
                    "tier": result.tier,
                    "entities": result.entities,
                })

                # Audit log for each quarantined file
                audit.file_quarantine(
                    source=result.path,
                    destination=str(new_path),
                    score=result.score,
                    tier=result.tier,
                )

                logger.debug(f"Moved {result.path} -> {new_path}")

                if not args.quiet:
                    p.set_description(f"[{i+1}/{len(matches)}] {Path(result.path).name}")

            except (OSError, ValueError) as e:
                errors.append({"path": result.path, "error": str(e)})
                logger.warning(f"Failed to quarantine {result.path}: {e}")
                if not args.quiet:
                    warn(f"Failed: {result.path} - {e}")

            p.advance()

    # Write manifest
    if args.manifest and moved_files:
        manifest_path = write_manifest(dest, moved_files, args.where)
        echo(f"\nManifest written to: {manifest_path}")
        logger.info(f"Manifest written to {manifest_path}")

    # Summary
    echo("")
    divider()
    if errors:
        warn(f"Quarantined: {len(moved_files)} files ({len(errors)} errors)")
    else:
        success(f"Quarantined: {len(moved_files)} files")
    echo(f"Destination: {dest}")

    logger.info(f"Quarantine complete", extra={
        "files_moved": len(moved_files),
        "errors": len(errors),
        "destination": str(dest),
    })

    return 0 if not errors else 1


def add_quarantine_parser(subparsers):
    """Add the quarantine subparser."""
    parser = subparsers.add_parser(
        "quarantine",
        help="Move matching files to quarantine location",
    )
    parser.add_argument(
        "source",
        help="Local source path to search",
    )
    parser.add_argument(
        "--where", "-w",
        required=True,
        help="Filter expression (required)",
    )
    parser.add_argument(
        "--to", "-t",
        required=True,
        help="Local destination quarantine directory",
    )
    parser.add_argument(
        "--recursive", "-r",
        action="store_true",
        default=True,
        help="Search recursively (default: true)",
    )
    parser.add_argument(
        "--no-recursive",
        action="store_false",
        dest="recursive",
        help="Do not search recursively",
    )
    parser.add_argument(
        "--exposure", "-e",
        choices=["PRIVATE", "INTERNAL", "ORG_WIDE", "PUBLIC"],
        default="PRIVATE",
        help="Exposure level for scoring",
    )
    parser.add_argument(
        "--extensions",
        help="Comma-separated list of file extensions",
    )
    parser.add_argument(
        "--dry-run", "-n",
        action="store_true",
        help="Preview what would be moved without moving",
    )
    parser.add_argument(
        "--force", "-y",
        action="store_true",
        help="Skip confirmation prompt",
    )
    parser.add_argument(
        "--preserve-structure", "-p",
        action="store_true",
        default=True,
        help="Preserve directory structure in destination",
    )
    parser.add_argument(
        "--no-preserve-structure",
        action="store_false",
        dest="preserve_structure",
        help="Flatten directory structure",
    )
    parser.add_argument(
        "--manifest", "-m",
        action="store_true",
        default=True,
        help="Write manifest file (default: true)",
    )
    parser.add_argument(
        "--no-manifest",
        action="store_false",
        dest="manifest",
        help="Skip manifest file",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress output",
    )
    parser.set_defaults(func=cmd_quarantine)

    return parser
