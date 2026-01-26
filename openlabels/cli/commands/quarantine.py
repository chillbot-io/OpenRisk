"""
OpenLabels quarantine command.

Move local files matching filter criteria to a quarantine location.

Usage:
    openlabels quarantine <source> --where "<filter>" --to <dest>
    openlabels quarantine ./data --where "score > 75" --to ./quarantine
"""

import json
import shutil
import sys
from pathlib import Path
from typing import Optional, List
from datetime import datetime

from openlabels import Client
from openlabels.cli.commands.find import find_matching


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
    """
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

    # Move file
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
        print("Error: --where filter is required for quarantine", file=sys.stderr)
        return 1

    if not args.to:
        print("Error: --to destination is required", file=sys.stderr)
        return 1

    source = Path(args.source)
    dest = Path(args.to)

    if not source.exists():
        print(f"Error: Source not found: {source}", file=sys.stderr)
        return 1

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
        print("No files match the filter criteria")
        return 0

    # Dry run - just show what would be moved
    if args.dry_run:
        print(f"Would quarantine {len(matches)} files to {dest}:\n")
        for result in matches[:20]:
            print(f"  {result.path} (score: {result.score})")
        if len(matches) > 20:
            print(f"  ... and {len(matches) - 20} more")
        return 0

    # Confirm if not forced
    if not args.force:
        print(f"About to quarantine {len(matches)} files to {dest}")
        print(f"Filter: {args.where}")
        print()
        for result in matches[:5]:
            print(f"  {result.path} (score: {result.score})")
        if len(matches) > 5:
            print(f"  ... and {len(matches) - 5} more")
        print()

        confirm = input("Proceed? [y/N] ")
        if confirm.lower() not in ("y", "yes"):
            print("Aborted")
            return 1

    # Create destination directory
    dest.mkdir(parents=True, exist_ok=True)

    # Move files
    moved_files = []
    errors = []
    base_path = source if source.is_dir() else source.parent

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

            if not args.quiet:
                print(f"[{i+1}/{len(matches)}] Moved: {result.path} -> {new_path}")

        except (OSError, ValueError) as e:
            errors.append({"path": result.path, "error": str(e)})
            if not args.quiet:
                print(f"[{i+1}/{len(matches)}] Error: {result.path} - {e}", file=sys.stderr)

    # Write manifest
    if args.manifest and moved_files:
        manifest_path = write_manifest(dest, moved_files, args.where)
        print(f"\nManifest written to: {manifest_path}")

    # Summary
    print()
    print("=" * 60)
    print(f"Quarantined: {len(moved_files)} files")
    if errors:
        print(f"Errors: {len(errors)} files")
    print(f"Destination: {dest}")

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
