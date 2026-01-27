"""
OpenLabels move command.

Move local files matching filter criteria to a new location.

Usage:
    openlabels move <source> --where "<filter>" --to <dest>
    openlabels move ./data --where "score < 20" --to ./archive
"""

import sys
from pathlib import Path

from openlabels import Client
from openlabels.cli import MAX_PREVIEW_RESULTS
from openlabels.cli.commands.find import find_matching
from openlabels.cli.commands.quarantine import move_file


def cmd_move(args) -> int:
    """Execute the move command."""
    if not args.where:
        print("Error: --where filter is required for move", file=sys.stderr)
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
        print(f"Would move {len(matches)} files to {dest}:\n")
        for result in matches[:MAX_PREVIEW_RESULTS]:
            print(f"  {result.path} (score: {result.score})")
        if len(matches) > MAX_PREVIEW_RESULTS:
            print(f"  ... and {len(matches) - MAX_PREVIEW_RESULTS} more")
        return 0

    # Confirm if not forced
    if not args.force:
        print(f"About to move {len(matches)} files to {dest}")
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
    moved_count = 0
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

            moved_count += 1
            if not args.quiet:
                print(f"[{i+1}/{len(matches)}] Moved: {result.path} -> {new_path}")

        except (OSError, ValueError) as e:
            errors.append({"path": result.path, "error": str(e)})
            if not args.quiet:
                print(f"[{i+1}/{len(matches)}] Error: {result.path} - {e}", file=sys.stderr)

    # Summary
    print()
    print("=" * 60)
    print(f"Moved: {moved_count} files")
    if errors:
        print(f"Errors: {len(errors)} files")
    print(f"Destination: {dest}")

    return 0 if not errors else 1


def add_move_parser(subparsers):
    """Add the move subparser."""
    parser = subparsers.add_parser(
        "move",
        help="Move matching files to a new location",
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
        help="Local destination directory",
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
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress output",
    )
    parser.set_defaults(func=cmd_move)

    return parser
