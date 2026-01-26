"""
OpenLabels delete command.

Delete local files matching filter criteria.

Usage:
    openlabels delete <source> --where "<filter>" --confirm
    openlabels delete ./data --where "score < 10 AND last_accessed > 7y" --confirm
"""

import sys
from pathlib import Path

from openlabels import Client
from openlabels.cli.commands.find import find_matching


def cmd_delete(args) -> int:
    """Execute the delete command."""
    if not args.where:
        print("Error: --where filter is required for delete", file=sys.stderr)
        return 1

    source = Path(args.source)

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

    # Dry run - just show what would be deleted
    if args.dry_run:
        total_size = sum(Path(r.path).stat().st_size for r in matches if Path(r.path).exists())
        print(f"Would delete {len(matches)} files ({total_size / 1024 / 1024:.2f} MB):\n")
        for result in matches[:20]:
            print(f"  {result.path} (score: {result.score})")
        if len(matches) > 20:
            print(f"  ... and {len(matches) - 20} more")
        return 0

    # Require explicit confirmation
    if not args.confirm:
        print("Error: --confirm is required for delete operations", file=sys.stderr)
        print("Use --dry-run to preview what would be deleted", file=sys.stderr)
        return 1

    # Additional confirmation prompt unless forced
    if not args.force:
        total_size = sum(Path(r.path).stat().st_size for r in matches if Path(r.path).exists())
        print(f"WARNING: About to permanently delete {len(matches)} files ({total_size / 1024 / 1024:.2f} MB)")
        print(f"Filter: {args.where}")
        print()
        for result in matches[:5]:
            print(f"  {result.path} (score: {result.score})")
        if len(matches) > 5:
            print(f"  ... and {len(matches) - 5} more")
        print()
        print("This action cannot be undone!")

        confirm = input("Type 'DELETE' to confirm: ")
        if confirm != "DELETE":
            print("Aborted")
            return 1

    # Delete files
    deleted_count = 0
    errors = []

    for i, result in enumerate(matches):
        try:
            file_path = Path(result.path)
            file_path.unlink()
            deleted_count += 1
            if not args.quiet:
                print(f"[{i+1}/{len(matches)}] Deleted: {result.path}")

        except FileNotFoundError:
            if not args.quiet:
                print(f"[{i+1}/{len(matches)}] Skipped (not found): {result.path}")

        except OSError as e:
            errors.append({"path": result.path, "error": str(e)})
            if not args.quiet:
                print(f"[{i+1}/{len(matches)}] Error: {result.path} - {e}", file=sys.stderr)

    # Summary
    print()
    print("=" * 60)
    print(f"Deleted: {deleted_count} files")
    if errors:
        print(f"Errors: {len(errors)} files")

    return 0 if not errors else 1


def add_delete_parser(subparsers):
    """Add the delete subparser."""
    parser = subparsers.add_parser(
        "delete",
        help="Delete matching files (requires --confirm)",
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
        "--confirm",
        action="store_true",
        help="Confirm deletion (required for actual deletion)",
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
        help="Preview what would be deleted without deleting",
    )
    parser.add_argument(
        "--force", "-y",
        action="store_true",
        help="Skip additional confirmation prompt",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress output",
    )
    parser.set_defaults(func=cmd_delete)

    return parser
