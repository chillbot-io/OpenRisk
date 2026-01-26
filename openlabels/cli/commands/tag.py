"""
OpenLabels tag command.

Apply or update OpenLabels tags on local files matching filter criteria.

Usage:
    openlabels tag <source> --where "<filter>"
    openlabels tag ./data --where "score > 50"
    openlabels tag ./data --where "has(SSN)" --force-rescan
"""

import sys
from pathlib import Path

from openlabels import Client
from openlabels.cli.commands.find import find_matching
from openlabels.output.virtual import write_virtual_label
from openlabels.output.embed import write_embedded_label
from openlabels.output.index import store_label


def cmd_tag(args) -> int:
    """Execute the tag command."""
    source = Path(args.source)

    if not source.exists():
        print(f"Error: Source not found: {source}", file=sys.stderr)
        return 1

    client = Client(default_exposure=args.exposure)
    extensions = args.extensions.split(",") if args.extensions else None

    # Find matching files (or all files if no filter)
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

    # Dry run - just show what would be tagged
    if args.dry_run:
        print(f"Would tag {len(matches)} files:\n")
        for result in matches[:20]:
            print(f"  {result.path} (score: {result.score})")
        if len(matches) > 20:
            print(f"  ... and {len(matches) - 20} more")
        return 0

    # Tag files
    tagged_count = 0
    embedded_count = 0
    virtual_count = 0
    errors = []

    for i, result in enumerate(matches):
        try:
            file_path = Path(result.path)

            # Get the label set from the scan result
            label_set = result.label_set if hasattr(result, 'label_set') else None

            if label_set is None:
                # Re-scan to get label set
                scan_result = client.score_file(str(file_path), exposure=args.exposure)
                label_set = scan_result.label_set if hasattr(scan_result, 'label_set') else None

            if label_set is None:
                if not args.quiet:
                    print(f"[{i+1}/{len(matches)}] Skipped (no labels): {result.path}")
                continue

            # Try embedded label first (for supported formats)
            embedded = False
            if args.embed:
                try:
                    write_embedded_label(str(file_path), label_set)
                    embedded = True
                    embedded_count += 1
                except Exception:
                    pass  # Fall back to virtual

            # Write virtual label if not embedded
            if not embedded:
                write_virtual_label(str(file_path), label_set.label_id, label_set.content_hash)
                virtual_count += 1

            # Store in index
            store_label(label_set, str(file_path), result.score, result.tier)

            tagged_count += 1
            if not args.quiet:
                tag_type = "embedded" if embedded else "virtual"
                print(f"[{i+1}/{len(matches)}] Tagged ({tag_type}): {result.path}")

        except Exception as e:
            errors.append({"path": result.path, "error": str(e)})
            if not args.quiet:
                print(f"[{i+1}/{len(matches)}] Error: {result.path} - {e}", file=sys.stderr)

    # Summary
    print()
    print("=" * 60)
    print(f"Tagged: {tagged_count} files")
    print(f"  Embedded: {embedded_count}")
    print(f"  Virtual: {virtual_count}")
    if errors:
        print(f"Errors: {len(errors)} files")

    return 0 if not errors else 1


def add_tag_parser(subparsers):
    """Add the tag subparser."""
    parser = subparsers.add_parser(
        "tag",
        help="Apply OpenLabels tags to files",
    )
    parser.add_argument(
        "source",
        help="Local source path to search",
    )
    parser.add_argument(
        "--where", "-w",
        help="Filter expression (optional, tags all files if not specified)",
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
        "--embed",
        action="store_true",
        default=True,
        help="Try to embed labels in file metadata (default: true)",
    )
    parser.add_argument(
        "--no-embed",
        action="store_false",
        dest="embed",
        help="Only use virtual labels (xattr)",
    )
    parser.add_argument(
        "--force-rescan",
        action="store_true",
        help="Re-scan files even if already tagged",
    )
    parser.add_argument(
        "--dry-run", "-n",
        action="store_true",
        help="Preview what would be tagged without tagging",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress output",
    )
    parser.set_defaults(func=cmd_tag)

    return parser
