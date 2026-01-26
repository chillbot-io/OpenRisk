"""
OpenLabels restrict command.

Restrict access permissions on files matching filter criteria.

Usage:
    openlabels restrict <source> --where "<filter>" --acl private
    openlabels restrict ./data --where "score > 75 AND exposure = public" --acl private
    openlabels restrict s3://bucket --where "has(SSN)" --acl private
"""

import os
import stat
import sys
import logging
from pathlib import Path
from typing import Optional

from openlabels import Client

logger = logging.getLogger(__name__)
from openlabels.cli.commands.find import find_matching


def restrict_posix(file_path: Path, mode: str) -> bool:
    """Restrict POSIX file permissions."""
    try:
        if mode == "private":
            # Owner only: rw-------
            os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)
        elif mode == "internal":
            # Owner + group: rw-r-----
            os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
        elif mode == "readonly":
            # Read-only for owner: r--------
            os.chmod(file_path, stat.S_IRUSR)
        return True
    except OSError as e:
        logger.warning(f"Could not apply ACL '{mode}' to {file_path}: {e}")
        return False


def cmd_restrict(args) -> int:
    """Execute the restrict command."""
    if not args.where:
        print("Error: --where filter is required for restrict", file=sys.stderr)
        return 1

    if not args.acl:
        print("Error: --acl is required", file=sys.stderr)
        return 1

    source = Path(args.source) if not args.source.startswith(('s3://', 'gs://', 'azure://')) else args.source

    # Check for cloud paths
    if isinstance(source, str):
        if source.startswith('s3://'):
            bucket = source.replace('s3://', '').split('/')[0]
            print(f"For S3 access restriction, use AWS CLI:")
            if args.acl == "private":
                print(f"  aws s3api put-object-acl --bucket {bucket} --acl private --key <key>")
                print(f"  # Or block public access at bucket level:")
                print(f"  aws s3api put-public-access-block --bucket {bucket} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true")
        elif source.startswith('gs://'):
            print("For GCS access restriction, use gsutil:")
            print(f"  gsutil acl set private {source}")
        elif source.startswith('azure://'):
            print("For Azure Blob, configure private access in portal or use az cli:")
            print("  az storage container set-permission --name <container> --public-access off")
        return 1

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

    # Dry run - just show what would be restricted
    if args.dry_run:
        print(f"Would restrict {len(matches)} files to '{args.acl}':\n")
        for result in matches[:20]:
            print(f"  {result.path} (score: {result.score})")
        if len(matches) > 20:
            print(f"  ... and {len(matches) - 20} more")
        return 0

    # Confirm if not forced
    if not args.force:
        print(f"About to restrict {len(matches)} files to '{args.acl}'")
        print(f"Filter: {args.where}")
        print()

        confirm = input("Proceed? [y/N] ")
        if confirm.lower() not in ("y", "yes"):
            print("Aborted")
            return 1

    # Restrict files
    restricted_count = 0
    errors = []

    for i, result in enumerate(matches):
        try:
            file_path = Path(result.path)

            if restrict_posix(file_path, args.acl):
                restricted_count += 1
                if not args.quiet:
                    print(f"[{i+1}/{len(matches)}] Restricted: {result.path}")
            else:
                errors.append({"path": result.path, "error": "Permission change failed"})
                if not args.quiet:
                    print(f"[{i+1}/{len(matches)}] Failed: {result.path}", file=sys.stderr)

        except OSError as e:
            errors.append({"path": result.path, "error": str(e)})
            if not args.quiet:
                print(f"[{i+1}/{len(matches)}] Error: {result.path} - {e}", file=sys.stderr)

    # Summary
    print()
    print("=" * 60)
    print(f"Restricted: {restricted_count} files")
    if errors:
        print(f"Errors: {len(errors)} files")

    return 0 if not errors else 1


def add_restrict_parser(subparsers):
    """Add the restrict subparser."""
    parser = subparsers.add_parser(
        "restrict",
        help="Restrict access permissions on matching files",
    )
    parser.add_argument(
        "source",
        help="Source path to search",
    )
    parser.add_argument(
        "--where", "-w",
        required=True,
        help="Filter expression (required)",
    )
    parser.add_argument(
        "--acl",
        required=True,
        choices=["private", "internal", "readonly"],
        help="Target access level",
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
        help="Preview what would be restricted without changing",
    )
    parser.add_argument(
        "--force", "-y",
        action="store_true",
        help="Skip confirmation prompt",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress output",
    )
    parser.set_defaults(func=cmd_restrict)

    return parser
