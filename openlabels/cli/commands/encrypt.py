"""
OpenLabels encrypt command.

Encrypt files matching filter criteria.

Usage:
    openlabels encrypt <source> --where "<filter>" --key <key-id>
    openlabels encrypt ./data --where "score > 75" --key alias/my-key
    openlabels encrypt s3://bucket --where "has(SSN)" --key arn:aws:kms:...

Note: This command provides guidance and integration with platform encryption.
For local files, it uses GPG or age. For cloud storage, it configures
server-side encryption settings.
"""

import subprocess
import sys
from pathlib import Path
from typing import Optional

from openlabels import Client
from openlabels.cli.commands.find import find_matching


def encrypt_file_gpg(file_path: Path, recipient: str) -> bool:
    """Encrypt a file using GPG."""
    try:
        result = subprocess.run(
            ["gpg", "--encrypt", "--recipient", recipient, str(file_path)],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            # Remove original file after successful encryption
            file_path.unlink()
            return True
        return False
    except FileNotFoundError:
        return False


def encrypt_file_age(file_path: Path, recipient: str) -> bool:
    """Encrypt a file using age."""
    try:
        output_path = file_path.with_suffix(file_path.suffix + ".age")
        result = subprocess.run(
            ["age", "--encrypt", "--recipient", recipient, "-o", str(output_path), str(file_path)],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            # Remove original file after successful encryption
            file_path.unlink()
            return True
        return False
    except FileNotFoundError:
        return False


def cmd_encrypt(args) -> int:
    """Execute the encrypt command."""
    if not args.where:
        print("Error: --where filter is required for encrypt", file=sys.stderr)
        return 1

    if not args.key:
        print("Error: --key is required for encryption", file=sys.stderr)
        return 1

    source = Path(args.source) if not args.source.startswith(('s3://', 'gs://', 'azure://')) else args.source

    # Check for cloud paths
    if isinstance(source, str):
        if source.startswith('s3://'):
            print("For S3 encryption, use AWS CLI or SDK to configure SSE-KMS:")
            print(f"  aws s3 cp {source} {source} --sse aws:kms --sse-kms-key-id {args.key}")
        elif source.startswith('gs://'):
            print("For GCS encryption, use gsutil to configure CMEK:")
            print(f"  gsutil rewrite -k {args.key} {source}")
        elif source.startswith('azure://'):
            print("For Azure Blob encryption, configure customer-managed keys in portal")
        return 1

    if not source.exists():
        print(f"Error: Source not found: {source}", file=sys.stderr)
        return 1

    # Check for encryption tool
    tool = args.tool
    if tool == "auto":
        # Try to detect available tool
        try:
            subprocess.run(["age", "--version"], capture_output=True)
            tool = "age"
        except FileNotFoundError:
            try:
                subprocess.run(["gpg", "--version"], capture_output=True)
                tool = "gpg"
            except FileNotFoundError:
                print("Error: No encryption tool found. Install 'age' or 'gpg'", file=sys.stderr)
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

    # Dry run - just show what would be encrypted
    if args.dry_run:
        print(f"Would encrypt {len(matches)} files using {tool}:\n")
        for result in matches[:20]:
            print(f"  {result.path} (score: {result.score})")
        if len(matches) > 20:
            print(f"  ... and {len(matches) - 20} more")
        return 0

    # Confirm if not forced
    if not args.force:
        print(f"About to encrypt {len(matches)} files using {tool}")
        print(f"Key/Recipient: {args.key}")
        print(f"Filter: {args.where}")
        print()
        print("WARNING: Original files will be replaced with encrypted versions!")
        print()

        confirm = input("Proceed? [y/N] ")
        if confirm.lower() not in ("y", "yes"):
            print("Aborted")
            return 1

    # Encrypt files
    encrypted_count = 0
    errors = []

    encrypt_func = encrypt_file_age if tool == "age" else encrypt_file_gpg

    for i, result in enumerate(matches):
        try:
            file_path = Path(result.path)

            if encrypt_func(file_path, args.key):
                encrypted_count += 1
                if not args.quiet:
                    print(f"[{i+1}/{len(matches)}] Encrypted: {result.path}")
            else:
                errors.append({"path": result.path, "error": "Encryption failed"})
                if not args.quiet:
                    print(f"[{i+1}/{len(matches)}] Failed: {result.path}", file=sys.stderr)

        except Exception as e:
            errors.append({"path": result.path, "error": str(e)})
            if not args.quiet:
                print(f"[{i+1}/{len(matches)}] Error: {result.path} - {e}", file=sys.stderr)

    # Summary
    print()
    print("=" * 60)
    print(f"Encrypted: {encrypted_count} files")
    if errors:
        print(f"Errors: {len(errors)} files")

    return 0 if not errors else 1


def add_encrypt_parser(subparsers):
    """Add the encrypt subparser."""
    parser = subparsers.add_parser(
        "encrypt",
        help="Encrypt matching files",
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
        "--key", "-k",
        required=True,
        help="Encryption key or recipient (GPG key ID, age public key, KMS key ARN)",
    )
    parser.add_argument(
        "--tool",
        choices=["auto", "gpg", "age"],
        default="auto",
        help="Encryption tool to use (default: auto-detect)",
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
        help="Preview what would be encrypted without encrypting",
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
    parser.set_defaults(func=cmd_encrypt)

    return parser
