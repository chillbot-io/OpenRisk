"""
OpenLabels scan command.

Scan files and directories for sensitive data and compute risk scores.

Usage:
    openlabels scan <path>
    openlabels scan s3://bucket/prefix
    openlabels scan gs://bucket/prefix
    openlabels scan azure://container/path
"""

import json
import sys
from pathlib import Path
from typing import Iterator, Optional, Dict, Any, List
from dataclasses import dataclass

from openlabels import Client
from openlabels.core.scorer import ScoringResult


@dataclass
class ScanResult:
    """Result of scanning a single file."""
    path: str
    score: int
    tier: str
    entities: Dict[str, int]
    exposure: str
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "path": self.path,
            "score": self.score,
            "tier": self.tier,
            "entities": self.entities,
            "exposure": self.exposure,
            "error": self.error,
        }


def scan_file(
    path: Path,
    client: Client,
    exposure: str = "PRIVATE",
) -> ScanResult:
    """Scan a single file and return result."""
    try:
        # First detect to get entity counts
        from openlabels.adapters.scanner import detect_file as scanner_detect

        detection = scanner_detect(path)
        entities = detection.entity_counts

        # Then score
        result = client.score_file(path, exposure=exposure)

        return ScanResult(
            path=str(path),
            score=result.score,
            tier=result.tier.value if hasattr(result.tier, 'value') else str(result.tier),
            entities=entities,
            exposure=exposure,
        )
    except Exception as e:
        return ScanResult(
            path=str(path),
            score=0,
            tier="UNKNOWN",
            entities={},
            exposure=exposure,
            error=str(e),
        )


def scan_directory(
    path: Path,
    client: Client,
    recursive: bool = False,
    exposure: str = "PRIVATE",
    extensions: Optional[List[str]] = None,
) -> Iterator[ScanResult]:
    """Scan all files in a directory."""
    if recursive:
        files = list(path.rglob("*"))
    else:
        files = list(path.glob("*"))

    # Filter to files only
    files = [f for f in files if f.is_file()]

    # Apply extension filter
    if extensions:
        exts = {e.lower().lstrip(".") for e in extensions}
        files = [f for f in files if f.suffix.lower().lstrip(".") in exts]

    for file_path in sorted(files):
        yield scan_file(file_path, client, exposure)


def format_scan_result(result: ScanResult, format: str = "text") -> str:
    """Format a scan result for output."""
    if format == "json":
        return json.dumps(result.to_dict(), indent=2)

    if format == "jsonl":
        return json.dumps(result.to_dict())

    # Text format
    tier_colors = {
        "CRITICAL": "\033[91m",  # Red
        "HIGH": "\033[93m",      # Yellow
        "MEDIUM": "\033[33m",    # Orange
        "LOW": "\033[92m",       # Green
        "MINIMAL": "\033[90m",   # Gray
    }
    reset = "\033[0m"
    color = tier_colors.get(result.tier, "")

    if result.error:
        return f"{result.path}: ERROR - {result.error}"

    entities_str = ", ".join(
        f"{k}({v})" for k, v in sorted(result.entities.items())
    ) if result.entities else "none"

    return f"{result.path}: {color}{result.score:>3}{reset} ({result.tier:<8}) [{entities_str}]"


def cmd_scan(args) -> int:
    """Execute the scan command."""
    client = Client(default_exposure=args.exposure)
    path = Path(args.path) if not args.path.startswith(('s3://', 'gs://', 'azure://')) else args.path

    # Check for cloud paths (future support)
    if isinstance(path, str):
        print(f"Cloud storage scanning not yet implemented: {path}", file=sys.stderr)
        return 1

    if not path.exists():
        print(f"Error: Path not found: {path}", file=sys.stderr)
        return 1

    results = []
    total_files = 0
    files_with_risk = 0
    max_score = 0

    if path.is_file():
        result = scan_file(path, client, args.exposure)
        results.append(result)
        total_files = 1
        if result.score > 0:
            files_with_risk = 1
            max_score = result.score
    else:
        extensions = args.extensions.split(",") if args.extensions else None

        for result in scan_directory(
            path, client,
            recursive=args.recursive,
            exposure=args.exposure,
            extensions=extensions,
        ):
            results.append(result)
            total_files += 1
            if result.score > 0:
                files_with_risk += 1
                max_score = max(max_score, result.score)

            # Print progress for text format
            if args.format == "text" and not args.quiet:
                print(format_scan_result(result, "text"))

    # Output results
    if args.format == "json":
        output = {
            "summary": {
                "total_files": total_files,
                "files_with_risk": files_with_risk,
                "max_score": max_score,
            },
            "results": [r.to_dict() for r in results],
        }
        print(json.dumps(output, indent=2))

    elif args.format == "jsonl":
        for result in results:
            print(json.dumps(result.to_dict()))

    elif args.format == "text" and args.quiet:
        # Quiet mode - only print summary
        pass

    # Print summary for text format
    if args.format == "text":
        print()
        print("=" * 60)
        print(f"Scanned: {total_files} files")
        print(f"At risk: {files_with_risk} files")
        print(f"Max score: {max_score}")

    # Return exit code based on threshold
    if args.fail_above and max_score > args.fail_above:
        return 1

    return 0


def add_scan_parser(subparsers):
    """Add the scan subparser."""
    parser = subparsers.add_parser(
        "scan",
        help="Scan files for sensitive data and compute risk scores",
    )
    parser.add_argument(
        "path",
        help="Path to file, directory, or cloud storage (s3://, gs://, azure://)",
    )
    parser.add_argument(
        "--recursive", "-r",
        action="store_true",
        help="Scan directories recursively",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["text", "json", "jsonl"],
        default="text",
        help="Output format",
    )
    parser.add_argument(
        "--exposure", "-e",
        choices=["PRIVATE", "INTERNAL", "ORG_WIDE", "PUBLIC"],
        default="PRIVATE",
        help="Exposure level for scoring",
    )
    parser.add_argument(
        "--extensions",
        help="Comma-separated list of file extensions to scan",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Only show summary",
    )
    parser.add_argument(
        "--fail-above",
        type=int,
        help="Exit with error if any score exceeds this threshold",
    )
    parser.set_defaults(func=cmd_scan)

    return parser
