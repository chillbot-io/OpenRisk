"""
OpenLabels scan command.

Scan local files and directories for sensitive data and compute risk scores.

Usage:
    openlabels scan <path>
    openlabels scan ./data --recursive
    openlabels scan /path/to/file.csv
"""

import json
import sys
from pathlib import Path
from typing import Iterator, Optional, Dict, Any, List
from dataclasses import dataclass

from openlabels import Client
from openlabels.core.scorer import ScoringResult


# ANSI color codes for terminal output
class TermColors:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    ORANGE = "\033[33m"
    GREEN = "\033[92m"
    GRAY = "\033[90m"
    RESET = "\033[0m"


# Risk tier to color mapping
TIER_COLORS = {
    "CRITICAL": TermColors.RED,
    "HIGH": TermColors.YELLOW,
    "MEDIUM": TermColors.ORANGE,
    "LOW": TermColors.GREEN,
    "MINIMAL": TermColors.GRAY,
}


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
    except (OSError, ValueError) as e:
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

    # Text format with color
    # Phase 5.3: Handle Optional score/tier fields
    tier_str = result.tier if result.tier is not None else "N/A"
    score_str = str(result.score) if result.score is not None else "N/A"
    color = TIER_COLORS.get(result.tier, "")

    if result.error:
        return f"{result.path}: ERROR - {result.error}"

    entities_str = ", ".join(
        f"{k}({v})" for k, v in sorted(result.entities.items())
    ) if result.entities else "none"

    return f"{result.path}: {color}{score_str:>3}{TermColors.RESET} ({tier_str:<8}) [{entities_str}]"


def cmd_scan(args) -> int:
    """Execute the scan command."""
    client = Client(default_exposure=args.exposure)
    path = Path(args.path)

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
        help="Path to local file or directory",
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
