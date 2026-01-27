"""
OpenLabels CLI - Command-line interface.

Labels are the primitive. Risk is derived.

Usage:
    # Risk scoring commands
    openlabels scan <path>                    # Scan and score files
    openlabels find <path> --where "..."      # Find files matching criteria
    openlabels quarantine <src> --to <dst>    # Move risky files
    openlabels report <path> --format html    # Generate reports
    openlabels heatmap <path>                 # Visual risk heatmap

    # Detection commands (legacy)
    openlabels detect "text to scan"
    openlabels detect-file document.pdf
    openlabels detect-dir ./data --recursive

    # Info
    openlabels --version
"""

import argparse
import json
import sys
import logging
from pathlib import Path
from typing import List, Optional

from openlabels import __version__
from openlabels.logging_config import setup_logging, get_logger
from openlabels.cli.output import set_progress_enabled, echo, error, divider
from openlabels.shutdown import install_signal_handlers, get_shutdown_coordinator

logger = get_logger(__name__)


# =============================================================================
# LEGACY DETECT COMMANDS (for backwards compatibility)
# =============================================================================

def format_result(result, output_format: str = "text") -> str:
    """Format detection result for output."""
    if output_format == "json":
        return json.dumps(result.to_dict(), indent=2)

    if output_format == "jsonl":
        return json.dumps(result.to_dict())

    # Text format
    lines = []
    if result.spans:
        lines.append(f"Found {len(result.spans)} entities:")
        for span in result.spans:
            lines.append(
                f"  [{span.start}:{span.end}] {span.entity_type}: "
                f"{span.text!r} (confidence: {span.confidence:.2f}, detector: {span.detector})"
            )
        lines.append("")
        lines.append(f"Entity counts: {result.entity_counts}")
    else:
        lines.append("No PII/PHI detected.")

    lines.append(f"Processing time: {result.processing_time_ms:.1f}ms")
    return "\n".join(lines)


def cmd_detect(args):
    """Detect PII/PHI in text."""
    from openlabels.adapters.scanner import Detector, Config

    # Maximum stdin input size (10MB) to prevent memory exhaustion
    MAX_STDIN_SIZE = 10 * 1024 * 1024

    config = Config(
        min_confidence=args.confidence,
        enable_ocr=False,
    )
    detector = Detector(config)

    text = args.text
    if text == "-":
        # SECURITY FIX (CVE-READY-001): Limit stdin read to prevent OOM
        text = sys.stdin.read(MAX_STDIN_SIZE + 1)
        if len(text) > MAX_STDIN_SIZE:
            error(f"stdin input exceeds maximum size ({MAX_STDIN_SIZE // (1024*1024)}MB)")
            sys.exit(1)

    result = detector.detect(text)
    echo(format_result(result, args.format))

    if args.fail_on_pii and result.has_pii:
        sys.exit(1)


def cmd_detect_file(args):
    """Detect PII/PHI in a file."""
    from openlabels.adapters.scanner import Detector, Config

    config = Config(
        min_confidence=args.confidence,
        enable_ocr=args.ocr,
    )
    detector = Detector(config)

    path = Path(args.file)
    if not path.exists():
        error(f"File not found: {path}")
        sys.exit(1)

    result = detector.detect_file(path)

    if args.format == "text":
        echo(f"File: {path}")
        echo(format_result(result, args.format))
    else:
        output = result.to_dict()
        output["file"] = str(path)
        echo(json.dumps(output, indent=2 if args.format == "json" else None))

    if args.fail_on_pii and result.has_pii:
        sys.exit(1)


def cmd_detect_dir(args):
    """Detect PII/PHI in all files in a directory."""
    from openlabels.adapters.scanner import Detector, Config

    config = Config(
        min_confidence=args.confidence,
        enable_ocr=args.ocr,
    )
    detector = Detector(config)

    base_path = Path(args.directory)
    if not base_path.exists():
        error(f"Directory not found: {base_path}")
        sys.exit(1)

    if not base_path.is_dir():
        error(f"Not a directory: {base_path}")
        sys.exit(1)

    # Collect files
    if args.recursive:
        files = list(base_path.rglob("*"))
    else:
        files = list(base_path.glob("*"))

    files = [f for f in files if f.is_file()]

    if args.extensions:
        exts = {e.lower().lstrip(".") for e in args.extensions.split(",")}
        files = [f for f in files if f.suffix.lower().lstrip(".") in exts]

    total_entities = 0
    files_with_pii = 0
    errors = 0

    for file_path in files:
        try:
            result = detector.detect_file(file_path)

            if result.has_pii:
                files_with_pii += 1
                total_entities += len(result.spans)

                if args.format == "json":
                    output = result.to_dict()
                    output["file"] = str(file_path)
                    echo(json.dumps(output))
                elif args.format == "summary":
                    echo(f"{file_path}: {result.entity_counts}")
                else:
                    echo("")
                    divider("=")
                    echo(f"File: {file_path}")
                    echo(format_result(result, "text"))

            elif args.verbose:
                echo(f"{file_path}: clean")

        except (OSError, ValueError) as e:
            errors += 1
            if args.verbose:
                logger.warning(f"Error processing {file_path}: {e}")

    if args.format != "json":
        echo("")
        divider("=")
        echo(f"Scanned {len(files)} files")
        echo(f"Files with PII/PHI: {files_with_pii}")
        echo(f"Total entities found: {total_entities}")
        if errors > 0:
            echo(f"Errors: {errors} file(s) failed to process")

    if args.fail_on_pii and files_with_pii > 0:
        sys.exit(1)


def cmd_version(args):
    """Show version information."""
    echo(f"openlabels {__version__}")
    echo("Universal Data Risk Scoring")
    echo("")
    echo("Commands:")
    echo("  scan        Scan files and compute risk scores")
    echo("  find        Find files matching filter criteria")
    echo("  quarantine  Move matching files to quarantine")
    echo("  report      Generate risk reports")
    echo("  heatmap     Display risk heatmap")
    echo("")
    echo("Run 'openlabels <command> --help' for details.")


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main(argv: Optional[List[str]] = None):
    """Main CLI entry point."""
    # Install signal handlers for graceful shutdown (Ctrl+C, SIGTERM)
    install_signal_handlers()

    parser = argparse.ArgumentParser(
        prog="openlabels",
        description="OpenLabels - Universal Data Risk Scoring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  openlabels scan ./data                          # Scan directory
  openlabels find . --where "score > 75"          # Find high-risk files
  openlabels quarantine ./data --where "score > 90" --to ./quarantine
  openlabels report ./data -f html -o report.html
  openlabels heatmap ./data --depth 3
        """,
    )
    parser.add_argument(
        "--version", "-V",
        action="store_true",
        help="Show version and exit",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Quiet mode (errors only)",
    )
    parser.add_argument(
        "--log-file",
        metavar="PATH",
        help="Write logs to file (JSON format)",
    )
    parser.add_argument(
        "--audit-log",
        metavar="PATH",
        help="Write audit logs to file (default: ~/.openlabels/audit.log)",
    )
    parser.add_argument(
        "--no-audit",
        action="store_true",
        help="Disable audit logging",
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable progress bars",
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # ==========================================================================
    # NEW RISK SCORING COMMANDS
    # ==========================================================================

    from openlabels.cli.commands import (
        add_scan_parser,
        add_find_parser,
        add_quarantine_parser,
        add_tag_parser,
        add_encrypt_parser,
        add_restrict_parser,
        add_report_parser,
        add_heatmap_parser,
        add_shell_parser,
        add_health_parser,
    )

    add_scan_parser(subparsers)
    add_find_parser(subparsers)
    add_quarantine_parser(subparsers)
    add_tag_parser(subparsers)
    add_encrypt_parser(subparsers)
    add_restrict_parser(subparsers)
    add_report_parser(subparsers)
    add_heatmap_parser(subparsers)
    add_shell_parser(subparsers)
    add_health_parser(subparsers)

    # ==========================================================================
    # LEGACY DETECT COMMANDS
    # ==========================================================================

    # detect command
    detect_parser = subparsers.add_parser(
        "detect",
        help="Detect PII/PHI in text (use - for stdin)",
    )
    detect_parser.add_argument("text", help="Text to scan (or - for stdin)")
    detect_parser.add_argument(
        "--format", "-f",
        choices=["text", "json", "jsonl"],
        default="text",
        help="Output format",
    )
    detect_parser.add_argument(
        "--confidence", "-c",
        type=float,
        default=0.5,
        help="Minimum confidence threshold (0-1)",
    )
    detect_parser.add_argument(
        "--fail-on-pii",
        action="store_true",
        help="Exit with code 1 if PII detected",
    )
    detect_parser.set_defaults(func=cmd_detect)

    # detect-file command
    file_parser = subparsers.add_parser(
        "detect-file",
        help="Detect PII/PHI in a file",
    )
    file_parser.add_argument("file", help="File to scan")
    file_parser.add_argument(
        "--format", "-f",
        choices=["text", "json", "jsonl"],
        default="text",
        help="Output format",
    )
    file_parser.add_argument(
        "--confidence", "-c",
        type=float,
        default=0.5,
        help="Minimum confidence threshold (0-1)",
    )
    file_parser.add_argument(
        "--ocr",
        action="store_true",
        help="Enable OCR for images/scanned PDFs",
    )
    file_parser.add_argument(
        "--fail-on-pii",
        action="store_true",
        help="Exit with code 1 if PII detected",
    )
    file_parser.set_defaults(func=cmd_detect_file)

    # detect-dir command
    dir_parser = subparsers.add_parser(
        "detect-dir",
        help="Detect PII/PHI in all files in a directory",
    )
    dir_parser.add_argument("directory", help="Directory to scan")
    dir_parser.add_argument(
        "--recursive", "-r",
        action="store_true",
        help="Scan subdirectories recursively",
    )
    dir_parser.add_argument(
        "--format", "-f",
        choices=["text", "json", "summary"],
        default="text",
        help="Output format",
    )
    dir_parser.add_argument(
        "--extensions", "-e",
        help="Comma-separated list of file extensions to scan",
    )
    dir_parser.add_argument(
        "--confidence", "-c",
        type=float,
        default=0.5,
        help="Minimum confidence threshold (0-1)",
    )
    dir_parser.add_argument(
        "--ocr",
        action="store_true",
        help="Enable OCR for images/scanned PDFs",
    )
    dir_parser.add_argument(
        "--fail-on-pii",
        action="store_true",
        help="Exit with code 1 if any PII detected",
    )
    dir_parser.set_defaults(func=cmd_detect_dir)

    # ==========================================================================
    # PARSE AND EXECUTE
    # ==========================================================================

    args = parser.parse_args(argv)

    if args.version:
        cmd_version(args)
        return

    # Configure logging
    setup_logging(
        verbose=getattr(args, "verbose", False),
        quiet=getattr(args, "quiet", False),
        log_file=getattr(args, "log_file", None),
        audit_log=getattr(args, "audit_log", None),
        no_audit=getattr(args, "no_audit", False),
    )

    # Configure progress bars
    if getattr(args, "no_progress", False):
        set_progress_enabled(False)

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    # Execute command
    result = args.func(args)

    # Handle return code
    if isinstance(result, int):
        sys.exit(result)


if __name__ == "__main__":
    main()
