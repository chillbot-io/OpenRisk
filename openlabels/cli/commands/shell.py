"""
OpenLabels shell command.

Interactive shell for exploring and managing data risk.

Usage:
    openlabels shell <path>
    openlabels shell ./data
    openlabels shell s3://bucket

Commands in shell:
    find <filter>     - Find files matching filter
    scan <path>       - Scan a specific file
    info <path>       - Show detailed info for a file
    stats             - Show statistics for current scope
    top [n]           - Show top N riskiest files
    help              - Show available commands
    exit              - Exit the shell
"""

import sys
import readline  # noqa: F401 - imported for side effect (enables command history)
from pathlib import Path
from typing import Optional, List

from openlabels import Client
from openlabels.cli.commands.find import find_matching
from openlabels.cli.commands.scan import ScanResult


class OpenLabelsShell:
    """Interactive shell for OpenLabels."""

    def __init__(self, base_path: str, exposure: str = "PRIVATE"):
        self.base_path = base_path
        self.exposure = exposure
        self.client = Client(default_exposure=exposure)
        self.results_cache: List[ScanResult] = []
        self.running = True

    def run(self):
        """Run the interactive shell."""
        print(f"OpenLabels Shell")
        print(f"Base path: {self.base_path}")
        print(f"Type 'help' for available commands, 'exit' to quit")
        print()

        while self.running:
            try:
                line = input("openlabels> ").strip()
                if not line:
                    continue

                self.execute(line)

            except KeyboardInterrupt:
                print()
                continue
            except EOFError:
                print()
                break

    def execute(self, line: str):
        """Execute a shell command."""
        parts = line.split(maxsplit=1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        commands = {
            "find": self.cmd_find,
            "scan": self.cmd_scan,
            "info": self.cmd_info,
            "stats": self.cmd_stats,
            "top": self.cmd_top,
            "help": self.cmd_help,
            "exit": self.cmd_exit,
            "quit": self.cmd_exit,
            "ls": self.cmd_ls,
            "cd": self.cmd_cd,
        }

        handler = commands.get(cmd)
        if handler:
            handler(args)
        else:
            print(f"Unknown command: {cmd}")
            print("Type 'help' for available commands")

    def cmd_find(self, args: str):
        """Find files matching filter."""
        if not args:
            print("Usage: find <filter>")
            print("Example: find score > 50 AND has(SSN)")
            return

        try:
            source = Path(self.base_path) if not self.base_path.startswith(('s3://', 'gs://', 'azure://')) else self.base_path

            if isinstance(source, str):
                print("Cloud storage not yet supported in shell")
                return

            results = list(find_matching(
                source,
                self.client,
                filter_expr=args,
                recursive=True,
                exposure=self.exposure,
            ))

            self.results_cache = results

            if not results:
                print("No files match the filter")
                return

            print(f"\nFound {len(results)} files:\n")
            for r in results[:20]:
                entities = ", ".join(f"{k}({v})" for k, v in r.entities.items()) if r.entities else "none"
                print(f"  {r.score:3d} {r.tier:8s} {r.path}")
                if r.entities:
                    print(f"      entities: {entities}")

            if len(results) > 20:
                print(f"\n  ... and {len(results) - 20} more")

        except Exception as e:
            print(f"Error: {e}")

    def cmd_scan(self, args: str):
        """Scan a specific file."""
        if not args:
            print("Usage: scan <path>")
            return

        try:
            path = Path(args)
            if not path.is_absolute():
                base = Path(self.base_path) if not self.base_path.startswith(('s3://',)) else Path('.')
                path = base / args

            if not path.exists():
                print(f"File not found: {path}")
                return

            result = self.client.score_file(str(path), exposure=self.exposure)

            print(f"\nFile: {path}")
            print(f"Score: {result.score} ({result.tier})")
            print(f"Content score: {result.content_score}")
            print(f"Exposure: {result.exposure} (×{result.exposure_multiplier})")

            if result.entities:
                print(f"\nEntities:")
                for k, v in result.entities.items():
                    print(f"  {k}: {v}")

            if result.co_occurrence_rules:
                print(f"\nCo-occurrence rules: {', '.join(result.co_occurrence_rules)}")

        except Exception as e:
            print(f"Error: {e}")

    def cmd_info(self, args: str):
        """Show detailed info for a file."""
        # Same as scan for now
        self.cmd_scan(args)

    def cmd_stats(self, args: str):
        """Show statistics for the base path."""
        try:
            source = Path(self.base_path)
            if not source.exists():
                print(f"Path not found: {source}")
                return

            # Quick scan
            print(f"Scanning {source}...")

            results = list(find_matching(
                source,
                self.client,
                filter_expr=None,
                recursive=True,
                exposure=self.exposure,
            ))

            self.results_cache = results

            if not results:
                print("No files found")
                return

            # Calculate statistics
            total = len(results)
            scores = [r.score for r in results]
            avg_score = sum(scores) / total
            max_score = max(scores)
            min_score = min(scores)

            tiers = {}
            for r in results:
                tiers[r.tier] = tiers.get(r.tier, 0) + 1

            entity_counts = {}
            for r in results:
                for k, v in r.entities.items():
                    entity_counts[k] = entity_counts.get(k, 0) + v

            print(f"\n{'='*60}")
            print(f"Statistics for: {source}")
            print(f"{'='*60}")
            print(f"Total files:  {total}")
            print(f"Avg score:    {avg_score:.1f}")
            print(f"Max score:    {max_score}")
            print(f"Min score:    {min_score}")
            print()
            print("By tier:")
            for tier in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"]:
                count = tiers.get(tier, 0)
                pct = count / total * 100
                bar = "█" * int(pct / 5)
                print(f"  {tier:8s}: {count:4d} ({pct:5.1f}%) {bar}")

            if entity_counts:
                print()
                print("Top entities:")
                sorted_entities = sorted(entity_counts.items(), key=lambda x: -x[1])[:10]
                for k, v in sorted_entities:
                    print(f"  {k}: {v}")

        except Exception as e:
            print(f"Error: {e}")

    def cmd_top(self, args: str):
        """Show top N riskiest files."""
        try:
            n = int(args) if args else 10
        except ValueError:
            n = 10

        if not self.results_cache:
            # Do a quick scan
            source = Path(self.base_path)
            if source.exists():
                self.results_cache = list(find_matching(
                    source,
                    self.client,
                    filter_expr=None,
                    recursive=True,
                    exposure=self.exposure,
                ))

        if not self.results_cache:
            print("No files scanned. Run 'stats' or 'find' first.")
            return

        sorted_results = sorted(self.results_cache, key=lambda x: -x.score)[:n]

        print(f"\nTop {n} riskiest files:\n")
        for i, r in enumerate(sorted_results, 1):
            print(f"  {i:2d}. [{r.score:3d}] {r.tier:8s} {r.path}")

    def cmd_ls(self, args: str):
        """List files in current scope."""
        try:
            path = Path(args) if args else Path(self.base_path)
            if not path.is_absolute() and args:
                path = Path(self.base_path) / args

            if not path.exists():
                print(f"Path not found: {path}")
                return

            if path.is_file():
                print(path)
                return

            for item in sorted(path.iterdir()):
                prefix = "d" if item.is_dir() else "-"
                print(f"  {prefix} {item.name}")

        except Exception as e:
            print(f"Error: {e}")

    def cmd_cd(self, args: str):
        """Change base path."""
        if not args:
            print(f"Current path: {self.base_path}")
            return

        new_path = Path(args)
        if not new_path.is_absolute():
            new_path = Path(self.base_path) / args

        if new_path.exists():
            self.base_path = str(new_path.resolve())
            self.results_cache = []
            print(f"Changed to: {self.base_path}")
        else:
            print(f"Path not found: {new_path}")

    def cmd_help(self, args: str):
        """Show help."""
        print("""
OpenLabels Shell Commands:

  find <filter>    Find files matching filter expression
                   Example: find score > 50 AND has(SSN)

  scan <path>      Scan and show details for a specific file
  info <path>      Same as scan

  stats            Show statistics for the current scope
  top [n]          Show top N riskiest files (default: 10)

  ls [path]        List files in path
  cd <path>        Change base path

  help             Show this help message
  exit / quit      Exit the shell

Filter syntax:
  score > 50                     Score greater than 50
  exposure = public              Public exposure
  has(SSN)                       Contains SSN entities
  last_accessed > 1y             Not accessed in 1 year
  score > 75 AND has(CREDIT_CARD)  Combine conditions
""")

    def cmd_exit(self, args: str):
        """Exit the shell."""
        self.running = False
        print("Goodbye!")


def cmd_shell(args) -> int:
    """Execute the shell command."""
    source = args.source

    # Validate path
    if not source.startswith(('s3://', 'gs://', 'azure://')):
        path = Path(source)
        if not path.exists():
            print(f"Error: Path not found: {source}", file=sys.stderr)
            return 1

    shell = OpenLabelsShell(source, exposure=args.exposure)
    shell.run()

    return 0


def add_shell_parser(subparsers):
    """Add the shell subparser."""
    parser = subparsers.add_parser(
        "shell",
        help="Interactive shell for exploring data risk",
    )
    parser.add_argument(
        "source",
        help="Base path to explore",
    )
    parser.add_argument(
        "--exposure", "-e",
        choices=["PRIVATE", "INTERNAL", "ORG_WIDE", "PUBLIC"],
        default="PRIVATE",
        help="Default exposure level for scoring",
    )
    parser.set_defaults(func=cmd_shell)

    return parser
