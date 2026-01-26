"""
OpenLabels heatmap command.

Display a visual risk heatmap of directory structure.

Usage:
    openlabels heatmap <path>
    openlabels heatmap ./data --depth 3
"""

import sys
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from openlabels import Client
from openlabels.cli.commands.scan import scan_file, ScanResult


@dataclass
class TreeNode:
    """A node in the directory tree."""
    name: str
    path: Path
    is_dir: bool
    score: int = 0
    tier: str = ""
    children: List["TreeNode"] = field(default_factory=list)
    entity_counts: Dict[str, int] = field(default_factory=dict)
    file_count: int = 0
    error: Optional[str] = None

    @property
    def avg_score(self) -> float:
        """Calculate average score including children."""
        if not self.is_dir:
            return float(self.score)

        if not self.children:
            return 0.0

        total = sum(c.avg_score for c in self.children)
        return total / len(self.children) if self.children else 0.0

    @property
    def max_score(self) -> int:
        """Get maximum score including children."""
        if not self.is_dir:
            return self.score

        if not self.children:
            return 0

        return max(c.max_score for c in self.children)


def build_tree(
    path: Path,
    client: Client,
    depth: int = 3,
    current_depth: int = 0,
    exposure: str = "PRIVATE",
    extensions: Optional[List[str]] = None,
) -> TreeNode:
    """Build a tree structure with risk scores."""
    node = TreeNode(
        name=path.name or str(path),
        path=path,
        is_dir=path.is_dir(),
    )

    if path.is_file():
        # Scan file using scan_file for proper entity tracking
        scan_result = scan_file(path, client, exposure)
        node.score = scan_result.score
        node.tier = scan_result.tier
        node.entity_counts = scan_result.entities
        node.file_count = 1
        node.error = scan_result.error
        return node

    if current_depth >= depth:
        # At max depth, scan all files in this directory recursively
        total_score = 0
        file_count = 0
        all_entities: Dict[str, int] = {}

        for file_path in path.rglob("*"):
            if not file_path.is_file():
                continue

            if extensions:
                if file_path.suffix.lower().lstrip(".") not in extensions:
                    continue

            scan_result = scan_file(file_path, client, exposure)
            total_score += scan_result.score
            file_count += 1

            for etype, count in scan_result.entities.items():
                all_entities[etype] = all_entities.get(etype, 0) + count

        node.score = total_score // file_count if file_count else 0
        node.file_count = file_count
        node.entity_counts = all_entities
        return node

    # Recurse into children
    try:
        children = sorted(path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
    except PermissionError:
        node.error = "Permission denied"
        return node

    for child_path in children:
        # Skip hidden files/dirs
        if child_path.name.startswith("."):
            continue

        if child_path.is_file():
            if extensions:
                if child_path.suffix.lower().lstrip(".") not in extensions:
                    continue

        child_node = build_tree(
            child_path,
            client,
            depth=depth,
            current_depth=current_depth + 1,
            exposure=exposure,
            extensions=extensions,
        )
        node.children.append(child_node)

    # Aggregate stats
    node.file_count = sum(c.file_count for c in node.children)
    for child in node.children:
        for etype, count in child.entity_counts.items():
            node.entity_counts[etype] = node.entity_counts.get(etype, 0) + count

    return node


def score_to_bar(score: float, width: int = 20) -> str:
    """Convert score to a visual bar."""
    filled = int(score / 100 * width)
    return "█" * filled + "░" * (width - filled)


def score_to_indicator(score: float) -> str:
    """Get color indicator for score."""
    if score >= 90:
        return "🔴"  # Critical
    elif score >= 70:
        return "🟠"  # High
    elif score >= 50:
        return "🟡"  # Medium
    elif score >= 25:
        return "🟢"  # Low
    else:
        return "⚪"  # Minimal


def score_to_ansi(score: float) -> str:
    """Get ANSI color code for score."""
    if score >= 90:
        return "\033[91m"  # Red
    elif score >= 70:
        return "\033[93m"  # Yellow
    elif score >= 50:
        return "\033[33m"  # Orange
    elif score >= 25:
        return "\033[92m"  # Green
    else:
        return "\033[90m"  # Gray


def render_tree(
    node: TreeNode,
    indent: int = 0,
    prefix: str = "",
    is_last: bool = True,
    use_color: bool = True,
    show_entities: bool = False,
) -> List[str]:
    """Render a tree node as formatted text lines."""
    lines = []
    reset = "\033[0m" if use_color else ""

    # Build the tree branch characters
    if indent == 0:
        branch = ""
    else:
        branch = prefix + ("└── " if is_last else "├── ")

    # Get score info
    if node.is_dir:
        avg = node.avg_score
        max_s = node.max_score
        color = score_to_ansi(max_s) if use_color else ""
        indicator = score_to_indicator(max_s)
        bar = score_to_bar(avg)
        score_str = f"{bar} avg:{avg:>5.1f} max:{max_s:>3}"
        icon = "📁"
        name = f"{node.name}/" if node.name else str(node.path)
        files_str = f"({node.file_count} files)"
    else:
        color = score_to_ansi(node.score) if use_color else ""
        indicator = score_to_indicator(node.score)
        bar = score_to_bar(node.score)
        score_str = f"{bar} {node.score:>3}"
        icon = "📄"
        name = node.name
        files_str = ""

    # Error handling
    if node.error:
        lines.append(f"{branch}{icon} {name} [ERROR: {node.error}]")
    else:
        line = f"{branch}{icon} {name:<40} {color}{score_str}{reset} {indicator} {files_str}"
        lines.append(line.rstrip())

        # Show entities if requested
        if show_entities and node.entity_counts:
            entities = ", ".join(f"{k}({v})" for k, v in sorted(node.entity_counts.items()))
            entity_prefix = prefix + ("    " if is_last else "│   ") if indent > 0 else ""
            lines.append(f"{entity_prefix}    └─ {entities}")

    # Render children
    if node.children:
        child_prefix = prefix + ("    " if is_last else "│   ") if indent > 0 else ""

        for i, child in enumerate(node.children):
            child_is_last = (i == len(node.children) - 1)
            lines.extend(render_tree(
                child,
                indent=indent + 1,
                prefix=child_prefix,
                is_last=child_is_last,
                use_color=use_color,
                show_entities=show_entities,
            ))

    return lines


def cmd_heatmap(args) -> int:
    """Execute the heatmap command."""
    path = Path(args.path)

    if not path.exists():
        print(f"Error: Path not found: {path}", file=sys.stderr)
        return 1

    client = Client(default_exposure=args.exposure)
    extensions = args.extensions.split(",") if args.extensions else None

    print(f"Building risk heatmap for {path}...\n", file=sys.stderr)

    # Build tree
    tree = build_tree(
        path,
        client,
        depth=args.depth,
        exposure=args.exposure,
        extensions=extensions,
    )

    # Render and print
    use_color = not args.no_color and sys.stdout.isatty()
    lines = render_tree(
        tree,
        use_color=use_color,
        show_entities=args.show_entities,
    )

    for line in lines:
        print(line)

    # Print legend
    print()
    print("Legend: 🔴 Critical(90+) 🟠 High(70-89) 🟡 Medium(50-69) 🟢 Low(25-49) ⚪ Minimal(<25)")

    # Print summary
    print()
    print(f"Total files: {tree.file_count}")
    print(f"Max score: {tree.max_score}")
    print(f"Avg score: {tree.avg_score:.1f}")

    if tree.entity_counts:
        top_entities = sorted(tree.entity_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        entities_str = ", ".join(f"{k}({v})" for k, v in top_entities)
        print(f"Top entities: {entities_str}")

    return 0


def add_heatmap_parser(subparsers):
    """Add the heatmap subparser."""
    parser = subparsers.add_parser(
        "heatmap",
        help="Display risk heatmap of directory structure",
    )
    parser.add_argument(
        "path",
        help="Path to visualize",
    )
    parser.add_argument(
        "--depth", "-d",
        type=int,
        default=3,
        help="Maximum directory depth to display (default: 3)",
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
        "--show-entities", "-s",
        action="store_true",
        help="Show entity types for each item",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    parser.set_defaults(func=cmd_heatmap)

    return parser
