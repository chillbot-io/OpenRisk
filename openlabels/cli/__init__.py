"""
OpenLabels CLI.

Command-line interface for scanning, finding, and managing data risk.

Usage:
    openlabels scan <path>                     # Scan and score files
    openlabels find <path> --where "<filter>"  # Find matching files
    openlabels quarantine <src> --to <dst>     # Move risky files
    openlabels report <path> --format html     # Generate reports
    openlabels heatmap <path>                  # Visual risk heatmap
"""

from .main import main
from .filter import Filter, parse_filter, matches_filter, FilterBuilder

__all__ = [
    "main",
    "Filter",
    "parse_filter",
    "matches_filter",
    "FilterBuilder",
]
