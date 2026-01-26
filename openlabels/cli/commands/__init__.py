"""
OpenLabels CLI commands.

Commands:
    scan        Scan files for sensitive data and compute risk scores
    find        Find files matching filter criteria
    quarantine  Move matching files to quarantine location
    report      Generate risk reports (json, csv, html)
    heatmap     Display risk heatmap of directory structure
"""

from .scan import add_scan_parser, cmd_scan
from .find import add_find_parser, cmd_find
from .quarantine import add_quarantine_parser, cmd_quarantine
from .report import add_report_parser, cmd_report
from .heatmap import add_heatmap_parser, cmd_heatmap

__all__ = [
    # Parsers
    "add_scan_parser",
    "add_find_parser",
    "add_quarantine_parser",
    "add_report_parser",
    "add_heatmap_parser",
    # Commands
    "cmd_scan",
    "cmd_find",
    "cmd_quarantine",
    "cmd_report",
    "cmd_heatmap",
]
