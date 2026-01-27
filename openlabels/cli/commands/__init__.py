"""
OpenLabels CLI commands.

Commands:
    scan        Scan files for sensitive data and compute risk scores
    find        Find files matching filter criteria
    quarantine  Move matching files to quarantine location
    tag         Apply OpenLabels tags to files
    encrypt     Encrypt files matching filter criteria
    restrict    Restrict access permissions on files
    report      Generate risk reports (json, csv, html)
    heatmap     Display risk heatmap of directory structure
    shell       Interactive shell for exploring data risk
"""

from .scan import add_scan_parser, cmd_scan
from .find import add_find_parser, cmd_find
from .quarantine import add_quarantine_parser, cmd_quarantine
from .tag import add_tag_parser, cmd_tag
from .encrypt import add_encrypt_parser, cmd_encrypt
from .restrict import add_restrict_parser, cmd_restrict
from .report import add_report_parser, cmd_report
from .heatmap import add_heatmap_parser, cmd_heatmap
from .shell import add_shell_parser, cmd_shell

__all__ = [
    # Parsers
    "add_scan_parser",
    "add_find_parser",
    "add_quarantine_parser",
    "add_tag_parser",
    "add_encrypt_parser",
    "add_restrict_parser",
    "add_report_parser",
    "add_heatmap_parser",
    "add_shell_parser",
    # Commands
    "cmd_scan",
    "cmd_find",
    "cmd_quarantine",
    "cmd_tag",
    "cmd_encrypt",
    "cmd_restrict",
    "cmd_report",
    "cmd_heatmap",
    "cmd_shell",
]
