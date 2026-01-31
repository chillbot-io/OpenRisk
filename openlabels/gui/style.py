"""
OpenLabels GUI Style.

Modern, clean stylesheet for the application with OpenLabels brand colors.
"""

# Brand colors
COLORS = {
    "primary": "#2563eb",       # Blue - main brand color
    "primary_dark": "#1d4ed8",  # Darker blue for hover
    "primary_light": "#3b82f6", # Lighter blue
    "accent": "#0ea5e9",        # Sky blue accent

    "success": "#22c55e",       # Green
    "warning": "#f59e0b",       # Amber
    "danger": "#ef4444",        # Red

    "bg": "#ffffff",            # White background
    "bg_secondary": "#f8fafc",  # Light gray background
    "bg_tertiary": "#f1f5f9",   # Slightly darker gray

    "border": "#e2e8f0",        # Light border
    "border_focus": "#2563eb",  # Focus border

    "text": "#1e293b",          # Dark text
    "text_secondary": "#64748b", # Gray text
    "text_muted": "#94a3b8",    # Muted text

    # Risk tier colors
    "tier_critical": "#dc2626",
    "tier_high": "#ea580c",
    "tier_medium": "#d97706",
    "tier_low": "#16a34a",
    "tier_minimal": "#64748b",
}


def get_stylesheet() -> str:
    """Return the complete Qt stylesheet."""
    return f"""
/* Global */
QWidget {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    font-size: 13px;
    color: {COLORS["text"]};
}}

QMainWindow {{
    background-color: {COLORS["bg"]};
}}

/* Group Boxes */
QGroupBox {{
    font-weight: 600;
    font-size: 14px;
    border: 1px solid {COLORS["border"]};
    border-radius: 8px;
    margin-top: 12px;
    padding: 16px 12px 12px 12px;
    background-color: {COLORS["bg"]};
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 12px;
    padding: 0 8px;
    background-color: {COLORS["bg"]};
    color: {COLORS["text"]};
}}

/* Buttons */
QPushButton {{
    background-color: {COLORS["primary"]};
    color: white;
    border: none;
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: 500;
    min-height: 20px;
}}

QPushButton:hover {{
    background-color: {COLORS["primary_dark"]};
}}

QPushButton:pressed {{
    background-color: {COLORS["primary_dark"]};
}}

QPushButton:disabled {{
    background-color: {COLORS["border"]};
    color: {COLORS["text_muted"]};
}}

/* Secondary buttons */
QPushButton[secondary="true"], QPushButton#secondaryButton {{
    background-color: {COLORS["bg_tertiary"]};
    color: {COLORS["text"]};
    border: 1px solid {COLORS["border"]};
}}

QPushButton[secondary="true"]:hover, QPushButton#secondaryButton:hover {{
    background-color: {COLORS["border"]};
}}

/* Danger buttons */
QPushButton[danger="true"], QPushButton#dangerButton {{
    background-color: {COLORS["danger"]};
}}

QPushButton[danger="true"]:hover, QPushButton#dangerButton:hover {{
    background-color: #dc2626;
}}

/* Input fields */
QLineEdit, QTextEdit, QPlainTextEdit {{
    background-color: {COLORS["bg"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 6px;
    padding: 8px 12px;
    selection-background-color: {COLORS["primary_light"]};
}}

QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {{
    border-color: {COLORS["border_focus"]};
    outline: none;
}}

QLineEdit:disabled {{
    background-color: {COLORS["bg_tertiary"]};
    color: {COLORS["text_muted"]};
}}

/* Combo boxes */
QComboBox {{
    background-color: {COLORS["bg"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 6px;
    padding: 8px 12px;
    min-width: 120px;
}}

QComboBox:focus {{
    border-color: {COLORS["border_focus"]};
}}

QComboBox::drop-down {{
    border: none;
    width: 24px;
}}

QComboBox::down-arrow {{
    width: 12px;
    height: 12px;
}}

QComboBox QAbstractItemView {{
    background-color: {COLORS["bg"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 6px;
    selection-background-color: {COLORS["primary_light"]};
    selection-color: white;
}}

/* Tables */
QTableWidget, QTableView {{
    background-color: {COLORS["bg"]};
    alternate-background-color: {COLORS["bg_secondary"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 8px;
    gridline-color: {COLORS["border"]};
    selection-background-color: {COLORS["primary_light"]};
    selection-color: white;
}}

QTableWidget::item, QTableView::item {{
    padding: 8px;
}}

QHeaderView::section {{
    background-color: {COLORS["bg_tertiary"]};
    color: {COLORS["text"]};
    font-weight: 600;
    padding: 10px 8px;
    border: none;
    border-bottom: 2px solid {COLORS["border"]};
}}

QHeaderView::section:first {{
    border-top-left-radius: 8px;
}}

QHeaderView::section:last {{
    border-top-right-radius: 8px;
}}

/* Tab widget */
QTabWidget::pane {{
    border: 1px solid {COLORS["border"]};
    border-radius: 8px;
    background-color: {COLORS["bg"]};
    top: -1px;
}}

QTabBar::tab {{
    background-color: {COLORS["bg_tertiary"]};
    color: {COLORS["text_secondary"]};
    border: 1px solid {COLORS["border"]};
    border-bottom: none;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    padding: 10px 20px;
    margin-right: 2px;
    font-weight: 500;
}}

QTabBar::tab:selected {{
    background-color: {COLORS["bg"]};
    color: {COLORS["primary"]};
    border-bottom: 2px solid {COLORS["primary"]};
}}

QTabBar::tab:hover:!selected {{
    background-color: {COLORS["bg_secondary"]};
}}

/* Progress bar */
QProgressBar {{
    background-color: {COLORS["bg_tertiary"]};
    border: none;
    border-radius: 4px;
    height: 8px;
    text-align: center;
}}

QProgressBar::chunk {{
    background-color: {COLORS["primary"]};
    border-radius: 4px;
}}

/* Scroll bars */
QScrollBar:vertical {{
    background-color: {COLORS["bg_secondary"]};
    width: 12px;
    border-radius: 6px;
    margin: 0;
}}

QScrollBar::handle:vertical {{
    background-color: {COLORS["border"]};
    border-radius: 6px;
    min-height: 30px;
    margin: 2px;
}}

QScrollBar::handle:vertical:hover {{
    background-color: {COLORS["text_muted"]};
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0;
}}

QScrollBar:horizontal {{
    background-color: {COLORS["bg_secondary"]};
    height: 12px;
    border-radius: 6px;
    margin: 0;
}}

QScrollBar::handle:horizontal {{
    background-color: {COLORS["border"]};
    border-radius: 6px;
    min-width: 30px;
    margin: 2px;
}}

QScrollBar::handle:horizontal:hover {{
    background-color: {COLORS["text_muted"]};
}}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0;
}}

/* Tree view */
QTreeView, QTreeWidget {{
    background-color: {COLORS["bg"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 8px;
    alternate-background-color: {COLORS["bg_secondary"]};
}}

QTreeView::item {{
    padding: 6px 4px;
}}

QTreeView::item:selected {{
    background-color: {COLORS["primary_light"]};
    color: white;
}}

QTreeView::item:hover:!selected {{
    background-color: {COLORS["bg_tertiary"]};
}}

/* Splitter */
QSplitter::handle {{
    background-color: {COLORS["border"]};
}}

QSplitter::handle:horizontal {{
    width: 2px;
}}

QSplitter::handle:vertical {{
    height: 2px;
}}

/* Status bar */
QStatusBar {{
    background-color: {COLORS["bg_secondary"]};
    border-top: 1px solid {COLORS["border"]};
    padding: 4px 8px;
}}

QStatusBar::item {{
    border: none;
}}

/* Menu bar */
QMenuBar {{
    background-color: {COLORS["bg"]};
    border-bottom: 1px solid {COLORS["border"]};
    padding: 4px;
}}

QMenuBar::item {{
    padding: 6px 12px;
    border-radius: 4px;
}}

QMenuBar::item:selected {{
    background-color: {COLORS["bg_tertiary"]};
}}

QMenu {{
    background-color: {COLORS["bg"]};
    border: 1px solid {COLORS["border"]};
    border-radius: 8px;
    padding: 4px;
}}

QMenu::item {{
    padding: 8px 24px;
    border-radius: 4px;
}}

QMenu::item:selected {{
    background-color: {COLORS["primary_light"]};
    color: white;
}}

QMenu::separator {{
    height: 1px;
    background-color: {COLORS["border"]};
    margin: 4px 8px;
}}

/* Labels */
QLabel {{
    color: {COLORS["text"]};
}}

QLabel[heading="true"] {{
    font-size: 18px;
    font-weight: 600;
}}

QLabel[subheading="true"] {{
    font-size: 14px;
    color: {COLORS["text_secondary"]};
}}

QLabel[muted="true"] {{
    color: {COLORS["text_muted"]};
}}

/* Check boxes */
QCheckBox {{
    spacing: 8px;
}}

QCheckBox::indicator {{
    width: 18px;
    height: 18px;
    border: 2px solid {COLORS["border"]};
    border-radius: 4px;
    background-color: {COLORS["bg"]};
}}

QCheckBox::indicator:checked {{
    background-color: {COLORS["primary"]};
    border-color: {COLORS["primary"]};
}}

/* Dialogs */
QDialog {{
    background-color: {COLORS["bg"]};
}}

QMessageBox {{
    background-color: {COLORS["bg"]};
}}

/* Tool tips */
QToolTip {{
    background-color: {COLORS["text"]};
    color: white;
    border: none;
    border-radius: 4px;
    padding: 6px 10px;
}}
"""


def get_tier_color(tier: str) -> str:
    """Get the color for a risk tier."""
    tier_colors = {
        "CRITICAL": COLORS["tier_critical"],
        "HIGH": COLORS["tier_high"],
        "MEDIUM": COLORS["tier_medium"],
        "LOW": COLORS["tier_low"],
        "MINIMAL": COLORS["tier_minimal"],
        "UNKNOWN": COLORS["text_muted"],
    }
    return tier_colors.get(tier.upper(), COLORS["text_muted"])
