"""
Results table widget.

Displays scan results with risk scores, tiers, entities, and action buttons.
"""

from pathlib import Path
from typing import Optional, Dict, Any, List

from PySide6.QtWidgets import (
    QTableWidget,
    QTableWidgetItem,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QHeaderView,
    QAbstractItemView,
    QLineEdit,
    QComboBox,
)
from PySide6.QtCore import Signal, Qt
from PySide6.QtGui import QColor, QBrush


# Tier colors
TIER_COLORS = {
    "CRITICAL": QColor(220, 53, 69),    # Red
    "HIGH": QColor(253, 126, 20),       # Orange
    "MEDIUM": QColor(255, 193, 7),      # Yellow
    "LOW": QColor(40, 167, 69),         # Green
    "MINIMAL": QColor(108, 117, 125),   # Gray
    "UNKNOWN": QColor(108, 117, 125),   # Gray
}


class ResultsTableWidget(QWidget):
    """Widget displaying scan results in a table."""

    # Signals
    quarantine_requested = Signal(str)  # file_path
    label_requested = Signal(str)       # file_path

    COLUMNS = [
        ("Name", 250),
        ("Size", 80),
        ("Score", 60),
        ("Tier", 80),
        ("Entities", 200),
        ("Actions", 100),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._all_results: List[Dict[str, Any]] = []
        self._filter_path: Optional[str] = None
        self._setup_ui()

    def _setup_ui(self):
        """Setup the UI."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        # Filter bar
        filter_layout = QHBoxLayout()

        filter_label = QLabel("Filter:")
        self._filter_input = QLineEdit()
        self._filter_input.setPlaceholderText("Search by name...")
        self._filter_input.textChanged.connect(self._apply_filters)

        self._tier_filter = QComboBox()
        self._tier_filter.addItem("All Tiers", "")
        for tier in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"]:
            self._tier_filter.addItem(tier, tier)
        self._tier_filter.currentIndexChanged.connect(self._apply_filters)

        filter_layout.addWidget(filter_label)
        filter_layout.addWidget(self._filter_input, stretch=1)
        filter_layout.addWidget(self._tier_filter)

        layout.addLayout(filter_layout)

        # Table
        self._table = QTableWidget()
        self._table.setColumnCount(len(self.COLUMNS))
        self._table.setHorizontalHeaderLabels([c[0] for c in self.COLUMNS])
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.setSortingEnabled(True)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)

        # Column widths
        header = self._table.horizontalHeader()
        for i, (name, width) in enumerate(self.COLUMNS):
            self._table.setColumnWidth(i, width)
        header.setStretchLastSection(False)
        header.setSectionResizeMode(4, QHeaderView.Stretch)  # Entities column stretches

        layout.addWidget(self._table)

    def add_result(self, result: Dict[str, Any]):
        """Add a scan result to the table."""
        self._all_results.append(result)
        self._add_row(result)

    def _add_row(self, result: Dict[str, Any]):
        """Add a row to the table for a result."""
        # Check if it passes current filter
        if not self._passes_filter(result):
            return

        row = self._table.rowCount()
        self._table.insertRow(row)

        path = result.get("path", "")
        name = Path(path).name if path else ""
        size = result.get("size", 0)
        score = result.get("score", 0)
        tier = result.get("tier", "UNKNOWN")
        entities = result.get("entities", {})
        error = result.get("error")

        # Name
        name_item = QTableWidgetItem(name)
        name_item.setToolTip(path)
        name_item.setData(Qt.UserRole, path)  # Store full path
        self._table.setItem(row, 0, name_item)

        # Size
        size_str = self._format_size(size)
        size_item = QTableWidgetItem(size_str)
        size_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self._table.setItem(row, 1, size_item)

        # Score
        score_item = QTableWidgetItem(str(score) if not error else "--")
        score_item.setTextAlignment(Qt.AlignCenter)
        score_item.setData(Qt.UserRole, score)  # For sorting
        if tier in TIER_COLORS:
            score_item.setForeground(QBrush(TIER_COLORS[tier]))
        self._table.setItem(row, 2, score_item)

        # Tier
        tier_item = QTableWidgetItem(tier if not error else "ERROR")
        tier_item.setTextAlignment(Qt.AlignCenter)
        if tier in TIER_COLORS:
            tier_item.setBackground(QBrush(TIER_COLORS[tier]))
            # White text for dark backgrounds
            if tier in ["CRITICAL", "HIGH", "MINIMAL", "UNKNOWN"]:
                tier_item.setForeground(QBrush(QColor(255, 255, 255)))
            else:
                tier_item.setForeground(QBrush(QColor(0, 0, 0)))
        self._table.setItem(row, 3, tier_item)

        # Entities
        if error:
            entities_str = f"Error: {error}"
        else:
            entities_str = ", ".join(f"{k}({v})" for k, v in entities.items()) if entities else "-"
        entities_item = QTableWidgetItem(entities_str)
        self._table.setItem(row, 4, entities_item)

        # Actions - widget with buttons
        actions_widget = QWidget()
        actions_layout = QHBoxLayout(actions_widget)
        actions_layout.setContentsMargins(4, 2, 4, 2)
        actions_layout.setSpacing(4)

        quarantine_btn = QPushButton("Q")
        quarantine_btn.setToolTip("Quarantine")
        quarantine_btn.setMaximumWidth(30)
        quarantine_btn.clicked.connect(lambda checked, p=path: self.quarantine_requested.emit(p))

        label_btn = QPushButton("L")
        label_btn.setToolTip("Add Label")
        label_btn.setMaximumWidth(30)
        label_btn.clicked.connect(lambda checked, p=path: self.label_requested.emit(p))

        actions_layout.addWidget(quarantine_btn)
        actions_layout.addWidget(label_btn)
        actions_layout.addStretch()

        self._table.setCellWidget(row, 5, actions_widget)

    def _passes_filter(self, result: Dict[str, Any]) -> bool:
        """Check if a result passes current filters."""
        path = result.get("path", "")
        tier = result.get("tier", "")

        # Path filter
        if self._filter_path:
            if not path.startswith(self._filter_path):
                return False

        # Text filter
        text_filter = self._filter_input.text().strip().lower()
        if text_filter:
            name = Path(path).name.lower() if path else ""
            if text_filter not in name:
                return False

        # Tier filter
        tier_filter = self._tier_filter.currentData()
        if tier_filter and tier != tier_filter:
            return False

        return True

    def _apply_filters(self):
        """Reapply all filters to the table."""
        self._table.setRowCount(0)
        for result in self._all_results:
            self._add_row(result)

    def filter_by_path(self, path: str):
        """Filter results to show only files under a path."""
        self._filter_path = path
        self._apply_filters()

    def clear_path_filter(self):
        """Clear the path filter."""
        self._filter_path = None
        self._apply_filters()

    def clear(self):
        """Clear all results."""
        self._all_results.clear()
        self._table.setRowCount(0)

    def remove_result(self, file_path: str):
        """Remove a result by file path."""
        # Remove from internal list
        self._all_results = [r for r in self._all_results if r.get("path") != file_path]

        # Remove from table
        for row in range(self._table.rowCount()):
            item = self._table.item(row, 0)
            if item and item.data(Qt.UserRole) == file_path:
                self._table.removeRow(row)
                break

    def get_all_results(self) -> List[Dict[str, Any]]:
        """Get all results."""
        return self._all_results.copy()

    def _format_size(self, size: int) -> str:
        """Format file size for display."""
        if size <= 0:
            return "-"
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.0f}{unit}" if unit == "B" else f"{size:.1f}{unit}"
            size /= 1024
        return f"{size:.1f}TB"
