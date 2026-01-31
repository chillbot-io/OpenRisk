"""
Label Preview Widget.

Displays the OpenLabels portable label format in a beautiful, readable way.
This is the core visual that shows what makes OpenLabels unique - the portable,
durable, risk-informed label that travels with files.
"""

import json
from typing import Dict, Any, List, Optional
from datetime import datetime

from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QFrame,
    QTextEdit,
    QPushButton,
    QScrollArea,
    QGridLayout,
    QSizePolicy,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QColor

from openlabels.gui.style import COLORS, get_tier_color


class LabelPreviewWidget(QWidget):
    """
    Widget that displays the OpenLabels format for a scanned file.

    Shows:
    - The portable label ID (ol_xxx)
    - Content hash for versioning
    - Detected entities with value hashes
    - Risk tier visualization
    - Export options (JSON, embed)
    """

    export_requested = Signal(str)  # format: "json", "embed", "xattr"
    label_copied = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._label_data: Optional[Dict[str, Any]] = None
        self._file_path: Optional[str] = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)

        # Header with OpenLabels branding
        header = self._create_header()
        layout.addWidget(header)

        # Main label card
        self._label_card = self._create_label_card()
        layout.addWidget(self._label_card)

        # JSON preview (collapsible)
        self._json_section = self._create_json_section()
        layout.addWidget(self._json_section)

        # Export actions
        actions = self._create_actions()
        layout.addWidget(actions)

        layout.addStretch()

    def _create_header(self) -> QWidget:
        """Create the OpenLabels branded header."""
        header = QFrame()
        header.setStyleSheet(f"""
            QFrame {{
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 {COLORS["primary"]},
                    stop:1 {COLORS["accent"]}
                );
                border-radius: 12px;
                padding: 16px;
            }}
        """)
        layout = QHBoxLayout(header)

        # Logo/icon
        logo = QLabel("<OL>")
        logo.setFont(QFont("Consolas, Monaco, monospace", 20, QFont.Bold))
        logo.setStyleSheet("color: white; background: transparent;")
        layout.addWidget(logo)

        # Title
        title_layout = QVBoxLayout()
        title_layout.setSpacing(2)

        title = QLabel("OpenLabels")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setStyleSheet("color: white; background: transparent;")
        title_layout.addWidget(title)

        subtitle = QLabel("Portable Risk Label")
        subtitle.setStyleSheet("color: rgba(255,255,255,0.8); background: transparent;")
        title_layout.addWidget(subtitle)

        layout.addLayout(title_layout)
        layout.addStretch()

        # Tier badge (will be updated)
        self._tier_badge = QLabel("--")
        self._tier_badge.setFont(QFont("Arial", 14, QFont.Bold))
        self._tier_badge.setStyleSheet("""
            background-color: rgba(255,255,255,0.2);
            color: white;
            padding: 8px 16px;
            border-radius: 20px;
        """)
        self._tier_badge.setAlignment(Qt.AlignCenter)
        layout.addWidget(self._tier_badge)

        return header

    def _create_label_card(self) -> QFrame:
        """Create the main label visualization card."""
        card = QFrame()
        card.setObjectName("labelCard")
        card.setStyleSheet(f"""
            QFrame#labelCard {{
                background-color: {COLORS["bg_secondary"]};
                border: 2px solid {COLORS["border"]};
                border-radius: 12px;
                padding: 20px;
            }}
            QFrame#labelCard QLabel {{
                background-color: transparent;
            }}
        """)
        layout = QVBoxLayout(card)
        layout.setSpacing(16)

        # Label ID row
        id_row = QHBoxLayout()

        id_label = QLabel("Label ID")
        id_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-weight: 500; background: transparent;")
        id_row.addWidget(id_label)

        self._label_id = QLabel("ol_____________")
        self._label_id.setFont(QFont("Consolas, Monaco, monospace", 16, QFont.Bold))
        self._label_id.setStyleSheet(f"color: {COLORS['primary']}; background: transparent;")
        self._label_id.setTextInteractionFlags(Qt.TextSelectableByMouse)
        id_row.addWidget(self._label_id)
        id_row.addStretch()

        layout.addLayout(id_row)

        # Divider
        divider = QFrame()
        divider.setFixedHeight(1)
        divider.setStyleSheet(f"background-color: {COLORS['border']};")
        layout.addWidget(divider)

        # Grid of label properties
        grid = QGridLayout()
        grid.setSpacing(12)

        # Content Hash
        grid.addWidget(self._create_property_label("Content Hash"), 0, 0)
        self._content_hash = self._create_value_label("____________")
        self._content_hash.setFont(QFont("Consolas, Monaco, monospace", 12))
        grid.addWidget(self._content_hash, 0, 1)

        # Timestamp
        grid.addWidget(self._create_property_label("Scanned"), 1, 0)
        self._timestamp = self._create_value_label("--")
        grid.addWidget(self._timestamp, 1, 1)

        # Source
        grid.addWidget(self._create_property_label("Source"), 2, 0)
        self._source = self._create_value_label("openlabels")
        grid.addWidget(self._source, 2, 1)

        # Score
        grid.addWidget(self._create_property_label("Risk Score"), 0, 2)
        self._score = self._create_value_label("--")
        self._score.setFont(QFont("Arial", 16, QFont.Bold))
        grid.addWidget(self._score, 0, 3)

        # Entity count
        grid.addWidget(self._create_property_label("Entities"), 1, 2)
        self._entity_count = self._create_value_label("--")
        grid.addWidget(self._entity_count, 1, 3)

        # Portable
        grid.addWidget(self._create_property_label("Format"), 2, 2)
        portable = self._create_value_label("OpenLabels v1")
        portable.setStyleSheet(f"color: {COLORS['success']}; font-weight: 500; background: transparent;")
        grid.addWidget(portable, 2, 3)

        layout.addLayout(grid)

        # Divider
        divider2 = QFrame()
        divider2.setFixedHeight(1)
        divider2.setStyleSheet(f"background-color: {COLORS['border']};")
        layout.addWidget(divider2)

        # Entities section
        entities_header = QLabel("Detected Entities")
        entities_header.setStyleSheet(f"""
            color: {COLORS['text']};
            font-weight: 600;
            font-size: 14px;
            background: transparent;
        """)
        layout.addWidget(entities_header)

        self._entities_container = QWidget()
        self._entities_layout = QHBoxLayout(self._entities_container)
        self._entities_layout.setContentsMargins(0, 0, 0, 0)
        self._entities_layout.setSpacing(8)
        layout.addWidget(self._entities_container)

        return card

    def _create_property_label(self, text: str) -> QLabel:
        """Create a property name label."""
        label = QLabel(text)
        label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 12px; background: transparent;")
        return label

    def _create_value_label(self, text: str) -> QLabel:
        """Create a property value label."""
        label = QLabel(text)
        label.setStyleSheet(f"color: {COLORS['text']}; font-weight: 500; background: transparent;")
        label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        return label

    def _create_json_section(self) -> QFrame:
        """Create the JSON preview section."""
        section = QFrame()
        section.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS["bg_secondary"]};
                border: 1px solid {COLORS["border"]};
                border-radius: 8px;
            }}
        """)
        layout = QVBoxLayout(section)
        layout.setContentsMargins(12, 8, 12, 12)

        # Toggle header
        header = QHBoxLayout()

        self._json_toggle = QPushButton("Show JSON")
        self._json_toggle.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                color: {COLORS["primary"]};
                border: none;
                text-align: left;
                font-weight: 500;
            }}
            QPushButton:hover {{
                text-decoration: underline;
            }}
        """)
        self._json_toggle.clicked.connect(self._toggle_json)
        header.addWidget(self._json_toggle)

        copy_btn = QPushButton("Copy")
        copy_btn.setMaximumWidth(80)
        copy_btn.setProperty("secondary", True)
        copy_btn.clicked.connect(self._copy_json)
        header.addWidget(copy_btn)

        layout.addLayout(header)

        # JSON text area (hidden by default)
        self._json_text = QTextEdit()
        self._json_text.setReadOnly(True)
        self._json_text.setFont(QFont("Consolas, Monaco, monospace", 11))
        self._json_text.setMaximumHeight(200)
        self._json_text.setVisible(False)
        self._json_text.setStyleSheet(f"""
            QTextEdit {{
                background-color: #1e293b;
                color: #e2e8f0;
                border: none;
                border-radius: 6px;
                padding: 12px;
            }}
        """)
        layout.addWidget(self._json_text)

        return section

    def _create_actions(self) -> QWidget:
        """Create the export actions row."""
        actions = QWidget()
        layout = QHBoxLayout(actions)
        layout.setContentsMargins(0, 0, 0, 0)

        # Embed label button
        embed_btn = QPushButton("Embed Label")
        embed_btn.setToolTip("Embed the label directly in the file (PDF, Office, images)")
        embed_btn.clicked.connect(lambda: self.export_requested.emit("embed"))
        layout.addWidget(embed_btn)

        # Save to index button
        index_btn = QPushButton("Save to Index")
        index_btn.setProperty("secondary", True)
        index_btn.setToolTip("Save the label to a local or remote index")
        index_btn.clicked.connect(lambda: self.export_requested.emit("index"))
        layout.addWidget(index_btn)

        # Export JSON button
        json_btn = QPushButton("Export JSON")
        json_btn.setProperty("secondary", True)
        json_btn.clicked.connect(lambda: self.export_requested.emit("json"))
        layout.addWidget(json_btn)

        layout.addStretch()

        return actions

    def _toggle_json(self):
        """Toggle JSON preview visibility."""
        visible = not self._json_text.isVisible()
        self._json_text.setVisible(visible)
        self._json_toggle.setText("Hide JSON" if visible else "Show JSON")

    def _copy_json(self):
        """Copy JSON to clipboard."""
        from PySide6.QtWidgets import QApplication

        if self._label_data:
            json_str = json.dumps(self._label_data, indent=2)
            QApplication.clipboard().setText(json_str)
            self.label_copied.emit()

    def set_label(
        self,
        label_id: str,
        content_hash: str,
        score: int,
        tier: str,
        entities: Dict[str, int],
        timestamp: int,
        source: str = "openlabels:1.0.0",
        file_path: Optional[str] = None,
    ):
        """Set the label data to display."""
        self._file_path = file_path

        # Update label ID
        self._label_id.setText(label_id)

        # Update content hash
        self._content_hash.setText(content_hash)

        # Update timestamp
        dt = datetime.fromtimestamp(timestamp)
        self._timestamp.setText(dt.strftime("%Y-%m-%d %H:%M:%S"))

        # Update source
        self._source.setText(source)

        # Update score with tier color
        tier_color = get_tier_color(tier)
        self._score.setText(str(score))
        self._score.setStyleSheet(f"color: {tier_color}; font-weight: bold;")

        # Update tier badge
        self._tier_badge.setText(tier)
        self._tier_badge.setStyleSheet(f"""
            background-color: {tier_color};
            color: white;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
        """)

        # Update entity count
        total_entities = sum(entities.values())
        self._entity_count.setText(str(total_entities))

        # Update entities display
        self._update_entities_display(entities)

        # Build label data structure
        self._label_data = {
            "v": 1,
            "id": label_id,
            "hash": content_hash,
            "labels": [
                {
                    "t": entity_type,
                    "c": 0.95,  # Placeholder confidence
                    "d": "pattern",
                    "h": "------",  # Placeholder value hash
                    "n": count,
                }
                for entity_type, count in entities.items()
            ],
            "src": source,
            "ts": timestamp,
        }

        # Update JSON preview
        json_str = json.dumps(self._label_data, indent=2)
        self._json_text.setPlainText(json_str)

    def _update_entities_display(self, entities: Dict[str, int]):
        """Update the entities pill display."""
        # Clear existing
        while self._entities_layout.count():
            item = self._entities_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if not entities:
            no_entities = QLabel("No sensitive entities detected")
            no_entities.setStyleSheet(f"color: {COLORS['text_muted']}; font-style: italic;")
            self._entities_layout.addWidget(no_entities)
            return

        # Add entity pills
        for entity_type, count in sorted(entities.items(), key=lambda x: -x[1]):
            pill = self._create_entity_pill(entity_type, count)
            self._entities_layout.addWidget(pill)

        self._entities_layout.addStretch()

    def _create_entity_pill(self, entity_type: str, count: int) -> QFrame:
        """Create an entity type pill."""
        pill = QFrame()
        pill.setStyleSheet(f"""
            QFrame {{
                background-color: {COLORS["primary"]};
                border-radius: 14px;
                padding: 4px 12px;
            }}
        """)
        layout = QHBoxLayout(pill)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(6)

        type_label = QLabel(entity_type)
        type_label.setStyleSheet("color: white; font-weight: 500; background: transparent;")
        layout.addWidget(type_label)

        count_label = QLabel(str(count))
        count_label.setStyleSheet("""
            color: white;
            background-color: rgba(255,255,255,0.2);
            border-radius: 10px;
            padding: 2px 8px;
            font-weight: bold;
        """)
        layout.addWidget(count_label)

        return pill

    def set_from_scan_result(self, result: Dict[str, Any]):
        """Set label from a scan result dictionary."""
        import time
        from openlabels.core.labels import generate_label_id, compute_content_hash_file

        file_path = result.get("path", "")
        entities = result.get("entities", {})
        score = result.get("score", 0)
        tier = result.get("tier", "UNKNOWN")

        # Generate or retrieve label ID
        label_id = result.get("label_id") or generate_label_id()

        # Compute content hash if we have file access
        try:
            content_hash = compute_content_hash_file(file_path)
        except Exception:
            content_hash = "____________"

        self.set_label(
            label_id=label_id,
            content_hash=content_hash,
            score=score,
            tier=tier,
            entities=entities,
            timestamp=int(time.time()),
            file_path=file_path,
        )

    def clear(self):
        """Clear the label preview."""
        self._label_id.setText("ol_____________")
        self._content_hash.setText("____________")
        self._timestamp.setText("--")
        self._source.setText("openlabels")
        self._score.setText("--")
        self._score.setStyleSheet(f"color: {COLORS['text']};")
        self._entity_count.setText("--")
        self._tier_badge.setText("--")
        self._tier_badge.setStyleSheet("""
            background-color: rgba(255,255,255,0.2);
            color: white;
            padding: 8px 16px;
            border-radius: 20px;
        """)
        self._label_data = None
        self._json_text.clear()

        # Clear entities
        while self._entities_layout.count():
            item = self._entities_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
