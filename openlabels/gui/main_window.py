"""
OpenLabels main window.

The main application window containing:
- Scan target panel (top)
- Folder tree (left)
- Results table (right)
- Status bar (bottom)
"""

import json
import csv
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime

from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QSplitter,
    QStatusBar,
    QProgressBar,
    QLabel,
    QPushButton,
    QFileDialog,
    QMessageBox,
    QToolBar,
    QApplication,
)
from PySide6.QtCore import Qt, Slot
from PySide6.QtGui import QAction, QIcon

from openlabels.gui.widgets.scan_target import ScanTargetPanel
from openlabels.gui.widgets.folder_tree import FolderTreeWidget
from openlabels.gui.widgets.results_table import ResultsTableWidget
from openlabels.gui.widgets.dialogs import SettingsDialog, LabelDialog, QuarantineConfirmDialog
from openlabels.gui.workers.scan_worker import ScanWorker


class MainWindow(QMainWindow):
    """Main application window."""

    def __init__(self, initial_path: Optional[str] = None):
        super().__init__()
        self.setWindowTitle("OpenLabels")
        self.setMinimumSize(1200, 700)
        self.resize(1400, 800)

        # State
        self._scan_results: List[Dict[str, Any]] = []
        self._current_path: Optional[str] = None
        self._scan_worker: Optional[ScanWorker] = None

        # Setup UI
        self._setup_ui()
        self._setup_menubar()
        self._setup_statusbar()
        self._connect_signals()

        # Load initial path if provided
        if initial_path:
            self._scan_target.set_path(initial_path)

    def _setup_ui(self):
        """Setup the main UI layout."""
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # Scan target panel (top)
        self._scan_target = ScanTargetPanel()
        layout.addWidget(self._scan_target)

        # Splitter for tree and table
        splitter = QSplitter(Qt.Horizontal)

        # Folder tree (left)
        self._folder_tree = FolderTreeWidget()
        self._folder_tree.setMinimumWidth(250)
        self._folder_tree.setMaximumWidth(400)
        splitter.addWidget(self._folder_tree)

        # Results table (right)
        self._results_table = ResultsTableWidget()
        splitter.addWidget(self._results_table)

        # Set splitter sizes (30% tree, 70% table)
        splitter.setSizes([300, 700])

        layout.addWidget(splitter, stretch=1)

        # Bottom actions bar
        actions_layout = QHBoxLayout()
        actions_layout.setContentsMargins(0, 4, 0, 0)

        self._export_csv_btn = QPushButton("Export CSV")
        self._export_json_btn = QPushButton("Export JSON")
        self._settings_btn = QPushButton("Settings")

        actions_layout.addWidget(self._export_csv_btn)
        actions_layout.addWidget(self._export_json_btn)
        actions_layout.addStretch()
        actions_layout.addWidget(self._settings_btn)

        layout.addLayout(actions_layout)

    def _setup_menubar(self):
        """Setup the menu bar."""
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("&File")

        open_action = QAction("&Open Folder...", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self._on_open_folder)
        file_menu.addAction(open_action)

        file_menu.addSeparator()

        export_csv_action = QAction("Export to &CSV...", self)
        export_csv_action.triggered.connect(self._on_export_csv)
        file_menu.addAction(export_csv_action)

        export_json_action = QAction("Export to &JSON...", self)
        export_json_action.triggered.connect(self._on_export_json)
        file_menu.addAction(export_json_action)

        file_menu.addSeparator()

        exit_action = QAction("E&xit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Scan menu
        scan_menu = menubar.addMenu("&Scan")

        start_scan_action = QAction("&Start Scan", self)
        start_scan_action.setShortcut("F5")
        start_scan_action.triggered.connect(self._on_start_scan)
        scan_menu.addAction(start_scan_action)

        stop_scan_action = QAction("S&top Scan", self)
        stop_scan_action.setShortcut("Escape")
        stop_scan_action.triggered.connect(self._on_stop_scan)
        scan_menu.addAction(stop_scan_action)

        # Help menu
        help_menu = menubar.addMenu("&Help")

        about_action = QAction("&About", self)
        about_action.triggered.connect(self._on_about)
        help_menu.addAction(about_action)

    def _setup_statusbar(self):
        """Setup the status bar."""
        self._statusbar = QStatusBar()
        self.setStatusBar(self._statusbar)

        # Progress bar
        self._progress_bar = QProgressBar()
        self._progress_bar.setMaximumWidth(200)
        self._progress_bar.setVisible(False)

        # Status labels
        self._status_label = QLabel("Ready")
        self._file_count_label = QLabel("")
        self._risk_summary_label = QLabel("")

        self._statusbar.addWidget(self._status_label)
        self._statusbar.addWidget(self._progress_bar)
        self._statusbar.addPermanentWidget(self._file_count_label)
        self._statusbar.addPermanentWidget(self._risk_summary_label)

    def _connect_signals(self):
        """Connect widget signals to slots."""
        # Scan target
        self._scan_target.scan_requested.connect(self._on_start_scan)
        self._scan_target.path_changed.connect(self._on_path_changed)

        # Folder tree
        self._folder_tree.folder_selected.connect(self._on_folder_selected)

        # Results table
        self._results_table.quarantine_requested.connect(self._on_quarantine_file)
        self._results_table.label_requested.connect(self._on_label_file)

        # Bottom buttons
        self._export_csv_btn.clicked.connect(self._on_export_csv)
        self._export_json_btn.clicked.connect(self._on_export_json)
        self._settings_btn.clicked.connect(self._on_settings)

    @Slot()
    def _on_open_folder(self):
        """Open folder dialog."""
        folder = QFileDialog.getExistingDirectory(
            self, "Select Folder to Scan", str(Path.home())
        )
        if folder:
            self._scan_target.set_target_type("local")
            self._scan_target.set_path(folder)

    @Slot()
    def _on_path_changed(self):
        """Handle path change in scan target."""
        path = self._scan_target.get_path()
        target_type = self._scan_target.get_target_type()

        # Update folder tree for local/SMB/NFS paths
        if target_type in ("local", "smb", "nfs") and path:
            self._folder_tree.set_root_path(path)
        else:
            self._folder_tree.clear()

    @Slot()
    def _on_start_scan(self):
        """Start scanning."""
        if self._scan_worker and self._scan_worker.isRunning():
            return  # Already scanning

        target_type = self._scan_target.get_target_type()
        path = self._scan_target.get_path()

        if not path:
            QMessageBox.warning(self, "No Path", "Please enter a path to scan.")
            return

        # Get S3 credentials if needed
        s3_credentials = None
        if target_type == "s3":
            s3_credentials = self._scan_target.get_s3_credentials()

        # Clear previous results
        self._scan_results.clear()
        self._results_table.clear()

        # Update UI
        self._status_label.setText("Scanning...")
        self._progress_bar.setVisible(True)
        self._progress_bar.setRange(0, 0)  # Indeterminate initially
        self._scan_target.set_enabled(False)

        # Start worker
        self._scan_worker = ScanWorker(
            target_type=target_type,
            path=path,
            s3_credentials=s3_credentials,
        )
        self._scan_worker.progress.connect(self._on_scan_progress)
        self._scan_worker.result.connect(self._on_scan_result)
        self._scan_worker.finished.connect(self._on_scan_finished)
        self._scan_worker.error.connect(self._on_scan_error)
        self._scan_worker.start()

    @Slot()
    def _on_stop_scan(self):
        """Stop scanning."""
        if self._scan_worker and self._scan_worker.isRunning():
            self._scan_worker.stop()
            self._status_label.setText("Stopping...")

    @Slot(int, int)
    def _on_scan_progress(self, current: int, total: int):
        """Handle scan progress update."""
        if total > 0:
            self._progress_bar.setRange(0, total)
            self._progress_bar.setValue(current)
        self._file_count_label.setText(f"{current}/{total} files")

    @Slot(dict)
    def _on_scan_result(self, result: Dict[str, Any]):
        """Handle single scan result."""
        self._scan_results.append(result)
        self._results_table.add_result(result)
        self._update_risk_summary()

    @Slot()
    def _on_scan_finished(self):
        """Handle scan completion."""
        self._status_label.setText("Scan complete")
        self._progress_bar.setVisible(False)
        self._scan_target.set_enabled(True)
        self._update_risk_summary()

    @Slot(str)
    def _on_scan_error(self, error: str):
        """Handle scan error."""
        self._status_label.setText("Error")
        self._progress_bar.setVisible(False)
        self._scan_target.set_enabled(True)
        QMessageBox.critical(self, "Scan Error", error)

    @Slot(str)
    def _on_folder_selected(self, folder_path: str):
        """Handle folder selection in tree - filter results."""
        self._results_table.filter_by_path(folder_path)

    @Slot(str)
    def _on_quarantine_file(self, file_path: str):
        """Handle quarantine request for a file."""
        # Find the result for this file
        result = next((r for r in self._scan_results if r.get("path") == file_path), None)
        if not result:
            return

        dialog = QuarantineConfirmDialog(
            self,
            file_path=file_path,
            score=result.get("score", 0),
            tier=result.get("tier", "UNKNOWN"),
        )
        if dialog.exec():
            # Perform quarantine
            self._do_quarantine(file_path)

    def _do_quarantine(self, file_path: str):
        """Actually quarantine a file."""
        try:
            from openlabels import Client

            client = Client()
            # Use default quarantine location
            quarantine_dir = Path.home() / ".openlabels" / "quarantine"
            quarantine_dir.mkdir(parents=True, exist_ok=True)

            source = Path(file_path)
            dest = quarantine_dir / source.name

            # Handle name collision
            if dest.exists():
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                dest = quarantine_dir / f"{source.stem}_{timestamp}{source.suffix}"

            source.rename(dest)

            # Remove from results
            self._scan_results = [r for r in self._scan_results if r.get("path") != file_path]
            self._results_table.remove_result(file_path)
            self._update_risk_summary()

            self._status_label.setText(f"Quarantined: {source.name}")

        except Exception as e:
            QMessageBox.critical(self, "Quarantine Error", str(e))

    @Slot(str)
    def _on_label_file(self, file_path: str):
        """Handle label request for a file."""
        dialog = LabelDialog(self, file_path=file_path)
        if dialog.exec():
            labels = dialog.get_labels()
            self._do_label(file_path, labels)

    def _do_label(self, file_path: str, labels: List[str]):
        """Actually apply labels to a file."""
        try:
            from openlabels import Client

            client = Client()
            # TODO: Implement label application via client
            # For now just update the local result
            for result in self._scan_results:
                if result.get("path") == file_path:
                    result["labels"] = labels
                    break

            self._status_label.setText(f"Labeled: {Path(file_path).name}")

        except Exception as e:
            QMessageBox.critical(self, "Label Error", str(e))

    @Slot()
    def _on_export_csv(self):
        """Export results to CSV."""
        if not self._scan_results:
            QMessageBox.information(self, "No Results", "No scan results to export.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export CSV", "openlabels_results.csv", "CSV Files (*.csv)"
        )
        if not file_path:
            return

        try:
            with open(file_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "path", "score", "tier", "exposure",
                    "entities", "entity_count", "labels", "error"
                ])
                for r in self._scan_results:
                    entities = r.get("entities", {})
                    entity_str = "|".join(f"{k}:{v}" for k, v in entities.items())
                    entity_count = sum(entities.values()) if entities else 0
                    labels = ",".join(r.get("labels", []))
                    writer.writerow([
                        r.get("path", ""),
                        r.get("score", 0),
                        r.get("tier", ""),
                        r.get("exposure", ""),
                        entity_str,
                        entity_count,
                        labels,
                        r.get("error", ""),
                    ])

            self._status_label.setText(f"Exported to {file_path}")

        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    @Slot()
    def _on_export_json(self):
        """Export results to JSON."""
        if not self._scan_results:
            QMessageBox.information(self, "No Results", "No scan results to export.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export JSON", "openlabels_results.json", "JSON Files (*.json)"
        )
        if not file_path:
            return

        try:
            export_data = {
                "exported_at": datetime.now().isoformat(),
                "total_files": len(self._scan_results),
                "summary": self._compute_summary(),
                "files": self._scan_results,
            }

            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2)

            self._status_label.setText(f"Exported to {file_path}")

        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    def _compute_summary(self) -> Dict[str, Any]:
        """Compute summary statistics."""
        if not self._scan_results:
            return {}

        tier_counts = {}
        entity_counts = {}
        scores = []

        for r in self._scan_results:
            tier = r.get("tier", "UNKNOWN")
            tier_counts[tier] = tier_counts.get(tier, 0) + 1

            for etype, count in r.get("entities", {}).items():
                entity_counts[etype] = entity_counts.get(etype, 0) + count

            scores.append(r.get("score", 0))

        return {
            "total_files": len(self._scan_results),
            "files_at_risk": sum(1 for s in scores if s > 0),
            "max_score": max(scores) if scores else 0,
            "avg_score": sum(scores) / len(scores) if scores else 0,
            "by_tier": tier_counts,
            "by_entity": dict(sorted(entity_counts.items(), key=lambda x: -x[1])[:20]),
        }

    @Slot()
    def _on_settings(self):
        """Open settings dialog."""
        dialog = SettingsDialog(self)
        dialog.exec()

    @Slot()
    def _on_about(self):
        """Show about dialog."""
        from openlabels import __version__
        QMessageBox.about(
            self,
            "About OpenLabels",
            f"OpenLabels v{__version__}\n\n"
            "Universal Data Risk Scoring\n\n"
            "https://openlabels.dev"
        )

    def _update_risk_summary(self):
        """Update risk summary in status bar."""
        if not self._scan_results:
            self._risk_summary_label.setText("")
            return

        tier_counts = {}
        for r in self._scan_results:
            tier = r.get("tier", "UNKNOWN")
            tier_counts[tier] = tier_counts.get(tier, 0) + 1

        parts = []
        for tier in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"]:
            if tier in tier_counts:
                parts.append(f"{tier_counts[tier]} {tier}")

        self._risk_summary_label.setText(" | ".join(parts))

    def closeEvent(self, event):
        """Handle window close."""
        if self._scan_worker and self._scan_worker.isRunning():
            reply = QMessageBox.question(
                self,
                "Scan in Progress",
                "A scan is in progress. Stop it and exit?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if reply == QMessageBox.Yes:
                self._scan_worker.stop()
                self._scan_worker.wait()
            else:
                event.ignore()
                return

        event.accept()
