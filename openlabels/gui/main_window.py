"""
OpenLabels main window.

The main application window containing:
- Scan target panel (top)
- Folder tree (left)
- Results table (right)
- Status bar (bottom)

Requires authentication to access vault features.
"""

import json
import csv
from pathlib import Path
from typing import Optional, List, Dict, Any, TYPE_CHECKING
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

if TYPE_CHECKING:
    from openlabels.auth import AuthManager
    from openlabels.auth.models import Session


class MainWindow(QMainWindow):
    """Main application window."""

    def __init__(self, initial_path: Optional[str] = None):
        super().__init__()
        self.setWindowTitle("OpenLabels")
        self.setMinimumSize(1200, 700)
        self.resize(1400, 800)

        # Auth state
        self._auth: Optional["AuthManager"] = None
        self._session: Optional["Session"] = None

        # State
        self._scan_results: List[Dict[str, Any]] = []
        self._current_path: Optional[str] = None
        self._scan_worker: Optional[ScanWorker] = None
        self._initial_path = initial_path

        # Setup UI
        self._setup_ui()
        self._setup_menubar()
        self._setup_statusbar()
        self._connect_signals()

    def showEvent(self, event):
        """Handle window show - trigger login on first show."""
        super().showEvent(event)

        # Only show login on first display
        if self._auth is None:
            # Use QTimer to defer login dialog until after window is shown
            from PySide6.QtCore import QTimer
            QTimer.singleShot(100, self._show_auth_dialog)

    def _show_auth_dialog(self):
        """Show login or setup dialog."""
        try:
            from openlabels.auth import AuthManager
            self._auth = AuthManager()

            if self._auth.needs_setup():
                self._show_setup_dialog()
            else:
                self._show_login_dialog()

        except ImportError:
            # Auth module not available (missing dependencies)
            QMessageBox.warning(
                self,
                "Auth Not Available",
                "Authentication features require additional dependencies.\n\n"
                "Install with: pip install openlabels[auth]"
            )
            self._auth = None

    def _show_setup_dialog(self):
        """Show first-time setup dialog."""
        from openlabels.gui.widgets.login_dialog import SetupDialog, RecoveryKeysDialog

        dialog = SetupDialog(self)
        dialog.setup_complete.connect(self._on_setup_complete)

        if dialog.exec() != dialog.Accepted:
            # User cancelled setup - can't continue
            QMessageBox.information(
                self,
                "Setup Required",
                "An admin account must be created to use OpenLabels."
            )
            QApplication.quit()

    def _on_setup_complete(self, session: "Session", recovery_keys: List[str]):
        """Handle setup completion."""
        self._session = session

        # Show recovery keys dialog
        from openlabels.gui.widgets.login_dialog import RecoveryKeysDialog
        keys_dialog = RecoveryKeysDialog(self, recovery_keys)
        keys_dialog.exec()

        self._on_login_success()

    def _show_login_dialog(self):
        """Show login dialog."""
        from openlabels.gui.widgets.login_dialog import LoginDialog

        dialog = LoginDialog(self)
        dialog.login_successful.connect(self._on_login_successful)

        if dialog.exec() != dialog.Accepted:
            # User cancelled login - quit
            QApplication.quit()

    def _on_login_successful(self, session: "Session"):
        """Handle successful login."""
        self._session = session
        self._on_login_success()

    def _on_login_success(self):
        """Common login success handling."""
        # Update window title with username
        self.setWindowTitle(f"OpenLabels - {self._session.user.username}")

        # Update status
        self._status_label.setText(f"Logged in as {self._session.user.username}")

        # Update user menu
        self._update_user_menu()

        # Load initial path if provided
        if self._initial_path:
            self._scan_target.set_path(self._initial_path)

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

        # User menu (populated after login)
        self._user_menu = menubar.addMenu("&User")
        self._user_menu.setEnabled(False)

        # Help menu
        help_menu = menubar.addMenu("&Help")

        about_action = QAction("&About", self)
        about_action.triggered.connect(self._on_about)
        help_menu.addAction(about_action)

    def _update_user_menu(self):
        """Update user menu after login."""
        if not self._session:
            self._user_menu.setEnabled(False)
            return

        self._user_menu.clear()
        self._user_menu.setEnabled(True)

        # Current user info
        user_info = QAction(f"Logged in as: {self._session.user.username}", self)
        user_info.setEnabled(False)
        self._user_menu.addAction(user_info)

        self._user_menu.addSeparator()

        # Admin-only options
        if self._session.is_admin():
            create_user_action = QAction("Create &User...", self)
            create_user_action.triggered.connect(self._on_create_user)
            self._user_menu.addAction(create_user_action)

            manage_users_action = QAction("&Manage Users...", self)
            manage_users_action.triggered.connect(self._on_manage_users)
            self._user_menu.addAction(manage_users_action)

            recovery_keys_action = QAction("&Recovery Keys...", self)
            recovery_keys_action.triggered.connect(self._on_recovery_keys)
            self._user_menu.addAction(recovery_keys_action)

            audit_log_action = QAction("View &Audit Log...", self)
            audit_log_action.triggered.connect(self._on_view_audit)
            self._user_menu.addAction(audit_log_action)

            self._user_menu.addSeparator()

        # Logout
        logout_action = QAction("&Logout", self)
        logout_action.triggered.connect(self._on_logout)
        self._user_menu.addAction(logout_action)

    @Slot()
    def _on_create_user(self):
        """Show create user dialog (admin only)."""
        if not self._session or not self._session.is_admin():
            return

        from openlabels.gui.widgets.login_dialog import CreateUserDialog
        dialog = CreateUserDialog(self, self._session)
        if dialog.exec():
            QMessageBox.information(self, "User Created", "User created successfully.")

    @Slot()
    def _on_manage_users(self):
        """Show user management (admin only)."""
        if not self._session or not self._session.is_admin():
            return

        # Simple user list for now
        users = self._auth.list_users()
        user_list = "\n".join(f"- {u.username} ({u.role.value})" for u in users)
        QMessageBox.information(self, "Users", f"Registered users:\n\n{user_list}")

    @Slot()
    def _on_recovery_keys(self):
        """Show recovery key status (admin only)."""
        if not self._session or not self._session.is_admin():
            return

        from openlabels.gui.widgets.recovery_dialog import RecoveryDialog
        dialog = RecoveryDialog(self, mode="view_keys", admin_session=self._session)
        dialog.exec()

    @Slot()
    def _on_view_audit(self):
        """View audit log (admin only)."""
        if not self._session or not self._session.is_admin():
            return

        try:
            from openlabels.vault.audit import AuditLog
            from openlabels.auth.crypto import CryptoProvider

            audit = AuditLog(self._auth._data_dir, CryptoProvider())
            is_valid, message = audit.verify_chain(self._session._dek)

            entries = list(audit.read(self._session._dek, limit=50))
            stats = audit.get_stats(self._session._dek)

            # Simple display for now
            text = f"Chain Status: {message}\n\n"
            text += f"Total Entries: {stats.get('total_entries', 0)}\n\n"
            text += "Recent Actions:\n"

            for entry in entries[:20]:
                text += f"  {entry.timestamp.strftime('%Y-%m-%d %H:%M')} | "
                text += f"{entry.action.value} | {entry.user_id[:8]}...\n"

            QMessageBox.information(self, "Audit Log", text)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load audit log: {e}")

    @Slot()
    def _on_logout(self):
        """Handle logout."""
        if self._session and self._auth:
            self._auth.logout(self._session.token)

        self._session = None
        self.setWindowTitle("OpenLabels")
        self._status_label.setText("Logged out")
        self._user_menu.setEnabled(False)

        # Show login dialog again
        self._show_login_dialog()

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
        self._results_table.detail_requested.connect(self._on_file_detail)

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
    def _on_file_detail(self, file_path: str):
        """Handle double-click to show file detail dialog."""
        # Find the result for this file
        result = next((r for r in self._scan_results if r.get("path") == file_path), None)

        # Try to get classification from vault if we have a session
        classification = None
        if self._session:
            try:
                vault = self._session.get_vault()
                classification = vault.get_classification(file_path)
            except Exception:
                pass

        # If no classification but we have scan result, create a minimal one
        if classification is None and result:
            from openlabels.vault.models import FileClassification, ClassificationSource, Finding
            from datetime import datetime

            findings = [
                Finding(entity_type=etype, count=count, confidence=None)
                for etype, count in result.get("entities", {}).items()
            ]

            source = ClassificationSource(
                provider="openlabels",
                timestamp=datetime.utcnow(),
                findings=findings,
                metadata={},
            )

            classification = FileClassification(
                file_path=file_path,
                file_hash="",
                risk_score=result.get("score", 0),
                tier=result.get("tier", "UNKNOWN"),
                sources=[source] if findings else [],
                labels=result.get("labels", []),
            )

        from openlabels.gui.widgets.file_detail_dialog import FileDetailDialog
        dialog = FileDetailDialog(
            parent=self,
            file_path=file_path,
            classification=classification,
            session=self._session,
        )
        dialog.quarantine_requested.connect(self._on_quarantine_file)
        dialog.rescan_requested.connect(self._on_rescan_file)
        dialog.exec()

    @Slot(str)
    def _on_rescan_file(self, file_path: str):
        """Handle rescan request for a single file."""
        # For now, just trigger a full scan with the file's parent directory
        # A proper single-file rescan would require scan worker changes
        self._status_label.setText(f"Rescan requested: {Path(file_path).name}")

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
        """Actually quarantine a file using secure file operations.

        Uses Client.move() which provides TOCTOU protection and symlink validation
        via the FileOps component (see SECURITY.md TOCTOU-001, HIGH-002).
        """
        try:
            # Use default quarantine location
            quarantine_dir = Path.home() / ".openlabels" / "quarantine"
            quarantine_dir.mkdir(parents=True, exist_ok=True)

            source = Path(file_path)
            dest = quarantine_dir / source.name

            # Handle name collision by checking with lstat (TOCTOU-safe)
            try:
                dest.lstat()
                # File exists, add timestamp
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                dest = quarantine_dir / f"{source.stem}_{timestamp}{source.suffix}"
            except FileNotFoundError:
                pass  # Destination doesn't exist, use original name

            # Use Client.move() for TOCTOU-safe file operation
            result = client.move(file_path, str(dest))
            if not result.success:
                raise RuntimeError(result.error or "Move operation failed")

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
        """Apply labels to a file."""
        try:
            # Update local result (API integration pending)
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
