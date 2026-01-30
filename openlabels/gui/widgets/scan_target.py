"""
Scan target panel widget.

Allows selecting target type (Local, SMB, NFS, S3) and entering the path.
"""

from typing import Optional, Dict, Any

from PySide6.QtWidgets import (
    QWidget,
    QHBoxLayout,
    QVBoxLayout,
    QComboBox,
    QLineEdit,
    QPushButton,
    QLabel,
    QFileDialog,
    QGroupBox,
    QCheckBox,
)
from PySide6.QtCore import Signal


class ScanTargetPanel(QWidget):
    """Panel for selecting scan target."""

    # Signals
    scan_requested = Signal()
    path_changed = Signal()
    monitoring_toggled = Signal(bool)  # True when monitoring enabled

    TARGET_TYPES = [
        ("local", "Local Path"),
        ("smb", "Network Share (SMB)"),
        ("nfs", "NFS Mount"),
        ("s3", "S3 Bucket"),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._s3_credentials: Optional[Dict[str, str]] = None
        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self):
        group = QGroupBox("Scan Target")
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(group)

        layout = QHBoxLayout(group)

        # Target type selector
        type_layout = QHBoxLayout()
        type_label = QLabel("Type:")
        self._type_combo = QComboBox()
        for value, label in self.TARGET_TYPES:
            self._type_combo.addItem(label, value)
        self._type_combo.setMinimumWidth(150)
        type_layout.addWidget(type_label)
        type_layout.addWidget(self._type_combo)
        layout.addLayout(type_layout)

        # Path input (changes based on type)
        self._path_label = QLabel("Path:")
        self._path_input = QLineEdit()
        self._path_input.setPlaceholderText("C:\\Data or /data")
        self._path_input.setMinimumWidth(400)
        layout.addWidget(self._path_label)
        layout.addWidget(self._path_input, stretch=1)

        # S3-specific inputs (hidden by default)
        self._bucket_label = QLabel("Bucket:")
        self._bucket_input = QLineEdit()
        self._bucket_input.setPlaceholderText("my-bucket")
        self._bucket_input.setMinimumWidth(150)
        self._bucket_label.setVisible(False)
        self._bucket_input.setVisible(False)
        layout.addWidget(self._bucket_label)
        layout.addWidget(self._bucket_input)

        self._prefix_label = QLabel("Prefix:")
        self._prefix_input = QLineEdit()
        self._prefix_input.setPlaceholderText("data/")
        self._prefix_input.setMinimumWidth(100)
        self._prefix_label.setVisible(False)
        self._prefix_input.setVisible(False)
        layout.addWidget(self._prefix_label)
        layout.addWidget(self._prefix_input)

        # Browse button
        self._browse_btn = QPushButton("Browse")
        self._browse_btn.setMaximumWidth(80)
        layout.addWidget(self._browse_btn)

        # S3 credentials button
        self._creds_btn = QPushButton("Credentials")
        self._creds_btn.setMaximumWidth(100)
        self._creds_btn.setVisible(False)
        layout.addWidget(self._creds_btn)

        # Monitor checkbox (real-time file watching)
        self._monitor_checkbox = QCheckBox("Monitor")
        self._monitor_checkbox.setToolTip("Watch for file changes and auto-scan")
        layout.addWidget(self._monitor_checkbox)

        # Scan button
        self._scan_btn = QPushButton("Scan")
        self._scan_btn.setMinimumWidth(80)
        self._scan_btn.setDefault(True)
        layout.addWidget(self._scan_btn)

    def _connect_signals(self):
        """Connect signals."""
        self._type_combo.currentIndexChanged.connect(self._on_type_changed)
        self._browse_btn.clicked.connect(self._on_browse)
        self._creds_btn.clicked.connect(self._on_credentials)
        self._scan_btn.clicked.connect(self.scan_requested)
        self._path_input.textChanged.connect(self.path_changed)
        self._path_input.returnPressed.connect(self.scan_requested)
        self._monitor_checkbox.toggled.connect(self._on_monitor_toggled)

    def _on_monitor_toggled(self, checked: bool):
        """Handle monitor checkbox toggle."""
        self.monitoring_toggled.emit(checked)

    def _on_type_changed(self, index: int):
        """Handle target type change."""
        target_type = self._type_combo.currentData()

        # Show/hide S3-specific inputs
        is_s3 = target_type == "s3"

        self._path_label.setVisible(not is_s3)
        self._path_input.setVisible(not is_s3)
        self._browse_btn.setVisible(not is_s3)

        self._bucket_label.setVisible(is_s3)
        self._bucket_input.setVisible(is_s3)
        self._prefix_label.setVisible(is_s3)
        self._prefix_input.setVisible(is_s3)
        self._creds_btn.setVisible(is_s3)

        # Hide monitor for S3 (not supported)
        self._monitor_checkbox.setVisible(not is_s3)
        if is_s3 and self._monitor_checkbox.isChecked():
            self._monitor_checkbox.setChecked(False)

        # Update placeholder text based on type
        if target_type == "local":
            self._path_input.setPlaceholderText("C:\\Data or /data")
        elif target_type == "smb":
            self._path_input.setPlaceholderText("\\\\server\\share\\path")
        elif target_type == "nfs":
            self._path_input.setPlaceholderText("/mnt/nfs/data")

        self.path_changed.emit()

    def _on_browse(self):
        """Open folder browser."""
        folder = QFileDialog.getExistingDirectory(
            self, "Select Folder", self._path_input.text() or ""
        )
        if folder:
            self._path_input.setText(folder)

    def _on_credentials(self):
        """Open S3 credentials dialog."""
        from openlabels.gui.widgets.dialogs import S3CredentialsDialog

        dialog = S3CredentialsDialog(self, current_credentials=self._s3_credentials)
        if dialog.exec():
            self._s3_credentials = dialog.get_credentials()
            # Update button text to indicate credentials are set
            if self._s3_credentials:
                self._creds_btn.setText("Credentials *")
            else:
                self._creds_btn.setText("Credentials")

    def get_target_type(self) -> str:
        """Get the selected target type."""
        return self._type_combo.currentData()

    def set_target_type(self, target_type: str):
        """Set the target type."""
        for i in range(self._type_combo.count()):
            if self._type_combo.itemData(i) == target_type:
                self._type_combo.setCurrentIndex(i)
                break

    def get_path(self) -> str:
        """Get the path/bucket."""
        target_type = self.get_target_type()
        if target_type == "s3":
            bucket = self._bucket_input.text().strip()
            prefix = self._prefix_input.text().strip()
            if prefix:
                return f"s3://{bucket}/{prefix}"
            return f"s3://{bucket}"
        return self._path_input.text().strip()

    def set_path(self, path: str):
        """Set the path."""
        target_type = self.get_target_type()
        if target_type == "s3" and path.startswith("s3://"):
            # Parse s3://bucket/prefix
            parts = path[5:].split("/", 1)
            self._bucket_input.setText(parts[0])
            if len(parts) > 1:
                self._prefix_input.setText(parts[1])
        else:
            self._path_input.setText(path)

    def get_s3_credentials(self) -> Optional[Dict[str, str]]:
        """Get S3 credentials."""
        return self._s3_credentials

    def is_monitoring(self) -> bool:
        """Check if monitoring is enabled."""
        return self._monitor_checkbox.isChecked()

    def set_monitoring(self, enabled: bool):
        """Set monitoring state."""
        self._monitor_checkbox.setChecked(enabled)

    def set_enabled(self, enabled: bool):
        """Enable or disable the panel."""
        self._type_combo.setEnabled(enabled)
        self._path_input.setEnabled(enabled)
        self._bucket_input.setEnabled(enabled)
        self._prefix_input.setEnabled(enabled)
        self._browse_btn.setEnabled(enabled)
        self._creds_btn.setEnabled(enabled)
        self._scan_btn.setEnabled(enabled)
        self._monitor_checkbox.setEnabled(enabled)
