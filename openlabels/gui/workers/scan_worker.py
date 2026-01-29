"""
Background scan worker.

Performs file scanning in a separate thread to keep the UI responsive.
"""

import stat as stat_module
from pathlib import Path
from typing import Optional, Dict, Any, List

from PySide6.QtCore import QThread, Signal


class ScanWorker(QThread):
    """Background worker for scanning files."""

    # Signals
    progress = Signal(int, int)      # current, total
    result = Signal(dict)            # single scan result
    finished = Signal()              # scan complete
    error = Signal(str)              # error message

    def __init__(
        self,
        target_type: str,
        path: str,
        s3_credentials: Optional[Dict[str, str]] = None,
        parent=None,
    ):
        super().__init__(parent)
        self._target_type = target_type
        self._path = path
        self._s3_credentials = s3_credentials
        self._stop_requested = False

    def stop(self):
        """Request the worker to stop."""
        self._stop_requested = True

    def run(self):
        """Main worker thread."""
        try:
            if self._target_type == "s3":
                self._scan_s3()
            else:
                self._scan_local()
        except Exception as e:
            self.error.emit(str(e))

    def _scan_local(self):
        """Scan local/SMB/NFS path."""
        from openlabels import Client
        from openlabels.adapters.scanner import detect_file as scanner_detect

        path = Path(self._path)

        if not path.exists():
            self.error.emit(f"Path not found: {path}")
            return

        client = Client()

        # Collect files first
        files = self._collect_files(path)
        total = len(files)

        self.progress.emit(0, total)

        for i, file_path in enumerate(files):
            if self._stop_requested:
                break

            result = self._scan_file(file_path, client)
            self.result.emit(result)
            self.progress.emit(i + 1, total)

        self.finished.emit()

    def _collect_files(self, path: Path) -> List[Path]:
        """Collect all files to scan."""
        files = []

        if path.is_file():
            return [path]

        try:
            for item in path.rglob("*"):
                if self._stop_requested:
                    break
                try:
                    st = item.lstat()
                    if stat_module.S_ISREG(st.st_mode):
                        # Skip hidden files and common excludes
                        if not any(part.startswith(".") for part in item.parts):
                            if not any(excl in str(item) for excl in ["node_modules", "__pycache__", ".git"]):
                                files.append(item)
                except OSError:
                    continue
        except PermissionError:
            pass

        return files

    def _scan_file(self, file_path: Path, client) -> Dict[str, Any]:
        """Scan a single file."""
        from openlabels.adapters.scanner import detect_file as scanner_detect

        try:
            # Get file size
            try:
                size = file_path.stat().st_size
            except OSError:
                size = 0

            # Detect entities
            detection = scanner_detect(file_path)
            entities = detection.entity_counts

            # Score the file
            score_result = client.score_file(file_path)

            return {
                "path": str(file_path),
                "size": size,
                "score": score_result.score,
                "tier": score_result.tier.value if hasattr(score_result.tier, 'value') else str(score_result.tier),
                "entities": entities,
                "exposure": "PRIVATE",
                "error": None,
            }

        except (OSError, IOError, ValueError, RuntimeError) as e:
            return {
                "path": str(file_path),
                "size": 0,
                "score": 0,
                "tier": "UNKNOWN",
                "entities": {},
                "exposure": "PRIVATE",
                "error": str(e),
            }

    def _scan_s3(self):
        """Scan S3 bucket."""
        try:
            import boto3
        except ImportError:
            self.error.emit("boto3 is required for S3 scanning. Install with: pip install boto3")
            return

        from openlabels import Client

        # Parse S3 path
        if self._path.startswith("s3://"):
            path_parts = self._path[5:].split("/", 1)
            bucket = path_parts[0]
            prefix = path_parts[1] if len(path_parts) > 1 else ""
        else:
            bucket = self._path
            prefix = ""

        # Create session
        try:
            if self._s3_credentials and self._s3_credentials.get("profile"):
                session = boto3.Session(profile_name=self._s3_credentials["profile"])
            elif self._s3_credentials:
                session = boto3.Session(
                    aws_access_key_id=self._s3_credentials.get("access_key"),
                    aws_secret_access_key=self._s3_credentials.get("secret_key"),
                    aws_session_token=self._s3_credentials.get("session_token"),
                    region_name=self._s3_credentials.get("region"),
                )
            else:
                session = boto3.Session()

            s3 = session.client("s3")
        except Exception as e:
            self.error.emit(f"Failed to connect to AWS: {e}")
            return

        client = Client()

        # List objects
        try:
            paginator = s3.get_paginator("list_objects_v2")
            pages = paginator.paginate(Bucket=bucket, Prefix=prefix)

            # First pass to count
            objects = []
            for page in pages:
                if self._stop_requested:
                    return
                for obj in page.get("Contents", []):
                    if not obj["Key"].endswith("/"):  # Skip "folders"
                        objects.append(obj)

            total = len(objects)
            self.progress.emit(0, total)

            # Process each object
            for i, obj in enumerate(objects):
                if self._stop_requested:
                    break

                result = self._scan_s3_object(s3, bucket, obj, client)
                self.result.emit(result)
                self.progress.emit(i + 1, total)

        except Exception as e:
            self.error.emit(f"Failed to list S3 objects: {e}")
            return

        self.finished.emit()

    def _scan_s3_object(self, s3_client, bucket: str, obj: Dict, client) -> Dict[str, Any]:
        """Scan a single S3 object."""
        import tempfile
        from pathlib import Path

        key = obj["Key"]
        size = obj.get("Size", 0)

        try:
            # Download to temp file for scanning
            with tempfile.NamedTemporaryFile(delete=False, suffix=Path(key).suffix) as tmp:
                s3_client.download_fileobj(bucket, key, tmp)
                tmp_path = Path(tmp.name)

            try:
                # Scan the temp file
                from openlabels.adapters.scanner import detect_file as scanner_detect

                detection = scanner_detect(tmp_path)
                entities = detection.entity_counts

                score_result = client.score_file(tmp_path)

                return {
                    "path": f"s3://{bucket}/{key}",
                    "size": size,
                    "score": score_result.score,
                    "tier": score_result.tier.value if hasattr(score_result.tier, 'value') else str(score_result.tier),
                    "entities": entities,
                    "exposure": "PRIVATE",  # TODO: Check bucket ACL
                    "error": None,
                }
            finally:
                # Clean up temp file
                tmp_path.unlink(missing_ok=True)

        except (OSError, IOError, ValueError, RuntimeError) as e:
            return {
                "path": f"s3://{bucket}/{key}",
                "size": size,
                "score": 0,
                "tier": "UNKNOWN",
                "entities": {},
                "exposure": "PRIVATE",
                "error": str(e),
            }
