"""Configuration for the OpenLabels Scanner."""

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional, Set, List
import logging

logger = logging.getLogger(__name__)


class DeviceMode(str, Enum):
    """Device configuration options for ML inference."""
    AUTO = "auto"
    CUDA = "cuda"
    CPU = "cpu"


# Paths that should never be used as data directories
FORBIDDEN_PATHS = frozenset([
    "/etc", "/var", "/usr", "/bin", "/sbin", "/lib", "/lib64",
    "/boot", "/dev", "/proc", "/sys", "/tmp",
    "/System", "/Library", "/Applications",
    "C:\\Windows", "C:\\Program Files",
])


def validate_data_path(path: Path) -> bool:
    """Validate data directory path is safe."""
    testing_mode = os.environ.get("OPENLABELS_SCANNER_TESTING", "").lower() in ("1", "true", "yes")
    resolved = path.resolve()
    path_str = str(resolved)

    if path_str == "/" or path_str == "\\":
        logger.warning(f"Data path {path} is root directory - rejected")
        return False

    for forbidden in FORBIDDEN_PATHS:
        if testing_mode and forbidden == "/tmp":
            continue
        if path_str == forbidden:
            logger.warning(f"Data path {path} is forbidden system directory")
            return False
        if path_str.startswith(forbidden + os.sep):
            logger.warning(f"Data path {path} is inside forbidden directory {forbidden}")
            return False

    return True


def default_data_dir() -> Path:
    """
    Default data directory, checked in order:
    1. OPENLABELS_SCANNER_HOME env var (if set)
    2. .openlabels/ in current working directory (project-local)
    3. ~/.openlabels (user home fallback)
    """
    env_dir = os.environ.get("OPENLABELS_SCANNER_HOME")
    if env_dir:
        path = Path(env_dir).expanduser()
        if not validate_data_path(path):
            logger.warning(f"OPENLABELS_SCANNER_HOME={env_dir} failed validation, using default")
        else:
            return path

    local_dir = Path.cwd() / ".openlabels"
    if local_dir.exists() and local_dir.is_dir():
        if validate_data_path(local_dir):
            logger.debug(f"Using local data directory: {local_dir}")
            return local_dir

    return Path.home() / ".openlabels"


@dataclass
class Config:
    """OpenLabels Scanner configuration."""

    # Paths
    data_dir: Path = field(default_factory=default_data_dir)
    _models_dir_override: Optional[Path] = field(default=None, repr=False)

    @property
    def models_dir(self) -> Path:
        """Directory for ML models (OCR, etc.)."""
        if self._models_dir_override is not None:
            return self._models_dir_override
        env_models = os.environ.get("OPENLABELS_SCANNER_MODELS_DIR")
        if env_models:
            return Path(env_models).expanduser()
        return self.data_dir / "models"

    @property
    def rapidocr_dir(self) -> Path:
        """Directory for RapidOCR models."""
        return self.models_dir / "rapidocr"

    @property
    def dictionaries_dir(self) -> Path:
        """Directory for dictionary files."""
        return self.data_dir / "dictionaries"

    # Detection Settings
    min_confidence: float = 0.50
    entity_types: Optional[List[str]] = None  # None = detect all types
    exclude_types: Optional[List[str]] = None  # Types to never detect

    # Device / GPU Configuration
    device: str = "auto"  # "auto", "cuda", "cpu"
    cuda_device_id: int = 0

    # OCR Settings
    enable_ocr: bool = True  # Enable OCR for images/scanned PDFs

    # Model Loading
    model_timeout_seconds: int = 45
    on_model_timeout: str = "degraded"  # "error" | "degraded" - continue without ML if timeout
    disabled_detectors: Set[str] = field(default_factory=set)

    # Parallel detection
    max_workers: int = 4  # Max threads for parallel detection

    def __post_init__(self):
        """Validate configuration values."""
        if not validate_data_path(self.data_dir):
            raise ValueError(
                f"Invalid data_dir '{self.data_dir}'. "
                f"Cannot use system directories like /etc, /var, /usr, etc."
            )

        valid_devices = {d.value for d in DeviceMode}
        if self.device not in valid_devices:
            raise ValueError(
                f"Invalid device '{self.device}'. "
                f"Must be one of: {', '.join(valid_devices)}"
            )

        if not 0 < self.min_confidence <= 1.0:
            raise ValueError("min_confidence must be between 0 and 1")

        valid_timeout_modes = {"error", "degraded"}
        if self.on_model_timeout not in valid_timeout_modes:
            raise ValueError(
                f"Invalid on_model_timeout '{self.on_model_timeout}'. "
                f"Must be one of: {', '.join(valid_timeout_modes)}"
            )

        if self.model_timeout_seconds < 1:
            raise ValueError("model_timeout_seconds must be at least 1")

        if self.max_workers < 1:
            raise ValueError("max_workers must be at least 1")

    def ensure_directories(self) -> None:
        """Create data directories with secure permissions (0700)."""
        import stat
        for dir_path in [self.data_dir, self.models_dir, self.dictionaries_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
            dir_path.chmod(stat.S_IRWXU)

    @classmethod
    def from_env(cls) -> "Config":
        """Create config from environment variables."""
        config = cls()

        if env_conf := os.environ.get("OPENLABELS_SCANNER_MIN_CONFIDENCE"):
            config.min_confidence = float(env_conf)

        if env_device := os.environ.get("OPENLABELS_SCANNER_DEVICE"):
            config.device = env_device.lower()

        if env_ocr := os.environ.get("OPENLABELS_SCANNER_ENABLE_OCR"):
            config.enable_ocr = env_ocr.lower() in ("1", "true", "yes")

        if env_workers := os.environ.get("OPENLABELS_SCANNER_MAX_WORKERS"):
            config.max_workers = int(env_workers)

        return config
