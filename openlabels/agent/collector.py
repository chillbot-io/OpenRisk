"""
File Metadata Collector.

Collects file system metadata and converts to OpenLabels NormalizedContext.

The collector gathers:
- File permissions (POSIX or NTFS)
- Owner/group information
- File timestamps (created, modified, accessed)
- File type and size
- Extended attributes (if available)
- Encryption indicators

Example:
    >>> from openlabels.agent import FileCollector
    >>>
    >>> collector = FileCollector()
    >>> metadata = collector.collect("/path/to/file.pdf")
    >>> print(f"Exposure: {metadata.exposure}")
    >>> print(f"Last modified: {metadata.last_modified}")
"""

import os
import stat
import logging
import hashlib
import platform
import mimetypes
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Iterator

from ..adapters.base import NormalizedContext, ExposureLevel
from ..adapters.scanner.constants import FILE_READ_CHUNK_SIZE, PARTIAL_HASH_SIZE
from ..utils.validation import validate_path_for_subprocess

logger = logging.getLogger(__name__)


@dataclass
class FileMetadata:
    """
    Complete file metadata.
    """
    # Basic info
    path: str
    name: str
    size_bytes: int
    file_type: str  # MIME type
    extension: str

    # Timestamps
    created_at: Optional[str] = None  # ISO format
    modified_at: Optional[str] = None
    accessed_at: Optional[str] = None

    # Ownership
    owner: Optional[str] = None
    group: Optional[str] = None
    owner_uid: Optional[int] = None
    group_gid: Optional[int] = None

    # Permissions
    mode: Optional[int] = None
    mode_string: Optional[str] = None
    exposure: ExposureLevel = ExposureLevel.PRIVATE

    # Protection
    is_encrypted: bool = False
    encryption_type: Optional[str] = None
    is_readonly: bool = False
    is_hidden: bool = False

    # Archive info
    is_archive: bool = False
    archive_type: Optional[str] = None

    # Content hash (optional)
    content_hash: Optional[str] = None
    partial_hash: Optional[str] = None  # First 64KB for quick comparison

    # Extended attributes
    xattrs: Dict[str, str] = field(default_factory=dict)

    # Errors during collection
    errors: List[str] = field(default_factory=list)

    def to_normalized_context(self) -> NormalizedContext:
        """Convert to NormalizedContext for scoring."""
        # Calculate staleness
        staleness_days = 0
        if self.modified_at:
            try:
                modified = datetime.fromisoformat(self.modified_at.replace('Z', '+00:00'))
                staleness_days = (datetime.now(modified.tzinfo) - modified).days
            except (ValueError, TypeError) as e:
                logger.debug(f"Could not parse modified_at '{self.modified_at}': {e}")

        encryption = "none"
        if self.is_encrypted:
            encryption = self.encryption_type or "platform"

        return NormalizedContext(
            exposure=self.exposure.name,
            encryption=encryption,
            last_modified=self.modified_at,
            last_accessed=self.accessed_at,
            staleness_days=staleness_days,
            path=self.path,
            owner=self.owner,
            size_bytes=self.size_bytes,
            file_type=self.file_type,
            is_archive=self.is_archive,
        )


class FileCollector:
    """
    Collects file system metadata.

    Platform-aware collector that handles POSIX and Windows file systems.
    """

    # Extensions that typically indicate encryption
    ENCRYPTED_EXTENSIONS = frozenset({
        '.gpg', '.pgp', '.asc',  # PGP
        '.enc', '.encrypted',    # Generic
        '.aes', '.aes256',       # AES
        '.vault',                # Ansible vault
        '.age',                  # age encryption
        '.crypt',                # Generic
    })

    # Archive extensions
    ARCHIVE_EXTENSIONS = frozenset({
        '.zip', '.tar', '.gz', '.tgz', '.tar.gz',
        '.bz2', '.xz', '.7z', '.rar',
    })

    # Common encrypted archive extensions
    ENCRYPTED_ARCHIVE_EXTENSIONS = frozenset({
        '.zip',  # Can be encrypted
        '.7z',   # Can be encrypted
        '.rar',  # Can be encrypted
    })

    def __init__(
        self,
        compute_hash: bool = False,
        compute_partial_hash: bool = True,
        hash_size_limit: int = 100 * 1024 * 1024,  # 100MB
        collect_xattrs: bool = True,
    ):
        """
        Initialize collector.

        Args:
            compute_hash: Compute full content hash (slow for large files)
            compute_partial_hash: Compute hash of first 64KB (fast)
            hash_size_limit: Max file size for full hash computation
            collect_xattrs: Collect extended attributes
        """
        self.compute_hash = compute_hash
        self.compute_partial_hash = compute_partial_hash
        self.hash_size_limit = hash_size_limit
        self.collect_xattrs = collect_xattrs
        self._platform = platform.system()

    def collect(self, path: str) -> FileMetadata:
        """
        Collect metadata for a file.

        Args:
            path: Path to file

        Returns:
            FileMetadata with all collected information

        Raises:
            FileNotFoundError: If file doesn't exist
            PermissionError: If file cannot be accessed
            ValueError: If path is a symlink (security protection)
        """
        original_path = Path(path)
        errors = []

        # SECURITY FIX (TOCTOU-001): Check the ORIGINAL path for symlinks BEFORE
        # resolving. Path.resolve() follows symlinks, so checking after resolve()
        # would miss symlink attacks. We use lstat() which doesn't follow symlinks.
        try:
            st = original_path.lstat()  # lstat = stat(follow_symlinks=False)
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {path}")
        except OSError as e:
            raise PermissionError(f"Cannot access file: {e}")

        # SECURITY: Reject symlinks to prevent symlink attacks
        # An attacker could create a symlink to a sensitive file to bypass access controls
        if stat.S_ISLNK(st.st_mode):
            raise ValueError(f"Refusing to collect metadata for symlink (security): {path}")

        # SECURITY: Only process regular files
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"Not a regular file: {path}")

        # Now safe to resolve the path for consistent path representation
        path = original_path.resolve()

        # Basic metadata
        metadata = FileMetadata(
            path=str(path),
            name=path.name,
            size_bytes=st.st_size,
            extension=path.suffix.lower(),
            file_type=self._get_mime_type(path),
        )

        # Timestamps
        metadata.created_at = self._format_timestamp(getattr(st, 'st_birthtime', st.st_ctime))
        metadata.modified_at = self._format_timestamp(st.st_mtime)
        metadata.accessed_at = self._format_timestamp(st.st_atime)

        # Permissions and exposure
        try:
            self._collect_permissions(path, st, metadata)
        except (OSError, KeyError) as e:
            errors.append(f"Permission collection failed: {e}")
            logger.debug(f"Permission collection failed for {path}: {e}")

        # Check for encryption indicators
        metadata.is_encrypted = self._check_encryption(path, metadata)

        # Check for archive
        metadata.is_archive = self._check_archive(path, metadata)

        # Hashes
        if self.compute_partial_hash:
            try:
                metadata.partial_hash = self._compute_partial_hash(path)
            except OSError as e:
                errors.append(f"Partial hash failed: {e}")

        if self.compute_hash and st.st_size <= self.hash_size_limit:
            try:
                metadata.content_hash = self._compute_content_hash(path)
            except OSError as e:
                errors.append(f"Content hash failed: {e}")

        # Extended attributes
        if self.collect_xattrs:
            try:
                metadata.xattrs = self._collect_xattrs(path)
            except OSError as e:
                errors.append(f"Xattr collection failed: {e}")
                logger.debug(f"Xattr collection failed for {path}: {e}")

        metadata.errors = errors
        return metadata

    def _collect_permissions(
        self,
        path: Path,
        st: os.stat_result,
        metadata: FileMetadata,
    ) -> None:
        """Collect permission information."""
        metadata.mode = st.st_mode

        if self._platform == "Windows":
            self._collect_windows_permissions(path, metadata)
        else:
            self._collect_posix_permissions(path, st, metadata)

    def _collect_posix_permissions(
        self,
        path: Path,
        st: os.stat_result,
        metadata: FileMetadata,
    ) -> None:
        """Collect POSIX permissions."""
        from .posix import get_posix_permissions

        try:
            perms = get_posix_permissions(str(path))
            metadata.owner = perms.owner_name
            metadata.group = perms.group_name
            metadata.owner_uid = perms.owner_uid
            metadata.group_gid = perms.group_gid
            metadata.mode_string = perms.mode_string
            metadata.exposure = perms.exposure
        except (OSError, KeyError, ValueError) as e:
            logger.debug(f"POSIX permission collection failed: {e}")
            # Fallback to basic mode parsing
            mode = st.st_mode
            metadata.exposure = self._mode_to_exposure(mode)

    def _collect_windows_permissions(
        self,
        path: Path,
        metadata: FileMetadata,
    ) -> None:
        """Collect Windows NTFS permissions."""
        # Try to import Windows-specific module
        try:
            from .ntfs import get_ntfs_permissions
            ntfs_perms = get_ntfs_permissions(str(path))
            metadata.owner = ntfs_perms.owner
            metadata.exposure = ntfs_perms.exposure
        except ImportError:
            # Windows module not available, use basic check
            metadata.exposure = ExposureLevel.PRIVATE
        except (OSError, ValueError) as e:
            logger.debug(f"NTFS permission collection failed: {e}")
            metadata.exposure = ExposureLevel.PRIVATE

    def _mode_to_exposure(self, mode: int) -> ExposureLevel:
        """Simple mode to exposure conversion."""
        if mode & stat.S_IWOTH:
            return ExposureLevel.PUBLIC
        if mode & stat.S_IROTH:
            return ExposureLevel.ORG_WIDE
        if mode & stat.S_IRGRP:
            return ExposureLevel.INTERNAL
        return ExposureLevel.PRIVATE

    def _get_mime_type(self, path: Path) -> str:
        """Get MIME type for file."""
        mime_type, _ = mimetypes.guess_type(str(path))
        return mime_type or "application/octet-stream"

    def _format_timestamp(self, ts: float) -> str:
        """Format Unix timestamp as ISO string."""
        return datetime.fromtimestamp(ts).isoformat()

    def _check_encryption(self, path: Path, metadata: FileMetadata) -> bool:
        """Check if file appears to be encrypted."""
        # Check extension
        if metadata.extension in self.ENCRYPTED_EXTENSIONS:
            metadata.encryption_type = "file_level"
            return True

        # Check for encrypted archives (basic heuristic)
        if metadata.extension in self.ENCRYPTED_ARCHIVE_EXTENSIONS:
            # Would need to inspect archive headers for definitive check
            pass

        # Check xattrs for encryption markers
        if metadata.xattrs:
            for key in metadata.xattrs:
                if "encrypt" in key.lower():
                    metadata.encryption_type = "platform"
                    return True

        return False

    def _check_archive(self, path: Path, metadata: FileMetadata) -> bool:
        """Check if file is an archive."""
        if metadata.extension in self.ARCHIVE_EXTENSIONS:
            metadata.archive_type = metadata.extension.lstrip('.')
            return True

        # Check for compound extensions like .tar.gz
        name_lower = path.name.lower()
        for ext in ['.tar.gz', '.tar.bz2', '.tar.xz']:
            if name_lower.endswith(ext):
                metadata.archive_type = ext.lstrip('.')
                return True

        return False

    def _compute_partial_hash(self, path: Path, size: int = PARTIAL_HASH_SIZE) -> str:
        """Compute hash of first N bytes."""
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            h.update(f.read(size))
        return h.hexdigest()[:16]  # Short hash

    def _compute_content_hash(self, path: Path) -> str:
        """Compute full content hash."""
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(FILE_READ_CHUNK_SIZE), b''):
                h.update(chunk)
        return h.hexdigest()

    # SECURITY FIX (LOW-006): Maximum xattr name length to prevent abuse
    MAX_XATTR_NAME_LENGTH = 256  # Linux limit is 255, macOS is similar
    MAX_XATTR_VALUE_LENGTH = 65536  # 64KB - reasonable limit for metadata
    MAX_XATTR_COUNT = 100  # Prevent collecting excessive attributes

    def _validate_xattr_name(self, attr_name: str) -> bool:
        """
        Validate xattr attribute name (LOW-006).

        Args:
            attr_name: The attribute name to validate

        Returns:
            True if valid, False otherwise
        """
        if not attr_name or not isinstance(attr_name, str):
            return False
        # Check length
        if len(attr_name) > self.MAX_XATTR_NAME_LENGTH:
            return False
        # Check for null bytes and control characters
        if '\x00' in attr_name or any(ord(c) < 32 for c in attr_name):
            return False
        # Must start with valid namespace prefix on Linux/macOS
        # user., security., system., trusted. (Linux)
        # com. (macOS)
        valid_prefixes = ('user.', 'security.', 'system.', 'trusted.', 'com.')
        if not any(attr_name.startswith(p) for p in valid_prefixes):
            # Allow unqualified names for compatibility but log
            if '.' not in attr_name:
                logger.debug(f"Xattr name without namespace prefix: {attr_name}")
        return True

    def _collect_xattrs(self, path: Path) -> Dict[str, str]:
        """
        Collect extended attributes.

        SECURITY FIX (LOW-006): Validates attribute names before reading
        to prevent processing of potentially malicious xattr values.
        """
        xattrs = {}

        if self._platform == "Windows":
            # Windows uses NTFS streams, not xattrs
            return xattrs

        try:
            import xattr as xattr_module
            attr_count = 0
            for attr_name in xattr_module.listxattr(str(path)):
                # SECURITY FIX (LOW-006): Validate attribute name before reading
                if not self._validate_xattr_name(attr_name):
                    logger.warning(f"Skipping invalid xattr name on {path}: {attr_name!r}")
                    continue

                # SECURITY FIX (LOW-006): Limit number of attributes collected
                if attr_count >= self.MAX_XATTR_COUNT:
                    logger.warning(f"Reached max xattr count ({self.MAX_XATTR_COUNT}) for {path}")
                    break

                try:
                    value = xattr_module.getxattr(str(path), attr_name)

                    # SECURITY FIX (LOW-006): Validate value length
                    if len(value) > self.MAX_XATTR_VALUE_LENGTH:
                        logger.warning(
                            f"Skipping oversized xattr '{attr_name}' on {path}: "
                            f"{len(value)} bytes (max {self.MAX_XATTR_VALUE_LENGTH})"
                        )
                        continue

                    try:
                        xattrs[attr_name] = value.decode('utf-8')
                    except UnicodeDecodeError:
                        xattrs[attr_name] = value.hex()
                    attr_count += 1
                except OSError as e:
                    logger.debug(f"Could not read xattr '{attr_name}' from {path}: {e}")
        except ImportError:
            # xattr module not installed, try getfattr command
            import subprocess
            path_str = str(path)
            if not validate_path_for_subprocess(path_str):
                logger.debug(f"Invalid path for xattr fallback: {path_str!r}")
                return xattrs
            try:
                result = subprocess.run(
                    ["getfattr", "-d", path_str],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    attr_count = 0
                    for line in result.stdout.splitlines():
                        if '=' in line and not line.startswith('#'):
                            key, _, value = line.partition('=')
                            key = key.strip()
                            value = value.strip().strip('"')

                            # SECURITY FIX (LOW-006): Validate from getfattr output too
                            if not self._validate_xattr_name(key):
                                logger.warning(f"Skipping invalid xattr name: {key!r}")
                                continue
                            if len(value) > self.MAX_XATTR_VALUE_LENGTH:
                                logger.warning(f"Skipping oversized xattr value for {key}")
                                continue
                            if attr_count >= self.MAX_XATTR_COUNT:
                                logger.warning(f"Reached max xattr count for {path}")
                                break

                            xattrs[key] = value
                            attr_count += 1
            except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                logger.debug(f"getfattr fallback failed for {path}: {e}")
        except OSError as e:
            logger.debug(f"Could not list xattrs for {path}: {e}")

        return xattrs


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def collect_metadata(path: str, **kwargs) -> FileMetadata:
    """
    Collect metadata for a single file.

    Convenience function that creates a FileCollector and collects metadata.

    Args:
        path: Path to file
        **kwargs: Arguments passed to FileCollector

    Returns:
        FileMetadata
    """
    collector = FileCollector(**kwargs)
    return collector.collect(path)


def collect_directory(
    path: str,
    recursive: bool = True,
    include_hidden: bool = False,
    max_files: Optional[int] = None,
    **kwargs,
) -> Iterator[FileMetadata]:
    """
    Collect metadata for all files in a directory.

    Args:
        path: Directory path
        recursive: Recurse into subdirectories
        include_hidden: Include hidden files
        max_files: Maximum files to collect
        **kwargs: Arguments passed to FileCollector

    Yields:
        FileMetadata for each file
    """
    collector = FileCollector(**kwargs)
    dir_path = Path(path)

    if not dir_path.is_dir():
        raise NotADirectoryError(f"Not a directory: {path}")

    walker = dir_path.rglob("*") if recursive else dir_path.glob("*")
    count = 0

    for file_path in walker:
        # SECURITY FIX (TOCTOU-001): Use stat() directly instead of is_file()
        # to eliminate race condition window where file could be replaced
        # with symlink between check and collect operation.
        try:
            st = file_path.stat(follow_symlinks=False)
            if not stat.S_ISREG(st.st_mode):
                # Skip non-regular files (directories, symlinks, devices, etc.)
                continue
        except OSError:
            # File doesn't exist, permission denied, or other issue - skip
            continue

        if not include_hidden and any(p.startswith('.') for p in file_path.parts):
            continue

        if max_files and count >= max_files:
            break

        try:
            yield collector.collect(str(file_path))
            count += 1
        except OSError as e:
            logger.warning(f"Failed to collect metadata for {file_path}: {e}")
            # Yield a minimal metadata object with error
            yield FileMetadata(
                path=str(file_path),
                name=file_path.name,
                size_bytes=0,
                file_type="unknown",
                extension=file_path.suffix.lower(),
                errors=[str(e)],
            )
            count += 1
