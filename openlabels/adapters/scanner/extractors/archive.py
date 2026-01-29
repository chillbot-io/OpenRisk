"""Archive extractor for ZIP, TAR, GZ, and 7Z files.

Supports recursive extraction of nested archives with security limits:
- Decompression bomb protection (MAX_DECOMPRESSED_SIZE, MAX_EXTRACTION_RATIO)
- Maximum nesting depth to prevent zip bombs
- Maximum file count per archive
- Path traversal prevention

Supported formats:
- ZIP (.zip)
- TAR (.tar, .tar.gz, .tgz, .tar.bz2, .tbz2, .tar.xz, .txz)
- GZIP (.gz) - single file compression
- 7Z (.7z) - requires py7zr optional dependency

Example:
    >>> from openlabels.adapters.scanner.extractors.archive import ArchiveExtractor
    >>> extractor = ArchiveExtractor()
    >>> result = extractor.extract(archive_bytes, "documents.zip")
    >>> print(result.text)  # Combined text from all extracted files
"""

import gzip
import io
import logging
import os
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import List, Optional, Tuple, Generator, TYPE_CHECKING

from ..constants import (
    MAX_DECOMPRESSED_SIZE,
    MAX_EXTRACTION_RATIO,
    MAX_FILE_SIZE_BYTES,
    MAX_FILENAME_LENGTH,
)
from .base import BaseExtractor, ExtractionResult

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Archive-specific constants
MAX_ARCHIVE_NESTING_DEPTH = 3  # Prevent deeply nested zip bombs
MAX_FILES_PER_ARCHIVE = 1000  # Limit file count per archive
MAX_SINGLE_FILE_SIZE = 50 * 1024 * 1024  # 50MB per extracted file
SUPPORTED_ARCHIVE_EXTENSIONS = frozenset({
    '.zip', '.tar', '.tgz', '.tar.gz', '.tar.bz2', '.tbz2',
    '.tar.xz', '.txz', '.gz', '.7z',
})

# MIME types for archives
ARCHIVE_MIME_TYPES = frozenset({
    'application/zip',
    'application/x-zip-compressed',
    'application/x-tar',
    'application/gzip',
    'application/x-gzip',
    'application/x-bzip2',
    'application/x-xz',
    'application/x-7z-compressed',
})


@dataclass
class ExtractedFile:
    """A file extracted from an archive."""
    path: str  # Path within the archive
    content: bytes
    size: int
    is_archive: bool = False  # True if this is a nested archive


@dataclass
class ArchiveExtractionStats:
    """Statistics about archive extraction."""
    total_files: int = 0
    total_bytes: int = 0
    files_processed: int = 0
    files_skipped: int = 0
    nested_archives: int = 0
    extraction_errors: List[str] = field(default_factory=list)


class ArchiveSecurityError(Exception):
    """Raised when archive extraction would violate security constraints."""
    pass


def _is_safe_path(path: str) -> bool:
    """
    Check if an archive member path is safe (no path traversal).

    Prevents:
    - Absolute paths
    - Parent directory references (..)
    - Null bytes
    - Reserved names (Windows)
    """
    if not path:
        return False

    # Check for null bytes
    if '\x00' in path:
        return False

    # Normalize and check for traversal
    try:
        # Use PurePosixPath for cross-platform path handling
        pure_path = PurePosixPath(path)

        # Check for absolute paths
        if pure_path.is_absolute():
            return False

        # Check for parent directory references
        parts = pure_path.parts
        if '..' in parts:
            return False

        # Check for leading slashes (another form of absolute path)
        if path.startswith('/') or path.startswith('\\'):
            return False

        # Check Windows reserved names
        reserved = {'CON', 'PRN', 'AUX', 'NUL'} | {f'COM{i}' for i in range(10)} | {f'LPT{i}' for i in range(10)}
        for part in parts:
            name_upper = part.upper().split('.')[0]
            if name_upper in reserved:
                return False

        return True
    except (ValueError, TypeError):
        return False


def _get_extension(filename: str) -> str:
    """Get lowercase extension, handling compound extensions like .tar.gz."""
    lower = filename.lower()

    # Handle compound extensions
    for compound in ('.tar.gz', '.tar.bz2', '.tar.xz'):
        if lower.endswith(compound):
            return compound

    # Standard extension
    return Path(filename).suffix.lower()


def _is_archive_extension(extension: str) -> bool:
    """Check if extension indicates an archive format."""
    return extension in SUPPORTED_ARCHIVE_EXTENSIONS


class ZipExtractor:
    """Extract files from ZIP archives."""

    @staticmethod
    def can_handle(content: bytes, extension: str) -> bool:
        """Check if this is a ZIP file."""
        # ZIP magic bytes: PK\x03\x04 or PK\x05\x06 (empty) or PK\x07\x08 (spanned)
        if len(content) >= 4:
            if content[:4] == b'PK\x03\x04':
                return True
            if content[:4] == b'PK\x05\x06':
                return True
            if content[:4] == b'PK\x07\x08':
                return True
        return extension == '.zip'

    @staticmethod
    def extract_files(
        content: bytes,
        max_total_size: int = MAX_DECOMPRESSED_SIZE,
        max_files: int = MAX_FILES_PER_ARCHIVE,
    ) -> Generator[ExtractedFile, None, ArchiveExtractionStats]:
        """
        Extract files from a ZIP archive.

        Yields ExtractedFile objects and returns stats.
        """
        stats = ArchiveExtractionStats()
        total_extracted = 0

        try:
            with zipfile.ZipFile(io.BytesIO(content), 'r') as zf:
                # Check for zip bomb via file count
                if len(zf.namelist()) > max_files:
                    raise ArchiveSecurityError(
                        f"Archive contains {len(zf.namelist())} files, exceeds limit of {max_files}"
                    )

                for info in zf.infolist():
                    stats.total_files += 1

                    # Skip directories
                    if info.is_dir():
                        continue

                    # Validate path safety
                    if not _is_safe_path(info.filename):
                        logger.warning(f"Skipping unsafe path in archive: {info.filename!r}")
                        stats.files_skipped += 1
                        stats.extraction_errors.append(f"Unsafe path: {info.filename}")
                        continue

                    # Check compression ratio (zip bomb detection)
                    if info.compress_size > 0:
                        ratio = info.file_size / info.compress_size
                        if ratio > MAX_EXTRACTION_RATIO:
                            logger.warning(
                                f"Suspicious compression ratio {ratio:.1f} for {info.filename}"
                            )
                            stats.files_skipped += 1
                            stats.extraction_errors.append(
                                f"Compression ratio {ratio:.1f} exceeds limit for {info.filename}"
                            )
                            continue

                    # Check individual file size
                    if info.file_size > MAX_SINGLE_FILE_SIZE:
                        logger.warning(
                            f"Skipping large file {info.filename} ({info.file_size} bytes)"
                        )
                        stats.files_skipped += 1
                        continue

                    # Check total extracted size
                    if total_extracted + info.file_size > max_total_size:
                        logger.warning(
                            f"Archive extraction would exceed {max_total_size} bytes, stopping"
                        )
                        stats.extraction_errors.append("Total size limit reached")
                        break

                    try:
                        file_content = zf.read(info.filename)
                        total_extracted += len(file_content)
                        stats.total_bytes += len(file_content)
                        stats.files_processed += 1

                        ext = _get_extension(info.filename)
                        is_nested = _is_archive_extension(ext)
                        if is_nested:
                            stats.nested_archives += 1

                        yield ExtractedFile(
                            path=info.filename,
                            content=file_content,
                            size=len(file_content),
                            is_archive=is_nested,
                        )
                    except Exception as e:
                        logger.warning(f"Failed to extract {info.filename}: {e}")
                        stats.extraction_errors.append(f"Extract error: {info.filename}: {e}")
                        stats.files_skipped += 1

        except zipfile.BadZipFile as e:
            raise ArchiveSecurityError(f"Invalid ZIP file: {e}")

        return stats


class TarExtractor:
    """Extract files from TAR archives (including .tar.gz, .tar.bz2, .tar.xz)."""

    @staticmethod
    def can_handle(content: bytes, extension: str) -> bool:
        """Check if this is a TAR file."""
        # TAR magic at offset 257: "ustar" (POSIX) or older formats
        if len(content) >= 262:
            if content[257:262] == b'ustar':
                return True
        # Check extension
        return extension in {'.tar', '.tar.gz', '.tgz', '.tar.bz2', '.tbz2', '.tar.xz', '.txz'}

    @staticmethod
    def extract_files(
        content: bytes,
        max_total_size: int = MAX_DECOMPRESSED_SIZE,
        max_files: int = MAX_FILES_PER_ARCHIVE,
    ) -> Generator[ExtractedFile, None, ArchiveExtractionStats]:
        """Extract files from a TAR archive."""
        stats = ArchiveExtractionStats()
        total_extracted = 0

        try:
            # tarfile auto-detects compression
            with tarfile.open(fileobj=io.BytesIO(content), mode='r:*') as tf:
                members = tf.getmembers()

                if len(members) > max_files:
                    raise ArchiveSecurityError(
                        f"Archive contains {len(members)} files, exceeds limit of {max_files}"
                    )

                for member in members:
                    stats.total_files += 1

                    # Skip non-files (directories, links, devices)
                    if not member.isfile():
                        continue

                    # Validate path safety
                    if not _is_safe_path(member.name):
                        logger.warning(f"Skipping unsafe path in archive: {member.name!r}")
                        stats.files_skipped += 1
                        stats.extraction_errors.append(f"Unsafe path: {member.name}")
                        continue

                    # Check file size
                    if member.size > MAX_SINGLE_FILE_SIZE:
                        logger.warning(
                            f"Skipping large file {member.name} ({member.size} bytes)"
                        )
                        stats.files_skipped += 1
                        continue

                    # Check total extracted size
                    if total_extracted + member.size > max_total_size:
                        logger.warning(
                            f"Archive extraction would exceed {max_total_size} bytes, stopping"
                        )
                        stats.extraction_errors.append("Total size limit reached")
                        break

                    try:
                        f = tf.extractfile(member)
                        if f is None:
                            continue

                        file_content = f.read()
                        total_extracted += len(file_content)
                        stats.total_bytes += len(file_content)
                        stats.files_processed += 1

                        ext = _get_extension(member.name)
                        is_nested = _is_archive_extension(ext)
                        if is_nested:
                            stats.nested_archives += 1

                        yield ExtractedFile(
                            path=member.name,
                            content=file_content,
                            size=len(file_content),
                            is_archive=is_nested,
                        )
                    except Exception as e:
                        logger.warning(f"Failed to extract {member.name}: {e}")
                        stats.extraction_errors.append(f"Extract error: {member.name}: {e}")
                        stats.files_skipped += 1

        except tarfile.TarError as e:
            raise ArchiveSecurityError(f"Invalid TAR file: {e}")

        return stats


class GzipExtractor:
    """Extract single files from GZIP compression."""

    @staticmethod
    def can_handle(content: bytes, extension: str) -> bool:
        """Check if this is a GZIP file (not .tar.gz)."""
        # GZIP magic bytes: 1f 8b
        if len(content) >= 2 and content[:2] == b'\x1f\x8b':
            # Exclude .tar.gz which is handled by TarExtractor
            if extension not in {'.tar.gz', '.tgz'}:
                return True
        return extension == '.gz' and extension not in {'.tar.gz', '.tgz'}

    @staticmethod
    def extract_files(
        content: bytes,
        original_filename: str,
        max_size: int = MAX_DECOMPRESSED_SIZE,
    ) -> Generator[ExtractedFile, None, ArchiveExtractionStats]:
        """Extract the single file from GZIP compression."""
        stats = ArchiveExtractionStats()
        stats.total_files = 1

        try:
            # Decompress incrementally to check size
            decompressed = io.BytesIO()
            with gzip.GzipFile(fileobj=io.BytesIO(content), mode='rb') as gz:
                while True:
                    chunk = gz.read(65536)  # 64KB chunks
                    if not chunk:
                        break
                    decompressed.write(chunk)

                    # Check size limit
                    if decompressed.tell() > max_size:
                        raise ArchiveSecurityError(
                            f"Decompressed size exceeds {max_size} bytes"
                        )

            file_content = decompressed.getvalue()
            stats.total_bytes = len(file_content)
            stats.files_processed = 1

            # Derive output filename (remove .gz extension)
            output_name = original_filename
            if output_name.lower().endswith('.gz'):
                output_name = output_name[:-3]
            if not output_name:
                output_name = "decompressed"

            ext = _get_extension(output_name)
            is_nested = _is_archive_extension(ext)
            if is_nested:
                stats.nested_archives += 1

            yield ExtractedFile(
                path=output_name,
                content=file_content,
                size=len(file_content),
                is_archive=is_nested,
            )

        except gzip.BadGzipFile as e:
            raise ArchiveSecurityError(f"Invalid GZIP file: {e}")
        except OSError as e:
            raise ArchiveSecurityError(f"GZIP decompression error: {e}")

        return stats


class SevenZipExtractor:
    """Extract files from 7Z archives (requires py7zr)."""

    _available: Optional[bool] = None

    @classmethod
    def is_available(cls) -> bool:
        """Check if py7zr is installed."""
        if cls._available is None:
            try:
                import py7zr
                cls._available = True
            except ImportError:
                cls._available = False
        return cls._available

    @staticmethod
    def can_handle(content: bytes, extension: str) -> bool:
        """Check if this is a 7Z file."""
        # 7Z magic bytes: 37 7A BC AF 27 1C
        if len(content) >= 6:
            if content[:6] == b'7z\xbc\xaf\x27\x1c':
                return True
        return extension == '.7z'

    @classmethod
    def extract_files(
        cls,
        content: bytes,
        max_total_size: int = MAX_DECOMPRESSED_SIZE,
        max_files: int = MAX_FILES_PER_ARCHIVE,
    ) -> Generator[ExtractedFile, None, ArchiveExtractionStats]:
        """Extract files from a 7Z archive."""
        stats = ArchiveExtractionStats()

        if not cls.is_available():
            stats.extraction_errors.append("py7zr not installed, cannot extract .7z files")
            logger.warning("py7zr not installed. Install with: pip install py7zr")
            return stats

        import py7zr

        total_extracted = 0

        try:
            with py7zr.SevenZipFile(io.BytesIO(content), mode='r') as sz:
                # Get file list first
                file_list = sz.getnames()

                if len(file_list) > max_files:
                    raise ArchiveSecurityError(
                        f"Archive contains {len(file_list)} files, exceeds limit of {max_files}"
                    )

                # Extract all to memory
                extracted = sz.readall()

                for filename, bio in extracted.items():
                    stats.total_files += 1

                    # Validate path safety
                    if not _is_safe_path(filename):
                        logger.warning(f"Skipping unsafe path in archive: {filename!r}")
                        stats.files_skipped += 1
                        stats.extraction_errors.append(f"Unsafe path: {filename}")
                        continue

                    file_content = bio.read()

                    # Check file size
                    if len(file_content) > MAX_SINGLE_FILE_SIZE:
                        logger.warning(
                            f"Skipping large file {filename} ({len(file_content)} bytes)"
                        )
                        stats.files_skipped += 1
                        continue

                    # Check total extracted size
                    if total_extracted + len(file_content) > max_total_size:
                        logger.warning(
                            f"Archive extraction would exceed {max_total_size} bytes, stopping"
                        )
                        stats.extraction_errors.append("Total size limit reached")
                        break

                    total_extracted += len(file_content)
                    stats.total_bytes += len(file_content)
                    stats.files_processed += 1

                    ext = _get_extension(filename)
                    is_nested = _is_archive_extension(ext)
                    if is_nested:
                        stats.nested_archives += 1

                    yield ExtractedFile(
                        path=filename,
                        content=file_content,
                        size=len(file_content),
                        is_archive=is_nested,
                    )

        except py7zr.Bad7zFile as e:
            raise ArchiveSecurityError(f"Invalid 7Z file: {e}")

        return stats


class ArchiveExtractor(BaseExtractor):
    """
    Unified archive extractor supporting ZIP, TAR, GZ, and 7Z formats.

    Recursively extracts nested archives up to MAX_ARCHIVE_NESTING_DEPTH.
    Combines text from all extracted files into a single ExtractionResult.
    """

    def __init__(
        self,
        max_nesting_depth: int = MAX_ARCHIVE_NESTING_DEPTH,
        max_files: int = MAX_FILES_PER_ARCHIVE,
        max_total_size: int = MAX_DECOMPRESSED_SIZE,
    ):
        self.max_nesting_depth = max_nesting_depth
        self.max_files = max_files
        self.max_total_size = max_total_size
        self._text_extractor = None  # Lazy-loaded to avoid circular imports

    @property
    def text_extractor(self):
        """Lazy-load the text extractor to avoid circular imports."""
        if self._text_extractor is None:
            from .registry import extract_text
            self._text_extractor = extract_text
        return self._text_extractor

    def can_handle(self, content_type: str, extension: str) -> bool:
        """Check if this extractor handles the file type."""
        if content_type in ARCHIVE_MIME_TYPES:
            return True
        return extension in SUPPORTED_ARCHIVE_EXTENSIONS

    def _get_archive_extractor(
        self, content: bytes, extension: str
    ) -> Optional[Tuple[str, callable]]:
        """Get the appropriate archive extractor for the content."""
        # Try each extractor in order
        if ZipExtractor.can_handle(content, extension):
            return ('zip', lambda c: ZipExtractor.extract_files(
                c, self.max_total_size, self.max_files
            ))

        if TarExtractor.can_handle(content, extension):
            return ('tar', lambda c: TarExtractor.extract_files(
                c, self.max_total_size, self.max_files
            ))

        if GzipExtractor.can_handle(content, extension):
            # GzipExtractor needs the filename
            return ('gzip', None)  # Special handling below

        if SevenZipExtractor.can_handle(content, extension):
            if SevenZipExtractor.is_available():
                return ('7z', lambda c: SevenZipExtractor.extract_files(
                    c, self.max_total_size, self.max_files
                ))
            else:
                logger.warning("7Z file detected but py7zr not installed")
                return None

        return None

    def _extract_archive_recursive(
        self,
        content: bytes,
        filename: str,
        depth: int = 0,
        parent_path: str = "",
    ) -> Tuple[List[Tuple[str, bytes]], List[str]]:
        """
        Recursively extract archive contents.

        Returns:
            Tuple of (list of (path, content) tuples, list of warnings)
        """
        if depth > self.max_nesting_depth:
            return [], [f"Maximum nesting depth {self.max_nesting_depth} exceeded"]

        extension = _get_extension(filename)
        extractor_info = self._get_archive_extractor(content, extension)

        if extractor_info is None:
            return [], [f"Unsupported archive format: {extension}"]

        archive_type, extractor_func = extractor_info
        extracted_files: List[Tuple[str, bytes]] = []
        warnings: List[str] = []

        try:
            # Special handling for GZIP (needs filename)
            if archive_type == 'gzip':
                gen = GzipExtractor.extract_files(content, filename, self.max_total_size)
            else:
                gen = extractor_func(content)

            # Consume the generator
            stats = None
            for extracted_file in gen:
                full_path = os.path.join(parent_path, extracted_file.path)

                if extracted_file.is_archive and depth < self.max_nesting_depth:
                    # Recursively extract nested archive
                    nested_files, nested_warnings = self._extract_archive_recursive(
                        extracted_file.content,
                        extracted_file.path,
                        depth + 1,
                        full_path,
                    )
                    extracted_files.extend(nested_files)
                    warnings.extend(nested_warnings)
                else:
                    extracted_files.append((full_path, extracted_file.content))

            # Get final stats from generator return value
            try:
                # The generator returns stats when exhausted
                pass
            except StopIteration as e:
                stats = e.value
                if stats and stats.extraction_errors:
                    warnings.extend(stats.extraction_errors)

        except ArchiveSecurityError as e:
            warnings.append(f"Security error in {filename}: {e}")
        except Exception as e:
            logger.error(f"Archive extraction error for {filename}: {e}")
            warnings.append(f"Extraction error: {e}")

        return extracted_files, warnings

    def extract(self, content: bytes, filename: str) -> ExtractionResult:
        """
        Extract text from all files within the archive.

        Recursively extracts nested archives and combines text from all files.
        """
        all_texts: List[str] = []
        all_warnings: List[str] = []
        files_processed = 0

        # Extract all files from the archive
        extracted_files, extract_warnings = self._extract_archive_recursive(
            content, filename
        )
        all_warnings.extend(extract_warnings)

        # Process each extracted file through appropriate extractors
        for file_path, file_content in extracted_files:
            if not file_content:
                continue

            try:
                # Use the registry to find appropriate extractor
                result = self.text_extractor(file_content, file_path)

                if result.text:
                    # Add file path as header for context
                    all_texts.append(f"=== {file_path} ===")
                    all_texts.append(result.text)
                    files_processed += 1

                if result.warnings:
                    all_warnings.extend(
                        f"[{file_path}] {w}" for w in result.warnings
                    )

            except Exception as e:
                logger.warning(f"Failed to extract text from {file_path}: {e}")
                all_warnings.append(f"Text extraction failed for {file_path}: {e}")

        combined_text = "\n\n".join(all_texts)

        return ExtractionResult(
            text=combined_text,
            pages=files_processed,
            needs_ocr=False,  # Individual extractors handle OCR
            warnings=all_warnings,
            confidence=1.0 if files_processed > 0 else 0.0,
        )
