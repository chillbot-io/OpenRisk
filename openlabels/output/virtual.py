"""
OpenLabels Virtual Label Writer.

Writes label pointers to extended attributes (xattr) for files that
don't support native metadata embedding.

Virtual labels store a pointer (labelID:content_hash) in xattr,
with the full LabelSet stored in the index.

Platform support:
- Linux: user.openlabels
- macOS: com.openlabels.label
- Windows: NTFS ADS (Alternate Data Stream)
- Cloud: S3 x-amz-meta-openlabels, GCS/Azure metadata
"""

import os
import logging
import platform
import subprocess
from pathlib import Path
from typing import Optional, Union, Tuple

from ..core.labels import LabelSet, VirtualLabelPointer

logger = logging.getLogger(__name__)

# Platform-specific attribute names
XATTR_LINUX = "user.openlabels"
XATTR_MACOS = "com.openlabels.label"
XATTR_WINDOWS_ADS = "openlabels"  # Stored as file.txt:openlabels


def _get_platform() -> str:
    """Detect current platform."""
    system = platform.system()
    if system == "Linux":
        return "linux"
    elif system == "Darwin":
        return "macos"
    elif system == "Windows":
        return "windows"
    return "unknown"


# =============================================================================
# LINUX IMPLEMENTATION
# =============================================================================

class LinuxXattrHandler:
    """Handle extended attributes on Linux using xattr module or setfattr."""

    ATTR_NAME = XATTR_LINUX

    def write(self, path: str, value: str) -> bool:
        """Write xattr value."""
        # Try using xattr module first
        try:
            import xattr
            xattr.setxattr(path, self.ATTR_NAME, value.encode('utf-8'))
            return True
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"xattr module failed: {e}")

        # Fallback to setfattr command
        try:
            result = subprocess.run(
                ["setfattr", "-n", self.ATTR_NAME, "-v", value, path],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except FileNotFoundError:
            logger.error("setfattr not found. Install attr package.")
            return False
        except Exception as e:
            logger.error(f"setfattr failed: {e}")
            return False

    def read(self, path: str) -> Optional[str]:
        """Read xattr value."""
        # Try using xattr module first
        try:
            import xattr
            value = xattr.getxattr(path, self.ATTR_NAME)
            return value.decode('utf-8')
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"xattr read failed for {path}: {e}")

        # Fallback to getfattr command
        try:
            result = subprocess.run(
                ["getfattr", "-n", self.ATTR_NAME, "--only-values", path],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except FileNotFoundError:
            logger.debug("getfattr not found")
        except Exception as e:
            logger.debug(f"getfattr failed for {path}: {e}")

        return None

    def remove(self, path: str) -> bool:
        """Remove xattr."""
        try:
            import xattr
            xattr.removexattr(path, self.ATTR_NAME)
            return True
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"xattr remove failed for {path}: {e}")

        try:
            result = subprocess.run(
                ["setfattr", "-x", self.ATTR_NAME, path],
                capture_output=True,
            )
            return result.returncode == 0
        except Exception as e:
            logger.debug(f"setfattr remove failed for {path}: {e}")
            return False


# =============================================================================
# MACOS IMPLEMENTATION
# =============================================================================

class MacOSXattrHandler:
    """Handle extended attributes on macOS using xattr command."""

    ATTR_NAME = XATTR_MACOS

    def write(self, path: str, value: str) -> bool:
        """Write xattr value using macOS xattr command."""
        try:
            result = subprocess.run(
                ["xattr", "-w", self.ATTR_NAME, value, path],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except Exception as e:
            logger.error(f"macOS xattr write failed: {e}")
            return False

    def read(self, path: str) -> Optional[str]:
        """Read xattr value using macOS xattr command."""
        try:
            result = subprocess.run(
                ["xattr", "-p", self.ATTR_NAME, path],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception as e:
            logger.debug(f"macOS xattr read failed for {path}: {e}")
        return None

    def remove(self, path: str) -> bool:
        """Remove xattr using macOS xattr command."""
        try:
            result = subprocess.run(
                ["xattr", "-d", self.ATTR_NAME, path],
                capture_output=True,
            )
            return result.returncode == 0
        except Exception as e:
            logger.debug(f"macOS xattr remove failed for {path}: {e}")
            return False


# =============================================================================
# WINDOWS IMPLEMENTATION
# =============================================================================

class WindowsADSHandler:
    """Handle NTFS Alternate Data Streams on Windows."""

    STREAM_NAME = XATTR_WINDOWS_ADS

    def write(self, path: str, value: str) -> bool:
        """Write to NTFS ADS."""
        ads_path = f"{path}:{self.STREAM_NAME}"
        try:
            with open(ads_path, 'w', encoding='utf-8') as f:
                f.write(value)
            return True
        except Exception as e:
            logger.error(f"Windows ADS write failed: {e}")
            return False

    def read(self, path: str) -> Optional[str]:
        """Read from NTFS ADS."""
        ads_path = f"{path}:{self.STREAM_NAME}"
        try:
            with open(ads_path, 'r', encoding='utf-8') as f:
                return f.read().strip()
        except FileNotFoundError:
            return None
        except Exception as e:
            logger.debug(f"Windows ADS read failed for {path}: {e}")
            return None

    def remove(self, path: str) -> bool:
        """Remove NTFS ADS."""
        ads_path = f"{path}:{self.STREAM_NAME}"
        try:
            os.remove(ads_path)
            return True
        except Exception as e:
            logger.debug(f"Windows ADS remove failed for {path}: {e}")
            return False


# =============================================================================
# UNIFIED INTERFACE
# =============================================================================

def _get_handler():
    """Get the appropriate xattr handler for the current platform."""
    plat = _get_platform()
    if plat == "linux":
        return LinuxXattrHandler()
    elif plat == "macos":
        return MacOSXattrHandler()
    elif plat == "windows":
        return WindowsADSHandler()
    else:
        logger.warning(f"Unknown platform: {plat}, using Linux handler")
        return LinuxXattrHandler()


_handler = None


def get_handler():
    """Get cached xattr handler."""
    global _handler
    if _handler is None:
        _handler = _get_handler()
    return _handler


def write_virtual_label(
    path: Union[str, Path],
    label_set: LabelSet,
) -> bool:
    """
    Write a virtual label pointer to a file's extended attributes.

    The pointer format is: labelID:content_hash
    The full LabelSet should be stored in the index separately.

    Args:
        path: Path to the file
        label_set: The LabelSet (used to extract pointer info)

    Returns:
        True if successful, False otherwise

    Example:
        >>> label_set = LabelSet.create(labels, content)
        >>> write_virtual_label("data.csv", label_set)
        True
        >>> # Store full LabelSet in index
        >>> index.store(label_set)
    """
    path = str(path)
    pointer = VirtualLabelPointer(
        label_id=label_set.label_id,
        content_hash=label_set.content_hash,
    )
    return get_handler().write(path, pointer.to_string())


def read_virtual_label(path: Union[str, Path]) -> Optional[VirtualLabelPointer]:
    """
    Read a virtual label pointer from a file's extended attributes.

    Args:
        path: Path to the file

    Returns:
        VirtualLabelPointer if found, None otherwise

    Example:
        >>> pointer = read_virtual_label("data.csv")
        >>> if pointer:
        ...     label_set = index.get(pointer.label_id, pointer.content_hash)
    """
    path = str(path)
    value = get_handler().read(path)
    if value:
        try:
            return VirtualLabelPointer.from_string(value)
        except ValueError as e:
            logger.warning(f"Invalid virtual label format: {e}")
    return None


def remove_virtual_label(path: Union[str, Path]) -> bool:
    """
    Remove a virtual label from a file's extended attributes.

    Args:
        path: Path to the file

    Returns:
        True if successful, False otherwise
    """
    return get_handler().remove(str(path))


def has_virtual_label(path: Union[str, Path]) -> bool:
    """Check if a file has a virtual label."""
    return read_virtual_label(path) is not None


# =============================================================================
# CLOUD STORAGE HANDLERS
# =============================================================================

class S3MetadataHandler:
    """Handle OpenLabels metadata on S3 objects."""

    METADATA_KEY = "openlabels"  # Becomes x-amz-meta-openlabels

    def write(self, bucket: str, key: str, value: str, s3_client=None) -> bool:
        """
        Write OpenLabels metadata to S3 object.

        Note: This requires copying the object to update metadata.
        """
        try:
            import boto3
        except ImportError:
            logger.error("boto3 not installed")
            return False

        client = s3_client or boto3.client('s3')

        try:
            # Get current metadata
            response = client.head_object(Bucket=bucket, Key=key)
            current_metadata = response.get('Metadata', {})

            # Update with our label
            current_metadata[self.METADATA_KEY] = value

            # Copy object to itself with new metadata
            client.copy_object(
                Bucket=bucket,
                Key=key,
                CopySource={'Bucket': bucket, 'Key': key},
                Metadata=current_metadata,
                MetadataDirective='REPLACE',
            )
            return True

        except Exception as e:
            logger.error(f"S3 metadata write failed: {e}")
            return False

    def read(self, bucket: str, key: str, s3_client=None) -> Optional[str]:
        """Read OpenLabels metadata from S3 object."""
        try:
            import boto3
        except ImportError:
            return None

        client = s3_client or boto3.client('s3')

        try:
            response = client.head_object(Bucket=bucket, Key=key)
            metadata = response.get('Metadata', {})
            return metadata.get(self.METADATA_KEY)
        except Exception as e:
            logger.debug(f"S3 metadata read failed for {bucket}/{key}: {e}")
            return None


class GCSMetadataHandler:
    """Handle OpenLabels metadata on GCS objects."""

    METADATA_KEY = "openlabels"

    def write(self, bucket: str, blob_name: str, value: str, client=None) -> bool:
        """Write OpenLabels metadata to GCS object."""
        try:
            from google.cloud import storage
        except ImportError:
            logger.error("google-cloud-storage not installed")
            return False

        gcs_client = client or storage.Client()

        try:
            bucket_obj = gcs_client.bucket(bucket)
            blob = bucket_obj.blob(blob_name)

            # Get current metadata
            blob.reload()
            metadata = blob.metadata or {}
            metadata[self.METADATA_KEY] = value
            blob.metadata = metadata
            blob.patch()
            return True

        except Exception as e:
            logger.error(f"GCS metadata write failed: {e}")
            return False

    def read(self, bucket: str, blob_name: str, client=None) -> Optional[str]:
        """Read OpenLabels metadata from GCS object."""
        try:
            from google.cloud import storage
        except ImportError:
            return None

        gcs_client = client or storage.Client()

        try:
            bucket_obj = gcs_client.bucket(bucket)
            blob = bucket_obj.blob(blob_name)
            blob.reload()
            metadata = blob.metadata or {}
            return metadata.get(self.METADATA_KEY)
        except Exception as e:
            logger.debug(f"GCS metadata read failed for {bucket}/{blob_name}: {e}")
            return None


class AzureBlobMetadataHandler:
    """Handle OpenLabels metadata on Azure Blob Storage."""

    METADATA_KEY = "openlabels"

    def write(
        self,
        container: str,
        blob_name: str,
        value: str,
        connection_string: Optional[str] = None,
    ) -> bool:
        """Write OpenLabels metadata to Azure Blob."""
        try:
            from azure.storage.blob import BlobServiceClient
        except ImportError:
            logger.error("azure-storage-blob not installed")
            return False

        try:
            conn_str = connection_string or os.environ.get('AZURE_STORAGE_CONNECTION_STRING')
            if not conn_str:
                logger.error("Azure connection string not provided")
                return False

            service = BlobServiceClient.from_connection_string(conn_str)
            blob_client = service.get_blob_client(container=container, blob=blob_name)

            # Get current metadata
            props = blob_client.get_blob_properties()
            metadata = props.metadata or {}
            metadata[self.METADATA_KEY] = value
            blob_client.set_blob_metadata(metadata)
            return True

        except Exception as e:
            logger.error(f"Azure Blob metadata write failed: {e}")
            return False

    def read(
        self,
        container: str,
        blob_name: str,
        connection_string: Optional[str] = None,
    ) -> Optional[str]:
        """Read OpenLabels metadata from Azure Blob."""
        try:
            from azure.storage.blob import BlobServiceClient
        except ImportError:
            return None

        try:
            conn_str = connection_string or os.environ.get('AZURE_STORAGE_CONNECTION_STRING')
            if not conn_str:
                return None

            service = BlobServiceClient.from_connection_string(conn_str)
            blob_client = service.get_blob_client(container=container, blob=blob_name)
            props = blob_client.get_blob_properties()
            metadata = props.metadata or {}
            return metadata.get(self.METADATA_KEY)
        except Exception as e:
            logger.debug(f"Azure blob metadata read failed for {container}/{blob_name}: {e}")
            return None


# Cloud handler singletons (lazy-loaded)
_s3_handler = None
_gcs_handler = None
_azure_handler = None


def _get_s3_handler():
    global _s3_handler
    if _s3_handler is None:
        _s3_handler = S3MetadataHandler()
    return _s3_handler


def _get_gcs_handler():
    global _gcs_handler
    if _gcs_handler is None:
        _gcs_handler = GCSMetadataHandler()
    return _gcs_handler


def _get_azure_handler():
    global _azure_handler
    if _azure_handler is None:
        _azure_handler = AzureBlobMetadataHandler()
    return _azure_handler


def write_cloud_label(
    uri: str,
    label_set: LabelSet,
    **kwargs,
) -> bool:
    """
    Write a virtual label to a cloud storage object.

    Supports:
    - s3://bucket/key
    - gs://bucket/blob
    - azure://container/blob (requires AZURE_STORAGE_CONNECTION_STRING)

    Args:
        uri: Cloud storage URI
        label_set: The LabelSet to write
        **kwargs: Additional arguments for the cloud client

    Returns:
        True if successful, False otherwise
    """
    pointer = VirtualLabelPointer(
        label_id=label_set.label_id,
        content_hash=label_set.content_hash,
    )
    value = pointer.to_string()

    if uri.startswith('s3://'):
        parts = uri[5:].split('/', 1)
        bucket, key = parts[0], parts[1] if len(parts) > 1 else ''
        return _get_s3_handler().write(bucket, key, value, kwargs.get('s3_client'))

    elif uri.startswith('gs://'):
        parts = uri[5:].split('/', 1)
        bucket, blob_name = parts[0], parts[1] if len(parts) > 1 else ''
        return _get_gcs_handler().write(bucket, blob_name, value, kwargs.get('gcs_client'))

    elif uri.startswith('azure://'):
        parts = uri[8:].split('/', 1)
        container, blob_name = parts[0], parts[1] if len(parts) > 1 else ''
        return _get_azure_handler().write(
            container, blob_name, value,
            kwargs.get('connection_string'),
        )

    else:
        logger.error(f"Unknown cloud URI scheme: {uri}")
        return False


def read_cloud_label(uri: str, **kwargs) -> Optional[VirtualLabelPointer]:
    """
    Read a virtual label from a cloud storage object.

    Args:
        uri: Cloud storage URI
        **kwargs: Additional arguments for the cloud client

    Returns:
        VirtualLabelPointer if found, None otherwise
    """
    value = None

    if uri.startswith('s3://'):
        parts = uri[5:].split('/', 1)
        bucket, key = parts[0], parts[1] if len(parts) > 1 else ''
        value = _get_s3_handler().read(bucket, key, kwargs.get('s3_client'))

    elif uri.startswith('gs://'):
        parts = uri[5:].split('/', 1)
        bucket, blob_name = parts[0], parts[1] if len(parts) > 1 else ''
        value = _get_gcs_handler().read(bucket, blob_name, kwargs.get('gcs_client'))

    elif uri.startswith('azure://'):
        parts = uri[8:].split('/', 1)
        container, blob_name = parts[0], parts[1] if len(parts) > 1 else ''
        value = _get_azure_handler().read(
            container, blob_name,
            kwargs.get('connection_string'),
        )

    if value:
        try:
            return VirtualLabelPointer.from_string(value)
        except ValueError:
            pass

    return None
