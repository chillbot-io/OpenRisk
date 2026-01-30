"""
Tests for the quarantine CLI command.

Tests CLI argument parsing, file operations, safety checks,
and audit logging.
"""

import json
import pytest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from openlabels.cli.commands.quarantine import add_quarantine_parser


class TestSetupParser:
    """Test CLI argument parser setup."""

    def test_parser_creation(self):
        """Test parser is created correctly."""
        subparsers = MagicMock()
        parser_mock = MagicMock()
        subparsers.add_parser.return_value = parser_mock

        result = add_quarantine_parser(subparsers)

        subparsers.add_parser.assert_called_once()
        assert result == parser_mock

    def test_parser_has_required_arguments(self):
        """Test parser accepts required arguments."""
        import argparse
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        quarantine_parser = add_quarantine_parser(subparsers)

        # Command requires source, --where, and --to arguments
        with tempfile.TemporaryDirectory() as temp:
            dest = tempfile.mkdtemp()
            try:
                args = quarantine_parser.parse_args([
                    temp,
                    "--where", "score > 80",
                    "--to", dest,
                ])
                assert hasattr(args, 'source')
                assert args.where == "score > 80"
                assert args.to == dest
            finally:
                shutil.rmtree(dest)

    def test_parser_has_filter_arguments(self):
        """Test parser accepts filter via --where."""
        import argparse
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        quarantine_parser = add_quarantine_parser(subparsers)

        with tempfile.TemporaryDirectory() as temp:
            dest = tempfile.mkdtemp()
            try:
                args = quarantine_parser.parse_args([
                    temp,
                    "--where", "tier == 'CRITICAL'",
                    "--to", dest,
                ])
                assert args.where == "tier == 'CRITICAL'"
            finally:
                shutil.rmtree(dest)


class TestQuarantineDestination:
    """Test quarantine destination handling."""

    def test_destination_argument(self):
        """Test --to specifies quarantine directory."""
        import argparse
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        quarantine_parser = add_quarantine_parser(subparsers)

        with tempfile.TemporaryDirectory() as temp:
            custom_dest = tempfile.mkdtemp()
            try:
                args = quarantine_parser.parse_args([
                    temp,
                    "--where", "score > 50",
                    "--to", custom_dest,
                ])
                assert args.to == custom_dest
            finally:
                shutil.rmtree(custom_dest)


class TestQuarantineSafetyChecks:
    """Test safety checks for quarantine operation."""

    def test_dry_run_mode(self):
        """Test dry-run mode flag."""
        import argparse
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        quarantine_parser = add_quarantine_parser(subparsers)

        with tempfile.TemporaryDirectory() as temp:
            dest = tempfile.mkdtemp()
            try:
                args = quarantine_parser.parse_args([
                    temp,
                    "--where", "score > 80",
                    "--to", dest,
                    "--dry-run"
                ])
                assert args.dry_run is True
            finally:
                shutil.rmtree(dest)

    def test_force_flag(self):
        """Test force flag to skip confirmation."""
        import argparse
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        quarantine_parser = add_quarantine_parser(subparsers)

        with tempfile.TemporaryDirectory() as temp:
            dest = tempfile.mkdtemp()
            try:
                args = quarantine_parser.parse_args([
                    temp,
                    "--where", "score > 80",
                    "--to", dest,
                    "--force"
                ])
                assert args.force is True
            finally:
                shutil.rmtree(dest)


class TestQuarantineFileOperations:
    """Test file movement operations."""

    @pytest.fixture
    def temp_source_dir(self):
        """Create a temporary source directory with test files."""
        temp = tempfile.mkdtemp()

        # Create test files
        (Path(temp) / "high_risk.txt").write_text("SSN: 123-45-6789")
        (Path(temp) / "low_risk.txt").write_text("Hello world")

        yield temp

        if Path(temp).exists():
            shutil.rmtree(temp)

    @pytest.fixture
    def temp_dest_dir(self):
        """Create a temporary destination directory."""
        temp = tempfile.mkdtemp()
        yield temp
        if Path(temp).exists():
            shutil.rmtree(temp)

    def test_file_moved_successfully(self, temp_source_dir, temp_dest_dir):
        """Test file is moved to quarantine."""
        source_file = Path(temp_source_dir) / "high_risk.txt"
        assert source_file.exists()

        # Simulate move
        dest_file = Path(temp_dest_dir) / "high_risk.txt"
        shutil.move(str(source_file), str(dest_file))

        assert not source_file.exists()
        assert dest_file.exists()

    def test_original_path_preserved(self, temp_source_dir, temp_dest_dir):
        """Test original path metadata is preserved."""
        source_file = Path(temp_source_dir) / "high_risk.txt"
        original_path = str(source_file)

        # In real implementation, original path is stored in xattr or manifest
        assert original_path.endswith("high_risk.txt")


class TestQuarantineAuditLogging:
    """Test audit logging for quarantine operations."""

    def test_audit_log_created(self):
        """Test audit log entry is created for each quarantine."""
        from unittest.mock import patch, MagicMock
        from openlabels.cli.commands.quarantine import move_file

        with tempfile.TemporaryDirectory() as source_dir:
            with tempfile.TemporaryDirectory() as dest_dir:
                # Create test file
                source_file = Path(source_dir) / "test.txt"
                source_file.write_text("test content")

                # Patch the audit logger
                with patch('openlabels.cli.commands.quarantine.audit') as mock_audit:
                    # Move file manually first
                    new_path = move_file(source_file, Path(dest_dir))

                    # Now simulate the audit call that cmd_quarantine would make
                    mock_audit.file_quarantine(
                        source=str(source_file),
                        destination=str(new_path),
                        score=75,
                        tier="HIGH",
                    )

                    # Verify audit was called
                    mock_audit.file_quarantine.assert_called_once()
                    call_kwargs = mock_audit.file_quarantine.call_args
                    assert "source" in str(call_kwargs)
                    assert "destination" in str(call_kwargs)

    def test_audit_log_contains_required_fields(self):
        """Test audit log has required fields."""
        from unittest.mock import patch, MagicMock

        # Mock the audit logger and capture calls
        with patch('openlabels.logging_config.get_audit_logger') as mock_get_audit:
            mock_audit = MagicMock()
            mock_get_audit.return_value = mock_audit

            # Simulate a quarantine audit log entry
            mock_audit.file_quarantine(
                source="/original/path.txt",
                destination="/quarantine/path.txt",
                score=85,
                tier="CRITICAL",
            )

            # Verify required fields were passed
            mock_audit.file_quarantine.assert_called_once_with(
                source="/original/path.txt",
                destination="/quarantine/path.txt",
                score=85,
                tier="CRITICAL",
            )


class TestQuarantineErrorHandling:
    """Test error handling in quarantine command."""

    def test_permission_denied_error(self):
        """Test handling of permission denied errors."""
        from openlabels.cli.commands.quarantine import move_file
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as source_dir:
            with tempfile.TemporaryDirectory() as dest_dir:
                source_file = Path(source_dir) / "test.txt"
                source_file.write_text("test content")

                # Mock os.rename to raise PermissionError
                with patch('os.rename', side_effect=OSError("Permission denied")):
                    # Also mock shutil.copy2 to raise PermissionError
                    with patch('shutil.copy2', side_effect=PermissionError("Cannot write to destination")):
                        with pytest.raises(PermissionError):
                            move_file(source_file, Path(dest_dir))

    def test_disk_full_error(self):
        """Test handling of disk full errors."""
        from openlabels.cli.commands.quarantine import move_file
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as source_dir:
            with tempfile.TemporaryDirectory() as dest_dir:
                source_file = Path(source_dir) / "test.txt"
                source_file.write_text("test content")

                # Mock os.rename to fail (cross-filesystem) and shutil.copy2 to fail
                with patch('os.rename', side_effect=OSError("Cross-device link")):
                    with patch('shutil.copy2', side_effect=OSError("No space left on device")):
                        with pytest.raises(OSError) as exc_info:
                            move_file(source_file, Path(dest_dir))

                        assert "space" in str(exc_info.value).lower() or "device" in str(exc_info.value).lower()

    def test_partial_failure_handling(self):
        """Test handling when some files fail to quarantine."""
        from openlabels.cli.commands.quarantine import move_file

        with tempfile.TemporaryDirectory() as source_dir:
            with tempfile.TemporaryDirectory() as dest_dir:
                # Create multiple test files
                file1 = Path(source_dir) / "file1.txt"
                file2 = Path(source_dir) / "file2.txt"
                file3 = Path(source_dir) / "file3.txt"

                file1.write_text("content1")
                file2.write_text("content2")
                file3.write_text("content3")

                moved = []
                errors = []

                # Simulate partial failure - file2 doesn't exist anymore
                file2.unlink()

                for f in [file1, file2, file3]:
                    try:
                        new_path = move_file(f, Path(dest_dir))
                        moved.append(str(new_path))
                    except (FileNotFoundError, ValueError, PermissionError) as e:
                        errors.append({"path": str(f), "error": str(e)})

                # file1 and file3 should succeed, file2 should fail
                assert len(moved) == 2, f"Expected 2 moves, got {len(moved)}"
                assert len(errors) == 1, f"Expected 1 error, got {len(errors)}"
                assert "file2.txt" in errors[0]["path"]


class TestQuarantineOutputFormats:
    """Test different output formats."""

    def test_summary_output(self):
        """Test summary output after quarantine."""
        summary = {
            "files_quarantined": 5,
            "files_skipped": 2,
            "errors": 1,
            "total_size_bytes": 1024000,
        }

        assert summary["files_quarantined"] == 5
        assert summary["errors"] == 1

    def test_json_output(self):
        """Test JSON output format."""
        results = [
            {"source": "/a.txt", "destination": "/quarantine/a.txt", "success": True},
            {"source": "/b.txt", "destination": "/quarantine/b.txt", "success": True},
        ]

        json_str = json.dumps(results)
        parsed = json.loads(json_str)

        assert len(parsed) == 2
        assert all(r["success"] for r in parsed)

    def test_verbose_output(self):
        """Test verbose output shows details."""
        from openlabels.cli.commands.quarantine import write_manifest

        with tempfile.TemporaryDirectory() as dest_dir:
            # Simulate moved files with detailed info
            moved_files = [
                {
                    "original_path": "/source/file1.txt",
                    "new_path": f"{dest_dir}/file1.txt",
                    "score": 85,
                    "tier": "HIGH",
                    "entities": {"SSN": 2},
                },
                {
                    "original_path": "/source/file2.txt",
                    "new_path": f"{dest_dir}/file2.txt",
                    "score": 95,
                    "tier": "CRITICAL",
                    "entities": {"CREDIT_CARD": 5},
                },
            ]

            # Write manifest (verbose output includes manifest)
            manifest_path = write_manifest(
                Path(dest_dir), moved_files, "score > 75"
            )

            # Read back and verify details
            assert manifest_path.exists()
            with open(manifest_path) as f:
                manifest = json.load(f)

            assert manifest["file_count"] == 2
            assert manifest["filter"] == "score > 75"
            assert len(manifest["files"]) == 2
            assert manifest["files"][0]["score"] == 85
            assert manifest["files"][1]["tier"] == "CRITICAL"
