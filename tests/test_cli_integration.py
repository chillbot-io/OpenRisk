"""
CLI Integration Tests.

Tests for the OpenLabels command-line interface.
These tests verify CLI commands work end-to-end.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def temp_dir():
    """Create a temporary directory with test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test files with PII-like content
        pii_file = Path(tmpdir) / "pii_data.txt"
        pii_file.write_text(
            "Customer: John Smith\n"
            "SSN: 123-45-6789\n"
            "Email: john.smith@example.com\n"
            "Phone: (555) 123-4567\n"
        )

        # Create clean file
        clean_file = Path(tmpdir) / "clean.txt"
        clean_file.write_text("This is just regular text without any sensitive data.")

        # Create nested structure
        subdir = Path(tmpdir) / "data"
        subdir.mkdir()
        (subdir / "nested.txt").write_text("Nested file content")

        yield Path(tmpdir)


def run_cli(*args, input_text=None):
    """Run the CLI command and return result."""
    cmd = [sys.executable, "-m", "openlabels.cli.main"] + list(args)
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=input_text,
        timeout=30,
    )
    return result


# =============================================================================
# Version Tests
# =============================================================================

class TestVersion:
    """Tests for --version flag."""

    def test_version_shows_version(self):
        """Test that --version displays version info."""
        result = run_cli("--version")

        # Should exit successfully and show version
        assert result.returncode == 0
        assert "openlabels" in result.stdout.lower() or "openrisk" in result.stdout.lower()


# =============================================================================
# Help Tests
# =============================================================================

class TestHelp:
    """Tests for --help flag."""

    def test_help_shows_usage(self):
        """Test that --help shows usage information."""
        result = run_cli("--help")

        assert result.returncode == 0
        assert "usage" in result.stdout.lower() or "Usage" in result.stdout

    def test_scan_help(self):
        """Test that scan --help shows scan options."""
        result = run_cli("scan", "--help")

        assert result.returncode == 0
        # Should mention path argument
        assert "path" in result.stdout.lower()


# =============================================================================
# Detect Command Tests
# =============================================================================

class TestDetectCommand:
    """Tests for the detect command (text detection)."""

    def test_detect_text_with_ssn(self):
        """Test detecting SSN in text."""
        result = run_cli("detect", "My SSN is 123-45-6789")

        # Should find the SSN
        assert result.returncode == 0
        # Output should mention entities found or SSN
        assert "SSN" in result.stdout or "entities" in result.stdout.lower()

    def test_detect_text_with_email(self):
        """Test detecting email in text."""
        result = run_cli("detect", "Contact me at test@example.com")

        assert result.returncode == 0
        assert "EMAIL" in result.stdout or "email" in result.stdout.lower()

    def test_detect_clean_text(self):
        """Test detecting no PII in clean text."""
        result = run_cli("detect", "The quick brown fox jumps over the lazy dog")

        assert result.returncode == 0
        # Should indicate no PII found
        assert "No PII" in result.stdout or "0" in result.stdout

    def test_detect_json_output(self):
        """Test JSON output format."""
        result = run_cli("detect", "SSN: 123-45-6789", "--format", "json")

        assert result.returncode == 0
        # Should be valid JSON
        data = json.loads(result.stdout)
        assert "spans" in data or "entity_counts" in data


# =============================================================================
# Detect-File Command Tests
# =============================================================================

class TestDetectFileCommand:
    """Tests for the detect-file command."""

    def test_detect_file_with_pii(self, temp_dir):
        """Test detecting PII in a file."""
        pii_file = temp_dir / "pii_data.txt"
        result = run_cli("detect-file", str(pii_file))

        assert result.returncode == 0
        # Should find entities
        assert "SSN" in result.stdout or "entities" in result.stdout.lower()

    def test_detect_file_clean(self, temp_dir):
        """Test detecting no PII in clean file."""
        clean_file = temp_dir / "clean.txt"
        result = run_cli("detect-file", str(clean_file))

        assert result.returncode == 0

    def test_detect_file_nonexistent(self):
        """Test error handling for nonexistent file."""
        result = run_cli("detect-file", "/nonexistent/file.txt")

        # Should exit with error
        assert result.returncode != 0

    def test_detect_file_json_output(self, temp_dir):
        """Test JSON output for file detection."""
        pii_file = temp_dir / "pii_data.txt"
        result = run_cli("detect-file", str(pii_file), "--format", "json")

        assert result.returncode == 0
        data = json.loads(result.stdout)
        assert isinstance(data, dict)


# =============================================================================
# Detect-Dir Command Tests
# =============================================================================

class TestDetectDirCommand:
    """Tests for the detect-dir command."""

    def test_detect_dir_scans_files(self, temp_dir):
        """Test that detect-dir scans files in directory."""
        result = run_cli("detect-dir", str(temp_dir))

        assert result.returncode == 0

    def test_detect_dir_recursive(self, temp_dir):
        """Test recursive directory scanning."""
        result = run_cli("detect-dir", str(temp_dir), "--recursive")

        assert result.returncode == 0

    def test_detect_dir_nonexistent(self):
        """Test error handling for nonexistent directory."""
        result = run_cli("detect-dir", "/nonexistent/directory")

        assert result.returncode != 0


# =============================================================================
# Scan Command Tests
# =============================================================================

class TestScanCommand:
    """Tests for the scan command."""

    def test_scan_file(self, temp_dir):
        """Test scanning a single file."""
        pii_file = temp_dir / "pii_data.txt"
        result = run_cli("scan", str(pii_file))

        assert result.returncode == 0

    def test_scan_directory(self, temp_dir):
        """Test scanning a directory."""
        result = run_cli("scan", str(temp_dir))

        assert result.returncode == 0

    def test_scan_with_json_output(self, temp_dir):
        """Test scan with JSON output (single JSON object, not JSONL)."""
        result = run_cli("scan", str(temp_dir), "--format", "json")

        assert result.returncode == 0
        # --format json outputs a single JSON object with summary and results
        output = json.loads(result.stdout)
        assert "summary" in output
        assert "results" in output
        assert isinstance(output["results"], list)

    def test_scan_with_jsonl_output(self, temp_dir):
        """Test scan with JSONL output (one JSON object per line)."""
        result = run_cli("scan", str(temp_dir), "--format", "jsonl")

        assert result.returncode == 0
        # --format jsonl outputs one JSON object per line
        for line in result.stdout.strip().split('\n'):
            if line:
                parsed = json.loads(line)
                assert "path" in parsed

    def test_scan_nonexistent_path(self):
        """Test error handling for nonexistent path."""
        result = run_cli("scan", "/nonexistent/path")

        assert result.returncode != 0


# =============================================================================
# Find Command Tests
# =============================================================================

class TestFindCommand:
    """Tests for the find command."""

    def test_find_basic(self, temp_dir):
        """Test basic find command."""
        result = run_cli("find", str(temp_dir))

        assert result.returncode == 0

    def test_find_with_limit(self, temp_dir):
        """Test find with --limit option."""
        result = run_cli("find", str(temp_dir), "--limit", "1")

        assert result.returncode == 0


# =============================================================================
# Health Command Tests
# =============================================================================

class TestHealthCommand:
    """Tests for the health command."""

    def test_health_runs(self):
        """Test that health command runs."""
        result = run_cli("health")

        # Health check should run (may pass or warn)
        assert result.returncode in [0, 1]  # 0=pass, 1=warn/fail


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_text_detect(self):
        """Test detecting with empty text."""
        result = run_cli("detect", "")

        # Should handle gracefully
        assert result.returncode == 0

    def test_unicode_text(self):
        """Test detecting unicode text."""
        result = run_cli("detect", "Naïve café résumé: test@example.com")

        # Should handle unicode without crashing
        assert result.returncode == 0

    def test_very_long_text(self):
        """Test detecting very long text."""
        # Generate long text with some PII
        long_text = "Regular text. " * 1000 + " SSN: 123-45-6789 " + " More text. " * 1000
        result = run_cli("detect", long_text)

        assert result.returncode == 0

    def test_special_characters_in_path(self, temp_dir):
        """Test file with special characters in name."""
        special_file = temp_dir / "file with spaces.txt"
        special_file.write_text("SSN: 123-45-6789")

        result = run_cli("detect-file", str(special_file))

        assert result.returncode == 0


# =============================================================================
# Output Format Tests
# =============================================================================

class TestOutputFormats:
    """Tests for different output formats."""

    def test_text_format(self):
        """Test default text format."""
        result = run_cli("detect", "Email: test@example.com", "--format", "text")

        assert result.returncode == 0
        # Should be human-readable
        assert "EMAIL" in result.stdout or "email" in result.stdout.lower()

    def test_json_format_is_valid(self):
        """Test that JSON format produces valid JSON."""
        result = run_cli("detect", "Email: test@example.com", "--format", "json")

        assert result.returncode == 0
        # Should parse as JSON
        data = json.loads(result.stdout)
        assert isinstance(data, dict)

    def test_jsonl_format(self):
        """Test JSONL (line-delimited JSON) format."""
        result = run_cli("detect", "Email: test@example.com", "--format", "jsonl")

        assert result.returncode == 0
        # Should be valid JSON
        data = json.loads(result.stdout.strip())
        assert isinstance(data, dict)
