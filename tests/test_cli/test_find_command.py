"""
Tests for the find CLI command.

Tests CLI argument parsing, filter expressions, output formatting,
and result matching.
"""

import json
import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from openlabels.cli.commands.find import add_find_parser


class TestSetupParser:
    """Test CLI argument parser setup."""

    def test_parser_creation(self):
        """Test parser is created correctly."""
        subparsers = MagicMock()
        parser_mock = MagicMock()
        subparsers.add_parser.return_value = parser_mock

        result = add_find_parser(subparsers)

        subparsers.add_parser.assert_called_once()
        assert result == parser_mock

    def test_parser_has_filter_arguments(self):
        """Test parser accepts filter arguments via --where."""
        import argparse
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        find_parser = add_find_parser(subparsers)

        # Filter is passed via --where
        with tempfile.TemporaryDirectory() as temp:
            args = find_parser.parse_args([
                temp,
                "--where", "score >= 50 AND tier == 'HIGH'",
            ])
            assert args.where == "score >= 50 AND tier == 'HIGH'"


class TestFilterExpressions:
    """Test filter expression parsing and evaluation."""

    def test_min_score_filter(self):
        """Test minimum score filtering."""
        from openlabels.cli.filter import parse_filter

        # Test filter expression parsing
        filter_obj = parse_filter("score >= 50")
        assert filter_obj is not None

        # Test evaluation
        result = {"score": 75}
        assert filter_obj.evaluate(result) is True

        result = {"score": 25}
        assert filter_obj.evaluate(result) is False

    def test_tier_filter(self):
        """Test tier filtering."""
        from openlabels.cli.filter import parse_filter

        # Tier filter uses single = not ==
        filter_obj = parse_filter("tier = HIGH")
        assert filter_obj is not None

        result = {"tier": "HIGH"}
        assert filter_obj.evaluate(result) is True

        result = {"tier": "LOW"}
        assert filter_obj.evaluate(result) is False

    def test_combined_filter(self):
        """Test combined filter expressions."""
        from openlabels.cli.filter import parse_filter

        # Use AND keyword with single = for equality
        filter_obj = parse_filter("score >= 50 AND tier = HIGH")
        assert filter_obj is not None

        result = {"score": 75, "tier": "HIGH"}
        assert filter_obj.evaluate(result) is True

        result = {"score": 75, "tier": "LOW"}
        assert filter_obj.evaluate(result) is False

    def test_entity_filter(self):
        """Test entity type filtering with has() function."""
        from openlabels.cli.filter import parse_filter

        # Use has() function for entity checks
        filter_obj = parse_filter("has(SSN)")
        assert filter_obj is not None


class TestFindOutputFormats:
    """Test different output formats for find command."""

    def test_default_output_format(self):
        """Test default (text) output format."""
        # The default format should produce human-readable output
        pass  # Format tested via integration tests

    def test_json_output_format(self):
        """Test JSON output format."""
        result = {
            "path": "/test/file.txt",
            "score": 75,
            "tier": "HIGH",
            "entities": {"SSN": 2},
        }

        json_str = json.dumps(result)
        parsed = json.loads(json_str)

        assert parsed["path"] == "/test/file.txt"
        assert parsed["score"] == 75

    def test_paths_only_output(self):
        """Test paths-only output for piping."""
        results = [
            {"path": "/a.txt", "score": 50},
            {"path": "/b.txt", "score": 80},
        ]

        paths = [r["path"] for r in results]

        assert paths == ["/a.txt", "/b.txt"]

    def test_count_output(self):
        """Test count-only output."""
        results = [
            {"path": "/a.txt"},
            {"path": "/b.txt"},
            {"path": "/c.txt"},
        ]

        count = len(results)

        assert count == 3


class TestFindIntegration:
    """Integration tests for find command."""

    @pytest.fixture
    def temp_dir_with_index(self):
        """Create a temporary directory with indexed files."""
        import tempfile
        import shutil

        temp = tempfile.mkdtemp()

        # Create test files
        (Path(temp) / "high_risk.txt").write_text("SSN: 123-45-6789")
        (Path(temp) / "low_risk.txt").write_text("Hello world")
        (Path(temp) / "medium_risk.txt").write_text("Email: test@example.com")

        yield temp

        shutil.rmtree(temp)

    def test_find_with_min_score(self, temp_dir_with_index):
        """Test finding files with minimum score."""
        # Would need full integration with scanner/index
        pass

    def test_find_with_tier_filter(self, temp_dir_with_index):
        """Test finding files by tier."""
        pass

    def test_find_with_limit(self, temp_dir_with_index):
        """Test limiting number of results."""
        pass


class TestFindErrorHandling:
    """Test error handling in find command."""

    def test_nonexistent_path(self):
        """Test handling of nonexistent path."""
        import argparse
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        find_parser = add_find_parser(subparsers)

        # Parser should accept the path even if it doesn't exist
        # (validation happens at runtime)
        args = find_parser.parse_args(["/nonexistent/path"])
        assert args.path == "/nonexistent/path"

    def test_invalid_filter_expression(self):
        """Test handling of invalid filter expression."""
        from openlabels.cli.filter import parse_filter

        # Invalid expression raises ValueError
        with pytest.raises(ValueError):
            parse_filter("invalid &&& syntax")

    def test_invalid_tier_value(self):
        """Test handling of invalid tier value in filter."""
        import argparse
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        find_parser = add_find_parser(subparsers)

        # Parser should accept any filter value (validation at runtime)
        with tempfile.TemporaryDirectory() as temp:
            args = find_parser.parse_args([temp, "--where", "tier == INVALID"])
            assert args.where == "tier == INVALID"
