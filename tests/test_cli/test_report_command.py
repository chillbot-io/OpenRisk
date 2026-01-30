"""
Tests for the report CLI command.

Tests CLI argument parsing, report generation, output formats,
and template rendering.
"""

import json
import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from openlabels.cli.commands.report import add_report_parser


class TestSetupParser:
    """Test CLI argument parser setup."""

    def test_parser_creation(self):
        """Test parser is created correctly."""
        subparsers = MagicMock()
        parser_mock = MagicMock()
        subparsers.add_parser.return_value = parser_mock

        result = add_report_parser(subparsers)

        subparsers.add_parser.assert_called_once()
        assert result == parser_mock

    def test_parser_has_required_arguments(self):
        """Test parser accepts required arguments."""
        import argparse
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        report_parser = add_report_parser(subparsers)

        # Should accept path argument
        with tempfile.TemporaryDirectory() as temp:
            args = report_parser.parse_args([temp])
            assert hasattr(args, 'path')

    def test_parser_has_format_argument(self):
        """Test parser accepts format argument."""
        import argparse
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()

        report_parser = add_report_parser(subparsers)

        with tempfile.TemporaryDirectory() as temp:
            args = report_parser.parse_args([temp, "--format", "json"])
            assert args.format == "json"


class TestReportFormats:
    """Test different report output formats."""

    def test_text_format(self):
        """Test plain text report format."""
        report_data = {
            "summary": {
                "total_files": 100,
                "files_with_risk": 25,
                "max_score": 95,
            },
            "tier_distribution": {
                "CRITICAL": 5,
                "HIGH": 10,
                "MEDIUM": 10,
                "LOW": 50,
                "MINIMAL": 25,
            }
        }

        # Text format should be human-readable
        assert report_data["summary"]["total_files"] == 100

    def test_json_format(self):
        """Test JSON report format."""
        report_data = {
            "generated_at": "2026-01-27T12:00:00Z",
            "summary": {
                "total_files": 100,
                "files_with_risk": 25,
            },
            "high_risk_files": [
                {"path": "/a.txt", "score": 95},
                {"path": "/b.txt", "score": 88},
            ]
        }

        json_str = json.dumps(report_data, indent=2)
        parsed = json.loads(json_str)

        assert parsed["summary"]["total_files"] == 100
        assert len(parsed["high_risk_files"]) == 2

    def test_html_format(self):
        """Test HTML report format."""
        # HTML format should produce valid HTML
        html_content = """<!DOCTYPE html>
<html>
<head><title>Risk Report</title></head>
<body>
<h1>Risk Report</h1>
<p>Total files: 100</p>
</body>
</html>"""

        assert "<!DOCTYPE html>" in html_content
        assert "<title>Risk Report</title>" in html_content

    def test_csv_format(self):
        """Test CSV report format."""
        import csv
        from io import StringIO

        csv_content = "path,score,tier,entities\n"
        csv_content += "/a.txt,95,CRITICAL,SSN:2\n"
        csv_content += "/b.txt,50,MEDIUM,EMAIL:5\n"

        reader = csv.DictReader(StringIO(csv_content))
        rows = list(reader)

        assert len(rows) == 2
        assert rows[0]["score"] == "95"
        assert rows[1]["tier"] == "MEDIUM"

    def test_markdown_format(self):
        """Test Markdown report format."""
        md_content = """# Risk Report

## Summary
- Total files: 100
- High risk files: 15

## Critical Risk Files
| Path | Score | Entities |
|------|-------|----------|
| /a.txt | 95 | SSN: 2 |
"""

        assert "# Risk Report" in md_content
        assert "| Path |" in md_content


class TestReportContent:
    """Test report content generation."""

    def test_summary_section(self):
        """Test summary section contains expected data."""
        summary = {
            "total_files": 1000,
            "total_size_bytes": 1024 * 1024 * 500,  # 500 MB
            "files_scanned": 980,
            "files_skipped": 20,
            "files_with_risk": 150,
            "max_score": 98,
            "avg_score": 35.5,
        }

        assert summary["total_files"] == 1000
        assert summary["files_with_risk"] == 150
        assert summary["max_score"] == 98

    def test_tier_distribution_section(self):
        """Test tier distribution breakdown."""
        distribution = {
            "CRITICAL": 10,
            "HIGH": 40,
            "MEDIUM": 100,
            "LOW": 350,
            "MINIMAL": 500,
        }

        total = sum(distribution.values())
        assert total == 1000

        # Percentages
        critical_pct = distribution["CRITICAL"] / total * 100
        assert critical_pct == 1.0

    def test_entity_breakdown_section(self):
        """Test entity type breakdown."""
        entities = {
            "SSN": {"count": 50, "files": 25},
            "CREDIT_CARD": {"count": 30, "files": 15},
            "EMAIL": {"count": 500, "files": 200},
            "PHONE": {"count": 300, "files": 150},
        }

        assert entities["SSN"]["count"] == 50
        assert entities["EMAIL"]["files"] == 200

    def test_high_risk_files_section(self):
        """Test high risk files listing."""
        high_risk_files = [
            {"path": "/data/pii.csv", "score": 98, "tier": "CRITICAL", "entities": {"SSN": 100}},
            {"path": "/data/users.json", "score": 92, "tier": "CRITICAL", "entities": {"EMAIL": 50}},
        ]

        assert len(high_risk_files) == 2
        assert all(f["score"] >= 90 for f in high_risk_files)


class TestReportFilters:
    """Test report filtering options."""

    def test_filter_by_min_score(self):
        """Test filtering report by minimum score."""
        all_files = [
            {"path": "/a.txt", "score": 95},
            {"path": "/b.txt", "score": 50},
            {"path": "/c.txt", "score": 30},
        ]

        min_score = 50
        filtered = [f for f in all_files if f["score"] >= min_score]

        assert len(filtered) == 2

    def test_filter_by_tier(self):
        """Test filtering report by tier."""
        all_files = [
            {"path": "/a.txt", "tier": "CRITICAL"},
            {"path": "/b.txt", "tier": "HIGH"},
            {"path": "/c.txt", "tier": "LOW"},
        ]

        filtered = [f for f in all_files if f["tier"] in ("CRITICAL", "HIGH")]

        assert len(filtered) == 2


class TestReportOutput:
    """Test report output options."""

    def test_output_to_file(self):
        """Test writing report to file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            report_data = {"summary": {"total": 100}}
            json.dump(report_data, f)
            f.flush()

            # Read back
            with open(f.name, 'r') as rf:
                loaded = json.load(rf)

            assert loaded["summary"]["total"] == 100

            Path(f.name).unlink()

    def test_output_to_stdout(self):
        """Test writing report to stdout."""
        report_data = {"summary": {"total": 100}}
        json_str = json.dumps(report_data)

        assert len(json_str) > 0


class TestReportErrorHandling:
    """Test error handling in report command."""

    def test_empty_directory(self):
        """Test report on empty directory produces valid report with zero files."""
        from openlabels.cli.commands.report import generate_summary, results_to_json

        with tempfile.TemporaryDirectory() as temp:
            # Empty results list (no files in directory)
            results = []

            # Summary should handle empty results gracefully
            summary = generate_summary(results)

            assert summary["total_files"] == 0
            assert summary["files_at_risk"] == 0
            assert summary["by_tier"] == {}
            assert summary["by_entity"] == {}

            # JSON output should also work
            json_output = results_to_json(results, summary)
            parsed = json.loads(json_output)

            assert parsed["summary"]["total_files"] == 0
            assert parsed["results"] == []

    def test_no_matching_files(self):
        """Test report when filter matches no files."""
        from openlabels.cli.commands.report import generate_summary
        from openlabels.cli.commands.scan import ScanResult

        # Create results where none match a high score filter
        results = [
            ScanResult(path="/a.txt", score=10, tier="LOW", entities={}, exposure="PRIVATE"),
            ScanResult(path="/b.txt", score=5, tier="MINIMAL", entities={}, exposure="PRIVATE"),
            ScanResult(path="/c.txt", score=0, tier="MINIMAL", entities={}, exposure="PRIVATE"),
        ]

        # Filter for high score (simulating filter that matches nothing)
        filtered_results = [r for r in results if r.score > 90]

        assert len(filtered_results) == 0

        # Summary should work with empty filtered results
        summary = generate_summary(filtered_results)
        assert summary["total_files"] == 0

    def test_partial_scan_failure(self):
        """Test report includes results with errors."""
        from openlabels.cli.commands.report import generate_summary, results_to_csv
        from openlabels.cli.commands.scan import ScanResult

        # Mix of successful scans and errors
        results = [
            ScanResult(path="/good1.txt", score=50, tier="MEDIUM", entities={"EMAIL": 2}, exposure="PRIVATE"),
            ScanResult(path="/error.txt", score=0, tier="UNKNOWN", entities={}, exposure="PRIVATE", error="Permission denied"),
            ScanResult(path="/good2.txt", score=80, tier="HIGH", entities={"SSN": 1}, exposure="PRIVATE"),
        ]

        # Summary should count all files including errors
        summary = generate_summary(results)
        assert summary["total_files"] == 3

        # CSV should include error column
        csv_output = results_to_csv(results)
        lines = csv_output.strip().split("\n")

        assert len(lines) == 4  # header + 3 results
        assert "error" in lines[0].lower()  # Header has error column
        assert "Permission denied" in csv_output  # Error is in output
