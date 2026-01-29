"""
Tests for Health Check System.

Tests health check functionality:
- Check registration and execution
- Individual check implementations
- Health report aggregation
- Error handling in checks
"""

import sys
import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from openlabels.health import (
    CheckStatus,
    CheckResult,
    HealthReport,
    HealthChecker,
    run_health_check,
)


class TestCheckStatus:
    """Tests for CheckStatus enum."""

    def test_pass_value(self):
        assert CheckStatus.PASS.value == "pass"

    def test_fail_value(self):
        assert CheckStatus.FAIL.value == "fail"

    def test_warn_value(self):
        assert CheckStatus.WARN.value == "warn"

    def test_skip_value(self):
        assert CheckStatus.SKIP.value == "skip"


class TestCheckResult:
    """Tests for CheckResult dataclass."""

    def test_passed_property(self):
        result = CheckResult(
            name="test",
            status=CheckStatus.PASS,
            message="OK",
            duration_ms=1.0,
        )
        assert result.passed is True
        assert result.failed is False

    def test_failed_property(self):
        result = CheckResult(
            name="test",
            status=CheckStatus.FAIL,
            message="Failed",
            duration_ms=1.0,
        )
        assert result.passed is False
        assert result.failed is True

    def test_to_dict(self):
        result = CheckResult(
            name="test_check",
            status=CheckStatus.PASS,
            message="Everything OK",
            duration_ms=5.5,
            details={"key": "value"},
            error=None,
        )

        d = result.to_dict()

        assert d["name"] == "test_check"
        assert d["status"] == "pass"
        assert d["message"] == "Everything OK"
        assert d["duration_ms"] == 5.5
        assert d["details"] == {"key": "value"}
        assert d["error"] is None

    def test_to_dict_with_error(self):
        result = CheckResult(
            name="test",
            status=CheckStatus.FAIL,
            message="Failed",
            duration_ms=1.0,
            error="Something went wrong",
        )

        d = result.to_dict()

        assert d["error"] == "Something went wrong"


class TestHealthReport:
    """Tests for HealthReport dataclass."""

    def test_healthy_when_no_failures(self):
        report = HealthReport(checks=[
            CheckResult("a", CheckStatus.PASS, "OK", 1.0),
            CheckResult("b", CheckStatus.PASS, "OK", 1.0),
            CheckResult("c", CheckStatus.WARN, "Warning", 1.0),
        ])

        assert report.healthy is True

    def test_unhealthy_when_failures(self):
        report = HealthReport(checks=[
            CheckResult("a", CheckStatus.PASS, "OK", 1.0),
            CheckResult("b", CheckStatus.FAIL, "Failed", 1.0),
        ])

        assert report.healthy is False

    def test_passed_property(self):
        report = HealthReport(checks=[
            CheckResult("a", CheckStatus.PASS, "OK", 1.0),
            CheckResult("b", CheckStatus.FAIL, "Failed", 1.0),
            CheckResult("c", CheckStatus.PASS, "OK", 1.0),
        ])

        assert len(report.passed) == 2

    def test_failed_property(self):
        report = HealthReport(checks=[
            CheckResult("a", CheckStatus.PASS, "OK", 1.0),
            CheckResult("b", CheckStatus.FAIL, "Failed", 1.0),
            CheckResult("c", CheckStatus.FAIL, "Failed", 1.0),
        ])

        assert len(report.failed) == 2

    def test_warnings_property(self):
        report = HealthReport(checks=[
            CheckResult("a", CheckStatus.PASS, "OK", 1.0),
            CheckResult("b", CheckStatus.WARN, "Warning", 1.0),
        ])

        assert len(report.warnings) == 1

    def test_to_dict(self):
        report = HealthReport(checks=[
            CheckResult("a", CheckStatus.PASS, "OK", 1.0),
            CheckResult("b", CheckStatus.FAIL, "Failed", 2.0),
        ])

        d = report.to_dict()

        assert d["healthy"] is False
        assert d["summary"]["total"] == 2
        assert d["summary"]["passed"] == 1
        assert d["summary"]["failed"] == 1
        assert len(d["checks"]) == 2


class TestHealthChecker:
    """Tests for HealthChecker class."""

    def test_init_registers_default_checks(self):
        checker = HealthChecker()

        check_names = [name for name, _ in checker._checks]

        assert "python_version" in check_names
        assert "dependencies" in check_names
        assert "detector" in check_names
        assert "database" in check_names
        assert "disk_space" in check_names
        assert "temp_directory" in check_names
        assert "audit_log" in check_names

    def test_register_custom_check(self):
        checker = HealthChecker()

        def custom_check():
            return CheckResult("custom", CheckStatus.PASS, "OK", 0)

        checker.register("custom", custom_check)

        check_names = [name for name, _ in checker._checks]
        assert "custom" in check_names

    def test_run_all(self):
        checker = HealthChecker()

        report = checker.run_all()

        assert isinstance(report, HealthReport)
        assert len(report.checks) > 0

    def test_run_check_by_name(self):
        checker = HealthChecker()

        result = checker.run_check("python_version")

        assert result is not None
        assert result.name == "python_version"

    def test_run_check_not_found(self):
        checker = HealthChecker()

        result = checker.run_check("nonexistent_check")

        assert result is None

    def test_run_check_handles_exception(self):
        checker = HealthChecker()

        def failing_check():
            raise RuntimeError("Check failed")

        checker.register("failing", failing_check)

        result = checker.run_check("failing")

        assert result is not None
        assert result.status == CheckStatus.FAIL
        assert "exception" in result.message.lower() or result.error is not None


class TestPythonVersionCheck:
    """Tests for Python version check."""

    def test_passes_on_supported_version(self):
        checker = HealthChecker()

        result = checker._check_python_version()

        # Current Python should be supported
        assert result.status == CheckStatus.PASS
        assert "3." in result.message

    def test_fails_on_old_version(self):
        checker = HealthChecker()

        # Mock old Python version using a named tuple-like object
        from collections import namedtuple
        VersionInfo = namedtuple('VersionInfo', ['major', 'minor', 'micro', 'releaselevel', 'serial'])
        old_version = VersionInfo(3, 7, 0, 'final', 0)

        with patch.object(sys, 'version_info', old_version):
            result = checker._check_python_version()

        assert result.status == CheckStatus.FAIL


class TestDependenciesCheck:
    """Tests for dependencies check."""

    def test_passes_when_deps_available(self):
        checker = HealthChecker()

        result = checker._check_dependencies()

        # Should pass or warn (optional deps might be missing)
        assert result.status in (CheckStatus.PASS, CheckStatus.WARN)

    def test_includes_version_info(self):
        checker = HealthChecker()

        result = checker._check_dependencies()

        assert "versions" in result.details


class TestDetectorCheck:
    """Tests for detector check."""

    def test_detector_check_runs(self):
        checker = HealthChecker()

        result = checker._check_detector()

        # Should pass if detector works, warn if no entities found
        assert result.status in (CheckStatus.PASS, CheckStatus.WARN, CheckStatus.FAIL)

    def test_detector_check_includes_details(self):
        checker = HealthChecker()

        result = checker._check_detector()

        if result.status == CheckStatus.PASS:
            assert "entity_count" in result.details or "entity_types" in result.details


class TestDatabaseCheck:
    """Tests for database check."""

    def test_sqlite_works(self):
        checker = HealthChecker()

        result = checker._check_database()

        # SQLite should work in most environments
        assert result.status in (CheckStatus.PASS, CheckStatus.WARN)

    def test_includes_sqlite_version(self):
        checker = HealthChecker()

        result = checker._check_database()

        if result.status == CheckStatus.PASS:
            assert "sqlite_version" in result.details


class TestDiskSpaceCheck:
    """Tests for disk space check."""

    def test_disk_space_check_runs(self):
        checker = HealthChecker()

        result = checker._check_disk_space()

        # Should pass on most systems
        assert result.status in (CheckStatus.PASS, CheckStatus.WARN, CheckStatus.FAIL)

    def test_includes_free_space_info(self):
        checker = HealthChecker()

        result = checker._check_disk_space()

        if result.status in (CheckStatus.PASS, CheckStatus.WARN):
            assert "free_gb" in result.details


class TestTempDirectoryCheck:
    """Tests for temp directory check."""

    def test_temp_directory_writable(self):
        checker = HealthChecker()

        result = checker._check_temp_directory()

        # Temp should be writable
        assert result.status == CheckStatus.PASS

    def test_includes_temp_path(self):
        checker = HealthChecker()

        result = checker._check_temp_directory()

        assert "temp_dir" in result.details


class TestAuditLogCheck:
    """Tests for audit log check."""

    def test_audit_log_check_runs(self):
        checker = HealthChecker()

        result = checker._check_audit_log()

        # May pass or warn depending on permissions
        assert result.status in (CheckStatus.PASS, CheckStatus.WARN)


class TestRunHealthCheck:
    """Tests for run_health_check convenience function."""

    def test_returns_health_report(self):
        report = run_health_check()

        assert isinstance(report, HealthReport)

    def test_runs_all_checks(self):
        report = run_health_check()

        assert len(report.checks) >= 7  # At least default checks


class TestCheckExceptionHandling:
    """Tests for exception handling in checks."""

    def test_exception_in_check_returns_fail(self):
        checker = HealthChecker()

        def bad_check():
            raise ValueError("Test error")

        checker.register("bad", bad_check)

        report = checker.run_all()

        bad_results = [c for c in report.checks if c.name == "bad"]
        assert len(bad_results) == 1
        assert bad_results[0].status == CheckStatus.FAIL
        assert bad_results[0].error is not None

    def test_exception_doesnt_stop_other_checks(self):
        checker = HealthChecker()

        def bad_check():
            raise ValueError("Test error")

        def good_check():
            return CheckResult("good", CheckStatus.PASS, "OK", 0)

        checker.register("bad", bad_check)
        checker.register("good", good_check)

        report = checker.run_all()

        # Both checks should be in results
        names = [c.name for c in report.checks]
        assert "bad" in names
        assert "good" in names


class TestCheckTiming:
    """Tests for check timing."""

    def test_duration_is_recorded(self):
        checker = HealthChecker()

        report = checker.run_all()

        for check in report.checks:
            assert check.duration_ms >= 0

    def test_individual_check_timing(self):
        checker = HealthChecker()

        result = checker.run_check("python_version")

        assert result.duration_ms >= 0


class TestCustomConfigPath:
    """Tests for custom config path."""

    def test_accepts_config_path(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("key: value")

        checker = HealthChecker(config_path=config_file)

        assert checker.config_path == config_file
