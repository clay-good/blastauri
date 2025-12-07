"""Tests for CLI module."""

import tempfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from blastauri import __version__
from blastauri.cli import app

runner = CliRunner()


@pytest.fixture
def temp_dir():
    """Create a temporary directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


class TestCLI:
    """Tests for CLI commands."""

    def test_version_flag(self) -> None:
        """Test --version flag."""
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert __version__ in result.stdout

    def test_help_flag(self) -> None:
        """Test --help flag."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "blastauri" in result.stdout.lower()

    def test_no_args_shows_help(self) -> None:
        """Test that no arguments shows help (no_args_is_help=True)."""
        result = runner.invoke(app, [])
        # With no_args_is_help=True, typer shows help and may exit with code 0 or 2
        assert result.exit_code in (0, 2)
        # Check for typical help output indicators
        assert "Usage" in result.stdout or "usage" in result.stdout.lower()


class TestAnalyzeCommand:
    """Tests for analyze command."""

    def test_analyze_requires_platform_args(self) -> None:
        """Test that analyze requires either GitLab or GitHub args or dry-run."""
        result = runner.invoke(app, ["analyze"])
        assert result.exit_code == 1
        assert "Must specify either --project/--mr, --repo/--pr, or --dry-run" in result.stdout

    def test_analyze_dry_run_mode(self) -> None:
        """Test that analyze --dry-run works without API tokens."""
        result = runner.invoke(app, ["analyze", "--dry-run"])
        assert result.exit_code == 0
        assert "Running in dry-run mode" in result.stdout
        assert "Sample Analysis Results" in result.stdout
        assert "Breaking Changes:" in result.stdout
        assert "CVEs Fixed:" in result.stdout
        assert "Dry-run complete" in result.stdout

    def test_analyze_gitlab_missing_token(self) -> None:
        """Test analyze with GitLab args but missing token shows attempt."""
        result = runner.invoke(app, ["analyze", "--project", "mygroup/myproject", "--mr", "123"])
        # Should attempt to analyze (even if it fails due to missing token)
        assert "Analyzing GitLab MR" in result.stdout or result.exit_code != 0

    def test_analyze_github_missing_token(self) -> None:
        """Test analyze with GitHub args but missing token shows attempt."""
        result = runner.invoke(app, ["analyze", "--repo", "owner/repo", "--pr", "456"])
        # Should attempt to analyze (even if it fails due to missing token)
        assert "Analyzing GitHub PR" in result.stdout or result.exit_code != 0


class TestScanCommand:
    """Tests for scan command."""

    def test_scan_current_directory(self, temp_dir: Path) -> None:
        """Test scanning directory."""
        result = runner.invoke(app, ["scan", str(temp_dir)])
        assert result.exit_code == 0
        assert "Scanning" in result.stdout or "No supported lockfiles" in result.stdout

    def test_scan_with_format(self, temp_dir: Path) -> None:
        """Test scan with format option."""
        result = runner.invoke(app, ["scan", str(temp_dir), "--format", "json"])
        assert result.exit_code == 0

    def test_scan_with_severity(self, temp_dir: Path) -> None:
        """Test scan with severity filter."""
        result = runner.invoke(app, ["scan", str(temp_dir), "--severity", "high"])
        assert result.exit_code == 0


class TestWafCommands:
    """Tests for WAF subcommands."""

    def test_waf_help(self) -> None:
        """Test WAF subcommand help."""
        result = runner.invoke(app, ["waf", "--help"])
        assert result.exit_code == 0
        assert "waf" in result.stdout.lower()

    def test_waf_generate(self, temp_dir: Path) -> None:
        """Test waf generate command."""
        result = runner.invoke(app, ["waf", "generate", str(temp_dir)])
        assert result.exit_code == 0
        assert "Generating WAF rules" in result.stdout or "WAF" in result.stdout

    def test_waf_generate_with_provider(self, temp_dir: Path) -> None:
        """Test waf generate with provider option."""
        result = runner.invoke(app, ["waf", "generate", str(temp_dir), "--provider", "cloudflare"])
        assert result.exit_code == 0
        assert "Provider: cloudflare" in result.stdout

    def test_waf_sync_help(self) -> None:
        """Test waf sync command help."""
        result = runner.invoke(app, ["waf", "sync", "--help"])
        assert result.exit_code == 0

    def test_waf_status(self, temp_dir: Path) -> None:
        """Test waf status command."""
        result = runner.invoke(app, ["waf", "status", str(temp_dir)])
        assert result.exit_code == 0


class TestConfigCommands:
    """Tests for config subcommands."""

    def test_config_help(self) -> None:
        """Test config subcommand help."""
        result = runner.invoke(app, ["config", "--help"])
        assert result.exit_code == 0
        assert "config" in result.stdout.lower()

    def test_config_init(self, temp_dir: Path) -> None:
        """Test config init command."""
        result = runner.invoke(app, ["config", "init", str(temp_dir)])
        assert result.exit_code == 0

    def test_config_show(self) -> None:
        """Test config show command."""
        result = runner.invoke(app, ["config", "show"])
        assert result.exit_code == 0


class TestGlobalOptions:
    """Tests for global CLI options."""

    def test_verbose_flag(self, temp_dir: Path) -> None:
        """Test --verbose flag."""
        result = runner.invoke(app, ["--verbose", "scan", str(temp_dir)])
        # Should run without error
        assert result.exit_code == 0

    def test_quiet_flag(self, temp_dir: Path) -> None:
        """Test --quiet flag."""
        result = runner.invoke(app, ["--quiet", "scan", str(temp_dir)])
        # Should run without error
        assert result.exit_code == 0
