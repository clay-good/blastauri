"""Tests for CLI module."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from blastauri import __version__
from blastauri.cli import app

runner = CliRunner()


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
        assert "Know what breaks before you merge" in result.stdout

    def test_no_args_shows_help(self) -> None:
        """Test that no arguments shows help."""
        result = runner.invoke(app, [])
        assert result.exit_code == 0
        assert "Usage:" in result.stdout


class TestAnalyzeCommand:
    """Tests for analyze command."""

    def test_analyze_requires_platform_args(self) -> None:
        """Test that analyze requires either GitLab or GitHub args."""
        result = runner.invoke(app, ["analyze"])
        assert result.exit_code == 1
        assert "Must specify either --project/--mr or --repo/--pr" in result.stdout

    def test_analyze_gitlab(self) -> None:
        """Test analyze with GitLab args."""
        result = runner.invoke(app, ["analyze", "--project", "mygroup/myproject", "--mr", "123"])
        assert result.exit_code == 0
        assert "Analyzing GitLab MR" in result.stdout

    def test_analyze_github(self) -> None:
        """Test analyze with GitHub args."""
        result = runner.invoke(app, ["analyze", "--repo", "owner/repo", "--pr", "456"])
        assert result.exit_code == 0
        assert "Analyzing GitHub PR" in result.stdout


class TestScanCommand:
    """Tests for scan command."""

    def test_scan_current_directory(self, temp_dir: Path) -> None:
        """Test scanning current directory."""
        result = runner.invoke(app, ["scan", str(temp_dir)])
        assert result.exit_code == 0
        assert "Scanning" in result.stdout

    def test_scan_with_format(self, temp_dir: Path) -> None:
        """Test scan with format option."""
        result = runner.invoke(app, ["scan", str(temp_dir), "--format", "json"])
        assert result.exit_code == 0
        assert "Output format: json" in result.stdout

    def test_scan_with_severity(self, temp_dir: Path) -> None:
        """Test scan with severity filter."""
        result = runner.invoke(app, ["scan", str(temp_dir), "--severity", "high"])
        assert result.exit_code == 0
        assert "Minimum severity: high" in result.stdout


class TestWafCommands:
    """Tests for WAF subcommands."""

    def test_waf_help(self) -> None:
        """Test WAF subcommand help."""
        result = runner.invoke(app, ["waf", "--help"])
        assert result.exit_code == 0
        assert "WAF rule generation" in result.stdout

    def test_waf_generate(self, temp_dir: Path) -> None:
        """Test waf generate command."""
        result = runner.invoke(app, ["waf", "generate", str(temp_dir)])
        assert result.exit_code == 0
        assert "Generating WAF rules" in result.stdout

    def test_waf_generate_with_provider(self, temp_dir: Path) -> None:
        """Test waf generate with provider option."""
        result = runner.invoke(app, ["waf", "generate", str(temp_dir), "--provider", "cloudflare"])
        assert result.exit_code == 0
        assert "Provider: cloudflare" in result.stdout

    def test_waf_sync(self) -> None:
        """Test waf sync command."""
        result = runner.invoke(app, ["waf", "sync"])
        assert result.exit_code == 0
        assert "Synchronizing WAF rules" in result.stdout

    def test_waf_status(self, temp_dir: Path) -> None:
        """Test waf status command."""
        result = runner.invoke(app, ["waf", "status", str(temp_dir)])
        assert result.exit_code == 0
        assert "WAF status" in result.stdout


class TestConfigCommands:
    """Tests for config subcommands."""

    def test_config_help(self) -> None:
        """Test config subcommand help."""
        result = runner.invoke(app, ["config", "--help"])
        assert result.exit_code == 0
        assert "Configuration management" in result.stdout

    def test_config_init(self, temp_dir: Path) -> None:
        """Test config init command."""
        result = runner.invoke(app, ["config", "init", str(temp_dir)])
        assert result.exit_code == 0
        assert "Creating configuration file" in result.stdout

    def test_config_show(self) -> None:
        """Test config show command."""
        result = runner.invoke(app, ["config", "show"])
        assert result.exit_code == 0
        assert "Current configuration" in result.stdout


class TestGlobalOptions:
    """Tests for global CLI options."""

    def test_verbose_flag(self, temp_dir: Path) -> None:
        """Test --verbose flag."""
        result = runner.invoke(app, ["--verbose", "scan", str(temp_dir)])
        assert result.exit_code == 0

    def test_quiet_flag(self, temp_dir: Path) -> None:
        """Test --quiet flag."""
        result = runner.invoke(app, ["--quiet", "scan", str(temp_dir)])
        assert result.exit_code == 0
