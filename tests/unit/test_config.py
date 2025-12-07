"""Tests for configuration module."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from blastauri.config import (
    AnalysisConfig,
    BlastauriConfig,
    ScannerConfig,
    WafConfig,
    find_config_file,
    generate_example_config,
    load_config,
)
from blastauri.core.models import Ecosystem, Severity


class TestAnalysisConfig:
    """Tests for AnalysisConfig."""

    def test_default_values(self) -> None:
        """Test default configuration values."""
        config = AnalysisConfig()
        assert config.ai_provider == "none"
        assert config.severity_threshold == Severity.LOW
        assert config.post_comment is True
        assert config.apply_labels is True

    def test_valid_ai_providers(self) -> None:
        """Test valid AI provider values."""
        for provider in ["claude", "augment", "none"]:
            config = AnalysisConfig(ai_provider=provider)
            assert config.ai_provider == provider

    def test_invalid_ai_provider(self) -> None:
        """Test that invalid AI provider raises error."""
        with pytest.raises(ValidationError):
            AnalysisConfig(ai_provider="invalid")


class TestWafConfig:
    """Tests for WafConfig."""

    def test_default_values(self) -> None:
        """Test default configuration values."""
        config = WafConfig()
        assert config.provider == "aws"
        assert config.mode == "log"
        assert config.output_dir == "./terraform/waf"
        assert config.promotion_days == 14

    def test_valid_providers(self) -> None:
        """Test valid WAF provider values."""
        for provider in ["aws", "cloudflare", "both"]:
            config = WafConfig(provider=provider)
            assert config.provider == provider

    def test_invalid_provider(self) -> None:
        """Test that invalid provider raises error."""
        with pytest.raises(ValidationError):
            WafConfig(provider="azure")

    def test_valid_modes(self) -> None:
        """Test valid WAF mode values."""
        for mode in ["log", "block"]:
            config = WafConfig(mode=mode)
            assert config.mode == mode

    def test_invalid_mode(self) -> None:
        """Test that invalid mode raises error."""
        with pytest.raises(ValidationError):
            WafConfig(mode="deny")


class TestScannerConfig:
    """Tests for ScannerConfig."""

    def test_default_ecosystems(self) -> None:
        """Test that all ecosystems are included by default."""
        config = ScannerConfig()
        assert len(config.ecosystems) == len(Ecosystem)

    def test_custom_ecosystems(self) -> None:
        """Test setting specific ecosystems."""
        config = ScannerConfig(ecosystems=[Ecosystem.NPM, Ecosystem.PYPI])
        assert len(config.ecosystems) == 2
        assert Ecosystem.NPM in config.ecosystems

    def test_default_exclude_patterns(self) -> None:
        """Test default exclude patterns."""
        config = ScannerConfig()
        assert "node_modules" in config.exclude_patterns
        assert "vendor" in config.exclude_patterns


class TestBlastauriConfig:
    """Tests for BlastauriConfig."""

    def test_default_config(self) -> None:
        """Test default configuration."""
        config = BlastauriConfig()
        assert config.version == 1
        assert config.platform == "gitlab"
        assert isinstance(config.analysis, AnalysisConfig)
        assert isinstance(config.waf, WafConfig)
        assert isinstance(config.scanner, ScannerConfig)

    def test_valid_platforms(self) -> None:
        """Test valid platform values."""
        for platform in ["gitlab", "github"]:
            config = BlastauriConfig(platform=platform)
            assert config.platform == platform

    def test_invalid_platform(self) -> None:
        """Test that invalid platform raises error."""
        with pytest.raises(ValidationError):
            BlastauriConfig(platform="bitbucket")


class TestFindConfigFile:
    """Tests for find_config_file function."""

    def test_finds_yml_config(self, temp_dir: Path) -> None:
        """Test finding .blastauri.yml file."""
        config_path = temp_dir / ".blastauri.yml"
        config_path.write_text("version: 1")

        found = find_config_file(temp_dir)
        # Use resolve() to handle macOS /private/var vs /var symlink
        assert found is not None
        assert found.resolve() == config_path.resolve()

    def test_finds_yaml_config(self, temp_dir: Path) -> None:
        """Test finding .blastauri.yaml file."""
        config_path = temp_dir / ".blastauri.yaml"
        config_path.write_text("version: 1")

        found = find_config_file(temp_dir)
        # Use resolve() to handle macOS /private/var vs /var symlink
        assert found is not None
        assert found.resolve() == config_path.resolve()

    def test_prefers_yml_over_yaml(self, temp_dir: Path) -> None:
        """Test that .yml is preferred over .yaml."""
        yml_path = temp_dir / ".blastauri.yml"
        yaml_path = temp_dir / ".blastauri.yaml"
        yml_path.write_text("version: 1")
        yaml_path.write_text("version: 2")

        found = find_config_file(temp_dir)
        # Use resolve() to handle macOS /private/var vs /var symlink
        assert found is not None
        assert found.resolve() == yml_path.resolve()

    def test_returns_none_when_not_found(self, temp_dir: Path) -> None:
        """Test that None is returned when no config exists."""
        found = find_config_file(temp_dir)
        assert found is None

    def test_searches_parent_directories(self, temp_dir: Path) -> None:
        """Test searching parent directories for config."""
        config_path = temp_dir / ".blastauri.yml"
        config_path.write_text("version: 1")

        subdir = temp_dir / "src" / "app"
        subdir.mkdir(parents=True)

        found = find_config_file(subdir)
        # Use resolve() to handle macOS /private/var vs /var symlink
        assert found is not None
        assert found.resolve() == config_path.resolve()


class TestLoadConfig:
    """Tests for load_config function."""

    def test_load_default_config(self, clean_env: None) -> None:
        """Test loading default configuration when no file exists."""
        config = load_config(config_path=Path("/nonexistent"))
        assert isinstance(config, BlastauriConfig)
        assert config.version == 1

    def test_load_from_file(self, sample_config: Path) -> None:
        """Test loading configuration from file."""
        config = load_config(config_path=sample_config)
        assert config.platform == "gitlab"
        assert config.analysis.ai_provider == "none"
        assert Ecosystem.NPM in config.scanner.ecosystems

    def test_env_vars_override_file(
        self, sample_config: Path, env_with_tokens: None
    ) -> None:
        """Test that environment variables override file values."""
        config = load_config(config_path=sample_config)
        assert config.gitlab.token == "test-gitlab-token"
        assert config.github.token == "test-github-token"


class TestGenerateExampleConfig:
    """Tests for generate_example_config function."""

    def test_generates_valid_yaml(self) -> None:
        """Test that generated example is valid YAML."""
        import yaml

        example = generate_example_config()
        parsed = yaml.safe_load(example)
        assert parsed["version"] == 1
        assert "analysis" in parsed
        assert "waf" in parsed
        assert "scanner" in parsed

    def test_contains_all_sections(self) -> None:
        """Test that example contains all configuration sections."""
        example = generate_example_config()
        assert "platform:" in example
        assert "analysis:" in example
        assert "waf:" in example
        assert "scanner:" in example
        assert "gitlab:" in example
        assert "github:" in example
