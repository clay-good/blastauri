"""Configuration management for blastauri."""

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator

from blastauri.core.models import Ecosystem, Severity


class AnalysisConfig(BaseModel):
    """Configuration for upgrade impact analysis."""

    ai_provider: str = Field(
        default="none",
        description="AI provider for enhanced analysis (claude, augment, none)",
    )
    severity_threshold: Severity = Field(
        default=Severity.LOW,
        description="Minimum severity to report",
    )
    post_comment: bool = Field(
        default=True,
        description="Post analysis as MR/PR comment",
    )
    apply_labels: bool = Field(
        default=True,
        description="Apply severity labels to MR/PR",
    )

    @field_validator("ai_provider")
    @classmethod
    def validate_ai_provider(cls, v: str) -> str:
        """Validate AI provider value."""
        allowed = {"claude", "augment", "none"}
        if v.lower() not in allowed:
            raise ValueError(f"ai_provider must be one of: {allowed}")
        return v.lower()


class WafConfig(BaseModel):
    """Configuration for WAF rule management."""

    provider: str = Field(
        default="aws",
        description="WAF provider (aws, cloudflare, both)",
    )
    mode: str = Field(
        default="log",
        description="WAF rule mode (log, block)",
    )
    output_dir: str = Field(
        default="./terraform/waf",
        description="Output directory for Terraform files",
    )
    promotion_days: int = Field(
        default=14,
        ge=1,
        description="Days before suggesting rule promotion from log to block",
    )

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, v: str) -> str:
        """Validate WAF provider value."""
        allowed = {"aws", "cloudflare", "both"}
        if v.lower() not in allowed:
            raise ValueError(f"provider must be one of: {allowed}")
        return v.lower()

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        """Validate WAF mode value."""
        allowed = {"log", "block"}
        if v.lower() not in allowed:
            raise ValueError(f"mode must be one of: {allowed}")
        return v.lower()


class ScannerConfig(BaseModel):
    """Configuration for dependency scanning."""

    ecosystems: list[Ecosystem] = Field(
        default_factory=lambda: list(Ecosystem),
        description="Ecosystems to scan",
    )
    exclude_dev: bool = Field(
        default=False,
        description="Exclude development dependencies",
    )
    exclude_patterns: list[str] = Field(
        default_factory=lambda: ["node_modules", "vendor", ".git", "__pycache__"],
        description="Patterns to exclude from scanning",
    )


class GitLabConfig(BaseModel):
    """Configuration for GitLab integration."""

    url: str = Field(
        default="https://gitlab.com",
        description="GitLab instance URL",
    )
    token: str | None = Field(
        default=None,
        description="GitLab personal access token (prefer GITLAB_TOKEN env var)",
    )


class GitHubConfig(BaseModel):
    """Configuration for GitHub integration."""

    api_url: str = Field(
        default="https://api.github.com",
        description="GitHub API URL",
    )
    token: str | None = Field(
        default=None,
        description="GitHub personal access token (prefer GITHUB_TOKEN env var)",
    )


class BlastauriConfig(BaseModel):
    """Complete blastauri configuration."""

    version: int = Field(default=1, description="Configuration file version")
    platform: str = Field(
        default="gitlab",
        description="Primary platform (gitlab, github)",
    )
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    waf: WafConfig = Field(default_factory=WafConfig)
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)
    gitlab: GitLabConfig = Field(default_factory=GitLabConfig)
    github: GitHubConfig = Field(default_factory=GitHubConfig)

    @field_validator("platform")
    @classmethod
    def validate_platform(cls, v: str) -> str:
        """Validate platform value."""
        allowed = {"gitlab", "github"}
        if v.lower() not in allowed:
            raise ValueError(f"platform must be one of: {allowed}")
        return v.lower()


def find_config_file(start_path: Path | None = None) -> Path | None:
    """Find the nearest .blastauri.yml configuration file.

    Searches from start_path up to the root directory.

    Args:
        start_path: Starting directory for search (defaults to cwd).

    Returns:
        Path to config file if found, None otherwise.
    """
    if start_path is None:
        start_path = Path.cwd()

    current = start_path.resolve()

    while current != current.parent:
        config_path = current / ".blastauri.yml"
        if config_path.exists():
            return config_path

        config_path = current / ".blastauri.yaml"
        if config_path.exists():
            return config_path

        current = current.parent

    return None


def load_config(
    config_path: Path | None = None,
    env_prefix: str = "BLASTAURI_",
) -> BlastauriConfig:
    """Load configuration from file and environment variables.

    Priority (highest to lowest):
    1. Environment variables
    2. Config file
    3. Defaults

    Args:
        config_path: Path to config file (searches if not provided).
        env_prefix: Prefix for environment variables.

    Returns:
        Loaded configuration.
    """
    config_data: dict[str, Any] = {}

    if config_path is None:
        config_path = find_config_file()

    if config_path and config_path.exists():
        with open(config_path) as f:
            file_data = yaml.safe_load(f)
            if file_data:
                config_data = file_data

    gitlab_token = os.environ.get("GITLAB_TOKEN")
    if gitlab_token:
        if "gitlab" not in config_data:
            config_data["gitlab"] = {}
        config_data["gitlab"]["token"] = gitlab_token

    github_token = os.environ.get("GITHUB_TOKEN")
    if github_token:
        if "github" not in config_data:
            config_data["github"] = {}
        config_data["github"]["token"] = github_token

    nvd_api_key = os.environ.get("NVD_API_KEY")
    if nvd_api_key:
        config_data["nvd_api_key"] = nvd_api_key

    return BlastauriConfig(**config_data)


def generate_example_config() -> str:
    """Generate an example configuration file.

    Returns:
        YAML string of example configuration.
    """
    example = """# Blastauri Configuration
# See https://github.com/clay-good/blastauri for documentation

version: 1

# Primary platform: gitlab or github
platform: gitlab

# Upgrade impact analysis settings
analysis:
  # AI provider for enhanced analysis: claude, augment, or none
  ai_provider: none
  # Minimum severity to report: critical, high, medium, low
  severity_threshold: low
  # Post analysis as MR/PR comment
  post_comment: true
  # Apply severity labels to MR/PR
  apply_labels: true

# WAF rule management settings
waf:
  # WAF provider: aws, cloudflare, or both
  provider: aws
  # Default rule mode: log or block
  mode: log
  # Output directory for generated Terraform
  output_dir: ./terraform/waf
  # Days before suggesting promotion from log to block
  promotion_days: 14

# Dependency scanner settings
scanner:
  # Ecosystems to scan (omit to scan all)
  ecosystems:
    - npm
    - pypi
    - go
    - rubygems
    - maven
    - cargo
    - composer
  # Exclude development dependencies
  exclude_dev: false
  # Patterns to exclude from scanning
  exclude_patterns:
    - node_modules
    - vendor
    - .git
    - __pycache__

# GitLab configuration (token via GITLAB_TOKEN env var)
gitlab:
  url: https://gitlab.com

# GitHub configuration (token via GITHUB_TOKEN env var)
github:
  api_url: https://api.github.com
"""
    return example
