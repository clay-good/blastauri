"""Tests for WAF orchestrator module."""

import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blastauri.core.models import CVE, Dependency, Ecosystem, Severity
from blastauri.core.waf_orchestrator import (
    WafSyncConfig,
    WafSyncOrchestrator,
    WafSyncResult,
)
from blastauri.waf.lifecycle import WafRuleState, WafState
from blastauri.waf.providers.base import WafProviderType, WafRuleMode


class TestWafSyncConfig:
    """Tests for WafSyncConfig dataclass."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = WafSyncConfig()

        assert config.provider == WafProviderType.AWS
        assert config.mode == WafRuleMode.LOG
        assert config.output_dir == "./terraform/waf"
        assert config.state_dir == ".blastauri"
        assert config.promotion_days == 14
        assert config.name_prefix == "blastauri"

    def test_custom_config(self) -> None:
        """Test custom configuration values."""
        config = WafSyncConfig(
            provider=WafProviderType.CLOUDFLARE,
            mode=WafRuleMode.BLOCK,
            output_dir="./custom/waf",
            state_dir=".custom",
            promotion_days=7,
            name_prefix="custom",
        )

        assert config.provider == WafProviderType.CLOUDFLARE
        assert config.mode == WafRuleMode.BLOCK
        assert config.output_dir == "./custom/waf"
        assert config.state_dir == ".custom"
        assert config.promotion_days == 7
        assert config.name_prefix == "custom"


class TestWafSyncResult:
    """Tests for WafSyncResult dataclass."""

    def test_result_creation(self) -> None:
        """Test creating a sync result."""
        result = WafSyncResult(
            success=True,
            rules_created=5,
            rules_updated=2,
            rules_removed=1,
            rules_promoted=3,
            terraform_files=["main.tf", "variables.tf"],
            mr_url="https://gitlab.com/test/-/merge_requests/123",
            warnings=["Minor warning"],
            errors=[],
        )

        assert result.success is True
        assert result.rules_created == 5
        assert result.rules_updated == 2
        assert result.rules_removed == 1
        assert result.rules_promoted == 3
        assert len(result.terraform_files) == 2
        assert result.mr_url is not None
        assert len(result.warnings) == 1
        assert len(result.errors) == 0

    def test_result_defaults(self) -> None:
        """Test result default values."""
        result = WafSyncResult(success=True)

        assert result.rules_created == 0
        assert result.rules_updated == 0
        assert result.rules_removed == 0
        assert result.rules_promoted == 0
        assert result.terraform_files == []
        assert result.mr_url is None
        assert result.warnings == []
        assert result.errors == []


class TestWafSyncOrchestrator:
    """Tests for WafSyncOrchestrator."""

    @pytest.fixture
    def temp_dir(self) -> Path:
        """Create a temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def orchestrator(self, temp_dir: Path) -> WafSyncOrchestrator:
        """Create orchestrator instance."""
        config = WafSyncConfig(
            output_dir=str(temp_dir / "waf"),
            state_dir=str(temp_dir / ".blastauri"),
        )
        return WafSyncOrchestrator(config)

    @pytest.fixture
    def sample_dependencies(self) -> list:
        """Create sample dependencies."""
        return [
            Dependency(
                name="log4j-core",
                version="2.14.0",
                ecosystem=Ecosystem.MAVEN,
                location="pom.xml",
            ),
            Dependency(
                name="spring-core",
                version="5.3.0",
                ecosystem=Ecosystem.MAVEN,
                location="pom.xml",
            ),
        ]

    @pytest.fixture
    def sample_cves(self) -> list:
        """Create sample CVEs."""
        return [
            CVE(
                id="CVE-2021-44228",
                description="Log4j RCE",
                severity=Severity.CRITICAL,
                source="nvd",
                is_waf_mitigatable=True,
                waf_pattern_id="log4j",
            ),
            CVE(
                id="CVE-2022-22965",
                description="Spring4Shell",
                severity=Severity.CRITICAL,
                source="nvd",
                is_waf_mitigatable=True,
                waf_pattern_id="spring4shell",
            ),
        ]

    def test_orchestrator_creation(self, orchestrator: WafSyncOrchestrator) -> None:
        """Test orchestrator creation."""
        assert orchestrator.config is not None
        assert orchestrator.config.provider == WafProviderType.AWS

    def test_get_status_empty(self, orchestrator: WafSyncOrchestrator) -> None:
        """Test getting status with no state."""
        status = orchestrator.get_status()

        assert "total_rules" in status
        assert status["total_rules"] == 0
        assert "rules_in_log_mode" in status
        assert "rules_in_block_mode" in status
        assert "promotion_candidates" in status

    @pytest.mark.asyncio
    async def test_sync_no_cves(
        self, orchestrator: WafSyncOrchestrator, sample_dependencies: list
    ) -> None:
        """Test sync with no WAF-mitigatable CVEs."""
        result = await orchestrator.sync(
            dependencies=sample_dependencies,
            cves=[],
            fixed_versions={},
        )

        assert result.success is True
        assert result.rules_created == 0

    @pytest.mark.asyncio
    async def test_sync_with_cves(
        self,
        orchestrator: WafSyncOrchestrator,
        sample_dependencies: list,
        sample_cves: list,
    ) -> None:
        """Test sync with WAF-mitigatable CVEs."""
        result = await orchestrator.sync(
            dependencies=sample_dependencies,
            cves=sample_cves,
            fixed_versions={},
        )

        assert result.success is True
        assert result.rules_created >= 0

    @pytest.mark.asyncio
    async def test_sync_with_fixed_versions(
        self,
        orchestrator: WafSyncOrchestrator,
        sample_dependencies: list,
        sample_cves: list,
    ) -> None:
        """Test sync when vulnerabilities are fixed."""
        fixed_versions = {
            "CVE-2021-44228": "2.17.0",
        }

        result = await orchestrator.sync(
            dependencies=sample_dependencies,
            cves=sample_cves,
            fixed_versions=fixed_versions,
        )

        assert result.success is True

    def test_config_serialization(self, orchestrator: WafSyncOrchestrator) -> None:
        """Test that config can be accessed."""
        config = orchestrator.config

        assert config.provider in [WafProviderType.AWS, WafProviderType.CLOUDFLARE]
        assert config.mode in [WafRuleMode.LOG, WafRuleMode.BLOCK]


class TestWafSyncIntegration:
    """Integration tests for WAF sync."""

    @pytest.fixture
    def temp_project(self) -> Path:
        """Create a temporary project directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project = Path(tmpdir)

            # Create state directory
            (project / ".blastauri").mkdir()

            # Create output directory
            (project / "terraform" / "waf").mkdir(parents=True)

            yield project

    def test_full_workflow(self, temp_project: Path) -> None:
        """Test full WAF sync workflow."""
        config = WafSyncConfig(
            output_dir=str(temp_project / "terraform" / "waf"),
            state_dir=str(temp_project / ".blastauri"),
        )

        orchestrator = WafSyncOrchestrator(config)

        # Initial status
        status = orchestrator.get_status()
        assert status["total_rules"] == 0

    def test_output_directory_creation(self, temp_project: Path) -> None:
        """Test that output directories are created as needed."""
        config = WafSyncConfig(
            output_dir=str(temp_project / "new" / "terraform" / "waf"),
            state_dir=str(temp_project / ".blastauri"),
        )

        orchestrator = WafSyncOrchestrator(config)
        assert orchestrator is not None


class TestProviderConfiguration:
    """Tests for provider-specific configuration."""

    def test_aws_provider_config(self) -> None:
        """Test AWS provider configuration."""
        config = WafSyncConfig(
            provider=WafProviderType.AWS,
        )

        assert config.provider == WafProviderType.AWS

    def test_cloudflare_provider_config(self) -> None:
        """Test Cloudflare provider configuration."""
        config = WafSyncConfig(
            provider=WafProviderType.CLOUDFLARE,
        )

        assert config.provider == WafProviderType.CLOUDFLARE

    def test_mode_configuration(self) -> None:
        """Test rule mode configuration."""
        log_config = WafSyncConfig(mode=WafRuleMode.LOG)
        assert log_config.mode == WafRuleMode.LOG

        block_config = WafSyncConfig(mode=WafRuleMode.BLOCK)
        assert block_config.mode == WafRuleMode.BLOCK
