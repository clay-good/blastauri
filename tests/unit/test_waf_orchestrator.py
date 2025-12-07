"""Tests for WAF orchestrator module."""

import tempfile
from pathlib import Path

import pytest

from blastauri.core.models import CVE, Dependency, Ecosystem, Severity
from blastauri.core.waf_orchestrator import (
    WafSyncConfig,
    WafSyncOrchestrator,
    WafSyncResult,
)
from blastauri.waf.providers.base import WafProviderType, WafRuleMode


class TestWafSyncConfig:
    """Tests for WafSyncConfig dataclass."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = WafSyncConfig()

        assert config.provider == WafProviderType.AWS
        assert config.mode == WafRuleMode.LOG
        assert config.output_dir == "./terraform/waf"
        assert config.promotion_days == 14
        assert config.name_prefix == "blastauri"

    def test_custom_config(self) -> None:
        """Test custom configuration values."""
        config = WafSyncConfig(
            provider=WafProviderType.CLOUDFLARE,
            mode=WafRuleMode.BLOCK,
            output_dir="./custom/waf",
            promotion_days=7,
            name_prefix="custom",
        )

        assert config.provider == WafProviderType.CLOUDFLARE
        assert config.mode == WafRuleMode.BLOCK
        assert config.output_dir == "./custom/waf"
        assert config.promotion_days == 7
        assert config.name_prefix == "custom"


class TestWafSyncResult:
    """Tests for WafSyncResult dataclass."""

    def test_result_creation(self) -> None:
        """Test creating a sync result."""
        result = WafSyncResult(
            success=True,
            analysis=None,
            terraform_files=["main.tf", "variables.tf"],
            mr_created=True,
            mr_url="https://gitlab.com/test/-/merge_requests/123",
            new_state=None,
            errors=[],
            summary="WAF sync complete",
        )

        assert result.success is True
        assert len(result.terraform_files) == 2
        assert result.mr_url is not None
        assert len(result.errors) == 0

    def test_result_with_errors(self) -> None:
        """Test result with errors."""
        result = WafSyncResult(
            success=False,
            analysis=None,
            terraform_files=[],
            mr_created=False,
            mr_url=None,
            new_state=None,
            errors=["Error 1", "Error 2"],
            summary="WAF sync failed",
        )

        assert result.success is False
        assert result.mr_created is False
        assert len(result.errors) == 2


class TestWafSyncOrchestrator:
    """Tests for WafSyncOrchestrator."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def orchestrator(self, temp_dir: Path) -> WafSyncOrchestrator:
        """Create orchestrator instance."""
        config = WafSyncConfig(
            output_dir=str(temp_dir / "waf"),
        )
        return WafSyncOrchestrator(str(temp_dir), config)

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

    def test_orchestrator_creation(self, temp_dir: Path) -> None:
        """Test orchestrator creation."""
        config = WafSyncConfig()
        orchestrator = WafSyncOrchestrator(str(temp_dir), config)
        assert orchestrator is not None

    def test_get_status_empty(self, orchestrator: WafSyncOrchestrator) -> None:
        """Test getting status with no state."""
        status = orchestrator.get_status()

        assert "total_rules" in status
        assert status["total_rules"] == 0

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


class TestWafSyncIntegration:
    """Integration tests for WAF sync."""

    @pytest.fixture
    def temp_project(self):
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
        )

        orchestrator = WafSyncOrchestrator(str(temp_project), config)

        # Initial status
        status = orchestrator.get_status()
        assert status["total_rules"] == 0

    def test_output_directory_creation(self, temp_project: Path) -> None:
        """Test that output directories are created as needed."""
        config = WafSyncConfig(
            output_dir=str(temp_project / "new" / "terraform" / "waf"),
        )

        orchestrator = WafSyncOrchestrator(str(temp_project), config)
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
