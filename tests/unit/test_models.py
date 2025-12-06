"""Tests for core data models."""

from datetime import datetime

import pytest
from pydantic import ValidationError

from blastauri.core.models import (
    AffectedPackage,
    AnalysisReport,
    BreakingChange,
    BreakingChangeType,
    CVE,
    Dependency,
    DependencyUpdate,
    Ecosystem,
    ImpactedLocation,
    ScanResult,
    Severity,
    UpgradeImpact,
    UsageLocation,
    WafRule,
    WafState,
)


class TestEcosystem:
    """Tests for Ecosystem enum."""

    def test_all_ecosystems_defined(self) -> None:
        """Verify all expected ecosystems are defined."""
        expected = {"npm", "pypi", "go", "rubygems", "maven", "cargo", "composer"}
        actual = {e.value for e in Ecosystem}
        assert actual == expected

    def test_ecosystem_string_values(self) -> None:
        """Verify ecosystem values are lowercase strings."""
        for eco in Ecosystem:
            assert eco.value == eco.value.lower()


class TestSeverity:
    """Tests for Severity enum."""

    def test_all_severities_defined(self) -> None:
        """Verify all expected severities are defined."""
        expected = {"critical", "high", "medium", "low", "none", "unknown"}
        actual = {s.value for s in Severity}
        assert actual == expected


class TestDependency:
    """Tests for Dependency model."""

    def test_minimal_dependency(self) -> None:
        """Test creating a dependency with minimal fields."""
        dep = Dependency(
            name="lodash",
            version="4.17.21",
            ecosystem=Ecosystem.NPM,
            location="package-lock.json",
        )
        assert dep.name == "lodash"
        assert dep.version == "4.17.21"
        assert dep.ecosystem == Ecosystem.NPM
        assert dep.is_dev is False
        assert dep.is_direct is True
        assert dep.parent is None

    def test_full_dependency(self) -> None:
        """Test creating a dependency with all fields."""
        dep = Dependency(
            name="pytest",
            version="8.0.0",
            ecosystem=Ecosystem.PYPI,
            location="requirements.txt",
            is_dev=True,
            is_direct=False,
            parent="pytest-cov",
        )
        assert dep.is_dev is True
        assert dep.is_direct is False
        assert dep.parent == "pytest-cov"

    def test_dependency_validation(self) -> None:
        """Test that missing required fields raise ValidationError."""
        with pytest.raises(ValidationError):
            Dependency(name="test", version="1.0.0")  # type: ignore[call-arg]


class TestScanResult:
    """Tests for ScanResult model."""

    def test_empty_scan_result(self) -> None:
        """Test creating an empty scan result."""
        result = ScanResult(repository_path="/path/to/repo")
        assert result.dependencies == []
        assert result.lockfiles_scanned == []
        assert result.errors == []
        assert isinstance(result.scan_timestamp, datetime)

    def test_scan_result_with_dependencies(self) -> None:
        """Test creating a scan result with dependencies."""
        deps = [
            Dependency(
                name="lodash",
                version="4.17.21",
                ecosystem=Ecosystem.NPM,
                location="package-lock.json",
            ),
        ]
        result = ScanResult(
            dependencies=deps,
            lockfiles_scanned=["package-lock.json"],
            repository_path="/path/to/repo",
        )
        assert len(result.dependencies) == 1
        assert result.dependencies[0].name == "lodash"


class TestCVE:
    """Tests for CVE model."""

    def test_minimal_cve(self) -> None:
        """Test creating a CVE with minimal fields."""
        cve = CVE(
            id="CVE-2021-44228",
            description="Log4j remote code execution",
            source="nvd",
        )
        assert cve.id == "CVE-2021-44228"
        assert cve.severity == Severity.UNKNOWN
        assert cve.is_waf_mitigatable is False

    def test_full_cve(self) -> None:
        """Test creating a CVE with all fields."""
        cve = CVE(
            id="CVE-2021-44228",
            description="Log4j remote code execution",
            severity=Severity.CRITICAL,
            cvss_score=10.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            affected_packages=[
                AffectedPackage(
                    ecosystem=Ecosystem.MAVEN,
                    name="log4j-core",
                    version_start="2.0",
                    version_end="2.14.1",
                    fixed_version="2.17.0",
                )
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            source="nvd",
            is_waf_mitigatable=True,
            waf_pattern_id="log4j",
        )
        assert cve.cvss_score == 10.0
        assert len(cve.affected_packages) == 1
        assert cve.is_waf_mitigatable is True

    def test_cvss_score_validation(self) -> None:
        """Test CVSS score validation."""
        with pytest.raises(ValidationError):
            CVE(
                id="CVE-2021-1234",
                description="Test",
                source="nvd",
                cvss_score=11.0,  # Invalid: > 10
            )


class TestBreakingChange:
    """Tests for BreakingChange model."""

    def test_breaking_change(self) -> None:
        """Test creating a breaking change."""
        change = BreakingChange(
            change_type=BreakingChangeType.REMOVED_FUNCTION,
            description="Function foo() was removed",
            old_api="foo(x, y)",
            new_api=None,
            migration_guide="Use bar(x, y) instead",
            source="CHANGELOG.md",
        )
        assert change.change_type == BreakingChangeType.REMOVED_FUNCTION
        assert change.old_api == "foo(x, y)"


class TestUsageLocation:
    """Tests for UsageLocation model."""

    def test_usage_location(self) -> None:
        """Test creating a usage location."""
        loc = UsageLocation(
            file_path="src/utils.py",
            line_number=42,
            column=8,
            code_snippet="from lodash import debounce",
            usage_type="import",
            symbol="debounce",
        )
        assert loc.line_number == 42
        assert loc.usage_type == "import"

    def test_line_number_validation(self) -> None:
        """Test that line number must be >= 1."""
        with pytest.raises(ValidationError):
            UsageLocation(
                file_path="test.py",
                line_number=0,
                column=0,
                code_snippet="test",
                usage_type="import",
                symbol="test",
            )


class TestUpgradeImpact:
    """Tests for UpgradeImpact model."""

    def test_upgrade_impact(self) -> None:
        """Test creating an upgrade impact."""
        impact = UpgradeImpact(
            dependency_name="lodash",
            ecosystem=Ecosystem.NPM,
            from_version="4.17.20",
            to_version="5.0.0",
            is_major_upgrade=True,
            risk_score=75,
            severity=Severity.HIGH,
        )
        assert impact.is_major_upgrade is True
        assert impact.risk_score == 75

    def test_risk_score_validation(self) -> None:
        """Test risk score bounds validation."""
        with pytest.raises(ValidationError):
            UpgradeImpact(
                dependency_name="test",
                ecosystem=Ecosystem.NPM,
                from_version="1.0.0",
                to_version="2.0.0",
                risk_score=101,
            )


class TestAnalysisReport:
    """Tests for AnalysisReport model."""

    def test_analysis_report(self) -> None:
        """Test creating an analysis report."""
        report = AnalysisReport(
            merge_request_id="123",
            repository="mygroup/myproject",
            overall_risk_score=50,
            overall_severity=Severity.MEDIUM,
            summary="2 dependencies updated with 1 breaking change",
            recommendations=["Review breaking changes before merging"],
        )
        assert report.merge_request_id == "123"
        assert len(report.recommendations) == 1


class TestWafState:
    """Tests for WAF state models."""

    def test_waf_rule(self) -> None:
        """Test creating a WAF rule."""
        rule = WafRule(
            rule_id="blastauri-log4j",
            cve_ids=["CVE-2021-44228"],
            mode="log",
            status="active",
        )
        assert rule.rule_id == "blastauri-log4j"
        assert "CVE-2021-44228" in rule.cve_ids

    def test_waf_state(self) -> None:
        """Test creating WAF state."""
        state = WafState(
            rules=[
                WafRule(
                    rule_id="blastauri-log4j",
                    cve_ids=["CVE-2021-44228"],
                )
            ]
        )
        assert state.version == 1
        assert len(state.rules) == 1
