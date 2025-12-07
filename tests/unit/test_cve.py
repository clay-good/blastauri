"""Tests for CVE intelligence module."""

from datetime import datetime
from pathlib import Path

import pytest

from blastauri.core.models import CVE, AffectedPackage, Ecosystem, Severity
from blastauri.cve.cache import CveCache
from blastauri.cve.waf_patterns import (
    get_all_patterns,
    get_waf_pattern,
    get_waf_pattern_id,
    is_waf_mitigatable,
)


class TestCveCache:
    """Tests for CVE cache."""

    @pytest.fixture
    def cache(self, temp_dir: Path) -> CveCache:
        """Create a cache instance with temp directory."""
        return CveCache(cache_dir=temp_dir, ttl_seconds=3600)

    @pytest.fixture
    def sample_cve(self) -> CVE:
        """Create a sample CVE."""
        return CVE(
            id="CVE-2021-44228",
            description="Apache Log4j2 JNDI injection vulnerability",
            severity=Severity.CRITICAL,
            cvss_score=10.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            affected_packages=[
                AffectedPackage(
                    ecosystem=Ecosystem.MAVEN,
                    name="org.apache.logging.log4j:log4j-core",
                    version_start="2.0",
                    version_end="2.17.0",
                    fixed_version="2.17.0",
                )
            ],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            published_date=datetime(2021, 12, 10),
            modified_date=datetime(2023, 11, 7),
            source="nvd",
            is_waf_mitigatable=True,
            waf_pattern_id="log4j",
        )

    def test_set_and_get_cve(self, cache: CveCache, sample_cve: CVE) -> None:
        """Test storing and retrieving a CVE."""
        cache.set_cve(sample_cve)

        retrieved = cache.get_cve(sample_cve.id)
        assert retrieved is not None
        assert retrieved.id == sample_cve.id
        assert retrieved.description == sample_cve.description
        assert retrieved.severity == sample_cve.severity
        assert retrieved.cvss_score == sample_cve.cvss_score

    def test_get_nonexistent_cve(self, cache: CveCache) -> None:
        """Test getting a CVE that doesn't exist."""
        retrieved = cache.get_cve("CVE-9999-99999")
        assert retrieved is None

    def test_delete_cve(self, cache: CveCache, sample_cve: CVE) -> None:
        """Test deleting a CVE."""
        cache.set_cve(sample_cve)
        cache.delete_cve(sample_cve.id)

        retrieved = cache.get_cve(sample_cve.id)
        assert retrieved is None

    def test_set_and_get_package_cves(
        self, cache: CveCache, sample_cve: CVE
    ) -> None:
        """Test storing and retrieving CVEs for a package."""
        ecosystem = Ecosystem.MAVEN
        package_name = "log4j-core"
        version = "2.14.0"

        cache.set_package_cves(ecosystem, package_name, [sample_cve], version)

        retrieved = cache.get_package_cves(ecosystem, package_name, version)
        assert retrieved is not None
        assert len(retrieved) == 1
        assert retrieved[0].id == sample_cve.id

    def test_get_package_cves_not_found(self, cache: CveCache) -> None:
        """Test getting CVEs for a package that's not cached."""
        retrieved = cache.get_package_cves(
            Ecosystem.NPM, "nonexistent-package", "1.0.0"
        )
        assert retrieved is None

    def test_clear_all(self, cache: CveCache, sample_cve: CVE) -> None:
        """Test clearing all cache entries."""
        cache.set_cve(sample_cve)
        cache.clear_all()

        retrieved = cache.get_cve(sample_cve.id)
        assert retrieved is None

    def test_get_stats(self, cache: CveCache, sample_cve: CVE) -> None:
        """Test getting cache statistics."""
        cache.set_cve(sample_cve)

        stats = cache.get_stats()
        assert stats["total_cves"] >= 1
        assert stats["valid_cves"] >= 1
        assert "db_path" in stats

    def test_affected_packages_serialization(
        self, cache: CveCache, sample_cve: CVE
    ) -> None:
        """Test that affected packages are correctly serialized/deserialized."""
        cache.set_cve(sample_cve)

        retrieved = cache.get_cve(sample_cve.id)
        assert retrieved is not None
        assert len(retrieved.affected_packages) == 1

        pkg = retrieved.affected_packages[0]
        assert pkg.ecosystem == Ecosystem.MAVEN
        assert pkg.name == "org.apache.logging.log4j:log4j-core"
        assert pkg.version_start == "2.0"
        assert pkg.fixed_version == "2.17.0"


class TestWafPatterns:
    """Tests for WAF pattern detection."""

    @pytest.fixture
    def log4j_cve(self) -> CVE:
        """Create a Log4j CVE."""
        return CVE(
            id="CVE-2021-44228",
            description="Apache Log4j2 JNDI injection vulnerability allows remote code execution",
            severity=Severity.CRITICAL,
            cvss_score=10.0,
            affected_packages=[
                AffectedPackage(
                    ecosystem=Ecosystem.MAVEN,
                    name="org.apache.logging.log4j:log4j-core",
                    version_start="2.0",
                    fixed_version="2.17.0",
                )
            ],
            source="nvd",
        )

    @pytest.fixture
    def spring4shell_cve(self) -> CVE:
        """Create a Spring4Shell CVE."""
        return CVE(
            id="CVE-2022-22965",
            description="Spring Framework RCE via Data Binding on JDK 9+ allows class loader manipulation",
            severity=Severity.CRITICAL,
            cvss_score=9.8,
            affected_packages=[
                AffectedPackage(
                    ecosystem=Ecosystem.MAVEN,
                    name="org.springframework:spring-core",
                    version_start="5.3.0",
                    fixed_version="5.3.18",
                )
            ],
            source="nvd",
        )

    @pytest.fixture
    def xss_cve(self) -> CVE:
        """Create an XSS CVE."""
        return CVE(
            id="CVE-2023-12345",
            description="Cross-site scripting vulnerability in template rendering",
            severity=Severity.MEDIUM,
            cvss_score=6.1,
            source="nvd",
        )

    @pytest.fixture
    def generic_cve(self) -> CVE:
        """Create a generic CVE that isn't WAF-mitigatable."""
        return CVE(
            id="CVE-2023-99999",
            description="Memory corruption vulnerability in parsing module",
            severity=Severity.HIGH,
            cvss_score=7.5,
            source="nvd",
        )

    def test_is_waf_mitigatable_log4j(self, log4j_cve: CVE) -> None:
        """Test Log4j CVE is WAF-mitigatable."""
        assert is_waf_mitigatable(log4j_cve) is True

    def test_is_waf_mitigatable_spring4shell(self, spring4shell_cve: CVE) -> None:
        """Test Spring4Shell CVE is WAF-mitigatable."""
        assert is_waf_mitigatable(spring4shell_cve) is True

    def test_is_waf_mitigatable_xss(self, xss_cve: CVE) -> None:
        """Test XSS CVE is WAF-mitigatable."""
        assert is_waf_mitigatable(xss_cve) is True

    def test_is_not_waf_mitigatable_generic(self, generic_cve: CVE) -> None:
        """Test generic CVE is not WAF-mitigatable."""
        assert is_waf_mitigatable(generic_cve) is False

    def test_get_waf_pattern_id_log4j(self, log4j_cve: CVE) -> None:
        """Test getting WAF pattern ID for Log4j."""
        pattern_id = get_waf_pattern_id(log4j_cve)
        assert pattern_id == "log4j"

    def test_get_waf_pattern_id_spring4shell(self, spring4shell_cve: CVE) -> None:
        """Test getting WAF pattern ID for Spring4Shell."""
        pattern_id = get_waf_pattern_id(spring4shell_cve)
        assert pattern_id == "spring4shell"

    def test_get_waf_pattern_id_xss(self, xss_cve: CVE) -> None:
        """Test getting WAF pattern ID for XSS."""
        pattern_id = get_waf_pattern_id(xss_cve)
        assert pattern_id == "xss"

    def test_get_waf_pattern_id_generic(self, generic_cve: CVE) -> None:
        """Test getting WAF pattern ID for generic CVE."""
        pattern_id = get_waf_pattern_id(generic_cve)
        assert pattern_id is None

    def test_get_waf_pattern(self) -> None:
        """Test getting WAF pattern by ID."""
        pattern = get_waf_pattern("log4j")
        assert pattern is not None
        assert pattern.id == "log4j"
        assert "CVE-2021-44228" in pattern.cve_ids

    def test_get_waf_pattern_not_found(self) -> None:
        """Test getting non-existent WAF pattern."""
        pattern = get_waf_pattern("nonexistent")
        assert pattern is None

    def test_get_all_patterns(self) -> None:
        """Test getting all WAF patterns."""
        patterns = get_all_patterns()
        assert len(patterns) >= 6

        pattern_ids = {p.id for p in patterns}
        assert "log4j" in pattern_ids
        assert "spring4shell" in pattern_ids
        assert "sqli" in pattern_ids
        assert "xss" in pattern_ids

    def test_cve_id_detection(self) -> None:
        """Test detection by CVE ID."""
        cve = CVE(
            id="CVE-2021-44228",
            description="Some generic description",
            severity=Severity.CRITICAL,
            source="nvd",
        )
        assert is_waf_mitigatable(cve) is True
        assert get_waf_pattern_id(cve) == "log4j"


class TestCveModel:
    """Tests for CVE model."""

    def test_cve_creation(self) -> None:
        """Test creating a CVE."""
        cve = CVE(
            id="CVE-2021-44228",
            description="Test vulnerability",
            severity=Severity.CRITICAL,
            source="nvd",
        )
        assert cve.id == "CVE-2021-44228"
        assert cve.severity == Severity.CRITICAL
        assert cve.is_waf_mitigatable is False

    def test_cve_with_affected_packages(self) -> None:
        """Test CVE with affected packages."""
        cve = CVE(
            id="CVE-2021-44228",
            description="Test vulnerability",
            severity=Severity.CRITICAL,
            source="nvd",
            affected_packages=[
                AffectedPackage(
                    ecosystem=Ecosystem.MAVEN,
                    name="log4j-core",
                    version_start="2.0",
                    version_end="2.17.0",
                    fixed_version="2.17.0",
                )
            ],
        )
        assert len(cve.affected_packages) == 1
        assert cve.affected_packages[0].ecosystem == Ecosystem.MAVEN

    def test_cve_cvss_score_validation(self) -> None:
        """Test CVSS score validation."""
        cve = CVE(
            id="CVE-2021-44228",
            description="Test vulnerability",
            severity=Severity.CRITICAL,
            cvss_score=10.0,
            source="nvd",
        )
        assert cve.cvss_score == 10.0

        with pytest.raises(ValueError):
            CVE(
                id="CVE-2021-44228",
                description="Test vulnerability",
                severity=Severity.CRITICAL,
                cvss_score=11.0,
                source="nvd",
            )
