"""Integration tests for CVE aggregation with mocked API responses."""

import json
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from blastauri.core.models import (
    CVE,
    AffectedPackage,
    Dependency,
    Ecosystem,
    Severity,
)
from blastauri.cve.aggregator import CveAggregator
from blastauri.cve.cache import CveCache
from blastauri.cve.github_advisories import GitHubAdvisoriesClient
from blastauri.cve.gitlab_advisories import GitLabAdvisoriesClient
from blastauri.cve.nvd import NvdClient
from blastauri.cve.osv import OsvClient

# Load fixtures
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "api_responses"


def load_fixture(name: str) -> dict:
    """Load a JSON fixture file."""
    with open(FIXTURES_DIR / name) as f:
        return json.load(f)


def create_cve(
    cve_id: str,
    description: str,
    severity: Severity,
    cvss_score: float | None = None,
    source: str = "osv",
    is_waf_mitigatable: bool = False,
) -> CVE:
    """Helper to create CVE objects."""
    return CVE(
        id=cve_id,
        description=description,
        severity=severity,
        cvss_score=cvss_score,
        source=source,
        is_waf_mitigatable=is_waf_mitigatable,
        affected_packages=[
            AffectedPackage(
                ecosystem=Ecosystem.PYPI,
                name="requests",
                vulnerable_versions=[">=2.3.0", "<2.31.0"],
                fixed_versions=["2.31.0"],
            )
        ],
    )


class TestCveDeduplication:
    """Test CVE deduplication logic."""

    def test_deduplicate_identical_cves(self) -> None:
        """Test that duplicate CVEs are deduplicated."""
        aggregator = CveAggregator(use_cache=False)

        cve1 = create_cve(
            cve_id="CVE-2023-32681",
            description="Requests vulnerability",
            severity=Severity.MEDIUM,
            cvss_score=6.1,
            source="osv",
        )
        cve2 = create_cve(
            cve_id="CVE-2023-32681",
            description="Requests vulnerability (from GitHub)",
            severity=Severity.MEDIUM,
            cvss_score=6.1,
            source="github",
        )

        deduplicated = aggregator._deduplicate_cves([cve1, cve2])

        assert len(deduplicated) == 1
        assert deduplicated[0].id == "CVE-2023-32681"

    def test_keep_more_complete_cve(self) -> None:
        """Test that more complete CVE entry is kept during deduplication."""
        aggregator = CveAggregator(use_cache=False)

        # Less complete - no references
        cve_minimal = CVE(
            id="CVE-2023-32681",
            description="Short description",
            severity=Severity.UNKNOWN,
            source="github",
        )

        # More complete - has CVSS, references, affected packages
        cve_complete = CVE(
            id="CVE-2023-32681",
            description="Detailed vulnerability description with more info",
            severity=Severity.MEDIUM,
            cvss_score=6.1,
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N",
            source="osv",
            references=[
                "https://github.com/psf/requests/security/advisories/GHSA-j8r2-6x86-q33q"
            ],
            affected_packages=[
                AffectedPackage(
                    ecosystem=Ecosystem.PYPI,
                    name="requests",
                    vulnerable_versions=[">=2.3.0", "<2.31.0"],
                    fixed_versions=["2.31.0"],
                )
            ],
        )

        # Pass minimal first, then complete
        deduplicated = aggregator._deduplicate_cves([cve_minimal, cve_complete])

        assert len(deduplicated) == 1
        # Should keep the more complete one
        assert deduplicated[0].cvss_score == 6.1
        assert len(deduplicated[0].references) > 0

    def test_deduplicate_preserves_unique_cves(self) -> None:
        """Test that unique CVEs are all preserved."""
        aggregator = CveAggregator(use_cache=False)

        cve1 = create_cve(
            cve_id="CVE-2023-32681",
            description="First vulnerability",
            severity=Severity.MEDIUM,
        )
        cve2 = create_cve(
            cve_id="CVE-2021-44228",
            description="Log4j vulnerability",
            severity=Severity.CRITICAL,
        )
        cve3 = create_cve(
            cve_id="CVE-2022-12345",
            description="Another vulnerability",
            severity=Severity.LOW,
        )

        deduplicated = aggregator._deduplicate_cves([cve1, cve2, cve3])

        assert len(deduplicated) == 3
        cve_ids = {cve.id for cve in deduplicated}
        assert cve_ids == {"CVE-2023-32681", "CVE-2021-44228", "CVE-2022-12345"}


class TestCveSorting:
    """Test CVE severity sorting."""

    def test_sort_by_severity(self) -> None:
        """Test that CVEs are sorted by severity (critical first)."""
        aggregator = CveAggregator(use_cache=False)

        cves = [
            create_cve("CVE-2023-001", "Low severity", Severity.LOW),
            create_cve("CVE-2023-002", "Critical severity", Severity.CRITICAL),
            create_cve("CVE-2023-003", "Medium severity", Severity.MEDIUM),
            create_cve("CVE-2023-004", "High severity", Severity.HIGH),
            create_cve("CVE-2023-005", "Unknown severity", Severity.UNKNOWN),
        ]

        sorted_cves = aggregator._sort_by_severity(cves)

        assert sorted_cves[0].severity == Severity.CRITICAL
        assert sorted_cves[1].severity == Severity.HIGH
        assert sorted_cves[2].severity == Severity.MEDIUM
        assert sorted_cves[3].severity == Severity.LOW
        assert sorted_cves[4].severity == Severity.UNKNOWN

    def test_secondary_sort_by_id(self) -> None:
        """Test that CVEs with same severity are sorted by ID."""
        aggregator = CveAggregator(use_cache=False)

        cves = [
            create_cve("CVE-2023-999", "Same severity Z", Severity.HIGH),
            create_cve("CVE-2023-001", "Same severity A", Severity.HIGH),
            create_cve("CVE-2023-500", "Same severity M", Severity.HIGH),
        ]

        sorted_cves = aggregator._sort_by_severity(cves)

        assert sorted_cves[0].id == "CVE-2023-001"
        assert sorted_cves[1].id == "CVE-2023-500"
        assert sorted_cves[2].id == "CVE-2023-999"


class TestCveEnrichment:
    """Test CVE enrichment with WAF information."""

    def test_enrich_sql_injection_cve(self) -> None:
        """Test that SQL injection CVEs are marked as WAF mitigatable."""
        aggregator = CveAggregator(use_cache=False)

        cve = CVE(
            id="CVE-2023-12345",
            description="SQL injection vulnerability allowing arbitrary query execution",
            severity=Severity.HIGH,
            source="osv",
        )

        enriched = aggregator._enrich_cves([cve])

        assert len(enriched) == 1
        assert enriched[0].is_waf_mitigatable is True

    def test_enrich_xss_cve(self) -> None:
        """Test that XSS CVEs are marked as WAF mitigatable."""
        aggregator = CveAggregator(use_cache=False)

        cve = CVE(
            id="CVE-2023-12346",
            description="Cross-site scripting (XSS) vulnerability in user input handling",
            severity=Severity.MEDIUM,
            source="github",
        )

        enriched = aggregator._enrich_cves([cve])

        assert len(enriched) == 1
        assert enriched[0].is_waf_mitigatable is True

    def test_non_waf_mitigatable_cve(self) -> None:
        """Test that non-WAF-mitigatable CVEs stay unmarked."""
        aggregator = CveAggregator(use_cache=False)

        cve = CVE(
            id="CVE-2023-12347",
            description="Memory corruption vulnerability in buffer handling",
            severity=Severity.HIGH,
            source="nvd",
        )

        enriched = aggregator._enrich_cves([cve])

        assert len(enriched) == 1
        # Memory corruption is not WAF mitigatable
        assert enriched[0].is_waf_mitigatable is False


class TestCveAggregatorWithMockedSources:
    """Test full aggregation workflow with mocked API sources."""

    @pytest.fixture
    def mock_osv_client(self) -> AsyncMock:
        """Create a mocked OSV client."""
        client = AsyncMock(spec=OsvClient)
        osv_data = load_fixture("osv_requests_vuln.json")

        # Create CVE from fixture
        vuln = osv_data["vulns"][0]
        cve = CVE(
            id="CVE-2023-32681",
            description=vuln["summary"],
            severity=Severity.MEDIUM,
            cvss_score=6.1,
            cvss_vector=vuln["severity"][0]["score"],
            source="osv",
            affected_packages=[
                AffectedPackage(
                    ecosystem=Ecosystem.PYPI,
                    name="requests",
                    vulnerable_versions=[">=2.3.0", "<2.31.0"],
                    fixed_versions=["2.31.0"],
                )
            ],
            references=[ref["url"] for ref in vuln["references"]],
        )
        client.query_by_package.return_value = [cve]
        return client

    @pytest.fixture
    def mock_github_client(self) -> AsyncMock:
        """Create a mocked GitHub Advisories client."""
        client = AsyncMock(spec=GitHubAdvisoriesClient)
        # Return same CVE from different source (for dedup testing)
        cve = CVE(
            id="CVE-2023-32681",
            description="Unintended leak of Proxy-Authorization header",
            severity=Severity.MEDIUM,
            source="github",
        )
        client.search_by_package.return_value = [cve]
        return client

    @pytest.fixture
    def mock_gitlab_client(self) -> AsyncMock:
        """Create a mocked GitLab Advisories client."""
        client = AsyncMock(spec=GitLabAdvisoriesClient)
        # Return empty (no additional CVEs)
        client.search_by_package.return_value = []
        return client

    @pytest.fixture
    def mock_nvd_client(self) -> AsyncMock:
        """Create a mocked NVD client."""
        client = AsyncMock(spec=NvdClient)
        nvd_data = load_fixture("nvd_cve_log4j.json")
        vuln_data = nvd_data["vulnerabilities"][0]["cve"]

        cve = CVE(
            id=vuln_data["id"],
            description=vuln_data["descriptions"][0]["value"],
            severity=Severity.CRITICAL,
            cvss_score=10.0,
            source="nvd",
        )
        client.get_cve.return_value = cve
        return client

    @pytest.mark.asyncio
    async def test_aggregate_from_multiple_sources(
        self,
        mock_osv_client: AsyncMock,
        mock_github_client: AsyncMock,
        mock_gitlab_client: AsyncMock,
    ) -> None:
        """Test aggregating CVEs from multiple sources."""
        aggregator = CveAggregator(
            osv_client=mock_osv_client,
            github_client=mock_github_client,
            gitlab_client=mock_gitlab_client,
            use_cache=False,
        )

        cves = await aggregator.find_vulnerabilities_for_package(
            ecosystem=Ecosystem.PYPI,
            package_name="requests",
            version="2.28.0",
        )

        # Should have queried both sources
        mock_osv_client.query_by_package.assert_called_once()
        mock_github_client.search_by_package.assert_called_once()

        # Should deduplicate the results
        assert len(cves) == 1
        assert cves[0].id == "CVE-2023-32681"

    @pytest.mark.asyncio
    async def test_aggregate_with_dependencies_list(
        self,
        mock_osv_client: AsyncMock,
        mock_github_client: AsyncMock,
        mock_gitlab_client: AsyncMock,
    ) -> None:
        """Test aggregating CVEs for a list of dependencies."""
        aggregator = CveAggregator(
            osv_client=mock_osv_client,
            github_client=mock_github_client,
            gitlab_client=mock_gitlab_client,
            use_cache=False,
        )

        dependencies = [
            Dependency(
                name="requests",
                version="2.28.0",
                ecosystem=Ecosystem.PYPI,
                location="requirements.txt",
            ),
        ]

        cves = await aggregator.find_vulnerabilities(dependencies)

        assert len(cves) == 1
        assert cves[0].id == "CVE-2023-32681"


class TestCveCache:
    """Test CVE caching behavior."""

    @pytest.mark.asyncio
    async def test_first_call_fetches_second_uses_cache(self, tmp_path: Path) -> None:
        """Test that first call fetches and second call uses cache."""
        mock_osv = AsyncMock(spec=OsvClient)
        mock_osv.query_by_package.return_value = [
            create_cve("CVE-2023-001", "Test vuln", Severity.MEDIUM)
        ]

        mock_github = AsyncMock(spec=GitHubAdvisoriesClient)
        mock_github.search_by_package.return_value = []

        mock_gitlab = AsyncMock(spec=GitLabAdvisoriesClient)
        mock_gitlab.search_by_package.return_value = []

        # Create a fresh cache instance in tmp directory
        cache = CveCache(cache_dir=tmp_path)

        aggregator = CveAggregator(
            osv_client=mock_osv,
            github_client=mock_github,
            gitlab_client=mock_gitlab,
            cache=cache,
            use_cache=True,
        )

        # First call - should fetch from sources
        cves1 = await aggregator.find_vulnerabilities_for_package(
            ecosystem=Ecosystem.PYPI,
            package_name="test-package",
            version="1.0.0",
        )

        # Second call - should use cache
        cves2 = await aggregator.find_vulnerabilities_for_package(
            ecosystem=Ecosystem.PYPI,
            package_name="test-package",
            version="1.0.0",
        )

        # OSV should only have been called once (second call uses cache)
        assert mock_osv.query_by_package.call_count == 1

        # Results should be same
        assert len(cves1) == 1
        assert len(cves2) == 1
        assert cves1[0].id == cves2[0].id

        # Cleanup
        cache.close()


class TestRateLimitHandling:
    """Test rate limit handling (429 responses)."""

    @pytest.mark.asyncio
    async def test_handles_source_errors_gracefully(self) -> None:
        """Test that errors from one source don't break entire aggregation."""
        mock_osv = AsyncMock(spec=OsvClient)
        mock_osv.query_by_package.side_effect = Exception("Rate limited (429)")

        mock_github = AsyncMock(spec=GitHubAdvisoriesClient)
        mock_github.search_by_package.return_value = [
            create_cve("CVE-2023-001", "GitHub found", Severity.HIGH, source="github")
        ]

        mock_gitlab = AsyncMock(spec=GitLabAdvisoriesClient)
        mock_gitlab.search_by_package.return_value = []

        aggregator = CveAggregator(
            osv_client=mock_osv,
            github_client=mock_github,
            gitlab_client=mock_gitlab,
            use_cache=False,
        )

        # Should not raise - just log warning and continue with other sources
        cves = await aggregator.find_vulnerabilities_for_package(
            ecosystem=Ecosystem.PYPI,
            package_name="requests",
            version="2.28.0",
        )

        # Should still have results from GitHub
        assert len(cves) == 1
        assert cves[0].source == "github"

    @pytest.mark.asyncio
    async def test_all_sources_fail(self) -> None:
        """Test handling when all sources fail."""
        mock_osv = AsyncMock(spec=OsvClient)
        mock_osv.query_by_package.side_effect = Exception("OSV error")

        mock_github = AsyncMock(spec=GitHubAdvisoriesClient)
        mock_github.search_by_package.side_effect = Exception("GitHub error")

        mock_gitlab = AsyncMock(spec=GitLabAdvisoriesClient)
        mock_gitlab.search_by_package.side_effect = Exception("GitLab error")

        aggregator = CveAggregator(
            osv_client=mock_osv,
            github_client=mock_github,
            gitlab_client=mock_gitlab,
            use_cache=False,
        )

        # Should not raise - just return empty list
        cves = await aggregator.find_vulnerabilities_for_package(
            ecosystem=Ecosystem.PYPI,
            package_name="requests",
            version="2.28.0",
        )

        assert len(cves) == 0


class TestCveCompleteness:
    """Test CVE completeness scoring."""

    def test_completeness_scoring(self) -> None:
        """Test that completeness is calculated correctly."""
        aggregator = CveAggregator(use_cache=False)

        minimal_cve = CVE(
            id="CVE-2023-001",
            description="",
            severity=Severity.UNKNOWN,
            source="test",
        )

        complete_cve = CVE(
            id="CVE-2023-002",
            description="Full description here",
            severity=Severity.HIGH,
            cvss_score=8.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            source="nvd",
            references=["https://example.com"],
            published_date=datetime(2023, 1, 1),
            affected_packages=[
                AffectedPackage(
                    ecosystem=Ecosystem.PYPI,
                    name="test",
                    vulnerable_versions=["<1.0.0"],
                    fixed_versions=["1.0.0"],
                )
            ],
        )

        minimal_score = aggregator._cve_completeness(minimal_cve)
        complete_score = aggregator._cve_completeness(complete_cve)

        assert complete_score > minimal_score
        assert minimal_score == 0  # No fields set
        assert complete_score >= 40  # Has description, cvss, vector, refs, date, severity, packages


class TestFixtureLoading:
    """Test that fixture files are correctly structured."""

    def test_osv_fixture_structure(self) -> None:
        """Test OSV fixture has correct structure."""
        osv_data = load_fixture("osv_requests_vuln.json")

        assert "vulns" in osv_data
        assert len(osv_data["vulns"]) >= 1

        vuln = osv_data["vulns"][0]
        assert "id" in vuln
        assert "summary" in vuln
        assert "severity" in vuln
        assert "affected" in vuln

    def test_nvd_fixture_structure(self) -> None:
        """Test NVD fixture has correct structure."""
        nvd_data = load_fixture("nvd_cve_log4j.json")

        assert "vulnerabilities" in nvd_data
        assert len(nvd_data["vulnerabilities"]) >= 1

        vuln = nvd_data["vulnerabilities"][0]
        assert "cve" in vuln
        assert "id" in vuln["cve"]
        assert "descriptions" in vuln["cve"]
