"""CVE aggregator that queries multiple sources and deduplicates results."""

import asyncio
from typing import Callable

from blastauri.core.models import CVE, Dependency, Ecosystem, Severity
from blastauri.cve.cache import CveCache
from blastauri.cve.github_advisories import GitHubAdvisoriesClient
from blastauri.cve.gitlab_advisories import GitLabAdvisoriesClient
from blastauri.cve.nvd import NvdClient
from blastauri.cve.osv import OsvClient
from blastauri.cve.waf_patterns import is_waf_mitigatable, get_waf_pattern_id
from blastauri.utils.logging import get_logger

logger = get_logger(__name__)


class CveAggregator:
    """Aggregates CVE data from multiple vulnerability databases.

    Queries NVD, GitHub Security Advisories, OSV, and GitLab Advisory
    Database, then deduplicates and enriches the results.
    """

    def __init__(
        self,
        nvd_client: NvdClient | None = None,
        github_client: GitHubAdvisoriesClient | None = None,
        osv_client: OsvClient | None = None,
        gitlab_client: GitLabAdvisoriesClient | None = None,
        cache: CveCache | None = None,
        use_cache: bool = True,
    ) -> None:
        """Initialize the CVE aggregator.

        Args:
            nvd_client: NVD API client.
            github_client: GitHub Security Advisories client.
            osv_client: OSV API client.
            gitlab_client: GitLab Advisory Database client.
            cache: CVE cache instance.
            use_cache: Whether to use caching.
        """
        self.nvd_client = nvd_client or NvdClient()
        self.github_client = github_client or GitHubAdvisoriesClient()
        self.osv_client = osv_client or OsvClient()
        self.gitlab_client = gitlab_client or GitLabAdvisoriesClient()
        self.cache = cache or CveCache() if use_cache else None
        self.use_cache = use_cache

    async def find_vulnerabilities(
        self,
        dependencies: list[Dependency],
        sources: list[str] | None = None,
    ) -> list[CVE]:
        """Find vulnerabilities for a list of dependencies.

        Args:
            dependencies: List of dependencies to check.
            sources: Optional list of sources to query (nvd, github, osv, gitlab).
                    Defaults to all sources.

        Returns:
            List of CVEs affecting the dependencies.
        """
        if sources is None:
            sources = ["osv", "github", "gitlab"]

        all_cves: list[CVE] = []
        tasks: list[asyncio.Task[list[CVE]]] = []

        for dep in dependencies:
            cached = self._get_cached_cves(dep.ecosystem, dep.name, dep.version)
            if cached is not None:
                all_cves.extend(cached)
                continue

            task = asyncio.create_task(
                self._query_sources(dep.ecosystem, dep.name, dep.version, sources)
            )
            tasks.append(task)

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error("Error querying CVEs: %s", result)
                    continue

                if isinstance(result, list):
                    all_cves.extend(result)

        deduplicated = self._deduplicate_cves(all_cves)

        enriched = self._enrich_cves(deduplicated)

        sorted_cves = self._sort_by_severity(enriched)

        return sorted_cves

    async def find_vulnerabilities_for_package(
        self,
        ecosystem: Ecosystem,
        package_name: str,
        version: str | None = None,
        sources: list[str] | None = None,
    ) -> list[CVE]:
        """Find vulnerabilities for a specific package.

        Args:
            ecosystem: Package ecosystem.
            package_name: Package name.
            version: Optional version to check.
            sources: Optional list of sources to query.

        Returns:
            List of CVEs affecting the package.
        """
        if sources is None:
            sources = ["osv", "github", "gitlab"]

        cached = self._get_cached_cves(ecosystem, package_name, version)
        if cached is not None:
            return cached

        cves = await self._query_sources(ecosystem, package_name, version, sources)

        deduplicated = self._deduplicate_cves(cves)
        enriched = self._enrich_cves(deduplicated)
        sorted_cves = self._sort_by_severity(enriched)

        self._cache_cves(ecosystem, package_name, sorted_cves, version)

        return sorted_cves

    async def get_cve(self, cve_id: str) -> CVE | None:
        """Get a specific CVE by ID.

        Args:
            cve_id: CVE identifier.

        Returns:
            CVE or None if not found.
        """
        if self.cache:
            cached = self.cache.get_cve(cve_id)
            if cached:
                return cached

        cve = await self.nvd_client.get_cve(cve_id)

        if cve and self.cache:
            self.cache.set_cve(cve)

        return cve

    async def _query_sources(
        self,
        ecosystem: Ecosystem,
        package_name: str,
        version: str | None,
        sources: list[str],
    ) -> list[CVE]:
        """Query multiple CVE sources for a package.

        Args:
            ecosystem: Package ecosystem.
            package_name: Package name.
            version: Optional version.
            sources: List of sources to query.

        Returns:
            Combined list of CVEs.
        """
        cves: list[CVE] = []
        tasks: list[tuple[str, asyncio.Task[list[CVE]]]] = []

        if "osv" in sources:
            task = asyncio.create_task(
                self.osv_client.query_by_package(ecosystem, package_name, version)
            )
            tasks.append(("osv", task))

        if "github" in sources:
            task = asyncio.create_task(
                self.github_client.search_by_package(ecosystem, package_name)
            )
            tasks.append(("github", task))

        if "gitlab" in sources:
            task = asyncio.create_task(
                self.gitlab_client.search_by_package(ecosystem, package_name)
            )
            tasks.append(("gitlab", task))

        for source_name, task in tasks:
            try:
                result = await task
                cves.extend(result)
                logger.debug(
                    "Found %d CVEs from %s for %s/%s",
                    len(result),
                    source_name,
                    ecosystem.value,
                    package_name,
                )
            except Exception as e:
                logger.warning(
                    "Error querying %s for %s/%s: %s",
                    source_name,
                    ecosystem.value,
                    package_name,
                    e,
                )

        return cves

    def _deduplicate_cves(self, cves: list[CVE]) -> list[CVE]:
        """Deduplicate CVEs by ID, keeping the most complete entry.

        Args:
            cves: List of CVEs with potential duplicates.

        Returns:
            Deduplicated list.
        """
        seen: dict[str, CVE] = {}

        for cve in cves:
            cve_id = cve.id

            if cve_id not in seen:
                seen[cve_id] = cve
            else:
                existing = seen[cve_id]
                if self._cve_completeness(cve) > self._cve_completeness(existing):
                    seen[cve_id] = cve

        return list(seen.values())

    def _cve_completeness(self, cve: CVE) -> int:
        """Calculate completeness score for a CVE.

        Args:
            cve: CVE to score.

        Returns:
            Completeness score (higher is more complete).
        """
        score = 0

        if cve.description:
            score += 10
        if cve.cvss_score is not None:
            score += 10
        if cve.cvss_vector:
            score += 5
        if cve.affected_packages:
            score += 10
        if cve.references:
            score += 5
        if cve.published_date:
            score += 5
        if cve.severity != Severity.UNKNOWN:
            score += 5

        return score

    def _enrich_cves(self, cves: list[CVE]) -> list[CVE]:
        """Enrich CVEs with WAF mitigation information.

        Args:
            cves: List of CVEs to enrich.

        Returns:
            Enriched CVEs.
        """
        enriched: list[CVE] = []

        for cve in cves:
            waf_mitigatable = is_waf_mitigatable(cve)
            waf_pattern_id = get_waf_pattern_id(cve) if waf_mitigatable else None

            if waf_mitigatable != cve.is_waf_mitigatable or waf_pattern_id != cve.waf_pattern_id:
                enriched_cve = CVE(
                    id=cve.id,
                    description=cve.description,
                    severity=cve.severity,
                    cvss_score=cve.cvss_score,
                    cvss_vector=cve.cvss_vector,
                    affected_packages=cve.affected_packages,
                    references=cve.references,
                    published_date=cve.published_date,
                    modified_date=cve.modified_date,
                    source=cve.source,
                    is_waf_mitigatable=waf_mitigatable,
                    waf_pattern_id=waf_pattern_id,
                )
                enriched.append(enriched_cve)
            else:
                enriched.append(cve)

        return enriched

    def _sort_by_severity(self, cves: list[CVE]) -> list[CVE]:
        """Sort CVEs by severity (critical first).

        Args:
            cves: List of CVEs to sort.

        Returns:
            Sorted list.
        """
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.NONE: 4,
            Severity.UNKNOWN: 5,
        }

        return sorted(cves, key=lambda c: (severity_order.get(c.severity, 5), c.id))

    def _get_cached_cves(
        self,
        ecosystem: Ecosystem,
        package_name: str,
        version: str | None,
    ) -> list[CVE] | None:
        """Get cached CVEs for a package.

        Args:
            ecosystem: Package ecosystem.
            package_name: Package name.
            version: Optional version.

        Returns:
            Cached CVEs or None if not cached.
        """
        if not self.cache:
            return None

        return self.cache.get_package_cves(ecosystem, package_name, version)

    def _cache_cves(
        self,
        ecosystem: Ecosystem,
        package_name: str,
        cves: list[CVE],
        version: str | None,
    ) -> None:
        """Cache CVEs for a package.

        Args:
            ecosystem: Package ecosystem.
            package_name: Package name.
            cves: CVEs to cache.
            version: Optional version.
        """
        if not self.cache:
            return

        self.cache.set_package_cves(ecosystem, package_name, cves, version)
