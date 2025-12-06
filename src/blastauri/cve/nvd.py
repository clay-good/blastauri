"""NVD (National Vulnerability Database) API 2.0 client."""

import os
import re
from datetime import datetime
from typing import Any

from blastauri.core.models import AffectedPackage, CVE, Ecosystem, Severity
from blastauri.utils.http import AsyncHttpClient, RateLimiter, create_nvd_rate_limiter
from blastauri.utils.logging import get_logger

logger = get_logger(__name__)

NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NvdClient:
    """Client for NVD API 2.0.

    The National Vulnerability Database provides CVE information with
    CVSS scores, affected software, and references.
    """

    def __init__(
        self,
        api_key: str | None = None,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        """Initialize the NVD client.

        Args:
            api_key: NVD API key (increases rate limit from 5 to 50 req/30s).
            rate_limiter: Custom rate limiter (uses default if None).
        """
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self.rate_limiter = rate_limiter or create_nvd_rate_limiter(
            has_api_key=bool(self.api_key)
        )
        self._headers: dict[str, str] = {}
        if self.api_key:
            self._headers["apiKey"] = self.api_key

    async def get_cve(self, cve_id: str) -> CVE | None:
        """Get a specific CVE by ID.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228").

        Returns:
            CVE object or None if not found.
        """
        if not re.match(r"^CVE-\d{4}-\d{4,}$", cve_id):
            logger.warning("Invalid CVE ID format: %s", cve_id)
            return None

        async with AsyncHttpClient(
            base_url=NVD_API_BASE_URL,
            rate_limiter=self.rate_limiter,
            headers=self._headers,
        ) as client:
            try:
                data = await client.get_json("", params={"cveId": cve_id})
                vulnerabilities = data.get("vulnerabilities", [])
                if vulnerabilities:
                    return self._parse_cve(vulnerabilities[0].get("cve", {}))
            except Exception as e:
                logger.error("Error fetching CVE %s: %s", cve_id, e)

        return None

    async def search_by_keyword(
        self,
        keyword: str,
        results_per_page: int = 100,
        start_index: int = 0,
    ) -> list[CVE]:
        """Search CVEs by keyword.

        Args:
            keyword: Search keyword.
            results_per_page: Number of results per page (max 2000).
            start_index: Starting index for pagination.

        Returns:
            List of matching CVEs.
        """
        async with AsyncHttpClient(
            base_url=NVD_API_BASE_URL,
            rate_limiter=self.rate_limiter,
            headers=self._headers,
        ) as client:
            try:
                data = await client.get_json(
                    "",
                    params={
                        "keywordSearch": keyword,
                        "resultsPerPage": min(results_per_page, 2000),
                        "startIndex": start_index,
                    },
                )
                return self._parse_vulnerabilities(data)
            except Exception as e:
                logger.error("Error searching CVEs by keyword '%s': %s", keyword, e)
                return []

    async def search_by_cpe(
        self,
        cpe_name: str,
        results_per_page: int = 100,
        start_index: int = 0,
    ) -> list[CVE]:
        """Search CVEs by CPE (Common Platform Enumeration) name.

        Args:
            cpe_name: CPE name string.
            results_per_page: Number of results per page.
            start_index: Starting index for pagination.

        Returns:
            List of matching CVEs.
        """
        async with AsyncHttpClient(
            base_url=NVD_API_BASE_URL,
            rate_limiter=self.rate_limiter,
            headers=self._headers,
        ) as client:
            try:
                data = await client.get_json(
                    "",
                    params={
                        "cpeName": cpe_name,
                        "resultsPerPage": min(results_per_page, 2000),
                        "startIndex": start_index,
                    },
                )
                return self._parse_vulnerabilities(data)
            except Exception as e:
                logger.error("Error searching CVEs by CPE '%s': %s", cpe_name, e)
                return []

    async def search_by_package(
        self,
        ecosystem: Ecosystem,
        package_name: str,
        version: str | None = None,
    ) -> list[CVE]:
        """Search CVEs affecting a specific package.

        This method converts package information to a keyword search
        since NVD doesn't have direct package-to-CVE mapping.

        Args:
            ecosystem: Package ecosystem.
            package_name: Package name.
            version: Optional version to filter results.

        Returns:
            List of potentially matching CVEs.
        """
        search_term = self._build_package_search_term(ecosystem, package_name)

        cves = await self.search_by_keyword(search_term)

        if version:
            cves = [
                cve for cve in cves
                if self._version_matches(cve, package_name, version)
            ]

        return cves

    def _build_package_search_term(
        self,
        ecosystem: Ecosystem,
        package_name: str,
    ) -> str:
        """Build a search term for a package.

        Args:
            ecosystem: Package ecosystem.
            package_name: Package name.

        Returns:
            Search term string.
        """
        if ecosystem == Ecosystem.NPM:
            return f"npm {package_name}"
        elif ecosystem == Ecosystem.PYPI:
            return f"python {package_name}"
        elif ecosystem == Ecosystem.MAVEN:
            if ":" in package_name:
                group_id, artifact_id = package_name.split(":", 1)
                return f"{group_id} {artifact_id}"
            return f"java {package_name}"
        elif ecosystem == Ecosystem.GO:
            parts = package_name.split("/")
            return parts[-1] if parts else package_name
        elif ecosystem == Ecosystem.RUBYGEMS:
            return f"ruby {package_name}"
        elif ecosystem == Ecosystem.CARGO:
            return f"rust {package_name}"
        elif ecosystem == Ecosystem.COMPOSER:
            return f"php {package_name}"
        return package_name

    def _version_matches(
        self,
        cve: CVE,
        package_name: str,
        version: str,
    ) -> bool:
        """Check if a CVE affects a specific package version.

        Args:
            cve: CVE to check.
            package_name: Package name.
            version: Version to check.

        Returns:
            True if the CVE might affect this version.
        """
        for affected in cve.affected_packages:
            if package_name.lower() in affected.name.lower():
                if affected.fixed_version:
                    if self._compare_versions(version, affected.fixed_version) < 0:
                        return True
                else:
                    return True
        return len(cve.affected_packages) == 0

    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare two version strings.

        Args:
            v1: First version.
            v2: Second version.

        Returns:
            -1 if v1 < v2, 0 if equal, 1 if v1 > v2.
        """
        def normalize(v: str) -> list[int]:
            return [int(x) for x in re.findall(r"\d+", v)]

        parts1 = normalize(v1)
        parts2 = normalize(v2)

        for p1, p2 in zip(parts1, parts2):
            if p1 < p2:
                return -1
            if p1 > p2:
                return 1

        if len(parts1) < len(parts2):
            return -1
        if len(parts1) > len(parts2):
            return 1
        return 0

    def _parse_vulnerabilities(self, data: dict[str, Any]) -> list[CVE]:
        """Parse vulnerabilities from NVD response.

        Args:
            data: NVD API response data.

        Returns:
            List of parsed CVEs.
        """
        cves: list[CVE] = []
        vulnerabilities = data.get("vulnerabilities", [])

        for vuln in vulnerabilities:
            cve_data = vuln.get("cve", {})
            cve = self._parse_cve(cve_data)
            if cve:
                cves.append(cve)

        return cves

    def _parse_cve(self, cve_data: dict[str, Any]) -> CVE | None:
        """Parse a single CVE from NVD data.

        Args:
            cve_data: CVE data dictionary.

        Returns:
            Parsed CVE or None.
        """
        cve_id = cve_data.get("id")
        if not cve_id:
            return None

        descriptions = cve_data.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        severity, cvss_score, cvss_vector = self._parse_cvss(cve_data)

        affected_packages = self._parse_affected_packages(cve_data)

        references = self._parse_references(cve_data)

        published_date = self._parse_date(cve_data.get("published"))
        modified_date = self._parse_date(cve_data.get("lastModified"))

        return CVE(
            id=cve_id,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            affected_packages=affected_packages,
            references=references,
            published_date=published_date,
            modified_date=modified_date,
            source="nvd",
            is_waf_mitigatable=False,
            waf_pattern_id=None,
        )

    def _parse_cvss(
        self,
        cve_data: dict[str, Any],
    ) -> tuple[Severity, float | None, str | None]:
        """Parse CVSS data from CVE.

        Args:
            cve_data: CVE data dictionary.

        Returns:
            Tuple of (severity, score, vector).
        """
        metrics = cve_data.get("metrics", {})

        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics and metrics[version]:
                metric = metrics[version][0]
                cvss_data = metric.get("cvssData", {})

                score = cvss_data.get("baseScore")
                vector = cvss_data.get("vectorString")
                severity_str = cvss_data.get(
                    "baseSeverity",
                    metric.get("baseSeverity", ""),
                )

                severity = self._map_severity(severity_str, score)
                return severity, score, vector

        return Severity.UNKNOWN, None, None

    def _map_severity(
        self,
        severity_str: str,
        score: float | None,
    ) -> Severity:
        """Map severity string or score to Severity enum.

        Args:
            severity_str: Severity string from NVD.
            score: CVSS score.

        Returns:
            Severity enum value.
        """
        severity_str = severity_str.upper()

        if severity_str == "CRITICAL":
            return Severity.CRITICAL
        elif severity_str == "HIGH":
            return Severity.HIGH
        elif severity_str == "MEDIUM":
            return Severity.MEDIUM
        elif severity_str == "LOW":
            return Severity.LOW
        elif severity_str == "NONE":
            return Severity.NONE

        if score is not None:
            if score >= 9.0:
                return Severity.CRITICAL
            elif score >= 7.0:
                return Severity.HIGH
            elif score >= 4.0:
                return Severity.MEDIUM
            elif score > 0:
                return Severity.LOW
            else:
                return Severity.NONE

        return Severity.UNKNOWN

    def _parse_affected_packages(
        self,
        cve_data: dict[str, Any],
    ) -> list[AffectedPackage]:
        """Parse affected packages from CVE configurations.

        Args:
            cve_data: CVE data dictionary.

        Returns:
            List of affected packages.
        """
        packages: list[AffectedPackage] = []
        configurations = cve_data.get("configurations", [])

        for config in configurations:
            nodes = config.get("nodes", [])
            for node in nodes:
                cpe_matches = node.get("cpeMatch", [])
                for match in cpe_matches:
                    if not match.get("vulnerable", False):
                        continue

                    cpe = match.get("criteria", "")
                    ecosystem, name = self._parse_cpe(cpe)
                    if not name:
                        continue

                    packages.append(
                        AffectedPackage(
                            ecosystem=ecosystem,
                            name=name,
                            version_start=match.get("versionStartIncluding")
                            or match.get("versionStartExcluding"),
                            version_end=match.get("versionEndIncluding")
                            or match.get("versionEndExcluding"),
                            fixed_version=None,
                        )
                    )

        return packages

    def _parse_cpe(self, cpe: str) -> tuple[Ecosystem, str]:
        """Parse CPE string to extract ecosystem and package name.

        Args:
            cpe: CPE 2.3 string.

        Returns:
            Tuple of (ecosystem, package_name).
        """
        parts = cpe.split(":")
        if len(parts) < 5:
            return Ecosystem.NPM, ""

        vendor = parts[3] if len(parts) > 3 else ""
        product = parts[4] if len(parts) > 4 else ""

        name = product or vendor

        ecosystem = Ecosystem.NPM

        return ecosystem, name

    def _parse_references(self, cve_data: dict[str, Any]) -> list[str]:
        """Parse reference URLs from CVE.

        Args:
            cve_data: CVE data dictionary.

        Returns:
            List of reference URLs.
        """
        references: list[str] = []
        refs = cve_data.get("references", [])

        for ref in refs:
            url = ref.get("url")
            if url:
                references.append(url)

        return references

    def _parse_date(self, date_str: str | None) -> datetime | None:
        """Parse ISO date string.

        Args:
            date_str: ISO format date string.

        Returns:
            Datetime object or None.
        """
        if not date_str:
            return None

        try:
            date_str = date_str.replace("Z", "+00:00")
            return datetime.fromisoformat(date_str)
        except ValueError:
            return None
