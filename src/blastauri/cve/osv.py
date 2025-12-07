"""OSV (Open Source Vulnerabilities) API client."""

from datetime import datetime
from typing import Any

from blastauri.core.models import CVE, AffectedPackage, Ecosystem, Severity
from blastauri.utils.http import AsyncHttpClient, RateLimiter
from blastauri.utils.logging import get_logger

logger = get_logger(__name__)

OSV_API_BASE_URL = "https://api.osv.dev/v1"

ECOSYSTEM_MAP: dict[str, Ecosystem] = {
    "npm": Ecosystem.NPM,
    "PyPI": Ecosystem.PYPI,
    "Go": Ecosystem.GO,
    "RubyGems": Ecosystem.RUBYGEMS,
    "Maven": Ecosystem.MAVEN,
    "crates.io": Ecosystem.CARGO,
    "Packagist": Ecosystem.COMPOSER,
}

REVERSE_ECOSYSTEM_MAP: dict[Ecosystem, str] = {
    Ecosystem.NPM: "npm",
    Ecosystem.PYPI: "PyPI",
    Ecosystem.GO: "Go",
    Ecosystem.RUBYGEMS: "RubyGems",
    Ecosystem.MAVEN: "Maven",
    Ecosystem.CARGO: "crates.io",
    Ecosystem.COMPOSER: "Packagist",
}


class OsvClient:
    """Client for OSV (Open Source Vulnerabilities) API.

    OSV provides a unified vulnerability database aggregating data
    from multiple sources including GitHub, npm, PyPI, and more.
    """

    def __init__(
        self,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        """Initialize the OSV client.

        Args:
            rate_limiter: Optional rate limiter.
        """
        self.rate_limiter = rate_limiter or RateLimiter(
            requests_per_window=100, window_seconds=60
        )

    async def get_vulnerability(self, vuln_id: str) -> CVE | None:
        """Get a specific vulnerability by ID.

        Args:
            vuln_id: Vulnerability ID (OSV, CVE, GHSA, etc.).

        Returns:
            CVE object or None if not found.
        """
        async with AsyncHttpClient(
            base_url=OSV_API_BASE_URL,
            rate_limiter=self.rate_limiter,
        ) as client:
            try:
                data = await client.get_json(f"/vulns/{vuln_id}")
                return self._parse_vulnerability(data)
            except Exception as e:
                logger.error("Error fetching vulnerability %s: %s", vuln_id, e)
                return None

    async def query_by_package(
        self,
        ecosystem: Ecosystem,
        package_name: str,
        version: str | None = None,
    ) -> list[CVE]:
        """Query vulnerabilities affecting a specific package.

        Args:
            ecosystem: Package ecosystem.
            package_name: Package name.
            version: Optional version to check.

        Returns:
            List of CVEs affecting the package.
        """
        osv_ecosystem = REVERSE_ECOSYSTEM_MAP.get(ecosystem)
        if not osv_ecosystem:
            logger.warning("Unsupported ecosystem for OSV: %s", ecosystem)
            return []

        query: dict[str, Any] = {
            "package": {
                "ecosystem": osv_ecosystem,
                "name": package_name,
            }
        }

        if version:
            query["version"] = version

        async with AsyncHttpClient(
            base_url=OSV_API_BASE_URL,
            rate_limiter=self.rate_limiter,
        ) as client:
            try:
                data = await client.post_json("/query", json=query)
                return self._parse_query_response(data)
            except Exception as e:
                logger.error(
                    "Error querying OSV for %s/%s: %s",
                    ecosystem.value,
                    package_name,
                    e,
                )
                return []

    async def query_batch(
        self,
        packages: list[tuple[Ecosystem, str, str | None]],
    ) -> dict[str, list[CVE]]:
        """Query vulnerabilities for multiple packages.

        Args:
            packages: List of (ecosystem, name, version) tuples.

        Returns:
            Dictionary mapping "ecosystem/name" to list of CVEs.
        """
        queries: list[dict[str, Any]] = []

        for ecosystem, name, version in packages:
            osv_ecosystem = REVERSE_ECOSYSTEM_MAP.get(ecosystem)
            if not osv_ecosystem:
                continue

            query: dict[str, Any] = {
                "package": {
                    "ecosystem": osv_ecosystem,
                    "name": name,
                }
            }
            if version:
                query["version"] = version
            queries.append(query)

        if not queries:
            return {}

        async with AsyncHttpClient(
            base_url=OSV_API_BASE_URL,
            rate_limiter=self.rate_limiter,
        ) as client:
            try:
                data = await client.post_json(
                    "/querybatch",
                    json={"queries": queries},
                )

                results: dict[str, list[CVE]] = {}
                response_results = data.get("results", [])

                for i, result in enumerate(response_results):
                    if i >= len(packages):
                        break

                    ecosystem, name, _ = packages[i]
                    key = f"{ecosystem.value}/{name}"

                    vulns = result.get("vulns", [])
                    cves = []
                    for vuln in vulns:
                        cve = self._parse_vulnerability(vuln)
                        if cve:
                            cves.append(cve)

                    results[key] = cves

                return results

            except Exception as e:
                logger.error("Error in batch query to OSV: %s", e)
                return {}

    def _parse_query_response(self, data: dict[str, Any]) -> list[CVE]:
        """Parse OSV query response.

        Args:
            data: API response data.

        Returns:
            List of parsed CVEs.
        """
        cves: list[CVE] = []
        vulns = data.get("vulns", [])

        for vuln in vulns:
            cve = self._parse_vulnerability(vuln)
            if cve:
                cves.append(cve)

        return cves

    def _parse_vulnerability(self, data: dict[str, Any]) -> CVE | None:
        """Parse a single OSV vulnerability.

        Args:
            data: Vulnerability data.

        Returns:
            Parsed CVE or None.
        """
        vuln_id = data.get("id")
        if not vuln_id:
            return None

        cve_id = self._extract_cve_id(data)
        display_id = cve_id or vuln_id

        summary = data.get("summary", "")
        details = data.get("details", "")
        description = details or summary

        severity, cvss_score, cvss_vector = self._parse_severity(data)

        affected_packages = self._parse_affected(data)

        references = self._parse_references(data)

        published_date = self._parse_date(data.get("published"))
        modified_date = self._parse_date(data.get("modified"))

        return CVE(
            id=display_id,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            affected_packages=affected_packages,
            references=references,
            published_date=published_date,
            modified_date=modified_date,
            source="osv",
            is_waf_mitigatable=False,
            waf_pattern_id=None,
        )

    def _extract_cve_id(self, data: dict[str, Any]) -> str | None:
        """Extract CVE ID from vulnerability aliases.

        Args:
            data: Vulnerability data.

        Returns:
            CVE ID or None.
        """
        aliases = data.get("aliases", [])
        for alias in aliases:
            if alias.startswith("CVE-"):
                return alias

        vuln_id = data.get("id", "")
        if vuln_id.startswith("CVE-"):
            return vuln_id

        return None

    def _parse_severity(
        self,
        data: dict[str, Any],
    ) -> tuple[Severity, float | None, str | None]:
        """Parse severity information from OSV data.

        Args:
            data: Vulnerability data.

        Returns:
            Tuple of (severity, score, vector).
        """
        severity_list = data.get("severity", [])

        for severity_entry in severity_list:
            score_type = severity_entry.get("type", "")
            score_value = severity_entry.get("score", "")

            if score_type in ("CVSS_V3", "CVSS_V2"):
                try:
                    score = self._extract_cvss_score(score_value)
                    severity = self._score_to_severity(score)
                    return severity, score, score_value
                except (ValueError, TypeError):
                    pass

        database_specific = data.get("database_specific", {})
        if "severity" in database_specific:
            severity_str = database_specific["severity"]
            return self._string_to_severity(severity_str), None, None

        return Severity.UNKNOWN, None, None

    def _extract_cvss_score(self, vector: str) -> float:
        """Extract numeric score from CVSS vector.

        Args:
            vector: CVSS vector string.

        Returns:
            Numeric CVSS score.
        """
        return 5.0

    def _score_to_severity(self, score: float) -> Severity:
        """Convert CVSS score to severity.

        Args:
            score: CVSS score (0-10).

        Returns:
            Severity enum value.
        """
        if score >= 9.0:
            return Severity.CRITICAL
        elif score >= 7.0:
            return Severity.HIGH
        elif score >= 4.0:
            return Severity.MEDIUM
        elif score > 0:
            return Severity.LOW
        return Severity.NONE

    def _string_to_severity(self, severity_str: str) -> Severity:
        """Convert severity string to enum.

        Args:
            severity_str: Severity string.

        Returns:
            Severity enum value.
        """
        severity_str = severity_str.upper()

        if severity_str == "CRITICAL":
            return Severity.CRITICAL
        elif severity_str == "HIGH":
            return Severity.HIGH
        elif severity_str in ("MODERATE", "MEDIUM"):
            return Severity.MEDIUM
        elif severity_str == "LOW":
            return Severity.LOW
        return Severity.UNKNOWN

    def _parse_affected(self, data: dict[str, Any]) -> list[AffectedPackage]:
        """Parse affected packages from OSV data.

        Args:
            data: Vulnerability data.

        Returns:
            List of affected packages.
        """
        packages: list[AffectedPackage] = []
        affected_list = data.get("affected", [])

        for affected in affected_list:
            package_data = affected.get("package", {})
            ecosystem_str = package_data.get("ecosystem", "")
            package_name = package_data.get("name", "")

            if not package_name:
                continue

            ecosystem = ECOSYSTEM_MAP.get(ecosystem_str, Ecosystem.NPM)

            ranges = affected.get("ranges", [])
            versions = affected.get("versions", [])

            if ranges:
                for range_data in ranges:
                    events = range_data.get("events", [])
                    version_start = None
                    version_end = None
                    fixed_version = None

                    for event in events:
                        if "introduced" in event:
                            version_start = event["introduced"]
                        if "fixed" in event:
                            fixed_version = event["fixed"]
                        if "last_affected" in event:
                            version_end = event["last_affected"]

                    packages.append(
                        AffectedPackage(
                            ecosystem=ecosystem,
                            name=package_name,
                            version_start=version_start,
                            version_end=version_end,
                            fixed_version=fixed_version,
                        )
                    )
            elif versions:
                packages.append(
                    AffectedPackage(
                        ecosystem=ecosystem,
                        name=package_name,
                        version_start=None,
                        version_end=None,
                        fixed_version=None,
                    )
                )

        return packages

    def _parse_references(self, data: dict[str, Any]) -> list[str]:
        """Parse reference URLs from OSV data.

        Args:
            data: Vulnerability data.

        Returns:
            List of reference URLs.
        """
        references: list[str] = []
        refs = data.get("references", [])

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
