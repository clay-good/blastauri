"""GitHub Security Advisories client using GraphQL API."""

import os
from datetime import datetime
from typing import Any

from blastauri.core.models import AffectedPackage, CVE, Ecosystem, Severity
from blastauri.utils.http import AsyncHttpClient, RateLimiter
from blastauri.utils.logging import get_logger

logger = get_logger(__name__)

GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"

ECOSYSTEM_MAP: dict[str, Ecosystem] = {
    "NPM": Ecosystem.NPM,
    "PIP": Ecosystem.PYPI,
    "GO": Ecosystem.GO,
    "RUBYGEMS": Ecosystem.RUBYGEMS,
    "MAVEN": Ecosystem.MAVEN,
    "RUST": Ecosystem.CARGO,
    "COMPOSER": Ecosystem.COMPOSER,
}

REVERSE_ECOSYSTEM_MAP: dict[Ecosystem, str] = {
    Ecosystem.NPM: "NPM",
    Ecosystem.PYPI: "PIP",
    Ecosystem.GO: "GO",
    Ecosystem.RUBYGEMS: "RUBYGEMS",
    Ecosystem.MAVEN: "MAVEN",
    Ecosystem.CARGO: "RUST",
    Ecosystem.COMPOSER: "COMPOSER",
}

SECURITY_ADVISORIES_QUERY = """
query($ecosystem: SecurityAdvisoryEcosystem, $package: String, $first: Int, $after: String) {
  securityVulnerabilities(
    ecosystem: $ecosystem,
    package: $package,
    first: $first,
    after: $after
  ) {
    pageInfo {
      hasNextPage
      endCursor
    }
    nodes {
      advisory {
        ghsaId
        summary
        description
        severity
        cvss {
          score
          vectorString
        }
        references {
          url
        }
        publishedAt
        updatedAt
        identifiers {
          type
          value
        }
      }
      package {
        ecosystem
        name
      }
      vulnerableVersionRange
      firstPatchedVersion {
        identifier
      }
    }
  }
}
"""

CVE_QUERY = """
query($ghsaId: String!) {
  securityAdvisory(ghsaId: $ghsaId) {
    ghsaId
    summary
    description
    severity
    cvss {
      score
      vectorString
    }
    references {
      url
    }
    publishedAt
    updatedAt
    identifiers {
      type
      value
    }
    vulnerabilities(first: 100) {
      nodes {
        package {
          ecosystem
          name
        }
        vulnerableVersionRange
        firstPatchedVersion {
          identifier
        }
      }
    }
  }
}
"""


class GitHubAdvisoriesClient:
    """Client for GitHub Security Advisories GraphQL API.

    GitHub provides security advisories with ecosystem-specific
    package information and vulnerability ranges.
    """

    def __init__(
        self,
        token: str | None = None,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        """Initialize the GitHub advisories client.

        Args:
            token: GitHub personal access token.
            rate_limiter: Optional rate limiter.
        """
        self.token = token or os.environ.get("GITHUB_TOKEN")
        self.rate_limiter = rate_limiter or RateLimiter(
            requests_per_window=30, window_seconds=60
        )

        if not self.token:
            logger.warning("No GitHub token provided, API access may be limited")

    def _get_headers(self) -> dict[str, str]:
        """Get request headers."""
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    async def get_advisory(self, ghsa_id: str) -> CVE | None:
        """Get a specific advisory by GHSA ID.

        Args:
            ghsa_id: GitHub Security Advisory ID (e.g., "GHSA-xxxx-xxxx-xxxx").

        Returns:
            CVE object or None if not found.
        """
        async with AsyncHttpClient(
            rate_limiter=self.rate_limiter,
            headers=self._get_headers(),
        ) as client:
            try:
                data = await client.post_json(
                    GITHUB_GRAPHQL_URL,
                    json={
                        "query": CVE_QUERY,
                        "variables": {"ghsaId": ghsa_id},
                    },
                )

                advisory = data.get("data", {}).get("securityAdvisory")
                if advisory:
                    return self._parse_advisory(advisory)

            except Exception as e:
                logger.error("Error fetching advisory %s: %s", ghsa_id, e)

        return None

    async def search_by_package(
        self,
        ecosystem: Ecosystem,
        package_name: str,
        max_results: int = 100,
    ) -> list[CVE]:
        """Search advisories affecting a specific package.

        Args:
            ecosystem: Package ecosystem.
            package_name: Package name.
            max_results: Maximum number of results.

        Returns:
            List of CVEs affecting the package.
        """
        gh_ecosystem = REVERSE_ECOSYSTEM_MAP.get(ecosystem)
        if not gh_ecosystem:
            logger.warning("Unsupported ecosystem for GitHub: %s", ecosystem)
            return []

        cves: list[CVE] = []
        cursor: str | None = None

        async with AsyncHttpClient(
            rate_limiter=self.rate_limiter,
            headers=self._get_headers(),
        ) as client:
            while len(cves) < max_results:
                try:
                    data = await client.post_json(
                        GITHUB_GRAPHQL_URL,
                        json={
                            "query": SECURITY_ADVISORIES_QUERY,
                            "variables": {
                                "ecosystem": gh_ecosystem,
                                "package": package_name,
                                "first": min(100, max_results - len(cves)),
                                "after": cursor,
                            },
                        },
                    )

                    vulns = data.get("data", {}).get("securityVulnerabilities", {})
                    nodes = vulns.get("nodes", [])

                    for node in nodes:
                        cve = self._parse_vulnerability_node(node)
                        if cve:
                            cves.append(cve)

                    page_info = vulns.get("pageInfo", {})
                    if not page_info.get("hasNextPage"):
                        break
                    cursor = page_info.get("endCursor")

                except Exception as e:
                    logger.error(
                        "Error searching advisories for %s/%s: %s",
                        ecosystem.value,
                        package_name,
                        e,
                    )
                    break

        return cves

    async def search_by_ecosystem(
        self,
        ecosystem: Ecosystem,
        max_results: int = 100,
    ) -> list[CVE]:
        """Get all advisories for an ecosystem.

        Args:
            ecosystem: Package ecosystem.
            max_results: Maximum number of results.

        Returns:
            List of CVEs for the ecosystem.
        """
        gh_ecosystem = REVERSE_ECOSYSTEM_MAP.get(ecosystem)
        if not gh_ecosystem:
            logger.warning("Unsupported ecosystem for GitHub: %s", ecosystem)
            return []

        cves: list[CVE] = []
        cursor: str | None = None

        async with AsyncHttpClient(
            rate_limiter=self.rate_limiter,
            headers=self._get_headers(),
        ) as client:
            while len(cves) < max_results:
                try:
                    data = await client.post_json(
                        GITHUB_GRAPHQL_URL,
                        json={
                            "query": SECURITY_ADVISORIES_QUERY,
                            "variables": {
                                "ecosystem": gh_ecosystem,
                                "package": None,
                                "first": min(100, max_results - len(cves)),
                                "after": cursor,
                            },
                        },
                    )

                    vulns = data.get("data", {}).get("securityVulnerabilities", {})
                    nodes = vulns.get("nodes", [])

                    for node in nodes:
                        cve = self._parse_vulnerability_node(node)
                        if cve:
                            cves.append(cve)

                    page_info = vulns.get("pageInfo", {})
                    if not page_info.get("hasNextPage"):
                        break
                    cursor = page_info.get("endCursor")

                except Exception as e:
                    logger.error(
                        "Error searching advisories for ecosystem %s: %s",
                        ecosystem.value,
                        e,
                    )
                    break

        return cves

    def _parse_vulnerability_node(self, node: dict[str, Any]) -> CVE | None:
        """Parse a vulnerability node from GraphQL response.

        Args:
            node: Vulnerability node data.

        Returns:
            Parsed CVE or None.
        """
        advisory = node.get("advisory", {})
        if not advisory:
            return None

        cve_id = self._extract_cve_id(advisory)
        ghsa_id = advisory.get("ghsaId", "")

        if not cve_id and not ghsa_id:
            return None

        display_id = cve_id or ghsa_id

        package_data = node.get("package", {})
        ecosystem_str = package_data.get("ecosystem", "")
        ecosystem = ECOSYSTEM_MAP.get(ecosystem_str, Ecosystem.NPM)
        package_name = package_data.get("name", "")

        version_range = node.get("vulnerableVersionRange", "")
        fixed_version = None
        first_patched = node.get("firstPatchedVersion")
        if first_patched:
            fixed_version = first_patched.get("identifier")

        version_start, version_end = self._parse_version_range(version_range)

        affected_packages = [
            AffectedPackage(
                ecosystem=ecosystem,
                name=package_name,
                version_start=version_start,
                version_end=version_end,
                fixed_version=fixed_version,
            )
        ] if package_name else []

        severity = self._map_severity(advisory.get("severity", ""))

        cvss = advisory.get("cvss", {}) or {}
        cvss_score = cvss.get("score")
        cvss_vector = cvss.get("vectorString")

        references = [
            ref.get("url") for ref in advisory.get("references", [])
            if ref.get("url")
        ]

        return CVE(
            id=display_id,
            description=advisory.get("description") or advisory.get("summary", ""),
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            affected_packages=affected_packages,
            references=references,
            published_date=self._parse_date(advisory.get("publishedAt")),
            modified_date=self._parse_date(advisory.get("updatedAt")),
            source="github",
            is_waf_mitigatable=False,
            waf_pattern_id=None,
        )

    def _parse_advisory(self, advisory: dict[str, Any]) -> CVE | None:
        """Parse a full advisory response.

        Args:
            advisory: Advisory data.

        Returns:
            Parsed CVE or None.
        """
        cve_id = self._extract_cve_id(advisory)
        ghsa_id = advisory.get("ghsaId", "")

        if not cve_id and not ghsa_id:
            return None

        display_id = cve_id or ghsa_id

        affected_packages: list[AffectedPackage] = []
        vulnerabilities = advisory.get("vulnerabilities", {}).get("nodes", [])

        for vuln in vulnerabilities:
            package_data = vuln.get("package", {})
            ecosystem_str = package_data.get("ecosystem", "")
            ecosystem = ECOSYSTEM_MAP.get(ecosystem_str, Ecosystem.NPM)
            package_name = package_data.get("name", "")

            version_range = vuln.get("vulnerableVersionRange", "")
            version_start, version_end = self._parse_version_range(version_range)

            fixed_version = None
            first_patched = vuln.get("firstPatchedVersion")
            if first_patched:
                fixed_version = first_patched.get("identifier")

            if package_name:
                affected_packages.append(
                    AffectedPackage(
                        ecosystem=ecosystem,
                        name=package_name,
                        version_start=version_start,
                        version_end=version_end,
                        fixed_version=fixed_version,
                    )
                )

        severity = self._map_severity(advisory.get("severity", ""))

        cvss = advisory.get("cvss", {}) or {}
        cvss_score = cvss.get("score")
        cvss_vector = cvss.get("vectorString")

        references = [
            ref.get("url") for ref in advisory.get("references", [])
            if ref.get("url")
        ]

        return CVE(
            id=display_id,
            description=advisory.get("description") or advisory.get("summary", ""),
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            affected_packages=affected_packages,
            references=references,
            published_date=self._parse_date(advisory.get("publishedAt")),
            modified_date=self._parse_date(advisory.get("updatedAt")),
            source="github",
            is_waf_mitigatable=False,
            waf_pattern_id=None,
        )

    def _extract_cve_id(self, advisory: dict[str, Any]) -> str | None:
        """Extract CVE ID from advisory identifiers.

        Args:
            advisory: Advisory data.

        Returns:
            CVE ID or None.
        """
        identifiers = advisory.get("identifiers", [])
        for identifier in identifiers:
            if identifier.get("type") == "CVE":
                return identifier.get("value")
        return None

    def _parse_version_range(
        self,
        range_str: str,
    ) -> tuple[str | None, str | None]:
        """Parse version range string.

        Args:
            range_str: Version range (e.g., ">= 1.0.0, < 2.0.0").

        Returns:
            Tuple of (start_version, end_version).
        """
        if not range_str:
            return None, None

        start = None
        end = None

        parts = range_str.split(",")
        for part in parts:
            part = part.strip()

            if part.startswith(">="):
                start = part[2:].strip()
            elif part.startswith(">"):
                start = part[1:].strip()
            elif part.startswith("<="):
                end = part[2:].strip()
            elif part.startswith("<"):
                end = part[1:].strip()
            elif part.startswith("="):
                start = part[1:].strip()
                end = start

        return start, end

    def _map_severity(self, severity_str: str) -> Severity:
        """Map GitHub severity string to Severity enum.

        Args:
            severity_str: Severity from GitHub (LOW, MODERATE, HIGH, CRITICAL).

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
