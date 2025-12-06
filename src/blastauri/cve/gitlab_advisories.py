"""GitLab Advisory Database client."""

import os
from datetime import datetime
from typing import Any

from blastauri.core.models import AffectedPackage, CVE, Ecosystem, Severity
from blastauri.utils.http import AsyncHttpClient, RateLimiter
from blastauri.utils.logging import get_logger

logger = get_logger(__name__)

GITLAB_ADVISORIES_URL = "https://gitlab.com/api/v4/security/advisories"

ECOSYSTEM_MAP: dict[str, Ecosystem] = {
    "npm": Ecosystem.NPM,
    "pypi": Ecosystem.PYPI,
    "go": Ecosystem.GO,
    "gem": Ecosystem.RUBYGEMS,
    "maven": Ecosystem.MAVEN,
    "cargo": Ecosystem.CARGO,
    "composer": Ecosystem.COMPOSER,
}

REVERSE_ECOSYSTEM_MAP: dict[Ecosystem, str] = {
    Ecosystem.NPM: "npm",
    Ecosystem.PYPI: "pypi",
    Ecosystem.GO: "go",
    Ecosystem.RUBYGEMS: "gem",
    Ecosystem.MAVEN: "maven",
    Ecosystem.CARGO: "cargo",
    Ecosystem.COMPOSER: "composer",
}


class GitLabAdvisoriesClient:
    """Client for GitLab Advisory Database API.

    GitLab provides security advisories through their API with
    package-specific vulnerability information.
    """

    def __init__(
        self,
        token: str | None = None,
        gitlab_url: str | None = None,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        """Initialize the GitLab advisories client.

        Args:
            token: GitLab personal access token.
            gitlab_url: GitLab instance URL (defaults to gitlab.com).
            rate_limiter: Optional rate limiter.
        """
        self.token = token or os.environ.get("GITLAB_TOKEN")
        self.gitlab_url = gitlab_url or os.environ.get(
            "GITLAB_URL", "https://gitlab.com"
        )
        self.rate_limiter = rate_limiter or RateLimiter(
            requests_per_window=60, window_seconds=60
        )

    def _get_headers(self) -> dict[str, str]:
        """Get request headers."""
        headers: dict[str, str] = {}
        if self.token:
            headers["PRIVATE-TOKEN"] = self.token
        return headers

    def _get_advisories_url(self) -> str:
        """Get the advisories API URL."""
        return f"{self.gitlab_url.rstrip('/')}/api/v4/security/advisories"

    async def get_advisory(self, advisory_id: str) -> CVE | None:
        """Get a specific advisory by ID.

        Args:
            advisory_id: Advisory ID.

        Returns:
            CVE object or None if not found.
        """
        async with AsyncHttpClient(
            rate_limiter=self.rate_limiter,
            headers=self._get_headers(),
        ) as client:
            try:
                url = f"{self._get_advisories_url()}/{advisory_id}"
                data = await client.get_json(url)
                return self._parse_advisory(data)
            except Exception as e:
                logger.error("Error fetching advisory %s: %s", advisory_id, e)
                return None

    async def search_by_package(
        self,
        ecosystem: Ecosystem,
        package_name: str,
        page: int = 1,
        per_page: int = 100,
    ) -> list[CVE]:
        """Search advisories affecting a specific package.

        Args:
            ecosystem: Package ecosystem.
            package_name: Package name.
            page: Page number for pagination.
            per_page: Results per page.

        Returns:
            List of CVEs affecting the package.
        """
        gl_ecosystem = REVERSE_ECOSYSTEM_MAP.get(ecosystem)
        if not gl_ecosystem:
            logger.warning("Unsupported ecosystem for GitLab: %s", ecosystem)
            return []

        async with AsyncHttpClient(
            rate_limiter=self.rate_limiter,
            headers=self._get_headers(),
        ) as client:
            try:
                data = await client.get_json(
                    self._get_advisories_url(),
                    params={
                        "package_manager": gl_ecosystem,
                        "package_name": package_name,
                        "page": page,
                        "per_page": per_page,
                    },
                )

                if isinstance(data, list):
                    return [
                        cve for advisory in data
                        if (cve := self._parse_advisory(advisory)) is not None
                    ]
                return []

            except Exception as e:
                logger.error(
                    "Error searching GitLab advisories for %s/%s: %s",
                    ecosystem.value,
                    package_name,
                    e,
                )
                return []

    async def search_all(
        self,
        ecosystem: Ecosystem | None = None,
        page: int = 1,
        per_page: int = 100,
    ) -> list[CVE]:
        """Get all advisories, optionally filtered by ecosystem.

        Args:
            ecosystem: Optional ecosystem filter.
            page: Page number for pagination.
            per_page: Results per page.

        Returns:
            List of CVEs.
        """
        params: dict[str, Any] = {
            "page": page,
            "per_page": per_page,
        }

        if ecosystem:
            gl_ecosystem = REVERSE_ECOSYSTEM_MAP.get(ecosystem)
            if gl_ecosystem:
                params["package_manager"] = gl_ecosystem

        async with AsyncHttpClient(
            rate_limiter=self.rate_limiter,
            headers=self._get_headers(),
        ) as client:
            try:
                data = await client.get_json(
                    self._get_advisories_url(),
                    params=params,
                )

                if isinstance(data, list):
                    return [
                        cve for advisory in data
                        if (cve := self._parse_advisory(advisory)) is not None
                    ]
                return []

            except Exception as e:
                logger.error("Error fetching GitLab advisories: %s", e)
                return []

    def _parse_advisory(self, data: dict[str, Any]) -> CVE | None:
        """Parse a GitLab advisory.

        Args:
            data: Advisory data.

        Returns:
            Parsed CVE or None.
        """
        advisory_id = data.get("id")
        if not advisory_id:
            return None

        identifiers = data.get("identifiers", [])
        cve_id = None
        for identifier in identifiers:
            if identifier.get("type") == "cve":
                cve_id = identifier.get("name")
                break

        display_id = cve_id or f"GITLAB-{advisory_id}"

        title = data.get("title", "")
        description = data.get("description", "") or title

        severity = self._map_severity(data.get("severity", ""))

        cvss = data.get("cvss", {}) or {}
        cvss_score = None
        cvss_vector = None

        if isinstance(cvss, dict):
            cvss_score = cvss.get("score")
            cvss_vector = cvss.get("vector")

        affected_packages = self._parse_affected_packages(data)

        urls = data.get("urls", []) or []
        references = [url for url in urls if isinstance(url, str)]

        published_date = self._parse_date(data.get("published_date"))

        return CVE(
            id=display_id,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            affected_packages=affected_packages,
            references=references,
            published_date=published_date,
            modified_date=None,
            source="gitlab",
            is_waf_mitigatable=False,
            waf_pattern_id=None,
        )

    def _parse_affected_packages(
        self,
        data: dict[str, Any],
    ) -> list[AffectedPackage]:
        """Parse affected packages from advisory.

        Args:
            data: Advisory data.

        Returns:
            List of affected packages.
        """
        packages: list[AffectedPackage] = []

        affected_range = data.get("affected_range", "")
        package_slug = data.get("package_slug", "")
        package_manager = data.get("package_manager", "")

        if not package_slug:
            return packages

        ecosystem = ECOSYSTEM_MAP.get(package_manager, Ecosystem.NPM)

        package_name = package_slug
        if "/" in package_slug:
            parts = package_slug.split("/")
            package_name = parts[-1]

        version_start, version_end = self._parse_affected_range(affected_range)

        fixed_versions = data.get("fixed_versions", []) or []
        fixed_version = fixed_versions[0] if fixed_versions else None

        packages.append(
            AffectedPackage(
                ecosystem=ecosystem,
                name=package_name,
                version_start=version_start,
                version_end=version_end,
                fixed_version=fixed_version,
            )
        )

        return packages

    def _parse_affected_range(
        self,
        range_str: str,
    ) -> tuple[str | None, str | None]:
        """Parse affected version range.

        Args:
            range_str: Version range string.

        Returns:
            Tuple of (start_version, end_version).
        """
        if not range_str:
            return None, None

        range_str = range_str.strip()

        if range_str.startswith(">=") and "<" in range_str:
            parts = range_str.split(",")
            start = None
            end = None

            for part in parts:
                part = part.strip()
                if part.startswith(">="):
                    start = part[2:].strip()
                elif part.startswith("<"):
                    end = part[1:].strip()

            return start, end

        if range_str.startswith("<"):
            return None, range_str[1:].strip()

        if range_str.startswith("="):
            version = range_str[1:].strip()
            return version, version

        return None, None

    def _map_severity(self, severity_str: str) -> Severity:
        """Map GitLab severity string to Severity enum.

        Args:
            severity_str: Severity from GitLab.

        Returns:
            Severity enum value.
        """
        severity_str = severity_str.lower()

        if severity_str == "critical":
            return Severity.CRITICAL
        elif severity_str == "high":
            return Severity.HIGH
        elif severity_str in ("medium", "moderate"):
            return Severity.MEDIUM
        elif severity_str == "low":
            return Severity.LOW
        elif severity_str in ("none", "info", "unknown"):
            return Severity.NONE
        return Severity.UNKNOWN

    def _parse_date(self, date_str: str | None) -> datetime | None:
        """Parse date string.

        Args:
            date_str: Date string.

        Returns:
            Datetime object or None.
        """
        if not date_str:
            return None

        try:
            if "T" in date_str:
                date_str = date_str.replace("Z", "+00:00")
                return datetime.fromisoformat(date_str)
            else:
                return datetime.strptime(date_str, "%Y-%m-%d")
        except ValueError:
            return None
