"""Changelog parser for detecting breaking changes in dependency upgrades."""

import re
from dataclasses import dataclass
from enum import Enum

import httpx

from blastauri.core.models import BreakingChange, BreakingChangeType, Ecosystem


class ChangelogSource(str, Enum):
    """Sources for changelog data."""

    GITHUB_RELEASES = "github_releases"
    CHANGELOG_FILE = "changelog_file"
    NPM_REGISTRY = "npm_registry"
    PYPI = "pypi"
    RUBYGEMS = "rubygems"
    CRATES_IO = "crates_io"
    MAVEN_CENTRAL = "maven_central"


@dataclass
class ChangelogEntry:
    """A single changelog entry."""

    version: str
    date: str | None
    content: str
    source: ChangelogSource


# Patterns for detecting breaking changes in changelog text
BREAKING_CHANGE_PATTERNS = [
    # Explicit breaking change markers
    (r"(?i)breaking\s*change[s]?", BreakingChangeType.CHANGED_BEHAVIOR),
    (r"(?i)breaking:", BreakingChangeType.CHANGED_BEHAVIOR),
    (r"(?i)\[breaking\]", BreakingChangeType.CHANGED_BEHAVIOR),
    (r"(?i)⚠️.*breaking", BreakingChangeType.CHANGED_BEHAVIOR),
    # Removed functionality
    (r"(?i)removed?\s+(?:the\s+)?(?:function|method|api|endpoint)", BreakingChangeType.REMOVED_FUNCTION),
    (r"(?i)removed?\s+(?:the\s+)?class", BreakingChangeType.REMOVED_CLASS),
    (r"(?i)removed?\s+(?:the\s+)?module", BreakingChangeType.REMOVED_MODULE),
    (r"(?i)(?:function|method|api)\s+(?:has\s+been\s+)?removed", BreakingChangeType.REMOVED_FUNCTION),
    (r"(?i)(?:class)\s+(?:has\s+been\s+)?removed", BreakingChangeType.REMOVED_CLASS),
    (r"(?i)(?:module)\s+(?:has\s+been\s+)?removed", BreakingChangeType.REMOVED_MODULE),
    (r"(?i)no\s+longer\s+(?:exports?|provides?)", BreakingChangeType.REMOVED_FUNCTION),
    (r"(?i)dropped\s+support\s+for", BreakingChangeType.REMOVED_FUNCTION),
    # Signature changes
    (r"(?i)changed?\s+(?:the\s+)?(?:function|method)\s+signature", BreakingChangeType.CHANGED_SIGNATURE),
    (r"(?i)signature\s+(?:has\s+)?changed", BreakingChangeType.CHANGED_SIGNATURE),
    (r"(?i)parameter[s]?\s+(?:have\s+been\s+)?(?:changed|removed|renamed)", BreakingChangeType.CHANGED_SIGNATURE),
    (r"(?i)argument[s]?\s+(?:have\s+been\s+)?(?:changed|removed|renamed)", BreakingChangeType.CHANGED_SIGNATURE),
    (r"(?i)return\s+type\s+(?:has\s+)?changed", BreakingChangeType.CHANGED_SIGNATURE),
    # Renames
    (r"(?i)renamed?\s+(?:from\s+)?[`'\"]?\w+[`'\"]?\s+to", BreakingChangeType.RENAMED_EXPORT),
    (r"(?i)(?:function|method|class|module)\s+(?:has\s+been\s+)?renamed", BreakingChangeType.RENAMED_EXPORT),
    # Default changes
    (r"(?i)default\s+(?:value\s+)?(?:has\s+)?changed", BreakingChangeType.CHANGED_DEFAULT),
    (r"(?i)changed?\s+(?:the\s+)?default", BreakingChangeType.CHANGED_DEFAULT),
    (r"(?i)new\s+default\s+(?:value|behavior)", BreakingChangeType.CHANGED_DEFAULT),
    # Behavior changes
    (r"(?i)behavior\s+(?:has\s+)?changed", BreakingChangeType.CHANGED_BEHAVIOR),
    (r"(?i)now\s+(?:throws?|raises?)", BreakingChangeType.CHANGED_BEHAVIOR),
    (r"(?i)no\s+longer\s+(?:returns?|accepts?)", BreakingChangeType.CHANGED_BEHAVIOR),
    (r"(?i)(?:strict|stricter)\s+validation", BreakingChangeType.CHANGED_BEHAVIOR),
    # Deprecations
    (r"(?i)deprecated?", BreakingChangeType.DEPRECATED),
    (r"(?i)will\s+be\s+removed", BreakingChangeType.DEPRECATED),
    (r"(?i)scheduled\s+for\s+removal", BreakingChangeType.DEPRECATED),
]

# Patterns to extract API names from breaking change descriptions
API_EXTRACTION_PATTERNS = [
    r"`([a-zA-Z_][a-zA-Z0-9_\.]*)`",  # Backtick quoted
    r"'([a-zA-Z_][a-zA-Z0-9_\.]*)'",  # Single quoted
    r'"([a-zA-Z_][a-zA-Z0-9_\.]*)"',  # Double quoted
    r"\b([A-Z][a-zA-Z0-9]*(?:\.[A-Z][a-zA-Z0-9]*)*)\b",  # PascalCase class names
    r"(?:function|method|class)\s+([a-zA-Z_][a-zA-Z0-9_]*)",  # Named entities
]


class ChangelogParser:
    """Parser for extracting breaking changes from changelogs."""

    def __init__(self, http_client: httpx.AsyncClient | None = None):
        """Initialize the changelog parser.

        Args:
            http_client: Optional HTTP client for fetching remote changelogs.
        """
        self._http_client = http_client
        self._owns_client = False

    async def __aenter__(self) -> "ChangelogParser":
        """Async context manager entry."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=30.0)
            self._owns_client = True
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        if self._owns_client and self._http_client:
            await self._http_client.aclose()

    def parse_changelog_text(
        self,
        text: str,
        from_version: str,
        to_version: str,
        source: ChangelogSource = ChangelogSource.CHANGELOG_FILE,
    ) -> list[BreakingChange]:
        """Parse changelog text and extract breaking changes.

        Args:
            text: Raw changelog text.
            from_version: Starting version.
            to_version: Target version.
            source: Source of the changelog.

        Returns:
            List of detected breaking changes.
        """
        # Extract relevant sections between versions
        relevant_text = self._extract_version_range(text, from_version, to_version)
        if not relevant_text:
            relevant_text = text

        return self._detect_breaking_changes(relevant_text, str(source.value))

    def _extract_version_range(
        self,
        text: str,
        from_version: str,
        to_version: str,
    ) -> str:
        """Extract changelog sections between two versions.

        Args:
            text: Full changelog text.
            from_version: Starting version (exclusive).
            to_version: Target version (inclusive).

        Returns:
            Extracted text between versions.
        """
        # Normalize versions for comparison
        from_v = self._normalize_version(from_version)
        to_v = self._normalize_version(to_version)

        # Common version header patterns
        version_patterns = [
            r"^##?\s*\[?v?(\d+\.\d+(?:\.\d+)?(?:-[\w.]+)?)\]?",  # ## [1.2.3] or # v1.2.3
            r"^v?(\d+\.\d+(?:\.\d+)?(?:-[\w.]+)?)\s*[-–—]\s*\d{4}",  # 1.2.3 - 2024-01-01
            r"^Version\s+v?(\d+\.\d+(?:\.\d+)?(?:-[\w.]+)?)",  # Version 1.2.3
            r"^\*\*v?(\d+\.\d+(?:\.\d+)?(?:-[\w.]+)?)\*\*",  # **1.2.3**
        ]

        lines = text.split("\n")
        sections: list[tuple[str, int, int]] = []  # (version, start_idx, end_idx)

        current_version: str | None = None
        current_start: int = 0

        for i, line in enumerate(lines):
            for pattern in version_patterns:
                match = re.match(pattern, line, re.IGNORECASE | re.MULTILINE)
                if match:
                    if current_version is not None:
                        sections.append((current_version, current_start, i))
                    current_version = match.group(1)
                    current_start = i
                    break

        # Add last section
        if current_version is not None:
            sections.append((current_version, current_start, len(lines)))

        # Filter sections within version range
        relevant_lines: list[str] = []
        for version, start, end in sections:
            norm_v = self._normalize_version(version)
            if self._version_in_range(norm_v, from_v, to_v):
                relevant_lines.extend(lines[start:end])

        return "\n".join(relevant_lines)

    def _normalize_version(self, version: str) -> tuple[int, ...]:
        """Normalize version string for comparison.

        Args:
            version: Version string.

        Returns:
            Tuple of version components.
        """
        # Remove common prefixes
        version = re.sub(r"^[v=]", "", version.strip())

        # Extract numeric parts
        parts = re.findall(r"\d+", version)
        return tuple(int(p) for p in parts[:3]) if parts else (0,)

    def _version_in_range(
        self,
        version: tuple[int, ...],
        from_v: tuple[int, ...],
        to_v: tuple[int, ...],
    ) -> bool:
        """Check if version is within range (from_v, to_v].

        Args:
            version: Version to check.
            from_v: Lower bound (exclusive).
            to_v: Upper bound (inclusive).

        Returns:
            True if version is in range.
        """
        # Pad versions to same length
        max_len = max(len(version), len(from_v), len(to_v))
        v = version + (0,) * (max_len - len(version))
        fv = from_v + (0,) * (max_len - len(from_v))
        tv = to_v + (0,) * (max_len - len(to_v))

        return fv < v <= tv

    def _detect_breaking_changes(
        self,
        text: str,
        source: str,
    ) -> list[BreakingChange]:
        """Detect breaking changes in text.

        Args:
            text: Changelog text to analyze.
            source: Source identifier.

        Returns:
            List of detected breaking changes.
        """
        breaking_changes: list[BreakingChange] = []
        seen_descriptions: set[str] = set()

        # Split into lines/paragraphs for better context
        lines = text.split("\n")

        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue

            for pattern, change_type in BREAKING_CHANGE_PATTERNS:
                if re.search(pattern, line):
                    # Get surrounding context
                    context_start = max(0, i - 1)
                    context_end = min(len(lines), i + 2)
                    context = "\n".join(lines[context_start:context_end])

                    # Extract API names
                    old_api, new_api = self._extract_api_names(context)

                    # Create description from the matched line
                    description = self._clean_description(line)

                    # Avoid duplicates
                    if description in seen_descriptions:
                        continue
                    seen_descriptions.add(description)

                    breaking_changes.append(
                        BreakingChange(
                            change_type=change_type,
                            description=description,
                            old_api=old_api,
                            new_api=new_api,
                            migration_guide=self._extract_migration_guide(context),
                            source=source,
                        )
                    )
                    break  # Only match first pattern per line

        return breaking_changes

    def _extract_api_names(self, text: str) -> tuple[str | None, str | None]:
        """Extract old and new API names from text.

        Args:
            text: Text containing API references.

        Returns:
            Tuple of (old_api, new_api).
        """
        # Look for rename patterns first
        rename_match = re.search(
            r"(?:renamed?|changed?)\s+(?:from\s+)?[`'\"]?(\w+(?:\.\w+)*)[`'\"]?\s+(?:to|->|=>)\s+[`'\"]?(\w+(?:\.\w+)*)[`'\"]?",
            text,
            re.IGNORECASE,
        )
        if rename_match:
            return rename_match.group(1), rename_match.group(2)

        # Extract any API names mentioned
        apis: list[str] = []
        for pattern in API_EXTRACTION_PATTERNS:
            apis.extend(re.findall(pattern, text))

        # Return first two unique APIs found
        unique_apis = list(dict.fromkeys(apis))
        if len(unique_apis) >= 2:
            return unique_apis[0], unique_apis[1]
        elif len(unique_apis) == 1:
            return unique_apis[0], None
        return None, None

    def _extract_migration_guide(self, text: str) -> str | None:
        """Extract migration guide from text.

        Args:
            text: Text that may contain migration guidance.

        Returns:
            Migration guide if found.
        """
        # Look for migration guidance patterns
        patterns = [
            r"(?:instead|use|migrate|upgrade|replace|change)\s+(?:to\s+)?(.+?)(?:\.|$)",
            r"(?:please\s+)?(?:use|switch\s+to)\s+(.+?)(?:\.|$)",
            r"->(.+?)(?:\.|$)",
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                guide = match.group(1).strip()
                if len(guide) > 10:  # Filter out very short matches
                    return guide

        return None

    def _clean_description(self, text: str) -> str:
        """Clean up description text.

        Args:
            text: Raw description text.

        Returns:
            Cleaned description.
        """
        # Remove markdown formatting
        text = re.sub(r"^\s*[-*+]\s*", "", text)  # List markers
        text = re.sub(r"^\s*#{1,6}\s*", "", text)  # Headers
        text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)  # Links

        # Truncate long descriptions
        if len(text) > 200:
            text = text[:197] + "..."

        return text.strip()

    async def fetch_github_releases(
        self,
        owner: str,
        repo: str,
        from_version: str,
        to_version: str,
    ) -> list[BreakingChange]:
        """Fetch and parse GitHub releases for breaking changes.

        Args:
            owner: Repository owner.
            repo: Repository name.
            from_version: Starting version.
            to_version: Target version.

        Returns:
            List of detected breaking changes.
        """
        if not self._http_client:
            return []

        breaking_changes: list[BreakingChange] = []
        page = 1
        per_page = 100
        from_v = self._normalize_version(from_version)
        to_v = self._normalize_version(to_version)

        while True:
            try:
                response = await self._http_client.get(
                    f"https://api.github.com/repos/{owner}/{repo}/releases",
                    params={"page": page, "per_page": per_page},
                    headers={"Accept": "application/vnd.github.v3+json"},
                )
                response.raise_for_status()
                releases = response.json()

                if not releases:
                    break

                for release in releases:
                    tag = release.get("tag_name", "")
                    body = release.get("body", "")

                    if not tag or not body:
                        continue

                    release_v = self._normalize_version(tag)
                    if self._version_in_range(release_v, from_v, to_v):
                        changes = self._detect_breaking_changes(
                            body, ChangelogSource.GITHUB_RELEASES.value
                        )
                        breaking_changes.extend(changes)

                # Check if we've passed the from_version
                oldest_release = releases[-1]
                oldest_v = self._normalize_version(oldest_release.get("tag_name", ""))
                if oldest_v <= from_v:
                    break

                page += 1

            except httpx.HTTPError:
                break

        return breaking_changes

    async def fetch_npm_changelog(
        self,
        package_name: str,
        from_version: str,
        to_version: str,
    ) -> list[BreakingChange]:
        """Fetch changelog from npm package repository.

        Args:
            package_name: NPM package name.
            from_version: Starting version.
            to_version: Target version.

        Returns:
            List of detected breaking changes.
        """
        if not self._http_client:
            return []

        try:
            # Get package metadata
            response = await self._http_client.get(
                f"https://registry.npmjs.org/{package_name}",
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
            data = response.json()

            # Check for repository URL
            repo = data.get("repository", {})
            if isinstance(repo, dict):
                repo_url = repo.get("url", "")
            else:
                repo_url = str(repo) if repo else ""

            # Parse GitHub URL
            github_match = re.search(
                r"github\.com[/:]([^/]+)/([^/\.]+)", repo_url
            )
            if github_match:
                owner, repo_name = github_match.groups()
                return await self.fetch_github_releases(
                    owner, repo_name, from_version, to_version
                )

        except httpx.HTTPError:
            pass

        return []

    async def fetch_pypi_changelog(
        self,
        package_name: str,
        from_version: str,
        to_version: str,
    ) -> list[BreakingChange]:
        """Fetch changelog from PyPI package.

        Args:
            package_name: PyPI package name.
            from_version: Starting version.
            to_version: Target version.

        Returns:
            List of detected breaking changes.
        """
        if not self._http_client:
            return []

        try:
            # Get package metadata
            response = await self._http_client.get(
                f"https://pypi.org/pypi/{package_name}/json",
            )
            response.raise_for_status()
            data = response.json()

            # Check for GitHub project URL
            project_urls = data.get("info", {}).get("project_urls", {}) or {}
            for key in ["Changelog", "Changes", "History", "Source", "Repository"]:
                url = project_urls.get(key, "")
                github_match = re.search(
                    r"github\.com/([^/]+)/([^/]+)", url
                )
                if github_match:
                    owner, repo_name = github_match.groups()
                    return await self.fetch_github_releases(
                        owner, repo_name, from_version, to_version
                    )

        except httpx.HTTPError:
            pass

        return []

    async def fetch_changelog(
        self,
        ecosystem: Ecosystem,
        package_name: str,
        from_version: str,
        to_version: str,
    ) -> list[BreakingChange]:
        """Fetch and parse changelog for a package.

        Args:
            ecosystem: Package ecosystem.
            package_name: Package name.
            from_version: Starting version.
            to_version: Target version.

        Returns:
            List of detected breaking changes.
        """
        if ecosystem == Ecosystem.NPM:
            return await self.fetch_npm_changelog(package_name, from_version, to_version)
        elif ecosystem == Ecosystem.PYPI:
            return await self.fetch_pypi_changelog(package_name, from_version, to_version)

        # For other ecosystems, try to find GitHub repository
        return []


def is_major_version_upgrade(from_version: str, to_version: str) -> bool:
    """Check if the upgrade is a major version bump.

    Args:
        from_version: Starting version.
        to_version: Target version.

    Returns:
        True if major version increased.
    """
    from_parts = re.findall(r"\d+", from_version)
    to_parts = re.findall(r"\d+", to_version)

    if from_parts and to_parts:
        return int(to_parts[0]) > int(from_parts[0])

    return False


def detect_breaking_changes_from_version(
    from_version: str,
    to_version: str,
) -> list[BreakingChange]:
    """Detect breaking changes based on version difference only.

    Args:
        from_version: Starting version.
        to_version: Target version.

    Returns:
        List of detected breaking changes (major version if applicable).
    """
    changes: list[BreakingChange] = []

    if is_major_version_upgrade(from_version, to_version):
        changes.append(
            BreakingChange(
                change_type=BreakingChangeType.MAJOR_VERSION,
                description=f"Major version upgrade from {from_version} to {to_version}",
                source="version_analysis",
            )
        )

    return changes
