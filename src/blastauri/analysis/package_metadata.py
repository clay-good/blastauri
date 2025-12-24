"""Package metadata analysis for breaking change signals.

This module gathers signals from package registries and repositories
that indicate potential breaking changes, deprecations, and maintenance status.
These signals work even when changelogs are missing or incomplete.

Signals collected:
- Deprecation warnings from npm/PyPI
- Package maintenance status (archived, last update)
- Major version jump patterns
- Dependency changes that may cascade
- Type definition availability
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

import httpx

from blastauri.core.models import (
    BreakingChange,
    BreakingChangeType,
    Ecosystem,
    Severity,
)
from blastauri.utils.logging import get_logger

logger = get_logger(__name__)


class MaintenanceStatus(str, Enum):
    """Package maintenance status."""

    ACTIVE = "active"
    SLOW = "slow"  # No updates in 6+ months
    STALE = "stale"  # No updates in 1+ year
    DEPRECATED = "deprecated"
    ARCHIVED = "archived"
    UNKNOWN = "unknown"


class RiskSignal(str, Enum):
    """Types of risk signals detected."""

    DEPRECATED = "deprecated"
    ARCHIVED = "archived"
    UNMAINTAINED = "unmaintained"
    MAJOR_REWRITE = "major_rewrite"
    BREAKING_PEER_DEP = "breaking_peer_dep"
    DROPPED_SUPPORT = "dropped_support"
    NEW_REQUIRED_PEER = "new_required_peer"
    ENGINE_REQUIREMENT_CHANGE = "engine_requirement_change"
    TYPE_DEFINITIONS_REMOVED = "type_definitions_removed"
    EXPORTS_CHANGED = "exports_changed"


@dataclass
class PackageSignal:
    """A detected signal from package metadata."""

    signal_type: RiskSignal
    severity: Severity
    description: str
    source: str
    details: dict | None = None


@dataclass
class PackageMetadata:
    """Collected metadata about a package version."""

    name: str
    version: str
    ecosystem: Ecosystem

    # Deprecation
    is_deprecated: bool = False
    deprecation_message: str | None = None

    # Maintenance
    maintenance_status: MaintenanceStatus = MaintenanceStatus.UNKNOWN
    last_publish_date: datetime | None = None

    # Repository
    repository_url: str | None = None
    is_archived: bool = False

    # Dependencies
    peer_dependencies: dict[str, str] = field(default_factory=dict)
    engines: dict[str, str] = field(default_factory=dict)

    # Types
    has_types: bool = False
    types_package: str | None = None  # e.g., @types/lodash

    # Exports (npm)
    exports: dict | None = None
    main_entry: str | None = None

    # Signals detected
    signals: list[PackageSignal] = field(default_factory=list)


class PackageMetadataAnalyzer:
    """Analyzes package metadata for breaking change signals."""

    def __init__(self, http_client: httpx.AsyncClient | None = None):
        """Initialize the analyzer.

        Args:
            http_client: Optional HTTP client.
        """
        self._http_client = http_client
        self._owns_client = False

    async def __aenter__(self) -> "PackageMetadataAnalyzer":
        """Async context manager entry."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=30.0)
            self._owns_client = True
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        if self._owns_client and self._http_client:
            await self._http_client.aclose()

    async def analyze_upgrade(
        self,
        ecosystem: Ecosystem,
        package_name: str,
        from_version: str,
        to_version: str,
    ) -> list[BreakingChange]:
        """Analyze package upgrade for breaking change signals.

        Args:
            ecosystem: Package ecosystem.
            package_name: Package name.
            from_version: Old version.
            to_version: New version.

        Returns:
            List of breaking changes detected from metadata signals.
        """
        if ecosystem == Ecosystem.NPM:
            return await self._analyze_npm_upgrade(package_name, from_version, to_version)
        elif ecosystem == Ecosystem.PYPI:
            return await self._analyze_pypi_upgrade(package_name, from_version, to_version)
        else:
            return []

    async def _analyze_npm_upgrade(
        self,
        package_name: str,
        from_version: str,
        to_version: str,
    ) -> list[BreakingChange]:
        """Analyze npm package upgrade."""
        if not self._http_client:
            return []

        breaking_changes: list[BreakingChange] = []

        try:
            # Fetch both versions' metadata
            old_meta = await self._fetch_npm_version_metadata(package_name, from_version)
            new_meta = await self._fetch_npm_version_metadata(package_name, to_version)

            if not old_meta or not new_meta:
                return []

            # Check for deprecation
            if new_meta.is_deprecated:
                breaking_changes.append(BreakingChange(
                    change_type=BreakingChangeType.DEPRECATED,
                    description=f"Package is deprecated: {new_meta.deprecation_message or 'No message provided'}",
                    source="npm_registry_metadata",
                ))

            # Check repository status (archived, unmaintained)
            if new_meta.repository_url:
                repo_signals = await self._check_repository_status(new_meta.repository_url)
                breaking_changes.extend(repo_signals)

            # Check for peer dependency changes
            peer_changes = self._compare_peer_deps(
                old_meta.peer_dependencies,
                new_meta.peer_dependencies,
            )
            breaking_changes.extend(peer_changes)

            # Check for engine requirement changes
            engine_changes = self._compare_engines(
                old_meta.engines,
                new_meta.engines,
            )
            breaking_changes.extend(engine_changes)

            # Check for type definitions removal
            if old_meta.has_types and not new_meta.has_types:
                breaking_changes.append(BreakingChange(
                    change_type=BreakingChangeType.REMOVED_MODULE,
                    description="TypeScript type definitions removed from package",
                    source="npm_registry_metadata",
                ))

            # Check for exports field changes (breaking for consumers)
            if old_meta.exports and new_meta.exports:
                export_changes = self._compare_exports(old_meta.exports, new_meta.exports)
                breaking_changes.extend(export_changes)

            # Check for main entry point change
            if old_meta.main_entry and new_meta.main_entry:
                if old_meta.main_entry != new_meta.main_entry:
                    # Check if it's just a path change or actual removal
                    old_base = old_meta.main_entry.rsplit("/", 1)[-1].replace(".js", "")
                    new_base = new_meta.main_entry.rsplit("/", 1)[-1].replace(".js", "")
                    if old_base != new_base:
                        breaking_changes.append(BreakingChange(
                            change_type=BreakingChangeType.CHANGED_BEHAVIOR,
                            description=f"Main entry point changed from {old_meta.main_entry} to {new_meta.main_entry}",
                            old_api=old_meta.main_entry,
                            new_api=new_meta.main_entry,
                            source="npm_registry_metadata",
                        ))

        except Exception as e:
            logger.debug(f"Failed to analyze npm package {package_name}: {e}")

        return breaking_changes

    async def _fetch_npm_version_metadata(
        self,
        package_name: str,
        version: str,
    ) -> PackageMetadata | None:
        """Fetch metadata for a specific npm package version."""
        if not self._http_client:
            return None

        try:
            response = await self._http_client.get(
                f"https://registry.npmjs.org/{package_name}/{version}",
            )
            response.raise_for_status()
            data = response.json()

            # Parse deprecation
            is_deprecated = "deprecated" in data
            deprecation_message = data.get("deprecated")

            # Parse dependencies
            peer_deps = data.get("peerDependencies", {})
            engines = data.get("engines", {})

            # Parse type information
            has_types = bool(data.get("types") or data.get("typings"))

            # Check for @types package if no embedded types
            types_package = None
            if not has_types:
                types_package = await self._check_types_package(package_name)
                has_types = types_package is not None

            # Parse exports
            exports = data.get("exports")
            main_entry = data.get("main")

            # Parse repository URL
            repository_url = None
            repo_field = data.get("repository")
            if isinstance(repo_field, dict):
                repository_url = repo_field.get("url", "")
            elif isinstance(repo_field, str):
                repository_url = repo_field
            # Normalize GitHub URLs
            if repository_url:
                repository_url = self._normalize_github_url(repository_url)

            # Parse publish date
            publish_date = None
            if "time" in data:
                time_str = data.get("time", {}).get(version)
                if time_str:
                    try:
                        publish_date = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
                    except (ValueError, TypeError):
                        pass

            return PackageMetadata(
                name=package_name,
                version=version,
                ecosystem=Ecosystem.NPM,
                is_deprecated=is_deprecated,
                deprecation_message=deprecation_message,
                peer_dependencies=peer_deps,
                engines=engines,
                has_types=has_types,
                types_package=types_package,
                exports=exports,
                main_entry=main_entry,
                repository_url=repository_url,
                last_publish_date=publish_date,
            )

        except Exception as e:
            logger.debug(f"Failed to fetch npm metadata for {package_name}@{version}: {e}")
            return None

    async def _check_types_package(self, package_name: str) -> str | None:
        """Check if a @types package exists for an npm package."""
        if not self._http_client:
            return None

        # Handle scoped packages
        if package_name.startswith("@"):
            # @scope/package -> @types/scope__package
            types_name = package_name.replace("@", "").replace("/", "__")
        else:
            types_name = package_name

        types_package = f"@types/{types_name}"

        try:
            response = await self._http_client.head(
                f"https://registry.npmjs.org/{types_package}",
            )
            if response.status_code == 200:
                return types_package
        except Exception:
            pass

        return None

    def _compare_peer_deps(
        self,
        old_peers: dict[str, str],
        new_peers: dict[str, str],
    ) -> list[BreakingChange]:
        """Compare peer dependencies for breaking changes."""
        changes: list[BreakingChange] = []

        # New required peer dependencies
        for name, version in new_peers.items():
            if name not in old_peers:
                changes.append(BreakingChange(
                    change_type=BreakingChangeType.CHANGED_BEHAVIOR,
                    description=f"New peer dependency required: {name}@{version}",
                    new_api=f"{name}@{version}",
                    source="npm_peer_dependencies",
                    migration_guide=f"Install peer dependency: npm install {name}@{version}",
                ))

        # Changed peer dependency versions (major bump)
        for name in set(old_peers.keys()) & set(new_peers.keys()):
            old_range = old_peers[name]
            new_range = new_peers[name]

            if old_range != new_range:
                # Check if it's a major version requirement change
                old_major = self._extract_major_from_range(old_range)
                new_major = self._extract_major_from_range(new_range)

                if old_major is not None and new_major is not None and new_major > old_major:
                    changes.append(BreakingChange(
                        change_type=BreakingChangeType.CHANGED_BEHAVIOR,
                        description=f"Peer dependency {name} now requires major version {new_major} (was {old_major})",
                        old_api=f"{name}@{old_range}",
                        new_api=f"{name}@{new_range}",
                        source="npm_peer_dependencies",
                        migration_guide=f"Upgrade {name} to version {new_major}.x",
                    ))

        return changes

    def _compare_engines(
        self,
        old_engines: dict[str, str],
        new_engines: dict[str, str],
    ) -> list[BreakingChange]:
        """Compare engine requirements for breaking changes."""
        changes: list[BreakingChange] = []

        for engine_name in ["node", "npm", "yarn"]:
            old_req = old_engines.get(engine_name)
            new_req = new_engines.get(engine_name)

            if new_req and not old_req:
                changes.append(BreakingChange(
                    change_type=BreakingChangeType.CHANGED_BEHAVIOR,
                    description=f"New {engine_name} engine requirement: {new_req}",
                    new_api=f"{engine_name} {new_req}",
                    source="npm_engines",
                    migration_guide=f"Ensure {engine_name} version satisfies: {new_req}",
                ))
            elif old_req and new_req and old_req != new_req:
                old_min = self._extract_min_version(old_req)
                new_min = self._extract_min_version(new_req)

                if old_min and new_min:
                    old_major = self._parse_version_major(old_min)
                    new_major = self._parse_version_major(new_min)

                    if new_major > old_major:
                        changes.append(BreakingChange(
                            change_type=BreakingChangeType.CHANGED_BEHAVIOR,
                            description=f"Minimum {engine_name} version increased from {old_min} to {new_min}",
                            old_api=f"{engine_name} {old_req}",
                            new_api=f"{engine_name} {new_req}",
                            source="npm_engines",
                            migration_guide=f"Upgrade {engine_name} to version {new_min} or higher",
                        ))

        return changes

    def _compare_exports(
        self,
        old_exports: dict,
        new_exports: dict,
    ) -> list[BreakingChange]:
        """Compare package.json exports field for breaking changes."""
        changes: list[BreakingChange] = []

        def flatten_exports(exports: dict, prefix: str = "") -> dict[str, str]:
            """Flatten nested exports to path -> target mapping."""
            result = {}
            for key, value in exports.items():
                full_key = f"{prefix}{key}" if prefix else key
                if isinstance(value, str):
                    result[full_key] = value
                elif isinstance(value, dict):
                    # Handle conditional exports
                    if any(k in value for k in ["import", "require", "default", "types"]):
                        for condition, target in value.items():
                            if isinstance(target, str):
                                result[f"{full_key}[{condition}]"] = target
                    else:
                        result.update(flatten_exports(value, f"{full_key}/"))
            return result

        old_flat = flatten_exports(old_exports)
        new_flat = flatten_exports(new_exports)

        # Check for removed exports
        for path in set(old_flat.keys()) - set(new_flat.keys()):
            if not path.startswith("./"):
                path = "./" + path.lstrip("./")
            changes.append(BreakingChange(
                change_type=BreakingChangeType.REMOVED_MODULE,
                description=f"Export path removed: {path}",
                old_api=path,
                source="npm_exports",
            ))

        return changes

    def _extract_major_from_range(self, version_range: str) -> int | None:
        """Extract the minimum major version from a semver range."""
        # Handle common patterns: ^1.0.0, >=1.0.0, 1.x, etc.
        match = re.search(r"(\d+)", version_range)
        if match:
            return int(match.group(1))
        return None

    def _extract_min_version(self, version_range: str) -> str | None:
        """Extract the minimum version from a semver range."""
        # Handle >=X.Y.Z, ^X.Y.Z, etc.
        match = re.search(r"(\d+\.\d+(?:\.\d+)?)", version_range)
        if match:
            return match.group(1)
        return None

    def _parse_version_major(self, version: str) -> int:
        """Parse major version from a version string."""
        parts = version.split(".")
        try:
            return int(parts[0])
        except (ValueError, IndexError):
            return 0

    async def _analyze_pypi_upgrade(
        self,
        package_name: str,
        from_version: str,
        to_version: str,
    ) -> list[BreakingChange]:
        """Analyze PyPI package upgrade."""
        if not self._http_client:
            return []

        breaking_changes: list[BreakingChange] = []

        try:
            # Fetch package metadata
            response = await self._http_client.get(
                f"https://pypi.org/pypi/{package_name}/json",
            )
            response.raise_for_status()
            data = response.json()

            info = data.get("info", {})
            releases = data.get("releases", {})

            # Check for yanked versions
            old_release = releases.get(from_version, [])

            # Check Python version requirements
            old_requires = self._get_python_requires(old_release)
            new_requires = info.get("requires_python", "")

            if old_requires and new_requires and old_requires != new_requires:
                old_min = self._extract_min_python(old_requires)
                new_min = self._extract_min_python(new_requires)

                if old_min and new_min and new_min > old_min:
                    breaking_changes.append(BreakingChange(
                        change_type=BreakingChangeType.CHANGED_BEHAVIOR,
                        description=f"Minimum Python version increased from {old_min} to {new_min}",
                        old_api=f"Python {old_requires}",
                        new_api=f"Python {new_requires}",
                        source="pypi_metadata",
                        migration_guide=f"Upgrade to Python {new_min} or higher",
                    ))

            # Check for classifier changes indicating dropped support
            old_classifiers = self._get_classifiers_from_release(old_release)
            new_classifiers = set(info.get("classifiers", []))

            dropped_python = self._detect_dropped_python_versions(old_classifiers, new_classifiers)
            for version in dropped_python:
                breaking_changes.append(BreakingChange(
                    change_type=BreakingChangeType.CHANGED_BEHAVIOR,
                    description=f"Dropped support for Python {version}",
                    source="pypi_classifiers",
                ))

            # Check development status classifiers for deprecation signals
            for classifier in new_classifiers:
                if "Development Status :: 7 - Inactive" in classifier:
                    breaking_changes.append(BreakingChange(
                        change_type=BreakingChangeType.DEPRECATED,
                        description="Package marked as inactive/deprecated",
                        source="pypi_classifiers",
                    ))

        except Exception as e:
            logger.debug(f"Failed to analyze PyPI package {package_name}: {e}")

        return breaking_changes

    def _get_python_requires(self, release_files: list) -> str | None:
        """Extract requires_python from release files."""
        for file_info in release_files:
            if "requires_python" in file_info:
                return file_info["requires_python"]
        return None

    def _get_classifiers_from_release(self, release_files: list) -> set[str]:
        """Extract classifiers from release metadata if available."""
        # PyPI API doesn't always include classifiers in release data
        # This is a best-effort extraction
        return set()

    def _extract_min_python(self, requires: str) -> str | None:
        """Extract minimum Python version from requires_python."""
        # Handle >=3.8, >=3.8.0, etc.
        match = re.search(r">=?\s*(\d+\.\d+)", requires)
        if match:
            return match.group(1)
        return None

    def _detect_dropped_python_versions(
        self,
        old_classifiers: set[str],
        new_classifiers: set[str],
    ) -> list[str]:
        """Detect dropped Python version support from classifiers."""
        dropped = []

        old_versions = set()
        new_versions = set()

        pattern = r"Programming Language :: Python :: (\d+\.\d+)"

        for classifier in old_classifiers:
            match = re.search(pattern, classifier)
            if match:
                old_versions.add(match.group(1))

        for classifier in new_classifiers:
            match = re.search(pattern, classifier)
            if match:
                new_versions.add(match.group(1))

        dropped = list(old_versions - new_versions)
        return sorted(dropped)

    def _normalize_github_url(self, url: str) -> str | None:
        """Normalize various GitHub URL formats to API-compatible format.

        Args:
            url: Repository URL in any format.

        Returns:
            Normalized GitHub URL or None if not a GitHub URL.
        """
        if not url:
            return None

        # Remove git+ prefix and .git suffix
        url = url.replace("git+", "").replace(".git", "")

        # Handle various formats
        patterns = [
            r"github\.com[:/]([^/]+)/([^/\s#]+)",  # github.com/owner/repo
            r"git@github\.com:([^/]+)/([^/\s#]+)",  # git@github.com:owner/repo
        ]

        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                owner = match.group(1)
                repo = match.group(2).rstrip("/")
                return f"https://github.com/{owner}/{repo}"

        return None

    async def _check_repository_status(
        self,
        repository_url: str,
    ) -> list[BreakingChange]:
        """Check repository status for maintenance signals.

        Args:
            repository_url: GitHub repository URL.

        Returns:
            List of breaking changes related to repository status.
        """
        if not self._http_client or not repository_url:
            return []

        changes: list[BreakingChange] = []

        # Only handle GitHub for now
        if "github.com" not in repository_url:
            return []

        try:
            # Extract owner/repo from URL
            match = re.search(r"github\.com/([^/]+)/([^/\s#]+)", repository_url)
            if not match:
                return []

            owner = match.group(1)
            repo = match.group(2).rstrip("/")

            # Check repository via GitHub API (unauthenticated has rate limits)
            api_url = f"https://api.github.com/repos/{owner}/{repo}"
            response = await self._http_client.get(
                api_url,
                headers={"Accept": "application/vnd.github.v3+json"},
            )

            if response.status_code == 404:
                changes.append(BreakingChange(
                    change_type=BreakingChangeType.DEPRECATED,
                    description="Repository no longer exists or is private",
                    source="github_repository_status",
                ))
                return changes

            if response.status_code != 200:
                # Rate limited or other error, skip
                return []

            data = response.json()

            # Check if archived
            if data.get("archived", False):
                changes.append(BreakingChange(
                    change_type=BreakingChangeType.DEPRECATED,
                    description=f"Repository is archived: {repository_url}",
                    source="github_repository_status",
                    migration_guide="Consider finding an actively maintained fork or alternative",
                ))

            # Check last push date for maintenance status
            pushed_at = data.get("pushed_at")
            if pushed_at:
                try:
                    last_push = datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
                    now = datetime.now(last_push.tzinfo)
                    days_since_push = (now - last_push).days

                    if days_since_push > 730:  # 2 years
                        changes.append(BreakingChange(
                            change_type=BreakingChangeType.CHANGED_BEHAVIOR,
                            description=f"Repository appears unmaintained (no commits in {days_since_push // 365}+ years)",
                            source="github_repository_status",
                        ))
                    elif days_since_push > 365:  # 1 year
                        changes.append(BreakingChange(
                            change_type=BreakingChangeType.CHANGED_BEHAVIOR,
                            description=f"Repository may be stale (no commits in {days_since_push} days)",
                            source="github_repository_status",
                        ))
                except (ValueError, TypeError):
                    pass

            # Check for low open issues count with high closed (might indicate abandoned)
            open_issues = data.get("open_issues_count", 0)
            if data.get("has_issues", True) and open_issues > 100:
                changes.append(BreakingChange(
                    change_type=BreakingChangeType.CHANGED_BEHAVIOR,
                    description=f"Repository has {open_issues} open issues, which may indicate maintenance backlog",
                    source="github_repository_status",
                ))

        except Exception as e:
            logger.debug(f"Failed to check repository status for {repository_url}: {e}")

        return changes


async def analyze_package_metadata(
    ecosystem: Ecosystem,
    package_name: str,
    from_version: str,
    to_version: str,
) -> list[BreakingChange]:
    """Convenience function to analyze package metadata.

    Args:
        ecosystem: Package ecosystem.
        package_name: Package name.
        from_version: Old version.
        to_version: New version.

    Returns:
        List of breaking changes detected from metadata.
    """
    async with PackageMetadataAnalyzer() as analyzer:
        return await analyzer.analyze_upgrade(
            ecosystem, package_name, from_version, to_version
        )
