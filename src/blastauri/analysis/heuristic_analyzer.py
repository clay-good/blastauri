"""Heuristic-based breaking change detection.

This module uses heuristics to detect likely breaking changes when
other methods (changelogs, API diff, known database) don't provide data.

Heuristics used:
1. Version number patterns (0.x -> 1.x is always breaking, major bumps)
2. Package size changes (significant size reduction = removed code)
3. Dependency changes (dropped dependencies may indicate removed features)
4. File structure changes (removed main files)
5. Export count changes (fewer exports = removed APIs)
"""

import re
import tarfile
import zipfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Optional

import httpx

from blastauri.core.models import BreakingChange, BreakingChangeType, Ecosystem
from blastauri.utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class PackageStats:
    """Statistics about a package version."""

    version: str
    total_size: int  # bytes
    file_count: int
    js_file_count: int
    py_file_count: int
    export_count: int  # estimated from index files
    dependency_count: int
    main_files: set[str]  # index.js, __init__.py, etc.
    has_types: bool


@dataclass
class HeuristicResult:
    """Result of heuristic analysis."""

    breaking_changes: list[BreakingChange]
    confidence: float  # 0.0 to 1.0


class HeuristicAnalyzer:
    """Heuristic-based breaking change detector."""

    # Thresholds for heuristics
    SIZE_REDUCTION_THRESHOLD = 0.3  # 30% size reduction
    FILE_REDUCTION_THRESHOLD = 0.2  # 20% fewer files
    EXPORT_REDUCTION_THRESHOLD = 0.15  # 15% fewer exports

    def __init__(self, http_client: Optional[httpx.AsyncClient] = None):
        """Initialize the analyzer."""
        self._http_client = http_client
        self._owns_client = False

    async def __aenter__(self) -> "HeuristicAnalyzer":
        """Async context manager entry."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=60.0)
            self._owns_client = True
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        if self._owns_client and self._http_client:
            await self._http_client.aclose()

    async def analyze(
        self,
        ecosystem: Ecosystem,
        package_name: str,
        from_version: str,
        to_version: str,
    ) -> HeuristicResult:
        """Analyze upgrade using heuristics.

        Args:
            ecosystem: Package ecosystem.
            package_name: Package name.
            from_version: Old version.
            to_version: New version.

        Returns:
            Heuristic analysis result.
        """
        breaking_changes: list[BreakingChange] = []

        # Version pattern heuristics (always apply, no network needed)
        version_changes = self._analyze_version_patterns(from_version, to_version)
        breaking_changes.extend(version_changes)

        # Package stats comparison (requires downloading packages)
        if ecosystem == Ecosystem.NPM:
            stats_changes = await self._analyze_npm_stats(
                package_name, from_version, to_version
            )
            breaking_changes.extend(stats_changes)
        elif ecosystem == Ecosystem.PYPI:
            stats_changes = await self._analyze_pypi_stats(
                package_name, from_version, to_version
            )
            breaking_changes.extend(stats_changes)

        # Calculate confidence based on how many heuristics triggered
        confidence = self._calculate_confidence(breaking_changes)

        return HeuristicResult(
            breaking_changes=breaking_changes,
            confidence=confidence,
        )

    def _analyze_version_patterns(
        self,
        from_version: str,
        to_version: str,
    ) -> list[BreakingChange]:
        """Analyze version patterns for breaking change indicators."""
        changes: list[BreakingChange] = []

        from_parts = self._parse_version(from_version)
        to_parts = self._parse_version(to_version)

        if not from_parts or not to_parts:
            return changes

        from_major, from_minor, from_patch = from_parts
        to_major, to_minor, to_patch = to_parts

        # 0.x -> 1.x is almost always breaking (leaving beta)
        if from_major == 0 and to_major >= 1:
            changes.append(BreakingChange(
                change_type=BreakingChangeType.MAJOR_VERSION,
                description=f"First stable release: {from_version} -> {to_version}. Expect significant API changes.",
                source="heuristic_version_pattern",
                migration_guide="Review the migration guide for v1.0 release",
            ))

        # Major version jump of more than 1 (e.g., v2 -> v5)
        elif to_major - from_major > 1:
            changes.append(BreakingChange(
                change_type=BreakingChangeType.MAJOR_VERSION,
                description=f"Skipped major versions: {from_version} -> {to_version}. Multiple breaking changes likely.",
                source="heuristic_version_pattern",
            ))

        # Pre-release to release (e.g., 2.0.0-rc.1 -> 2.0.0)
        if "-" in from_version and "-" not in to_version:
            if from_major == to_major and from_minor == to_minor:
                changes.append(BreakingChange(
                    change_type=BreakingChangeType.CHANGED_BEHAVIOR,
                    description=f"Pre-release to stable: {from_version} -> {to_version}. APIs may have changed from beta.",
                    source="heuristic_version_pattern",
                ))

        # Check for rewrite indicators in version
        # Some packages use -next, -new, -rewrite suffixes
        rewrite_patterns = ["-next", "-new", "-rewrite", "-v2", "-modern"]
        for pattern in rewrite_patterns:
            if pattern in to_version.lower() and pattern not in from_version.lower():
                changes.append(BreakingChange(
                    change_type=BreakingChangeType.MAJOR_VERSION,
                    description=f"Package rewrite detected: {to_version} appears to be a new version/rewrite",
                    source="heuristic_version_pattern",
                ))
                break

        return changes

    def _parse_version(self, version: str) -> Optional[tuple[int, int, int]]:
        """Parse version string to (major, minor, patch) tuple."""
        # Remove common prefixes
        version = re.sub(r"^[v=]", "", version.strip())

        # Extract numeric parts
        match = re.match(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", version)
        if match:
            major = int(match.group(1))
            minor = int(match.group(2) or 0)
            patch = int(match.group(3) or 0)
            return (major, minor, patch)
        return None

    async def _analyze_npm_stats(
        self,
        package_name: str,
        from_version: str,
        to_version: str,
    ) -> list[BreakingChange]:
        """Compare npm package statistics between versions."""
        if not self._http_client:
            return []

        changes: list[BreakingChange] = []

        try:
            old_stats = await self._get_npm_stats(package_name, from_version)
            new_stats = await self._get_npm_stats(package_name, to_version)

            if not old_stats or not new_stats:
                return changes

            # Check for significant size reduction
            if old_stats.total_size > 0:
                size_ratio = new_stats.total_size / old_stats.total_size
                if size_ratio < (1 - self.SIZE_REDUCTION_THRESHOLD):
                    reduction_pct = int((1 - size_ratio) * 100)
                    changes.append(BreakingChange(
                        change_type=BreakingChangeType.REMOVED_MODULE,
                        description=f"Package size reduced by {reduction_pct}%. Functionality may have been removed.",
                        source="heuristic_size_analysis",
                    ))

            # Check for file count reduction
            if old_stats.file_count > 0:
                file_ratio = new_stats.file_count / old_stats.file_count
                if file_ratio < (1 - self.FILE_REDUCTION_THRESHOLD):
                    reduction_pct = int((1 - file_ratio) * 100)
                    changes.append(BreakingChange(
                        change_type=BreakingChangeType.REMOVED_MODULE,
                        description=f"Package has {reduction_pct}% fewer files. Modules may have been removed.",
                        source="heuristic_file_analysis",
                    ))

            # Check for removed main files
            removed_mains = old_stats.main_files - new_stats.main_files
            for removed in removed_mains:
                changes.append(BreakingChange(
                    change_type=BreakingChangeType.REMOVED_MODULE,
                    description=f"Main entry file removed: {removed}",
                    old_api=removed,
                    source="heuristic_file_analysis",
                ))

            # Check for dependency removals (might indicate removed features)
            if old_stats.dependency_count > new_stats.dependency_count:
                diff = old_stats.dependency_count - new_stats.dependency_count
                if diff >= 3:  # Only flag if multiple deps removed
                    changes.append(BreakingChange(
                        change_type=BreakingChangeType.CHANGED_BEHAVIOR,
                        description=f"{diff} dependencies removed. Related functionality may be dropped.",
                        source="heuristic_dependency_analysis",
                    ))

            # Check for TypeScript types removal
            if old_stats.has_types and not new_stats.has_types:
                changes.append(BreakingChange(
                    change_type=BreakingChangeType.REMOVED_MODULE,
                    description="TypeScript type definitions removed",
                    source="heuristic_types_analysis",
                ))

            # Check for export count reduction
            if old_stats.export_count > 0:
                export_ratio = new_stats.export_count / old_stats.export_count
                if export_ratio < (1 - self.EXPORT_REDUCTION_THRESHOLD):
                    reduction_pct = int((1 - export_ratio) * 100)
                    removed_count = old_stats.export_count - new_stats.export_count
                    changes.append(BreakingChange(
                        change_type=BreakingChangeType.REMOVED_FUNCTION,
                        description=f"Approximately {removed_count} exports removed ({reduction_pct}% reduction)",
                        source="heuristic_export_analysis",
                    ))

        except Exception as e:
            logger.debug(f"Failed to analyze npm stats for {package_name}: {e}")

        return changes

    async def _get_npm_stats(
        self,
        package_name: str,
        version: str,
    ) -> Optional[PackageStats]:
        """Get statistics for an npm package version."""
        if not self._http_client:
            return None

        try:
            # Get package metadata
            response = await self._http_client.get(
                f"https://registry.npmjs.org/{package_name}/{version}",
            )
            response.raise_for_status()
            data = response.json()

            # Get tarball size without downloading full package
            dist = data.get("dist", {})
            tarball_size = dist.get("unpackedSize", 0)

            # Get dependency count
            deps = data.get("dependencies", {})
            dep_count = len(deps)

            # Check for types
            has_types = bool(data.get("types") or data.get("typings"))

            # Get main entry
            main_entry = data.get("main", "index.js")
            main_files = {main_entry} if main_entry else set()

            # Estimate export count from package structure
            # This is a rough heuristic
            exports_field = data.get("exports", {})
            export_count = self._count_exports(exports_field) if exports_field else 1

            # For more accurate stats, we'd need to download the package
            # For now, use metadata-based estimates
            file_count = data.get("fileCount", 0)
            if not file_count:
                # Estimate from size
                file_count = max(1, tarball_size // 5000)  # Rough estimate

            return PackageStats(
                version=version,
                total_size=tarball_size,
                file_count=file_count,
                js_file_count=0,  # Would need full download
                py_file_count=0,
                export_count=export_count,
                dependency_count=dep_count,
                main_files=main_files,
                has_types=has_types,
            )

        except Exception as e:
            logger.debug(f"Failed to get npm stats for {package_name}@{version}: {e}")
            return None

    def _count_exports(self, exports: dict) -> int:
        """Count the number of exports in package.json exports field."""
        count = 0
        for key, value in exports.items():
            if isinstance(value, str):
                count += 1
            elif isinstance(value, dict):
                count += self._count_exports(value)
        return max(1, count)

    async def _analyze_pypi_stats(
        self,
        package_name: str,
        from_version: str,
        to_version: str,
    ) -> list[BreakingChange]:
        """Compare PyPI package statistics between versions."""
        if not self._http_client:
            return []

        changes: list[BreakingChange] = []

        try:
            response = await self._http_client.get(
                f"https://pypi.org/pypi/{package_name}/json",
            )
            response.raise_for_status()
            data = response.json()

            releases = data.get("releases", {})
            old_files = releases.get(from_version, [])
            new_files = releases.get(to_version, [])

            if not old_files or not new_files:
                return changes

            # Compare wheel/sdist sizes
            old_size = self._get_largest_file_size(old_files)
            new_size = self._get_largest_file_size(new_files)

            if old_size > 0:
                size_ratio = new_size / old_size
                if size_ratio < (1 - self.SIZE_REDUCTION_THRESHOLD):
                    reduction_pct = int((1 - size_ratio) * 100)
                    changes.append(BreakingChange(
                        change_type=BreakingChangeType.REMOVED_MODULE,
                        description=f"Package size reduced by {reduction_pct}%. Modules may have been removed.",
                        source="heuristic_size_analysis",
                    ))

            # Check for dropped wheel types (e.g., py2 support dropped)
            old_python_versions = self._extract_python_versions(old_files)
            new_python_versions = self._extract_python_versions(new_files)

            dropped = old_python_versions - new_python_versions
            for py_version in dropped:
                changes.append(BreakingChange(
                    change_type=BreakingChangeType.CHANGED_BEHAVIOR,
                    description=f"Dropped support for Python {py_version}",
                    source="heuristic_wheel_analysis",
                ))

        except Exception as e:
            logger.debug(f"Failed to analyze PyPI stats for {package_name}: {e}")

        return changes

    def _get_largest_file_size(self, files: list) -> int:
        """Get the size of the largest distribution file."""
        max_size = 0
        for f in files:
            size = f.get("size", 0)
            if size > max_size:
                max_size = size
        return max_size

    def _extract_python_versions(self, files: list) -> set[str]:
        """Extract Python versions from wheel filenames."""
        versions = set()
        for f in files:
            filename = f.get("filename", "")
            # Parse wheel filename: package-version-py3-none-any.whl
            # or package-version-cp39-cp39-manylinux.whl
            if filename.endswith(".whl"):
                parts = filename.rsplit("-", 3)
                if len(parts) >= 2:
                    py_tag = parts[-3] if len(parts) > 3 else parts[-2]
                    # Extract python version from tag
                    match = re.search(r"(?:py|cp)(\d+)", py_tag)
                    if match:
                        major = match.group(1)[0]
                        versions.add(f"{major}.x")
        return versions

    def _calculate_confidence(self, changes: list[BreakingChange]) -> float:
        """Calculate confidence score based on heuristics triggered."""
        if not changes:
            return 0.0

        # Weight different sources differently
        weights = {
            "heuristic_version_pattern": 0.8,  # Version patterns are quite reliable
            "heuristic_size_analysis": 0.6,
            "heuristic_file_analysis": 0.7,
            "heuristic_export_analysis": 0.7,
            "heuristic_dependency_analysis": 0.5,
            "heuristic_types_analysis": 0.8,
            "heuristic_wheel_analysis": 0.9,
        }

        total_weight = 0.0
        for change in changes:
            weight = weights.get(change.source, 0.5)
            total_weight += weight

        # Normalize to 0-1 range, capping at 1.0
        confidence = min(1.0, total_weight / 3.0)
        return confidence


async def analyze_with_heuristics(
    ecosystem: Ecosystem,
    package_name: str,
    from_version: str,
    to_version: str,
) -> list[BreakingChange]:
    """Convenience function for heuristic analysis.

    Args:
        ecosystem: Package ecosystem.
        package_name: Package name.
        from_version: Old version.
        to_version: New version.

    Returns:
        List of breaking changes detected via heuristics.
    """
    async with HeuristicAnalyzer() as analyzer:
        result = await analyzer.analyze(ecosystem, package_name, from_version, to_version)
        return result.breaking_changes
