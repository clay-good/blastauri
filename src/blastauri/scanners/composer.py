"""PHP/Composer ecosystem scanner for composer.lock."""

import json
from pathlib import Path
from typing import Any, ClassVar

from blastauri.core.models import Dependency, Ecosystem
from blastauri.scanners.base import BaseScanner
from blastauri.utils.logging import get_logger

logger = get_logger(__name__)


class ComposerScanner(BaseScanner):
    """Scanner for PHP/Composer ecosystem lockfiles."""

    lockfile_patterns: ClassVar[list[str]] = [
        "composer.lock",
    ]

    @property
    def ecosystem(self) -> Ecosystem:
        """Return the Composer ecosystem."""
        return Ecosystem.COMPOSER

    def parse_lockfile(self, path: Path) -> list[Dependency]:
        """Parse a Composer ecosystem lockfile.

        Args:
            path: Path to the lockfile.

        Returns:
            List of dependencies found.

        Raises:
            ValueError: If the file format is invalid.
        """
        filename = path.name

        if filename == "composer.lock":
            return self._parse_composer_lock(path)
        else:
            raise ValueError(f"Unknown Composer lockfile format: {filename}")

    def _parse_composer_lock(self, path: Path) -> list[Dependency]:
        """Parse composer.lock file.

        The composer.lock file contains:
        - packages: Production dependencies
        - packages-dev: Development dependencies

        Each package has:
        - name: Package name (vendor/package format)
        - version: Version string (may have 'v' prefix)
        - require: Dependencies
        - require-dev: Dev dependencies

        Args:
            path: Path to composer.lock.

        Returns:
            List of dependencies.
        """
        with open(path, encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError as e:
                logger.warning("Failed to parse composer.lock: %s", e)
                return []

        dependencies: list[Dependency] = []
        location = str(path)

        packages = data.get("packages", [])
        for pkg in packages:
            dep = self._parse_package(pkg, location, is_dev=False)
            if dep:
                dependencies.append(dep)

        packages_dev = data.get("packages-dev", [])
        for pkg in packages_dev:
            dep = self._parse_package(pkg, location, is_dev=True)
            if dep:
                dependencies.append(dep)

        return dependencies

    def _parse_package(
        self,
        pkg: dict[str, Any],
        location: str,
        is_dev: bool,
    ) -> Dependency | None:
        """Parse a single package from composer.lock.

        Args:
            pkg: Package dictionary.
            location: Lockfile location.
            is_dev: Whether this is a dev dependency.

        Returns:
            Dependency or None.
        """
        name = pkg.get("name")
        version = pkg.get("version")

        if not name or not version:
            return None

        version = self._normalize_version(version)

        return Dependency(
            name=name,
            version=version,
            ecosystem=Ecosystem.COMPOSER,
            location=location,
            is_dev=is_dev,
            is_direct=True,
            parent=None,
        )

    def _normalize_version(self, version: str) -> str:
        """Normalize a Composer version string.

        Args:
            version: Version string (e.g., "v1.2.3", "1.2.3", "dev-main").

        Returns:
            Normalized version string.
        """
        if version.startswith("v") and len(version) > 1 and version[1].isdigit():
            version = version[1:]

        return version
