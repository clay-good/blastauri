"""Rust/Cargo ecosystem scanner for Cargo.lock."""

from pathlib import Path
from typing import Any, ClassVar

import toml

from blastauri.core.models import Dependency, Ecosystem
from blastauri.scanners.base import BaseScanner
from blastauri.utils.logging import get_logger

logger = get_logger(__name__)


class CargoScanner(BaseScanner):
    """Scanner for Rust/Cargo ecosystem lockfiles."""

    lockfile_patterns: ClassVar[list[str]] = [
        "Cargo.lock",
    ]

    @property
    def ecosystem(self) -> Ecosystem:
        """Return the Cargo ecosystem."""
        return Ecosystem.CARGO

    def parse_lockfile(self, path: Path) -> list[Dependency]:
        """Parse a Cargo ecosystem lockfile.

        Args:
            path: Path to the lockfile.

        Returns:
            List of dependencies found.

        Raises:
            ValueError: If the file format is invalid.
        """
        filename = path.name

        if filename == "Cargo.lock":
            return self._parse_cargo_lock(path)
        else:
            raise ValueError(f"Unknown Cargo lockfile format: {filename}")

    def _parse_cargo_lock(self, path: Path) -> list[Dependency]:
        """Parse Cargo.lock file (TOML format).

        The Cargo.lock file contains a [[package]] array with all dependencies.
        Each package has:
        - name: Package name
        - version: Exact version
        - source: Optional source (registry, git, path)
        - dependencies: Optional list of dependencies

        Args:
            path: Path to Cargo.lock.

        Returns:
            List of dependencies.
        """
        content = path.read_text(encoding="utf-8")

        try:
            data = toml.loads(content)
        except toml.TomlDecodeError as e:
            logger.warning("Failed to parse Cargo.lock: %s", e)
            return []

        dependencies: list[Dependency] = []
        location = str(path)

        root_package: str | None = None
        if "package" in data and isinstance(data["package"], list):
            for pkg in data["package"]:
                if isinstance(pkg, dict) and pkg.get("source") is None:
                    root_package = pkg.get("name")
                    break

        packages = data.get("package", [])
        if not isinstance(packages, list):
            return dependencies

        for pkg in packages:
            if not isinstance(pkg, dict):
                continue

            dep = self._parse_package(pkg, location, root_package)
            if dep:
                dependencies.append(dep)

        return dependencies

    def _parse_package(
        self,
        pkg: dict[str, Any],
        location: str,
        root_package: str | None,
    ) -> Dependency | None:
        """Parse a single package from Cargo.lock.

        Args:
            pkg: Package dictionary.
            location: Lockfile location.
            root_package: Name of the root package (if any).

        Returns:
            Dependency or None.
        """
        name = pkg.get("name")
        version = pkg.get("version")

        if not name or not version:
            return None

        if name == root_package:
            return None

        is_direct = False

        is_dev = False

        return Dependency(
            name=name,
            version=version,
            ecosystem=Ecosystem.CARGO,
            location=location,
            is_dev=is_dev,
            is_direct=is_direct,
            parent=None,
        )
