"""Go ecosystem scanner for go.mod and go.sum."""

import re
from pathlib import Path
from typing import ClassVar

from blastauri.core.models import Dependency, Ecosystem
from blastauri.scanners.base import BaseScanner
from blastauri.utils.logging import get_logger

logger = get_logger(__name__)


class GoScanner(BaseScanner):
    """Scanner for Go ecosystem lockfiles."""

    lockfile_patterns: ClassVar[list[str]] = [
        "go.mod",
        "go.sum",
    ]

    @property
    def ecosystem(self) -> Ecosystem:
        """Return the Go ecosystem."""
        return Ecosystem.GO

    def parse_lockfile(self, path: Path) -> list[Dependency]:
        """Parse a Go ecosystem lockfile.

        Args:
            path: Path to the lockfile.

        Returns:
            List of dependencies found.

        Raises:
            ValueError: If the file format is invalid.
        """
        filename = path.name

        if filename == "go.mod":
            return self._parse_go_mod(path)
        elif filename == "go.sum":
            return self._parse_go_sum(path)
        else:
            raise ValueError(f"Unknown Go lockfile format: {filename}")

    def _parse_go_mod(self, path: Path) -> list[Dependency]:
        """Parse go.mod file.

        Supports:
        - require directives (single and block)
        - replace directives
        - indirect markers
        - exclude directives (skipped)

        Args:
            path: Path to go.mod.

        Returns:
            List of dependencies.
        """
        content = path.read_text(encoding="utf-8")
        dependencies: list[Dependency] = []
        location = str(path)

        replacements: dict[str, tuple[str, str]] = {}
        replace_pattern = re.compile(
            r"replace\s+(\S+)(?:\s+\S+)?\s+=>\s+(\S+)\s+(\S+)"
        )
        for match in replace_pattern.finditer(content):
            old_module = match.group(1)
            new_module = match.group(2)
            new_version = match.group(3)
            replacements[old_module] = (new_module, new_version)

        in_require_block = False
        lines = content.split("\n")

        for line in lines:
            line = line.strip()

            if not line or line.startswith("//"):
                continue

            if line.startswith("require ("):
                in_require_block = True
                continue

            if in_require_block and line == ")":
                in_require_block = False
                continue

            if in_require_block:
                dep = self._parse_require_line(line, location, replacements)
                if dep:
                    dependencies.append(dep)
                continue

            if line.startswith("require ") and "(" not in line:
                line = line[8:].strip()
                dep = self._parse_require_line(line, location, replacements)
                if dep:
                    dependencies.append(dep)

        return dependencies

    def _parse_require_line(
        self,
        line: str,
        location: str,
        replacements: dict[str, tuple[str, str]],
    ) -> Dependency | None:
        """Parse a single require line from go.mod.

        Args:
            line: Require line.
            location: Lockfile location.
            replacements: Dictionary of module replacements.

        Returns:
            Dependency or None.
        """
        is_indirect = "// indirect" in line
        line = line.split("//")[0].strip()

        parts = line.split()
        if len(parts) < 2:
            return None

        module = parts[0]
        version = parts[1]

        if module in replacements:
            module, version = replacements[module]

        version = self._normalize_go_version(version)

        return Dependency(
            name=module,
            version=version,
            ecosystem=Ecosystem.GO,
            location=location,
            is_dev=False,
            is_direct=not is_indirect,
            parent=None,
        )

    def _parse_go_sum(self, path: Path) -> list[Dependency]:
        """Parse go.sum file.

        The go.sum file contains checksums for module versions.
        Each module may have two entries: one for the module and one for go.mod.

        Args:
            path: Path to go.sum.

        Returns:
            List of dependencies (deduplicated).
        """
        content = path.read_text(encoding="utf-8")
        dependencies: list[Dependency] = []
        location = str(path)
        seen: set[tuple[str, str]] = set()

        for line in content.split("\n"):
            line = line.strip()

            if not line:
                continue

            parts = line.split()
            if len(parts) < 3:
                continue

            module = parts[0]
            version = parts[1]

            version = version.split("/")[0]
            version = self._normalize_go_version(version)

            if (module, version) in seen:
                continue
            seen.add((module, version))

            dependencies.append(
                Dependency(
                    name=module,
                    version=version,
                    ecosystem=Ecosystem.GO,
                    location=location,
                    is_dev=False,
                    is_direct=False,
                    parent=None,
                )
            )

        return dependencies

    def _normalize_go_version(self, version: str) -> str:
        """Normalize a Go module version string.

        Args:
            version: Version string (e.g., "v1.2.3", "v0.0.0-20200101120000-abcdef123456").

        Returns:
            Normalized version string.
        """
        if version.startswith("v"):
            version = version[1:]

        if "+incompatible" in version:
            version = version.replace("+incompatible", "")

        return version
