"""Ruby ecosystem scanner for Gemfile.lock."""

import re
from pathlib import Path
from typing import ClassVar

from blastauri.core.models import Dependency, Ecosystem
from blastauri.scanners.base import BaseScanner
from blastauri.utils.logging import get_logger

logger = get_logger(__name__)


class RubyScanner(BaseScanner):
    """Scanner for Ruby ecosystem lockfiles."""

    lockfile_patterns: ClassVar[list[str]] = [
        "Gemfile.lock",
    ]

    @property
    def ecosystem(self) -> Ecosystem:
        """Return the RubyGems ecosystem."""
        return Ecosystem.RUBYGEMS

    def parse_lockfile(self, path: Path) -> list[Dependency]:
        """Parse a Ruby ecosystem lockfile.

        Args:
            path: Path to the lockfile.

        Returns:
            List of dependencies found.

        Raises:
            ValueError: If the file format is invalid.
        """
        filename = path.name

        if filename == "Gemfile.lock":
            return self._parse_gemfile_lock(path)
        else:
            raise ValueError(f"Unknown Ruby lockfile format: {filename}")

    def _parse_gemfile_lock(self, path: Path) -> list[Dependency]:
        """Parse Gemfile.lock file.

        The Gemfile.lock format has several sections:
        - GEM: Remote gems with their versions and dependencies
        - GIT: Git-sourced gems
        - PATH: Local path gems
        - PLATFORMS: Target platforms
        - DEPENDENCIES: Direct dependencies
        - BUNDLED WITH: Bundler version

        Args:
            path: Path to Gemfile.lock.

        Returns:
            List of dependencies.
        """
        content = path.read_text(encoding="utf-8")
        dependencies: list[Dependency] = []
        location = str(path)

        direct_deps: set[str] = set()
        all_gems: dict[str, str] = {}

        current_section: str | None = None
        in_specs = False
        current_indent = 0

        lines = content.split("\n")

        for line in lines:
            stripped = line.strip()

            if not stripped:
                continue

            if stripped in ("GEM", "GIT", "PATH", "PLATFORMS", "DEPENDENCIES", "BUNDLED WITH", "RUBY VERSION"):
                current_section = stripped
                in_specs = False
                continue

            if stripped == "specs:":
                in_specs = True
                continue

            if current_section == "DEPENDENCIES":
                dep_match = re.match(r"^([a-zA-Z0-9_-]+)", stripped)
                if dep_match:
                    direct_deps.add(dep_match.group(1).lower())
                continue

            if current_section in ("GEM", "GIT", "PATH") and in_specs:
                indent = len(line) - len(line.lstrip())

                gem_match = re.match(r"^([a-zA-Z0-9_-]+)\s+\(([^)]+)\)", stripped)
                if gem_match:
                    name = gem_match.group(1).lower()
                    version = gem_match.group(2)

                    version = version.split(",")[0].strip()

                    all_gems[name] = version
                    current_indent = indent

        for name, version in all_gems.items():
            is_direct = name in direct_deps

            dependencies.append(
                Dependency(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.RUBYGEMS,
                    location=location,
                    is_dev=False,
                    is_direct=is_direct,
                    parent=None,
                )
            )

        return dependencies
