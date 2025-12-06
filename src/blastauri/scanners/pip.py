"""Python ecosystem scanner for requirements.txt, Pipfile.lock, and poetry.lock."""

import json
import re
from pathlib import Path
from typing import Any, ClassVar

import toml

from blastauri.core.models import Dependency, Ecosystem
from blastauri.scanners.base import BaseScanner
from blastauri.utils.logging import get_logger

logger = get_logger(__name__)


class PipScanner(BaseScanner):
    """Scanner for Python ecosystem lockfiles."""

    lockfile_patterns: ClassVar[list[str]] = [
        "requirements.txt",
        "requirements-dev.txt",
        "requirements-prod.txt",
        "requirements*.txt",
        "Pipfile.lock",
        "poetry.lock",
    ]

    @property
    def ecosystem(self) -> Ecosystem:
        """Return the PyPI ecosystem."""
        return Ecosystem.PYPI

    def parse_lockfile(self, path: Path) -> list[Dependency]:
        """Parse a Python ecosystem lockfile.

        Args:
            path: Path to the lockfile.

        Returns:
            List of dependencies found.

        Raises:
            ValueError: If the file format is invalid.
        """
        filename = path.name

        if filename == "Pipfile.lock":
            return self._parse_pipfile_lock(path)
        elif filename == "poetry.lock":
            return self._parse_poetry_lock(path)
        elif filename.startswith("requirements") and filename.endswith(".txt"):
            return self._parse_requirements_txt(path)
        else:
            raise ValueError(f"Unknown Python lockfile format: {filename}")

    def _parse_requirements_txt(self, path: Path) -> list[Dependency]:
        """Parse requirements.txt file.

        Supports:
        - Simple requirements: package==1.0.0
        - Version specifiers: package>=1.0.0,<2.0.0
        - Comments and blank lines
        - -r includes (file references)
        - -e editable installs
        - Extras: package[extra]==1.0.0
        - Environment markers: package==1.0.0 ; python_version >= "3.8"

        Args:
            path: Path to requirements.txt.

        Returns:
            List of dependencies.
        """
        dependencies: list[Dependency] = []
        location = str(path)
        is_dev = "dev" in path.name.lower()

        content = path.read_text(encoding="utf-8")

        for line in content.split("\n"):
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            if line.startswith("-r"):
                included_file = line[2:].strip()
                included_path = path.parent / included_file
                if included_path.exists():
                    deps = self._parse_requirements_txt(included_path)
                    dependencies.extend(deps)
                continue

            if line.startswith("-e"):
                dep = self._parse_editable_requirement(line, location, is_dev)
                if dep:
                    dependencies.append(dep)
                continue

            if line.startswith("-"):
                continue

            dep = self._parse_requirement_line(line, location, is_dev)
            if dep:
                dependencies.append(dep)

        return dependencies

    def _parse_requirement_line(
        self, line: str, location: str, is_dev: bool
    ) -> Dependency | None:
        """Parse a single requirement line.

        Args:
            line: Requirement line.
            location: Lockfile location.
            is_dev: Whether this is a dev dependency.

        Returns:
            Dependency or None if parsing fails.
        """
        line = line.split(";")[0].strip()

        line = line.split("#")[0].strip()

        if not line:
            return None

        match = re.match(
            r"^([a-zA-Z0-9][-a-zA-Z0-9._]*(?:\[[^\]]+\])?)\s*(==|>=|<=|~=|!=|>|<)?\s*([^\s,;#]*)?",
            line,
        )

        if not match:
            return None

        name = match.group(1)
        name = re.sub(r"\[.*\]", "", name)

        version = match.group(3) or ""
        version = version.strip()

        if not version:
            version = "unknown"

        return Dependency(
            name=name.lower(),
            version=version,
            ecosystem=Ecosystem.PYPI,
            location=location,
            is_dev=is_dev,
            is_direct=True,
            parent=None,
        )

    def _parse_editable_requirement(
        self, line: str, location: str, is_dev: bool
    ) -> Dependency | None:
        """Parse an editable (-e) requirement.

        Args:
            line: Editable requirement line.
            location: Lockfile location.
            is_dev: Whether this is a dev dependency.

        Returns:
            Dependency or None.
        """
        line = line[2:].strip()

        egg_match = re.search(r"#egg=([a-zA-Z0-9_-]+)", line)
        if egg_match:
            name = egg_match.group(1)
            return Dependency(
                name=name.lower(),
                version="editable",
                ecosystem=Ecosystem.PYPI,
                location=location,
                is_dev=is_dev,
                is_direct=True,
                parent=None,
            )

        return None

    def _parse_pipfile_lock(self, path: Path) -> list[Dependency]:
        """Parse Pipfile.lock file.

        Args:
            path: Path to Pipfile.lock.

        Returns:
            List of dependencies.
        """
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        dependencies: list[Dependency] = []
        location = str(path)

        for section, is_dev in [("default", False), ("develop", True)]:
            packages = data.get(section, {})

            for name, info in packages.items():
                if not isinstance(info, dict):
                    continue

                version = info.get("version", "")
                if version.startswith("=="):
                    version = version[2:]

                if not version:
                    version = "unknown"

                dependencies.append(
                    Dependency(
                        name=name.lower(),
                        version=version,
                        ecosystem=Ecosystem.PYPI,
                        location=location,
                        is_dev=is_dev,
                        is_direct=True,
                        parent=None,
                    )
                )

        return dependencies

    def _parse_poetry_lock(self, path: Path) -> list[Dependency]:
        """Parse poetry.lock file (TOML format).

        Args:
            path: Path to poetry.lock.

        Returns:
            List of dependencies.
        """
        content = path.read_text(encoding="utf-8")
        data = toml.loads(content)

        dependencies: list[Dependency] = []
        location = str(path)

        packages = data.get("package", [])

        for pkg in packages:
            if not isinstance(pkg, dict):
                continue

            name = pkg.get("name", "")
            version = pkg.get("version", "")

            if not name or not version:
                continue

            category = pkg.get("category", "main")
            is_dev = category == "dev"

            optional = pkg.get("optional", False)

            dependencies.append(
                Dependency(
                    name=name.lower(),
                    version=version,
                    ecosystem=Ecosystem.PYPI,
                    location=location,
                    is_dev=is_dev or optional,
                    is_direct=False,
                    parent=None,
                )
            )

        return dependencies
