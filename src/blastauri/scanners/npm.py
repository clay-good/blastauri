"""NPM ecosystem scanner for package-lock.json, yarn.lock, and pnpm-lock.yaml."""

import json
import re
from pathlib import Path
from typing import Any, ClassVar

import yaml

from blastauri.core.models import Dependency, Ecosystem
from blastauri.scanners.base import BaseScanner
from blastauri.utils.logging import get_logger

logger = get_logger(__name__)


class NpmScanner(BaseScanner):
    """Scanner for NPM ecosystem lockfiles."""

    lockfile_patterns: ClassVar[list[str]] = [
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
    ]

    @property
    def ecosystem(self) -> Ecosystem:
        """Return the NPM ecosystem."""
        return Ecosystem.NPM

    def parse_lockfile(self, path: Path) -> list[Dependency]:
        """Parse an NPM ecosystem lockfile.

        Args:
            path: Path to the lockfile.

        Returns:
            List of dependencies found.

        Raises:
            ValueError: If the file format is invalid.
        """
        filename = path.name

        if filename == "package-lock.json":
            return self._parse_package_lock(path)
        elif filename == "yarn.lock":
            return self._parse_yarn_lock(path)
        elif filename == "pnpm-lock.yaml":
            return self._parse_pnpm_lock(path)
        else:
            raise ValueError(f"Unknown NPM lockfile format: {filename}")

    def _parse_package_lock(self, path: Path) -> list[Dependency]:
        """Parse package-lock.json (v2 and v3 formats).

        Args:
            path: Path to package-lock.json.

        Returns:
            List of dependencies.
        """
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        lockfile_version = data.get("lockfileVersion", 1)
        dependencies: list[Dependency] = []
        location = str(path)

        if lockfile_version >= 2:
            dependencies = self._parse_package_lock_v2(data, location)
        else:
            dependencies = self._parse_package_lock_v1(data, location)

        return dependencies

    def _parse_package_lock_v2(
        self, data: dict[str, Any], location: str
    ) -> list[Dependency]:
        """Parse package-lock.json v2/v3 format using packages field.

        Args:
            data: Parsed JSON data.
            location: Lockfile location.

        Returns:
            List of dependencies.
        """
        dependencies: list[Dependency] = []
        packages = data.get("packages", {})

        root_deps = set()
        root_dev_deps = set()

        root_pkg = packages.get("", {})
        root_deps.update(root_pkg.get("dependencies", {}).keys())
        root_dev_deps.update(root_pkg.get("devDependencies", {}).keys())

        for pkg_path, pkg_info in packages.items():
            if not pkg_path:
                continue

            name = self._extract_package_name_from_path(pkg_path)
            if not name:
                continue

            version = pkg_info.get("version", "")
            if not version:
                continue

            is_dev = pkg_info.get("dev", False)
            is_direct = name in root_deps or name in root_dev_deps

            dependencies.append(
                Dependency(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.NPM,
                    location=location,
                    is_dev=is_dev,
                    is_direct=is_direct,
                    parent=None,
                )
            )

        return dependencies

    def _parse_package_lock_v1(
        self, data: dict[str, Any], location: str
    ) -> list[Dependency]:
        """Parse package-lock.json v1 format using dependencies field.

        Args:
            data: Parsed JSON data.
            location: Lockfile location.

        Returns:
            List of dependencies.
        """
        dependencies: list[Dependency] = []

        def parse_deps(
            deps_dict: dict[str, Any],
            parent: str | None = None,
            is_direct: bool = True,
        ) -> None:
            for name, info in deps_dict.items():
                version = info.get("version", "")
                if not version:
                    continue

                is_dev = info.get("dev", False)

                dependencies.append(
                    Dependency(
                        name=name,
                        version=version,
                        ecosystem=Ecosystem.NPM,
                        location=location,
                        is_dev=is_dev,
                        is_direct=is_direct,
                        parent=parent,
                    )
                )

                nested = info.get("dependencies", {})
                if nested:
                    parse_deps(nested, parent=name, is_direct=False)

        root_deps = data.get("dependencies", {})
        parse_deps(root_deps, is_direct=True)

        return dependencies

    def _extract_package_name_from_path(self, pkg_path: str) -> str | None:
        """Extract package name from node_modules path.

        Args:
            pkg_path: Path like "node_modules/lodash" or "node_modules/@scope/pkg".

        Returns:
            Package name or None.
        """
        parts = pkg_path.split("node_modules/")
        if len(parts) < 2:
            return None

        name = parts[-1]
        if "/" in name and not name.startswith("@"):
            name = name.split("/")[0]

        return name if name else None

    def _parse_yarn_lock(self, path: Path) -> list[Dependency]:
        """Parse yarn.lock file (classic and berry formats).

        Args:
            path: Path to yarn.lock.

        Returns:
            List of dependencies.
        """
        content = path.read_text(encoding="utf-8")
        dependencies: list[Dependency] = []
        location = str(path)

        if content.strip().startswith("# THIS IS AN AUTOGENERATED FILE"):
            dependencies = self._parse_yarn_lock_classic(content, location)
        else:
            dependencies = self._parse_yarn_lock_berry(content, location)

        return dependencies

    def _parse_yarn_lock_classic(
        self, content: str, location: str
    ) -> list[Dependency]:
        """Parse yarn.lock classic format.

        Args:
            content: File content.
            location: Lockfile location.

        Returns:
            List of dependencies.
        """
        dependencies: list[Dependency] = []
        seen: set[tuple[str, str]] = set()

        current_packages: list[str] = []
        current_version: str | None = None

        for line in content.split("\n"):
            line = line.rstrip()

            if not line or line.startswith("#"):
                continue

            if not line.startswith(" ") and not line.startswith("\t"):
                if current_packages and current_version:
                    for pkg_spec in current_packages:
                        name = self._extract_yarn_package_name(pkg_spec)
                        if name and (name, current_version) not in seen:
                            seen.add((name, current_version))
                            dependencies.append(
                                Dependency(
                                    name=name,
                                    version=current_version,
                                    ecosystem=Ecosystem.NPM,
                                    location=location,
                                    is_dev=False,
                                    is_direct=False,
                                    parent=None,
                                )
                            )

                current_packages = []
                current_version = None

                specs = line.rstrip(":").split(", ")
                current_packages = [s.strip().strip('"') for s in specs]

            elif line.strip().startswith("version"):
                match = re.match(r'\s*version\s+"?([^"]+)"?', line)
                if match:
                    current_version = match.group(1)

        if current_packages and current_version:
            for pkg_spec in current_packages:
                name = self._extract_yarn_package_name(pkg_spec)
                if name and (name, current_version) not in seen:
                    seen.add((name, current_version))
                    dependencies.append(
                        Dependency(
                            name=name,
                            version=current_version,
                            ecosystem=Ecosystem.NPM,
                            location=location,
                            is_dev=False,
                            is_direct=False,
                            parent=None,
                        )
                    )

        return dependencies

    def _parse_yarn_lock_berry(self, content: str, location: str) -> list[Dependency]:
        """Parse yarn.lock berry (v2+) format using YAML.

        Args:
            content: File content.
            location: Lockfile location.

        Returns:
            List of dependencies.
        """
        dependencies: list[Dependency] = []
        seen: set[tuple[str, str]] = set()

        try:
            data = yaml.safe_load(content)
            if not isinstance(data, dict):
                return dependencies

            for key, value in data.items():
                if key == "__metadata":
                    continue

                if not isinstance(value, dict):
                    continue

                version = value.get("version", "")
                if not version:
                    continue

                name = self._extract_yarn_package_name(key)
                if name and (name, version) not in seen:
                    seen.add((name, version))
                    dependencies.append(
                        Dependency(
                            name=name,
                            version=version,
                            ecosystem=Ecosystem.NPM,
                            location=location,
                            is_dev=False,
                            is_direct=False,
                            parent=None,
                        )
                    )
        except yaml.YAMLError as e:
            logger.warning("Failed to parse yarn.lock as YAML: %s", e)

        return dependencies

    def _extract_yarn_package_name(self, spec: str) -> str | None:
        """Extract package name from yarn package specifier.

        Args:
            spec: Package specifier like "lodash@^4.17.21" or "@scope/pkg@^1.0.0".

        Returns:
            Package name or None.
        """
        spec = spec.strip().strip('"')

        if spec.startswith("@"):
            match = re.match(r"(@[^@/]+/[^@]+)@", spec)
            if match:
                return match.group(1)
            if "/" in spec and "@" not in spec[1:]:
                return spec
        else:
            match = re.match(r"([^@]+)@", spec)
            if match:
                return match.group(1)

        return None

    def _parse_pnpm_lock(self, path: Path) -> list[Dependency]:
        """Parse pnpm-lock.yaml file.

        Args:
            path: Path to pnpm-lock.yaml.

        Returns:
            List of dependencies.
        """
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)

        dependencies: list[Dependency] = []
        location = str(path)
        seen: set[tuple[str, str]] = set()

        if not isinstance(data, dict):
            return dependencies

        packages = data.get("packages", {})
        if not packages:
            packages = data.get("snapshots", {})

        for pkg_path, pkg_info in packages.items():
            name, version = self._parse_pnpm_package_path(pkg_path)
            if not name or not version:
                continue

            if (name, version) in seen:
                continue
            seen.add((name, version))

            is_dev = False
            if isinstance(pkg_info, dict):
                is_dev = pkg_info.get("dev", False)

            dependencies.append(
                Dependency(
                    name=name,
                    version=version,
                    ecosystem=Ecosystem.NPM,
                    location=location,
                    is_dev=is_dev,
                    is_direct=False,
                    parent=None,
                )
            )

        return dependencies

    def _parse_pnpm_package_path(self, pkg_path: str) -> tuple[str | None, str | None]:
        """Parse pnpm package path to extract name and version.

        Args:
            pkg_path: Path like "/lodash@4.17.21" or "/@scope/pkg@1.0.0".

        Returns:
            Tuple of (name, version) or (None, None).
        """
        pkg_path = pkg_path.lstrip("/")

        if pkg_path.startswith("@"):
            match = re.match(r"(@[^@/]+/[^@]+)@(.+)", pkg_path)
            if match:
                return match.group(1), match.group(2).split("(")[0]
        else:
            match = re.match(r"([^@]+)@(.+)", pkg_path)
            if match:
                return match.group(1), match.group(2).split("(")[0]

        return None, None
