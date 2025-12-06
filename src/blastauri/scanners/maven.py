"""Maven ecosystem scanner for pom.xml."""

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import ClassVar

from blastauri.core.models import Dependency, Ecosystem
from blastauri.scanners.base import BaseScanner
from blastauri.utils.logging import get_logger

logger = get_logger(__name__)

MAVEN_NS = "{http://maven.apache.org/POM/4.0.0}"


class MavenScanner(BaseScanner):
    """Scanner for Maven ecosystem lockfiles."""

    lockfile_patterns: ClassVar[list[str]] = [
        "pom.xml",
    ]

    @property
    def ecosystem(self) -> Ecosystem:
        """Return the Maven ecosystem."""
        return Ecosystem.MAVEN

    def parse_lockfile(self, path: Path) -> list[Dependency]:
        """Parse a Maven ecosystem lockfile.

        Args:
            path: Path to the lockfile.

        Returns:
            List of dependencies found.

        Raises:
            ValueError: If the file format is invalid.
        """
        filename = path.name

        if filename == "pom.xml":
            return self._parse_pom_xml(path)
        else:
            raise ValueError(f"Unknown Maven lockfile format: {filename}")

    def _parse_pom_xml(self, path: Path) -> list[Dependency]:
        """Parse pom.xml file.

        Extracts dependencies from:
        - <dependencies> section
        - <dependencyManagement> section
        - Resolves properties like ${project.version}

        Args:
            path: Path to pom.xml.

        Returns:
            List of dependencies.
        """
        content = path.read_text(encoding="utf-8")

        content_no_ns = re.sub(r'\sxmlns="[^"]+"', "", content, count=1)

        try:
            root = ET.fromstring(content_no_ns)
        except ET.ParseError as e:
            logger.warning("Failed to parse pom.xml: %s", e)
            return []

        dependencies: list[Dependency] = []
        location = str(path)

        properties = self._extract_properties(root)

        project_version = self._get_text(root, "version") or "unknown"
        properties["project.version"] = project_version

        for deps_element in root.findall(".//dependencies"):
            for dep_element in deps_element.findall("dependency"):
                dep = self._parse_dependency_element(
                    dep_element, location, properties
                )
                if dep:
                    dependencies.append(dep)

        return dependencies

    def _extract_properties(self, root: ET.Element) -> dict[str, str]:
        """Extract properties from pom.xml.

        Args:
            root: Root XML element.

        Returns:
            Dictionary of property names to values.
        """
        properties: dict[str, str] = {}

        props_element = root.find("properties")
        if props_element is not None:
            for prop in props_element:
                tag = prop.tag
                if tag.startswith("{"):
                    tag = tag.split("}")[-1]
                if prop.text:
                    properties[tag] = prop.text.strip()

        return properties

    def _parse_dependency_element(
        self,
        element: ET.Element,
        location: str,
        properties: dict[str, str],
    ) -> Dependency | None:
        """Parse a single dependency element.

        Args:
            element: XML dependency element.
            location: Lockfile location.
            properties: Property values for substitution.

        Returns:
            Dependency or None.
        """
        group_id = self._get_text(element, "groupId")
        artifact_id = self._get_text(element, "artifactId")
        version = self._get_text(element, "version")
        scope = self._get_text(element, "scope")

        if not group_id or not artifact_id:
            return None

        group_id = self._resolve_properties(group_id, properties)
        artifact_id = self._resolve_properties(artifact_id, properties)

        if version:
            version = self._resolve_properties(version, properties)
        else:
            version = "managed"

        name = f"{group_id}:{artifact_id}"

        is_dev = scope in ("test", "provided")

        return Dependency(
            name=name,
            version=version,
            ecosystem=Ecosystem.MAVEN,
            location=location,
            is_dev=is_dev,
            is_direct=True,
            parent=None,
        )

    def _get_text(self, element: ET.Element, tag: str) -> str | None:
        """Get text content of a child element.

        Args:
            element: Parent element.
            tag: Child tag name.

        Returns:
            Text content or None.
        """
        child = element.find(tag)
        if child is not None and child.text:
            return child.text.strip()

        child = element.find(f"{MAVEN_NS}{tag}")
        if child is not None and child.text:
            return child.text.strip()

        return None

    def _resolve_properties(self, value: str, properties: dict[str, str]) -> str:
        """Resolve property placeholders in a value.

        Args:
            value: Value with potential ${property} placeholders.
            properties: Property values.

        Returns:
            Resolved value.
        """

        def replace_prop(match: re.Match[str]) -> str:
            prop_name = match.group(1)
            return properties.get(prop_name, match.group(0))

        return re.sub(r"\$\{([^}]+)\}", replace_prop, value)
