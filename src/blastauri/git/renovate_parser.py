"""Renovate MR detection and parsing."""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from blastauri.core.models import DependencyUpdate, Ecosystem
from blastauri.git.gitlab_client import MergeRequestChange, MergeRequestInfo


class UpdateType(str, Enum):
    """Type of dependency update."""

    MAJOR = "major"
    MINOR = "minor"
    PATCH = "patch"
    PIN = "pin"
    DIGEST = "digest"
    LOCKFILE = "lockfile"
    UNKNOWN = "unknown"


@dataclass
class RenovateMRInfo:
    """Parsed Renovate MR information."""

    is_renovate: bool
    updates: list[DependencyUpdate] = field(default_factory=list)
    update_type: UpdateType = UpdateType.UNKNOWN
    is_grouped: bool = False
    group_name: Optional[str] = None
    branch_name: str = ""
    schedule: Optional[str] = None


# Renovate bot usernames
RENOVATE_BOT_USERNAMES = {
    "renovate",
    "renovate-bot",
    "renovate[bot]",
    "mend-renovate",
    "whitesource-renovate",
}

# Renovate branch prefixes
RENOVATE_BRANCH_PREFIXES = [
    "renovate/",
    "renovate-",
]

# Title patterns for Renovate MRs
RENOVATE_TITLE_PATTERNS = [
    # Single package updates
    r"^Update (?:dependency )?(.+) to v?(.+)$",
    r"^(?:fix|chore|build)\(deps\): update (.+) to v?(.+)$",
    r"^Update (.+) from v?(.+) to v?(.+)$",
    # Group updates
    r"^Update (.+) packages?$",
    r"^Update (.+) monorepo$",
    r"^Update (.+) to v?(.+) \(major\)$",
    r"^Update (.+) to v?(.+) \(minor\)$",
    # Lock file maintenance
    r"^Lock file maintenance$",
    r"^Update lockfile$",
    # Digest updates
    r"^Update (.+) digest to (.+)$",
    # Pin updates
    r"^Pin (.+) to v?(.+)$",
]

# Ecosystem detection patterns for lockfiles
LOCKFILE_ECOSYSTEM_MAP = {
    "package-lock.json": Ecosystem.NPM,
    "yarn.lock": Ecosystem.NPM,
    "pnpm-lock.yaml": Ecosystem.NPM,
    "requirements.txt": Ecosystem.PYPI,
    "Pipfile.lock": Ecosystem.PYPI,
    "poetry.lock": Ecosystem.PYPI,
    "go.mod": Ecosystem.GO,
    "go.sum": Ecosystem.GO,
    "Gemfile.lock": Ecosystem.RUBYGEMS,
    "Cargo.lock": Ecosystem.CARGO,
    "composer.lock": Ecosystem.COMPOSER,
    "pom.xml": Ecosystem.MAVEN,
}

# Package name to ecosystem mapping based on naming conventions
PACKAGE_ECOSYSTEM_PATTERNS = [
    # NPM - scoped packages or package.json context
    (r"^@[\w-]+/[\w-]+$", Ecosystem.NPM),
    # Maven - group:artifact format
    (r"^[\w.-]+:[\w.-]+$", Ecosystem.MAVEN),
    # Go - URL-like paths
    (r"^(?:github\.com|golang\.org|gopkg\.in)/", Ecosystem.GO),
    # PyPI - common Python package patterns
    (r"^python-", Ecosystem.PYPI),
    (r"^py-", Ecosystem.PYPI),
    # Ruby - common gem patterns
    (r"-rb$", Ecosystem.RUBYGEMS),
    (r"^ruby-", Ecosystem.RUBYGEMS),
    # Cargo - Rust crate patterns
    (r"^(?:tokio|serde|actix|rocket|diesel)", Ecosystem.CARGO),
]


class RenovateParser:
    """Parser for Renovate merge requests."""

    def is_renovate_mr(self, mr: MergeRequestInfo) -> bool:
        """Check if an MR is from Renovate.

        Args:
            mr: Merge request information.

        Returns:
            True if this is a Renovate MR.
        """
        # Check author
        if mr.author_username.lower() in RENOVATE_BOT_USERNAMES:
            return True

        # Check branch name
        branch_lower = mr.source_branch.lower()
        for prefix in RENOVATE_BRANCH_PREFIXES:
            if branch_lower.startswith(prefix):
                return True

        # Check title patterns
        for pattern in RENOVATE_TITLE_PATTERNS:
            if re.match(pattern, mr.title, re.IGNORECASE):
                return True

        return False

    def parse_mr(
        self,
        mr: MergeRequestInfo,
        changes: Optional[list[MergeRequestChange]] = None,
    ) -> RenovateMRInfo:
        """Parse a Renovate MR to extract update information.

        Args:
            mr: Merge request information.
            changes: Optional list of file changes.

        Returns:
            Parsed Renovate MR information.
        """
        if not self.is_renovate_mr(mr):
            return RenovateMRInfo(is_renovate=False)

        result = RenovateMRInfo(
            is_renovate=True,
            branch_name=mr.source_branch,
        )

        # Parse title for update info
        self._parse_title(mr.title, result)

        # Parse description for additional details
        self._parse_description(mr.description, result)

        # Detect ecosystems from changed files
        if changes:
            self._detect_ecosystems_from_changes(changes, result)

        # Determine update type from branch name
        result.update_type = self._detect_update_type(mr.source_branch, mr.title)

        # Check for grouped updates
        result.is_grouped = self._is_grouped_update(mr.source_branch, mr.title)
        if result.is_grouped:
            result.group_name = self._extract_group_name(mr.source_branch)

        return result

    def _parse_title(self, title: str, result: RenovateMRInfo) -> None:
        """Parse MR title for update information."""
        # Try each pattern
        for pattern in RENOVATE_TITLE_PATTERNS:
            match = re.match(pattern, title, re.IGNORECASE)
            if match:
                groups = match.groups()

                if len(groups) >= 2:
                    # Package and version
                    package = groups[0]
                    to_version = groups[-1]

                    # Check for "from X to Y" pattern
                    from_version = ""
                    if len(groups) >= 3:
                        from_version = groups[1]

                    ecosystem = self._detect_ecosystem_from_package(package)

                    result.updates.append(
                        DependencyUpdate(
                            ecosystem=ecosystem,
                            name=package,
                            from_version=from_version,
                            to_version=to_version,
                            is_major=self._is_major_update(from_version, to_version),
                        )
                    )

                elif len(groups) == 1:
                    # Group update without specific version
                    pass

                break

    def _parse_description(self, description: str, result: RenovateMRInfo) -> None:
        """Parse MR description for update information."""
        if not description:
            return

        # Renovate includes a table of updates in the description
        # Format: | Package | From | To | Change |
        table_pattern = r"\|\s*([^\|]+)\s*\|\s*([^\|]*)\s*\|\s*([^\|]+)\s*\|\s*([^\|]*)\s*\|"

        for match in re.finditer(table_pattern, description):
            package = match.group(1).strip()
            from_version = match.group(2).strip()
            to_version = match.group(3).strip()

            # Skip header row
            if package.lower() in ("package", "dependency", "name"):
                continue

            # Skip separator rows
            if package.startswith("-"):
                continue

            # Clean up version strings
            from_version = self._clean_version(from_version)
            to_version = self._clean_version(to_version)

            ecosystem = self._detect_ecosystem_from_package(package)

            # Check if we already have this update
            existing = next(
                (u for u in result.updates if u.name == package),
                None,
            )

            if existing:
                # Update with more info if available
                if from_version and not existing.from_version:
                    existing.from_version = from_version
                if to_version and not existing.to_version:
                    existing.to_version = to_version
            else:
                result.updates.append(
                    DependencyUpdate(
                        ecosystem=ecosystem,
                        name=package,
                        from_version=from_version,
                        to_version=to_version,
                        is_major=self._is_major_update(from_version, to_version),
                    )
                )

        # Also look for package mentions in bullet points
        bullet_pattern = r"[-*]\s*`?([^\s`]+)`?\s*(?:from\s+)?v?([\d.]+)?\s*(?:to|->|=>)\s*v?([\d.]+)"

        for match in re.finditer(bullet_pattern, description, re.IGNORECASE):
            package = match.group(1)
            from_version = match.group(2) or ""
            to_version = match.group(3)

            # Skip if already parsed
            if any(u.name == package for u in result.updates):
                continue

            ecosystem = self._detect_ecosystem_from_package(package)

            result.updates.append(
                DependencyUpdate(
                    ecosystem=ecosystem,
                    name=package,
                    from_version=from_version,
                    to_version=to_version,
                    is_major=self._is_major_update(from_version, to_version),
                )
            )

    def _detect_ecosystems_from_changes(
        self,
        changes: list[MergeRequestChange],
        result: RenovateMRInfo,
    ) -> None:
        """Detect ecosystems from changed files."""
        detected_ecosystems: set[Ecosystem] = set()

        for change in changes:
            file_name = change.new_path.split("/")[-1]

            ecosystem = LOCKFILE_ECOSYSTEM_MAP.get(file_name)
            if ecosystem:
                detected_ecosystems.add(ecosystem)

        # Update updates without ecosystem
        if detected_ecosystems and len(detected_ecosystems) == 1:
            ecosystem = next(iter(detected_ecosystems))
            for update in result.updates:
                if update.ecosystem == Ecosystem.NPM:  # Default
                    update.ecosystem = ecosystem

    def _detect_ecosystem_from_package(self, package: str) -> Ecosystem:
        """Detect ecosystem from package name."""
        for pattern, ecosystem in PACKAGE_ECOSYSTEM_PATTERNS:
            if re.match(pattern, package, re.IGNORECASE):
                return ecosystem

        # Default to NPM for unknown packages
        return Ecosystem.NPM

    def _detect_update_type(self, branch: str, title: str) -> UpdateType:
        """Detect the type of update."""
        branch_lower = branch.lower()
        title_lower = title.lower()

        if "major" in branch_lower or "major" in title_lower:
            return UpdateType.MAJOR
        elif "minor" in branch_lower or "minor" in title_lower:
            return UpdateType.MINOR
        elif "patch" in branch_lower or "patch" in title_lower:
            return UpdateType.PATCH
        elif "pin" in branch_lower or "pin" in title_lower:
            return UpdateType.PIN
        elif "digest" in branch_lower or "digest" in title_lower:
            return UpdateType.DIGEST
        elif "lockfile" in branch_lower or "lock file" in title_lower:
            return UpdateType.LOCKFILE

        return UpdateType.UNKNOWN

    def _is_grouped_update(self, branch: str, title: str) -> bool:
        """Check if this is a grouped update."""
        # Renovate groups updates in branches like "renovate/react-monorepo"
        if re.search(r"monorepo|group|packages?$", branch, re.IGNORECASE):
            return True

        if re.search(r"monorepo|packages?$", title, re.IGNORECASE):
            return True

        return False

    def _extract_group_name(self, branch: str) -> Optional[str]:
        """Extract group name from branch."""
        # Remove renovate prefix
        name = branch
        for prefix in RENOVATE_BRANCH_PREFIXES:
            if name.lower().startswith(prefix):
                name = name[len(prefix):]
                break

        # Remove version suffix
        name = re.sub(r"-[\d.]+$", "", name)

        return name if name else None

    def _is_major_update(self, from_version: str, to_version: str) -> bool:
        """Check if update is a major version bump."""
        if not from_version or not to_version:
            return False

        from_parts = re.findall(r"\d+", from_version)
        to_parts = re.findall(r"\d+", to_version)

        if from_parts and to_parts:
            return int(to_parts[0]) > int(from_parts[0])

        return False

    def _clean_version(self, version: str) -> str:
        """Clean up version string."""
        if not version:
            return ""

        # Remove markdown links
        version = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", version)

        # Remove backticks and other formatting
        version = version.strip("`'\"")

        # Remove 'v' prefix
        version = re.sub(r"^v", "", version)

        return version.strip()


def parse_renovate_mr(
    mr: MergeRequestInfo,
    changes: Optional[list[MergeRequestChange]] = None,
) -> RenovateMRInfo:
    """Convenience function to parse a Renovate MR.

    Args:
        mr: Merge request information.
        changes: Optional list of file changes.

    Returns:
        Parsed Renovate MR information.
    """
    parser = RenovateParser()
    return parser.parse_mr(mr, changes)


def is_renovate_branch(branch_name: str) -> bool:
    """Check if a branch name is from Renovate.

    Args:
        branch_name: Branch name to check.

    Returns:
        True if this is a Renovate branch.
    """
    branch_lower = branch_name.lower()
    for prefix in RENOVATE_BRANCH_PREFIXES:
        if branch_lower.startswith(prefix):
            return True
    return False
