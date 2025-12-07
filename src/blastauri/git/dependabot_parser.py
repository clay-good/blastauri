"""Dependabot and Renovate PR detection and parsing for GitHub."""

import re
from dataclasses import dataclass, field
from enum import Enum

from blastauri.core.models import DependencyUpdate, Ecosystem
from blastauri.git.github_client import PullRequestFile, PullRequestInfo


class BotType(str, Enum):
    """Type of dependency update bot."""

    DEPENDABOT = "dependabot"
    RENOVATE = "renovate"
    UNKNOWN = "unknown"


@dataclass
class DependencyPRInfo:
    """Parsed dependency PR information."""

    is_dependency_update: bool
    bot_type: BotType = BotType.UNKNOWN
    updates: list[DependencyUpdate] = field(default_factory=list)
    is_security_update: bool = False
    is_grouped: bool = False
    group_name: str | None = None
    branch_name: str = ""


# Dependabot bot usernames
DEPENDABOT_USERNAMES = {
    "dependabot[bot]",
    "dependabot",
    "dependabot-preview[bot]",
}

# Renovate bot usernames (on GitHub)
RENOVATE_USERNAMES = {
    "renovate[bot]",
    "renovate",
    "mend-renovate[bot]",
    "whitesource-renovate[bot]",
}

# Branch prefixes
DEPENDABOT_BRANCH_PREFIXES = [
    "dependabot/",
]

RENOVATE_BRANCH_PREFIXES = [
    "renovate/",
    "renovate-",
]

# Dependabot title patterns
DEPENDABOT_TITLE_PATTERNS = [
    # Standard format: Bump X from Y to Z
    r"^Bump (.+) from v?([\d.]+(?:-[\w.]+)?) to v?([\d.]+(?:-[\w.]+)?)$",
    # With scope: Bump X from Y to Z in /path
    r"^Bump (.+) from v?([\d.]+(?:-[\w.]+)?) to v?([\d.]+(?:-[\w.]+)?) in (.+)$",
    # Security update format
    r"^\[Security\] Bump (.+) from v?([\d.]+(?:-[\w.]+)?) to v?([\d.]+(?:-[\w.]+)?)$",
    # Build dependency format
    r"^build\(deps(?:-dev)?\): bump (.+) from v?([\d.]+(?:-[\w.]+)?) to v?([\d.]+(?:-[\w.]+)?)$",
    # Chore format
    r"^chore\(deps(?:-dev)?\): bump (.+) from v?([\d.]+(?:-[\w.]+)?) to v?([\d.]+(?:-[\w.]+)?)$",
]

# Renovate title patterns (on GitHub)
RENOVATE_TITLE_PATTERNS = [
    r"^Update (?:dependency )?(.+) to v?(.+)$",
    r"^(?:fix|chore|build)\(deps\): update (.+) to v?(.+)$",
    r"^Update (.+) from v?(.+) to v?(.+)$",
    r"^Update (.+) packages?$",
    r"^Update (.+) monorepo$",
    r"^Pin (.+) to v?(.+)$",
    r"^Lock file maintenance$",
]

# Ecosystem detection from branch paths
ECOSYSTEM_PATH_MAP = {
    "npm_and_yarn": Ecosystem.NPM,
    "npm": Ecosystem.NPM,
    "yarn": Ecosystem.NPM,
    "pip": Ecosystem.PYPI,
    "poetry": Ecosystem.PYPI,
    "pipenv": Ecosystem.PYPI,
    "gomod": Ecosystem.GO,
    "go_modules": Ecosystem.GO,
    "bundler": Ecosystem.RUBYGEMS,
    "cargo": Ecosystem.CARGO,
    "composer": Ecosystem.COMPOSER,
    "maven": Ecosystem.MAVEN,
    "gradle": Ecosystem.MAVEN,
    "nuget": Ecosystem.NPM,  # Fallback
    "docker": Ecosystem.NPM,  # Fallback
    "github_actions": Ecosystem.NPM,  # Fallback
}

# Lockfile to ecosystem mapping
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
    "build.gradle": Ecosystem.MAVEN,
    "build.gradle.kts": Ecosystem.MAVEN,
}


class DependabotParser:
    """Parser for Dependabot and Renovate pull requests on GitHub."""

    def detect_bot_type(self, pr: PullRequestInfo) -> BotType:
        """Detect which bot created the PR.

        Args:
            pr: Pull request information.

        Returns:
            Bot type.
        """
        author_lower = pr.author_login.lower()

        # Check author
        if author_lower in {u.lower() for u in DEPENDABOT_USERNAMES}:
            return BotType.DEPENDABOT

        if author_lower in {u.lower() for u in RENOVATE_USERNAMES}:
            return BotType.RENOVATE

        # Check branch prefix
        branch_lower = pr.head_branch.lower()

        for prefix in DEPENDABOT_BRANCH_PREFIXES:
            if branch_lower.startswith(prefix):
                return BotType.DEPENDABOT

        for prefix in RENOVATE_BRANCH_PREFIXES:
            if branch_lower.startswith(prefix):
                return BotType.RENOVATE

        return BotType.UNKNOWN

    def is_dependency_pr(self, pr: PullRequestInfo) -> bool:
        """Check if a PR is a dependency update.

        Args:
            pr: Pull request information.

        Returns:
            True if this is a dependency update PR.
        """
        return self.detect_bot_type(pr) != BotType.UNKNOWN

    def parse_pr(
        self,
        pr: PullRequestInfo,
        files: list[PullRequestFile] | None = None,
    ) -> DependencyPRInfo:
        """Parse a dependency update PR.

        Args:
            pr: Pull request information.
            files: Optional list of changed files.

        Returns:
            Parsed PR information.
        """
        bot_type = self.detect_bot_type(pr)

        if bot_type == BotType.UNKNOWN:
            return DependencyPRInfo(is_dependency_update=False)

        result = DependencyPRInfo(
            is_dependency_update=True,
            bot_type=bot_type,
            branch_name=pr.head_branch,
        )

        # Parse based on bot type
        if bot_type == BotType.DEPENDABOT:
            self._parse_dependabot_pr(pr, result)
        else:
            self._parse_renovate_pr(pr, result)

        # Detect ecosystems from files
        if files:
            self._detect_ecosystems_from_files(files, result)

        # Check for security update
        result.is_security_update = self._is_security_update(pr)

        return result

    def _parse_dependabot_pr(
        self,
        pr: PullRequestInfo,
        result: DependencyPRInfo,
    ) -> None:
        """Parse Dependabot PR details."""
        # Try each title pattern
        for pattern in DEPENDABOT_TITLE_PATTERNS:
            match = re.match(pattern, pr.title, re.IGNORECASE)
            if match:
                groups = match.groups()

                package = groups[0]
                from_version = groups[1] if len(groups) > 1 else ""
                to_version = groups[2] if len(groups) > 2 else ""

                ecosystem = self._detect_ecosystem_from_branch(pr.head_branch)

                result.updates.append(
                    DependencyUpdate(
                        ecosystem=ecosystem,
                        name=package,
                        from_version=from_version,
                        to_version=to_version,
                        is_major=self._is_major_update(from_version, to_version),
                    )
                )
                break

        # Parse body for additional info
        self._parse_dependabot_body(pr.body, result)

    def _parse_renovate_pr(
        self,
        pr: PullRequestInfo,
        result: DependencyPRInfo,
    ) -> None:
        """Parse Renovate PR details."""
        # Try each title pattern
        for pattern in RENOVATE_TITLE_PATTERNS:
            match = re.match(pattern, pr.title, re.IGNORECASE)
            if match:
                groups = match.groups()

                if len(groups) >= 2:
                    package = groups[0]
                    to_version = groups[-1]

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

                break

        # Check for grouped updates
        if "monorepo" in pr.title.lower() or "packages" in pr.title.lower():
            result.is_grouped = True
            result.group_name = self._extract_group_name(pr.head_branch)

        # Parse body for table updates
        self._parse_renovate_body(pr.body, result)

    def _parse_dependabot_body(
        self,
        body: str,
        result: DependencyPRInfo,
    ) -> None:
        """Parse Dependabot PR body for additional info."""
        if not body:
            return

        # Look for "Bumps [package](url) from X to Y"
        bump_pattern = r"Bumps \[([^\]]+)\]\([^)]+\) from `?v?([\d.]+(?:-[\w.]+)?)`? to `?v?([\d.]+(?:-[\w.]+)?)`?"

        for match in re.finditer(bump_pattern, body, re.IGNORECASE):
            package = match.group(1)
            from_version = match.group(2)
            to_version = match.group(3)

            # Check if we already have this update
            if not any(u.name == package for u in result.updates):
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

    def _parse_renovate_body(
        self,
        body: str,
        result: DependencyPRInfo,
    ) -> None:
        """Parse Renovate PR body for table updates."""
        if not body:
            return

        # Look for update table
        table_pattern = r"\|\s*([^\|]+)\s*\|\s*([^\|]*)\s*\|\s*([^\|]+)\s*\|"

        for match in re.finditer(table_pattern, body):
            package = match.group(1).strip()
            from_version = match.group(2).strip()
            to_version = match.group(3).strip()

            # Skip header row
            if package.lower() in ("package", "dependency", "name"):
                continue

            # Skip separator
            if package.startswith("-"):
                continue

            # Clean versions
            from_version = self._clean_version(from_version)
            to_version = self._clean_version(to_version)

            # Check if we already have this update
            existing = next(
                (u for u in result.updates if u.name == package),
                None,
            )

            if existing:
                if from_version and not existing.from_version:
                    existing.from_version = from_version
            else:
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

    def _detect_ecosystem_from_branch(self, branch: str) -> Ecosystem:
        """Detect ecosystem from Dependabot branch name."""
        # Dependabot branches: dependabot/npm_and_yarn/package-1.2.3
        parts = branch.split("/")

        if len(parts) >= 2:
            ecosystem_part = parts[1].lower()
            ecosystem = ECOSYSTEM_PATH_MAP.get(ecosystem_part)
            if ecosystem:
                return ecosystem

        return Ecosystem.NPM  # Default

    def _detect_ecosystem_from_package(self, package: str) -> Ecosystem:
        """Detect ecosystem from package name."""
        # Scoped npm packages
        if package.startswith("@"):
            return Ecosystem.NPM

        # Maven group:artifact format
        if ":" in package:
            return Ecosystem.MAVEN

        # Go paths
        if "/" in package and ("github.com" in package or "golang.org" in package):
            return Ecosystem.GO

        return Ecosystem.NPM  # Default

    def _detect_ecosystems_from_files(
        self,
        files: list[PullRequestFile],
        result: DependencyPRInfo,
    ) -> None:
        """Detect ecosystems from changed files."""
        detected: set[Ecosystem] = set()

        for f in files:
            filename = f.filename.split("/")[-1]
            ecosystem = LOCKFILE_ECOSYSTEM_MAP.get(filename)
            if ecosystem:
                detected.add(ecosystem)

        # Update updates without specific ecosystem
        if detected and len(detected) == 1:
            ecosystem = next(iter(detected))
            for update in result.updates:
                if update.ecosystem == Ecosystem.NPM:  # Default
                    update.ecosystem = ecosystem

    def _is_security_update(self, pr: PullRequestInfo) -> bool:
        """Check if this is a security update."""
        # Check title
        if "[security]" in pr.title.lower():
            return True

        # Check labels
        security_labels = {"security", "security-update", "vulnerability"}
        if any(label.lower() in security_labels for label in pr.labels):
            return True

        # Check body for security indicators
        if pr.body:
            security_keywords = [
                "security advisory",
                "vulnerability",
                "cve-",
                "security update",
                "security fix",
            ]
            body_lower = pr.body.lower()
            if any(kw in body_lower for kw in security_keywords):
                return True

        return False

    def _is_major_update(self, from_version: str, to_version: str) -> bool:
        """Check if this is a major version update."""
        if not from_version or not to_version:
            return False

        from_parts = re.findall(r"\d+", from_version)
        to_parts = re.findall(r"\d+", to_version)

        if from_parts and to_parts:
            return int(to_parts[0]) > int(from_parts[0])

        return False

    def _extract_group_name(self, branch: str) -> str | None:
        """Extract group name from branch."""
        # Remove prefix
        for prefix in DEPENDABOT_BRANCH_PREFIXES + RENOVATE_BRANCH_PREFIXES:
            if branch.lower().startswith(prefix):
                branch = branch[len(prefix):]
                break

        # Remove version suffix
        branch = re.sub(r"-[\d.]+$", "", branch)

        return branch if branch else None

    def _clean_version(self, version: str) -> str:
        """Clean up version string."""
        if not version:
            return ""

        # Remove markdown links
        version = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", version)

        # Remove backticks and formatting
        version = version.strip("`'\"")

        # Remove v prefix
        version = re.sub(r"^v", "", version)

        return version.strip()


def parse_dependency_pr(
    pr: PullRequestInfo,
    files: list[PullRequestFile] | None = None,
) -> DependencyPRInfo:
    """Convenience function to parse a dependency PR.

    Args:
        pr: Pull request information.
        files: Optional list of changed files.

    Returns:
        Parsed PR information.
    """
    parser = DependabotParser()
    return parser.parse_pr(pr, files)


def is_dependabot_branch(branch_name: str) -> bool:
    """Check if a branch name is from Dependabot.

    Args:
        branch_name: Branch name to check.

    Returns:
        True if this is a Dependabot branch.
    """
    branch_lower = branch_name.lower()
    for prefix in DEPENDABOT_BRANCH_PREFIXES:
        if branch_lower.startswith(prefix):
            return True
    return False


def is_dependency_bot_branch(branch_name: str) -> bool:
    """Check if a branch name is from any dependency bot.

    Args:
        branch_name: Branch name to check.

    Returns:
        True if this is a dependency bot branch.
    """
    branch_lower = branch_name.lower()

    all_prefixes = DEPENDABOT_BRANCH_PREFIXES + RENOVATE_BRANCH_PREFIXES

    for prefix in all_prefixes:
        if branch_lower.startswith(prefix):
            return True

    return False
