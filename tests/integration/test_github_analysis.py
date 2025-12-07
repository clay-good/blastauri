"""Integration tests for GitHub PR analysis with mocked API responses."""

import json
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from blastauri.core.models import Ecosystem, Severity
from blastauri.git.dependabot_parser import BotType, DependabotParser
from blastauri.git.github_client import (
    GitHubClient,
    PullRequestFile,
    PullRequestInfo,
)

# Load fixtures
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "api_responses"


def load_fixture(name: str) -> dict:
    """Load a JSON fixture file."""
    with open(FIXTURES_DIR / name) as f:
        return json.load(f)


def create_pr_info(
    number: int,
    title: str,
    body: str,
    head_branch: str,
    base_branch: str,
    author_login: str,
    state: str = "open",
    html_url: str = "",
) -> PullRequestInfo:
    """Helper to create PullRequestInfo with correct field names."""
    return PullRequestInfo(
        number=number,
        title=title,
        body=body,
        head_branch=head_branch,
        base_branch=base_branch,
        author_login=author_login,
        state=state,
        html_url=html_url or f"https://github.com/owner/repo/pull/{number}",
        created_at=datetime.now(),
        updated_at=datetime.now(),
    )


class TestDependabotPRDetection:
    """Test Dependabot PR detection logic."""

    def test_detect_dependabot_pr_by_username(self) -> None:
        """Test detection via dependabot[bot] username."""
        pr_info = create_pr_info(
            number=156,
            title="Bump requests from 2.28.0 to 2.31.0",
            body="Dependabot update",
            head_branch="dependabot/pip/requests-2.31.0",
            base_branch="main",
            author_login="dependabot[bot]",
        )

        parser = DependabotParser()
        result = parser.parse_pr(pr_info)

        assert result.is_dependency_update is True
        assert result.bot_type == BotType.DEPENDABOT

    def test_detect_dependabot_pr_by_branch(self) -> None:
        """Test detection via dependabot/ branch prefix."""
        pr_info = create_pr_info(
            number=156,
            title="Bump requests from 2.28.0 to 2.31.0",
            body="Update",
            head_branch="dependabot/pip/requests-2.31.0",
            base_branch="main",
            author_login="some-user",
        )

        parser = DependabotParser()
        result = parser.parse_pr(pr_info)

        assert result.is_dependency_update is True
        assert result.bot_type == BotType.DEPENDABOT

    def test_detect_non_dependabot_pr(self) -> None:
        """Test that regular PRs are not detected as Dependabot."""
        pr_info = create_pr_info(
            number=157,
            title="Add new feature",
            body="Feature implementation",
            head_branch="feature/new-thing",
            base_branch="main",
            author_login="developer",
        )

        parser = DependabotParser()
        result = parser.parse_pr(pr_info)

        assert result.is_dependency_update is False
        assert result.bot_type == BotType.UNKNOWN

    def test_parse_dependabot_title_bump_format(self) -> None:
        """Test parsing 'Bump X from Y to Z' format."""
        pr_info = create_pr_info(
            number=156,
            title="Bump requests from 2.28.0 to 2.31.0",
            body="",
            head_branch="dependabot/pip/requests-2.31.0",
            base_branch="main",
            author_login="dependabot[bot]",
        )

        parser = DependabotParser()
        result = parser.parse_pr(pr_info)

        assert result.is_dependency_update is True
        assert result.bot_type == BotType.DEPENDABOT
        assert len(result.updates) >= 1
        update = result.updates[0]
        assert update.name == "requests"
        assert update.from_version == "2.28.0"
        assert update.to_version == "2.31.0"

    def test_parse_dependabot_ecosystem_from_branch(self) -> None:
        """Test ecosystem detection from branch name."""
        pr_info = create_pr_info(
            number=156,
            title="Bump requests from 2.28.0 to 2.31.0",
            body="",
            head_branch="dependabot/pip/requests-2.31.0",
            base_branch="main",
            author_login="dependabot[bot]",
        )

        parser = DependabotParser()
        result = parser.parse_pr(pr_info)

        assert result.is_dependency_update is True
        if result.updates:
            assert result.updates[0].ecosystem == Ecosystem.PYPI

    def test_parse_dependabot_npm_ecosystem(self) -> None:
        """Test npm ecosystem detection."""
        pr_info = create_pr_info(
            number=200,
            title="Bump lodash from 4.17.21 to 5.0.0",
            body="",
            head_branch="dependabot/npm_and_yarn/lodash-5.0.0",
            base_branch="main",
            author_login="dependabot[bot]",
        )

        parser = DependabotParser()
        result = parser.parse_pr(pr_info)

        assert result.is_dependency_update is True
        if result.updates:
            assert result.updates[0].ecosystem == Ecosystem.NPM


class TestRenovateOnGitHub:
    """Test Renovate PR detection on GitHub."""

    def test_detect_renovate_pr_by_branch(self) -> None:
        """Test Renovate detection on GitHub via branch prefix."""
        pr_info = create_pr_info(
            number=300,
            title="Update dependency lodash to v5",
            body="Renovate update",
            head_branch="renovate/lodash-5.x",
            base_branch="main",
            author_login="renovate[bot]",
        )

        # Using DependabotParser which also handles Renovate on GitHub
        parser = DependabotParser()
        result = parser.parse_pr(pr_info)

        # Should detect as dependency update with Renovate bot type
        assert result.is_dependency_update is True
        assert result.bot_type == BotType.RENOVATE


class TestGitHubAnalysisWorkflow:
    """Test full GitHub analysis workflow with mocked API."""

    @pytest.fixture
    def mock_github_client(self) -> MagicMock:
        """Create a mocked GitHub client."""
        client = MagicMock(spec=GitHubClient)

        # Load fixtures
        pr_data = load_fixture("github_pr_dependabot.json")
        files_data = load_fixture("github_pr_files.json")

        # Create PullRequestInfo from fixture
        pr_info = PullRequestInfo(
            number=pr_data["number"],
            title=pr_data["title"],
            body=pr_data["body"],
            head_branch=pr_data["head"]["ref"],
            base_branch=pr_data["base"]["ref"],
            author_login=pr_data["user"]["login"],
            state=pr_data["state"],
            html_url=pr_data["html_url"],
            created_at=datetime.fromisoformat(pr_data["created_at"].replace("Z", "+00:00")),
            updated_at=datetime.fromisoformat(pr_data["updated_at"].replace("Z", "+00:00")),
            labels=[],
            mergeable=pr_data.get("mergeable", True),
        )

        # Create PullRequestFile objects (without sha field)
        files = [
            PullRequestFile(
                filename=f["filename"],
                status=f["status"],
                additions=f["additions"],
                deletions=f["deletions"],
                changes=f["changes"],
                patch=f.get("patch", ""),
            )
            for f in files_data
        ]

        client.get_pull_request.return_value = pr_info
        client.get_pr_files.return_value = files

        return client

    def test_pr_info_creation_from_fixture(self, mock_github_client: MagicMock) -> None:
        """Test that PR info is correctly created from fixture."""
        pr_info = mock_github_client.get_pull_request("owner/repo", 156)

        assert pr_info.number == 156
        assert "requests" in pr_info.title.lower()
        assert pr_info.author_login == "dependabot[bot]"
        assert "dependabot" in pr_info.head_branch

    def test_pr_files_from_fixture(self, mock_github_client: MagicMock) -> None:
        """Test that PR files are correctly loaded from fixture."""
        files = mock_github_client.get_pr_files("owner/repo", 156)

        assert len(files) == 1
        assert files[0].filename == "requirements.txt"
        assert "requests" in files[0].patch


class TestGitHubLabelDetermination:
    """Test label determination for GitHub PRs."""

    def test_security_labels_for_cve_fix(self) -> None:
        """Test that CVE fixes get security labels."""
        from blastauri.git.label_manager import determine_labels_for_analysis

        labels_add, labels_remove = determine_labels_for_analysis(
            severity=Severity.HIGH,
            breaking_changes_count=0,
            cves_fixed_count=1,
            waf_mitigatable_count=0,
        )

        assert "security:high" in labels_add

    def test_safe_label_for_minor_update(self) -> None:
        """Test safe label for non-breaking minor updates."""
        from blastauri.git.label_manager import determine_labels_for_analysis

        labels_add, labels_remove = determine_labels_for_analysis(
            severity=Severity.LOW,
            breaking_changes_count=0,
            cves_fixed_count=0,
            waf_mitigatable_count=0,
        )

        assert "blastauri:safe" in labels_add
        assert "blastauri:breaking" not in labels_add
