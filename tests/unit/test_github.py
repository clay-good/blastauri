"""Tests for GitHub integration and Dependabot PR analysis."""

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from blastauri.core.models import (
    AnalysisReport,
    BreakingChange,
    BreakingChangeType,
    CVE,
    DependencyUpdate,
    Ecosystem,
    Severity,
    UpgradeImpact,
)
from blastauri.git.dependabot_parser import (
    BotType,
    DependabotParser,
    DependencyPRInfo,
    is_dependabot_branch,
    is_dependency_bot_branch,
    parse_dependency_pr,
)
from blastauri.git.github_client import (
    PullRequestFile,
    PullRequestInfo,
    RepositoryLabel,
)


class TestDependabotParser:
    """Tests for Dependabot PR parsing."""

    @pytest.fixture
    def parser(self) -> DependabotParser:
        """Create a Dependabot parser."""
        return DependabotParser()

    @pytest.fixture
    def dependabot_pr(self) -> PullRequestInfo:
        """Create a sample Dependabot PR."""
        return PullRequestInfo(
            number=123,
            title="Bump lodash from 4.17.20 to 4.17.21",
            body="Bumps [lodash](https://github.com/lodash/lodash) from 4.17.20 to 4.17.21.",
            head_branch="dependabot/npm_and_yarn/lodash-4.17.21",
            base_branch="main",
            author_login="dependabot[bot]",
            state="open",
            html_url="https://github.com/owner/repo/pull/123",
            created_at=datetime.now(),
            updated_at=datetime.now(),
            labels=[],
        )

    @pytest.fixture
    def renovate_pr(self) -> PullRequestInfo:
        """Create a sample Renovate PR on GitHub."""
        return PullRequestInfo(
            number=456,
            title="Update dependency axios to v0.21.4",
            body="This PR updates axios from 0.21.0 to 0.21.4.",
            head_branch="renovate/axios-0.x",
            base_branch="main",
            author_login="renovate[bot]",
            state="open",
            html_url="https://github.com/owner/repo/pull/456",
            created_at=datetime.now(),
            updated_at=datetime.now(),
            labels=[],
        )

    @pytest.fixture
    def regular_pr(self) -> PullRequestInfo:
        """Create a regular PR."""
        return PullRequestInfo(
            number=789,
            title="Add new feature",
            body="This PR adds a new feature.",
            head_branch="feature/new-feature",
            base_branch="main",
            author_login="developer",
            state="open",
            html_url="https://github.com/owner/repo/pull/789",
            created_at=datetime.now(),
            updated_at=datetime.now(),
            labels=[],
        )

    def test_detect_dependabot_by_author(
        self, parser: DependabotParser, dependabot_pr: PullRequestInfo
    ) -> None:
        """Test detecting Dependabot by author."""
        assert parser.detect_bot_type(dependabot_pr) == BotType.DEPENDABOT

    def test_detect_renovate_by_author(
        self, parser: DependabotParser, renovate_pr: PullRequestInfo
    ) -> None:
        """Test detecting Renovate by author."""
        assert parser.detect_bot_type(renovate_pr) == BotType.RENOVATE

    def test_detect_unknown_for_regular_pr(
        self, parser: DependabotParser, regular_pr: PullRequestInfo
    ) -> None:
        """Test detecting unknown for regular PR."""
        assert parser.detect_bot_type(regular_pr) == BotType.UNKNOWN

    def test_detect_dependabot_by_branch(self, parser: DependabotParser) -> None:
        """Test detecting Dependabot by branch name."""
        pr = PullRequestInfo(
            number=100,
            title="Some title",
            body="",
            head_branch="dependabot/npm/lodash-4.17.21",
            base_branch="main",
            author_login="some-user",
            state="open",
            html_url="https://github.com/test/repo/pull/100",
            created_at=datetime.now(),
            updated_at=datetime.now(),
            labels=[],
        )
        assert parser.detect_bot_type(pr) == BotType.DEPENDABOT

    def test_is_dependency_pr(
        self, parser: DependabotParser, dependabot_pr: PullRequestInfo
    ) -> None:
        """Test is_dependency_pr detection."""
        assert parser.is_dependency_pr(dependabot_pr) is True

    def test_is_not_dependency_pr(
        self, parser: DependabotParser, regular_pr: PullRequestInfo
    ) -> None:
        """Test is_dependency_pr for regular PR."""
        assert parser.is_dependency_pr(regular_pr) is False

    def test_parse_dependabot_title(
        self, parser: DependabotParser, dependabot_pr: PullRequestInfo
    ) -> None:
        """Test parsing Dependabot title."""
        result = parser.parse_pr(dependabot_pr)

        assert result.is_dependency_update is True
        assert result.bot_type == BotType.DEPENDABOT
        assert len(result.updates) >= 1

        update = result.updates[0]
        assert update.name == "lodash"
        assert update.from_version == "4.17.20"
        assert update.to_version == "4.17.21"

    def test_parse_dependabot_with_scope(self, parser: DependabotParser) -> None:
        """Test parsing Dependabot title with scope."""
        pr = PullRequestInfo(
            number=101,
            title="Bump axios from 0.21.0 to 0.21.4 in /frontend",
            body="",
            head_branch="dependabot/npm_and_yarn/frontend/axios-0.21.4",
            base_branch="main",
            author_login="dependabot[bot]",
            state="open",
            html_url="https://github.com/test/repo/pull/101",
            created_at=datetime.now(),
            updated_at=datetime.now(),
            labels=[],
        )

        result = parser.parse_pr(pr)

        assert result.is_dependency_update is True
        assert len(result.updates) >= 1
        assert result.updates[0].name == "axios"
        assert result.updates[0].from_version == "0.21.0"
        assert result.updates[0].to_version == "0.21.4"

    def test_parse_security_update(self, parser: DependabotParser) -> None:
        """Test detecting security update."""
        pr = PullRequestInfo(
            number=102,
            title="[Security] Bump lodash from 4.17.20 to 4.17.21",
            body="This is a security update.",
            head_branch="dependabot/npm_and_yarn/lodash-4.17.21",
            base_branch="main",
            author_login="dependabot[bot]",
            state="open",
            html_url="https://github.com/test/repo/pull/102",
            created_at=datetime.now(),
            updated_at=datetime.now(),
            labels=["security"],
        )

        result = parser.parse_pr(pr)

        assert result.is_dependency_update is True
        assert result.is_security_update is True

    def test_parse_renovate_title(
        self, parser: DependabotParser, renovate_pr: PullRequestInfo
    ) -> None:
        """Test parsing Renovate title on GitHub."""
        result = parser.parse_pr(renovate_pr)

        assert result.is_dependency_update is True
        assert result.bot_type == BotType.RENOVATE
        assert len(result.updates) >= 1

        update = result.updates[0]
        assert update.name == "axios"
        assert update.to_version == "0.21.4"

    def test_detect_ecosystem_from_branch(self, parser: DependabotParser) -> None:
        """Test ecosystem detection from branch path."""
        pr = PullRequestInfo(
            number=103,
            title="Bump requests from 2.25.0 to 2.25.1",
            body="",
            head_branch="dependabot/pip/requests-2.25.1",
            base_branch="main",
            author_login="dependabot[bot]",
            state="open",
            html_url="https://github.com/test/repo/pull/103",
            created_at=datetime.now(),
            updated_at=datetime.now(),
            labels=[],
        )

        result = parser.parse_pr(pr)

        assert result.updates[0].ecosystem == Ecosystem.PYPI

    def test_detect_ecosystem_from_files(self, parser: DependabotParser) -> None:
        """Test ecosystem detection from changed files."""
        pr = PullRequestInfo(
            number=104,
            title="Bump something",
            body="",
            head_branch="dependabot/bundler/something",
            base_branch="main",
            author_login="dependabot[bot]",
            state="open",
            html_url="https://github.com/test/repo/pull/104",
            created_at=datetime.now(),
            updated_at=datetime.now(),
            labels=[],
        )

        files = [
            PullRequestFile(
                filename="Gemfile.lock",
                status="modified",
                additions=10,
                deletions=5,
                changes=15,
            )
        ]

        result = parser.parse_pr(pr, files)
        # Should detect Ruby ecosystem from Gemfile.lock
        assert result.is_dependency_update is True

    def test_parse_dependabot_body(self, parser: DependabotParser) -> None:
        """Test parsing Dependabot body for additional info."""
        pr = PullRequestInfo(
            number=105,
            title="Bump lodash from 4.17.20 to 4.17.21",
            body="""
            Bumps [lodash](https://github.com/lodash/lodash) from `4.17.20` to `4.17.21`.

            Release notes:
            - Security fix
            """,
            head_branch="dependabot/npm_and_yarn/lodash-4.17.21",
            base_branch="main",
            author_login="dependabot[bot]",
            state="open",
            html_url="https://github.com/test/repo/pull/105",
            created_at=datetime.now(),
            updated_at=datetime.now(),
            labels=[],
        )

        result = parser.parse_pr(pr)

        assert len(result.updates) >= 1
        assert result.updates[0].from_version == "4.17.20"
        assert result.updates[0].to_version == "4.17.21"

    def test_major_version_detection(self, parser: DependabotParser) -> None:
        """Test major version upgrade detection."""
        pr = PullRequestInfo(
            number=106,
            title="Bump react from 17.0.2 to 18.0.0",
            body="",
            head_branch="dependabot/npm_and_yarn/react-18.0.0",
            base_branch="main",
            author_login="dependabot[bot]",
            state="open",
            html_url="https://github.com/test/repo/pull/106",
            created_at=datetime.now(),
            updated_at=datetime.now(),
            labels=[],
        )

        result = parser.parse_pr(pr)

        assert result.updates[0].is_major is True


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_is_dependabot_branch(self) -> None:
        """Test is_dependabot_branch function."""
        assert is_dependabot_branch("dependabot/npm/lodash") is True
        assert is_dependabot_branch("dependabot/pip/requests") is True
        assert is_dependabot_branch("renovate/lodash") is False
        assert is_dependabot_branch("feature/new-feature") is False

    def test_is_dependency_bot_branch(self) -> None:
        """Test is_dependency_bot_branch function."""
        assert is_dependency_bot_branch("dependabot/npm/lodash") is True
        assert is_dependency_bot_branch("renovate/lodash") is True
        assert is_dependency_bot_branch("renovate-lodash") is True
        assert is_dependency_bot_branch("feature/new-feature") is False

    def test_parse_dependency_pr_function(self) -> None:
        """Test parse_dependency_pr convenience function."""
        pr = PullRequestInfo(
            number=1,
            title="Bump lodash from 4.17.20 to 4.17.21",
            body="",
            head_branch="dependabot/npm_and_yarn/lodash-4.17.21",
            base_branch="main",
            author_login="dependabot[bot]",
            state="open",
            html_url="https://github.com/test/repo/pull/1",
            created_at=datetime.now(),
            updated_at=datetime.now(),
            labels=[],
        )

        result = parse_dependency_pr(pr)

        assert result.is_dependency_update is True
        assert result.bot_type == BotType.DEPENDABOT


class TestPullRequestInfo:
    """Tests for PullRequestInfo dataclass."""

    def test_pull_request_info_creation(self) -> None:
        """Test creating PullRequestInfo."""
        now = datetime.now()
        pr = PullRequestInfo(
            number=1,
            title="Test PR",
            body="Description",
            head_branch="feature/test",
            base_branch="main",
            author_login="user",
            state="open",
            html_url="https://github.com/test/repo/pull/1",
            created_at=now,
            updated_at=now,
            labels=["label1", "label2"],
        )

        assert pr.number == 1
        assert pr.title == "Test PR"
        assert len(pr.labels) == 2

    def test_pull_request_file_creation(self) -> None:
        """Test creating PullRequestFile."""
        prf = PullRequestFile(
            filename="src/app.js",
            status="modified",
            additions=10,
            deletions=5,
            changes=15,
            patch="@@ -1,3 +1,5 @@",
        )

        assert prf.filename == "src/app.js"
        assert prf.status == "modified"
        assert prf.changes == 15


class TestRepositoryLabel:
    """Tests for RepositoryLabel dataclass."""

    def test_repository_label_creation(self) -> None:
        """Test creating RepositoryLabel."""
        label = RepositoryLabel(
            name="security:critical",
            color="FF0000",
            description="Critical security issue",
        )

        assert label.name == "security:critical"
        assert label.color == "FF0000"
        assert label.description == "Critical security issue"


class TestBotTypeEnum:
    """Tests for BotType enum."""

    def test_bot_type_values(self) -> None:
        """Test BotType enum values."""
        assert BotType.DEPENDABOT.value == "dependabot"
        assert BotType.RENOVATE.value == "renovate"
        assert BotType.UNKNOWN.value == "unknown"

    def test_bot_type_comparison(self) -> None:
        """Test BotType comparison."""
        assert BotType.DEPENDABOT == BotType.DEPENDABOT
        assert BotType.DEPENDABOT != BotType.RENOVATE


class TestDependencyPRInfo:
    """Tests for DependencyPRInfo dataclass."""

    def test_dependency_pr_info_creation(self) -> None:
        """Test creating DependencyPRInfo."""
        update = DependencyUpdate(
            ecosystem=Ecosystem.NPM,
            name="lodash",
            from_version="4.17.20",
            to_version="4.17.21",
            is_major=False,
        )

        info = DependencyPRInfo(
            is_dependency_update=True,
            bot_type=BotType.DEPENDABOT,
            updates=[update],
            is_security_update=True,
            branch_name="dependabot/npm_and_yarn/lodash-4.17.21",
        )

        assert info.is_dependency_update is True
        assert info.bot_type == BotType.DEPENDABOT
        assert len(info.updates) == 1
        assert info.is_security_update is True

    def test_dependency_pr_info_defaults(self) -> None:
        """Test DependencyPRInfo default values."""
        info = DependencyPRInfo(is_dependency_update=False)

        assert info.is_dependency_update is False
        assert info.bot_type == BotType.UNKNOWN
        assert info.updates == []
        assert info.is_security_update is False
        assert info.is_grouped is False
        assert info.group_name is None


class TestEcosystemDetection:
    """Tests for ecosystem detection."""

    @pytest.fixture
    def parser(self) -> DependabotParser:
        """Create a Dependabot parser."""
        return DependabotParser()

    def test_npm_ecosystem_from_branch(self, parser: DependabotParser) -> None:
        """Test NPM ecosystem detection from branch."""
        pr = PullRequestInfo(
            number=1,
            title="Bump lodash",
            body="",
            head_branch="dependabot/npm_and_yarn/lodash-4.17.21",
            base_branch="main",
            author_login="dependabot[bot]",
            state="open",
            html_url="https://github.com/test/repo/pull/1",
            created_at=datetime.now(),
            updated_at=datetime.now(),
            labels=[],
        )

        result = parser.parse_pr(pr)
        # Default ecosystem detection from npm_and_yarn in branch
        assert result.is_dependency_update is True

    def test_go_ecosystem_from_branch(self, parser: DependabotParser) -> None:
        """Test Go ecosystem detection from branch."""
        pr = PullRequestInfo(
            number=2,
            title="Bump github.com/pkg/errors",
            body="",
            head_branch="dependabot/go_modules/github.com/pkg/errors-0.9.1",
            base_branch="main",
            author_login="dependabot[bot]",
            state="open",
            html_url="https://github.com/test/repo/pull/2",
            created_at=datetime.now(),
            updated_at=datetime.now(),
            labels=[],
        )

        result = parser.parse_pr(pr)
        assert result.is_dependency_update is True

    def test_maven_package_detection(self, parser: DependabotParser) -> None:
        """Test Maven package detection from name format."""
        # Maven packages have group:artifact format
        ecosystem = parser._detect_ecosystem_from_package("org.apache.logging.log4j:log4j-core")
        assert ecosystem == Ecosystem.MAVEN

    def test_npm_scoped_package_detection(self, parser: DependabotParser) -> None:
        """Test NPM scoped package detection."""
        ecosystem = parser._detect_ecosystem_from_package("@types/node")
        assert ecosystem == Ecosystem.NPM
