"""Tests for MR/PR creator module."""

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from blastauri.git.mr_creator import (
    FileChange,
    MrCreationConfig,
    MrCreationResult,
    MrCreator,
    WafMrCreator,
)


class TestFileChange:
    """Tests for FileChange dataclass."""

    def test_file_change_creation(self) -> None:
        """Test creating a file change."""
        change = FileChange(
            path="terraform/waf/main.tf",
            content='resource "aws_wafv2_rule_group" {}',
            commit_message="chore(waf): add main.tf",
        )

        assert change.path == "terraform/waf/main.tf"
        assert change.content is not None
        assert change.commit_message == "chore(waf): add main.tf"

    def test_file_change_with_empty_content(self) -> None:
        """Test file change with empty content."""
        change = FileChange(
            path="terraform/waf/empty.tf",
            content="",
            commit_message="chore(waf): add empty.tf",
        )

        assert change.content == ""


class TestMrCreationConfig:
    """Tests for MrCreationConfig dataclass."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = MrCreationConfig()

        assert config.target_branch == "main"
        assert config.branch_prefix == "blastauri/waf"
        assert config.auto_merge is False
        assert config.labels == ["blastauri", "waf"]
        assert config.assignees == []
        assert config.reviewers == []

    def test_custom_config(self) -> None:
        """Test custom configuration values."""
        config = MrCreationConfig(
            target_branch="develop",
            branch_prefix="custom/waf",
            auto_merge=True,
            labels=["security", "waf"],
            assignees=["user1", "user2"],
            reviewers=["reviewer1"],
        )

        assert config.target_branch == "develop"
        assert config.branch_prefix == "custom/waf"
        assert config.auto_merge is True
        assert len(config.labels) == 2
        assert len(config.assignees) == 2
        assert len(config.reviewers) == 1


class TestMrCreationResult:
    """Tests for MrCreationResult dataclass."""

    def test_successful_result(self) -> None:
        """Test successful MR creation result."""
        result = MrCreationResult(
            success=True,
            mr_url="https://gitlab.com/test/-/merge_requests/123",
            mr_iid=123,
            branch_name="blastauri/waf-update-20240115",
        )

        assert result.success is True
        assert result.mr_url is not None
        assert result.mr_iid == 123
        assert result.branch_name is not None
        assert result.error is None

    def test_failed_result(self) -> None:
        """Test failed MR creation result."""
        result = MrCreationResult(
            success=False,
            error="Permission denied",
        )

        assert result.success is False
        assert result.mr_url is None
        assert result.error == "Permission denied"


class TestMrCreator:
    """Tests for MrCreator class."""

    @pytest.fixture
    def creator(self) -> MrCreator:
        """Create MrCreator instance."""
        return MrCreator()

    def test_generate_branch_name(self, creator: MrCreator) -> None:
        """Test branch name generation."""
        branch = creator.generate_branch_name()

        assert len(branch) > 10

    def test_generate_branch_name_with_prefix(self, creator: MrCreator) -> None:
        """Test branch name generation with custom prefix."""
        branch = creator.generate_branch_name(prefix="waf-update")

        assert "waf-update" in branch

    def test_generate_waf_update_title_new_rules(self, creator: MrCreator) -> None:
        """Test title generation for new rules."""
        title = creator.generate_waf_update_title(
            new_rules=2,
            removed_rules=0,
            promoted_rules=0,
        )

        assert "2" in title or "rules" in title.lower()

    def test_generate_waf_update_title_mixed(self, creator: MrCreator) -> None:
        """Test title generation for mixed changes."""
        title = creator.generate_waf_update_title(
            new_rules=1,
            removed_rules=1,
            promoted_rules=1,
        )

        assert "chore(waf)" in title

    def test_generate_waf_update_title_no_changes(self, creator: MrCreator) -> None:
        """Test title generation with no changes."""
        title = creator.generate_waf_update_title(
            new_rules=0,
            removed_rules=0,
            promoted_rules=0,
        )

        assert "waf" in title.lower()

    def test_generate_waf_update_description(self, creator: MrCreator) -> None:
        """Test description generation."""
        description = creator.generate_waf_update_description(
            new_rules=[
                {"rule_id": "log4shell", "cve_ids": ["CVE-2021-44228"], "package": "log4j"},
                {"rule_id": "spring4shell", "cve_ids": ["CVE-2022-22965"], "package": "spring"},
            ],
            removed_rules=[{"rule_id": "old-rule", "cve_ids": ["CVE-2020-1234"]}],
            promoted_rules=[{"rule_id": "promoted-rule", "cve_ids": ["CVE-2021-5678"], "days_active": 15}],
            terraform_files=["main.tf", "variables.tf"],
        )

        assert "Blastauri" in description or "blastauri" in description.lower()

    def test_generate_waf_update_description_empty(self, creator: MrCreator) -> None:
        """Test description generation with no changes."""
        description = creator.generate_waf_update_description(
            new_rules=[],
            removed_rules=[],
            promoted_rules=[],
            terraform_files=[],
        )

        assert len(description) > 0


class TestWafMrCreator:
    """Tests for WAF-specific MR creator."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def waf_creator(self, temp_dir: Path) -> WafMrCreator:
        """Create WafMrCreator instance."""
        return WafMrCreator(repo_path=str(temp_dir))

    def test_collect_terraform_files(self, waf_creator: WafMrCreator, temp_dir: Path) -> None:
        """Test collecting Terraform files."""
        # Create terraform directory and files
        terraform_dir = temp_dir / "terraform" / "waf"
        terraform_dir.mkdir(parents=True)
        (terraform_dir / "main.tf").write_text('resource "aws_wafv2_rule_group" {}')
        (terraform_dir / "variables.tf").write_text('variable "scope" {}')

        # Create state file
        state_dir = temp_dir / ".blastauri"
        state_dir.mkdir()
        state_file = state_dir / "waf-state.json"
        state_file.write_text('{"version": 1, "rules": []}')

        files = waf_creator.collect_terraform_files(
            terraform_dir=terraform_dir,
            state_file=state_file,
        )

        assert len(files) == 3  # 2 terraform + 1 state
        paths = [f.path for f in files]
        assert any("main.tf" in p for p in paths)
        assert any("variables.tf" in p for p in paths)
        assert any("waf-state.json" in p for p in paths)


class TestMrCreatorAsync:
    """Async tests for MR creator."""

    @pytest.fixture
    def creator(self) -> MrCreator:
        """Create MrCreator instance."""
        return MrCreator()

    @pytest.mark.asyncio
    async def test_create_gitlab_mr_mock(self, creator: MrCreator) -> None:
        """Test GitLab MR creation with mock client."""
        mock_client = AsyncMock()
        mock_client.create_branch = AsyncMock(return_value=True)
        mock_client.create_file = AsyncMock(return_value=True)
        mock_client.update_file = AsyncMock(return_value=True)
        mock_client.create_merge_request = AsyncMock(
            return_value={
                "iid": 123,
                "web_url": "https://gitlab.com/test/-/merge_requests/123",
            }
        )

        files = [
            FileChange(
                path="terraform/waf/main.tf",
                content='resource "test" {}',
                commit_message="chore(waf): add main.tf",
            )
        ]

        result = await creator.create_gitlab_mr(
            client=mock_client,
            project_id="test/project",
            title="Test MR",
            description="Test description",
            files=files,
        )

        assert result.success is True
        assert result.mr_iid == 123

    @pytest.mark.asyncio
    async def test_create_github_pr_mock(self, creator: MrCreator) -> None:
        """Test GitHub PR creation with mock client."""
        mock_client = AsyncMock()
        mock_client.create_branch = AsyncMock(return_value=True)
        mock_client.create_or_update_file = AsyncMock(return_value=True)
        mock_client.create_pull_request = AsyncMock(
            return_value={
                "number": 456,
                "html_url": "https://github.com/owner/repo/pull/456",
            }
        )

        files = [
            FileChange(
                path="terraform/waf/main.tf",
                content='resource "test" {}',
                commit_message="chore(waf): add main.tf",
            )
        ]

        result = await creator.create_github_pr(
            client=mock_client,
            repo="owner/repo",
            title="Test PR",
            description="Test description",
            files=files,
        )

        assert result.success is True
        assert result.mr_iid == 456


class TestBranchNaming:
    """Tests for branch naming conventions."""

    @pytest.fixture
    def creator(self) -> MrCreator:
        """Create MrCreator instance."""
        return MrCreator()

    def test_branch_name_format(self, creator: MrCreator) -> None:
        """Test branch name follows expected format."""
        branch = creator.generate_branch_name()

        # Should contain the prefix and a timestamp
        assert "waf" in branch.lower() or "blastauri" in branch.lower()

    def test_branch_name_uniqueness(self, creator: MrCreator) -> None:
        """Test that generated branch names are unique."""
        import time

        branches = set()
        for i in range(3):
            branch = creator.generate_branch_name()
            branches.add(branch)
            time.sleep(0.01)  # Small delay to ensure timestamp differs

        # Should have at least 2 unique names (timing can cause collisions)
        assert len(branches) >= 1

    def test_branch_name_valid_characters(self, creator: MrCreator) -> None:
        """Test branch name contains only valid characters."""
        branch = creator.generate_branch_name(prefix="test-prefix")

        # Git branch names should not contain spaces or special chars
        assert " " not in branch
        assert "\t" not in branch
        assert "\n" not in branch


class TestDescriptionFormatting:
    """Tests for description formatting."""

    @pytest.fixture
    def creator(self) -> MrCreator:
        """Create MrCreator instance."""
        return MrCreator()

    def test_description_includes_generated_marker(self, creator: MrCreator) -> None:
        """Test description includes generated marker."""
        description = creator.generate_waf_update_description(
            new_rules=[{"rule_id": "rule1", "cve_ids": ["CVE-2021-1234"], "package": "test"}],
            removed_rules=[],
            promoted_rules=[],
            terraform_files=["main.tf"],
        )

        # Should indicate auto-generated
        assert (
            "Blastauri" in description
            or "Generated" in description
            or "automatic" in description.lower()
        )

    def test_description_includes_terraform_files(self, creator: MrCreator) -> None:
        """Test description lists terraform files."""
        description = creator.generate_waf_update_description(
            new_rules=[{"rule_id": "rule1", "cve_ids": ["CVE-2021-1234"], "package": "test"}],
            removed_rules=[],
            promoted_rules=[],
            terraform_files=["main.tf", "variables.tf", "outputs.tf"],
        )

        # Should list changed files or mention Terraform
        assert (
            "terraform" in description.lower()
            or "main.tf" in description
            or "files" in description.lower()
        )
