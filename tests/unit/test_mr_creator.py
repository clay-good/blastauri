"""Tests for MR/PR creator module."""

import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

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
            action="create",
        )

        assert change.path == "terraform/waf/main.tf"
        assert change.content is not None
        assert change.action == "create"

    def test_file_change_modify(self) -> None:
        """Test file change for modification."""
        change = FileChange(
            path="terraform/waf/main.tf",
            content='resource "aws_wafv2_rule_group" { updated }',
            action="modify",
        )

        assert change.action == "modify"

    def test_file_change_delete(self) -> None:
        """Test file change for deletion."""
        change = FileChange(
            path="terraform/waf/obsolete.tf",
            content=None,
            action="delete",
        )

        assert change.action == "delete"
        assert change.content is None


class TestMrCreationConfig:
    """Tests for MrCreationConfig dataclass."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = MrCreationConfig()

        assert config.draft is False
        assert config.labels == []
        assert config.assignees == []
        assert config.auto_merge is False

    def test_custom_config(self) -> None:
        """Test custom configuration values."""
        config = MrCreationConfig(
            draft=True,
            labels=["security", "waf"],
            assignees=["user1", "user2"],
            auto_merge=True,
        )

        assert config.draft is True
        assert len(config.labels) == 2
        assert len(config.assignees) == 2
        assert config.auto_merge is True


class TestMrCreationResult:
    """Tests for MrCreationResult dataclass."""

    def test_successful_result(self) -> None:
        """Test successful MR creation result."""
        result = MrCreationResult(
            success=True,
            mr_url="https://gitlab.com/test/-/merge_requests/123",
            mr_id=123,
            branch_name="blastauri/waf-update-20240115",
        )

        assert result.success is True
        assert result.mr_url is not None
        assert result.mr_id == 123
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

        assert branch.startswith("blastauri/")
        assert len(branch) > 15

    def test_generate_branch_name_with_prefix(self, creator: MrCreator) -> None:
        """Test branch name generation with custom prefix."""
        branch = creator.generate_branch_name(prefix="waf-update")

        assert "waf-update" in branch
        assert branch.startswith("blastauri/")

    def test_generate_waf_update_title_new_rules(self, creator: MrCreator) -> None:
        """Test title generation for new rules."""
        title = creator.generate_waf_update_title(
            new_rules=["log4shell", "spring4shell"],
            removed_rules=[],
            promoted_rules=[],
        )

        assert "WAF" in title
        assert "2" in title or "rules" in title.lower()

    def test_generate_waf_update_title_mixed(self, creator: MrCreator) -> None:
        """Test title generation for mixed changes."""
        title = creator.generate_waf_update_title(
            new_rules=["log4shell"],
            removed_rules=["old-rule"],
            promoted_rules=["promoted-rule"],
        )

        assert "WAF" in title

    def test_generate_waf_update_title_no_changes(self, creator: MrCreator) -> None:
        """Test title generation with no changes."""
        title = creator.generate_waf_update_title(
            new_rules=[],
            removed_rules=[],
            promoted_rules=[],
        )

        assert "WAF" in title

    def test_generate_waf_update_description(self, creator: MrCreator) -> None:
        """Test description generation."""
        description = creator.generate_waf_update_description(
            new_rules=["log4shell", "spring4shell"],
            removed_rules=["old-rule"],
            promoted_rules=["promoted-rule"],
            terraform_files=["main.tf", "variables.tf"],
        )

        assert "## Summary" in description or "Summary" in description
        assert "log4shell" in description or "2" in description
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
    def waf_creator(self) -> WafMrCreator:
        """Create WafMrCreator instance."""
        return WafMrCreator()

    def test_create_waf_update_files(self, waf_creator: WafMrCreator) -> None:
        """Test creating file changes for WAF update."""
        terraform_content = {
            "main.tf": 'resource "aws_wafv2_rule_group" {}',
            "variables.tf": 'variable "scope" {}',
        }
        state_content = '{"version": 1, "rules": {}}'

        files = waf_creator.create_waf_update_files(
            terraform_content=terraform_content,
            state_content=state_content,
            output_dir="terraform/waf",
            state_dir=".blastauri",
        )

        assert len(files) == 3  # 2 terraform + 1 state
        paths = [f.path for f in files]
        assert "terraform/waf/main.tf" in paths
        assert "terraform/waf/variables.tf" in paths
        assert ".blastauri/waf-state.json" in paths

    def test_create_waf_update_files_with_existing(
        self, waf_creator: WafMrCreator
    ) -> None:
        """Test creating file changes with existing files to update."""
        terraform_content = {
            "main.tf": 'resource "aws_wafv2_rule_group" { updated }',
        }

        files = waf_creator.create_waf_update_files(
            terraform_content=terraform_content,
            state_content="{}",
            output_dir="terraform/waf",
            state_dir=".blastauri",
        )

        assert len(files) == 2


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
                action="create",
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
        assert result.mr_id == 123

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
                action="create",
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
        assert result.mr_id == 456


class TestBranchNaming:
    """Tests for branch naming conventions."""

    @pytest.fixture
    def creator(self) -> MrCreator:
        """Create MrCreator instance."""
        return MrCreator()

    def test_branch_name_format(self, creator: MrCreator) -> None:
        """Test branch name follows expected format."""
        branch = creator.generate_branch_name()

        # Should be in format: blastauri/{timestamp}
        parts = branch.split("/")
        assert len(parts) == 2
        assert parts[0] == "blastauri"

    def test_branch_name_uniqueness(self, creator: MrCreator) -> None:
        """Test that generated branch names are unique."""
        branches = set()
        for _ in range(10):
            branch = creator.generate_branch_name()
            branches.add(branch)

        # All should be unique (may fail very rarely due to timing)
        assert len(branches) >= 9

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
            new_rules=["rule1"],
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
            new_rules=["rule1"],
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
