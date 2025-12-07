"""Integration tests for GitLab MR analysis with mocked API responses."""

import json
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from blastauri.core.models import Severity
from blastauri.git.gitlab_client import (
    GitLabClient,
    MergeRequestChange,
    MergeRequestInfo,
)
from blastauri.git.mr_analyzer import AnalysisConfig, MergeRequestAnalyzer
from blastauri.git.renovate_parser import RenovateParser

# Load fixtures
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "api_responses"


def load_fixture(name: str) -> dict:
    """Load a JSON fixture file."""
    with open(FIXTURES_DIR / name) as f:
        return json.load(f)


class TestRenovateMRDetection:
    """Test Renovate MR detection logic."""

    def test_detect_renovate_mr_by_branch_prefix(self) -> None:
        """Test detection via renovate/ branch prefix."""
        mr_info = MergeRequestInfo(
            iid=42,
            title="Update dependency lodash to v5",
            description="Renovate update",
            source_branch="renovate/lodash-5.x",
            target_branch="main",
            author_username="some-user",  # Not a bot username
            state="opened",
            web_url="https://gitlab.com/test/project/-/merge_requests/42",
            created_at=datetime.now(),
            updated_at=datetime.now(),
        )

        parser = RenovateParser()
        result = parser.parse_mr(mr_info)

        assert result.is_renovate is True

    def test_detect_renovate_mr_by_bot_username(self) -> None:
        """Test detection via renovate bot username."""
        mr_info = MergeRequestInfo(
            iid=42,
            title="Update dependency lodash to v5",
            description="Renovate update",
            source_branch="feature/something",  # Not a renovate branch
            target_branch="main",
            author_username="renovate-bot",
            state="opened",
            web_url="https://gitlab.com/test/project/-/merge_requests/42",
            created_at=datetime.now(),
            updated_at=datetime.now(),
        )

        parser = RenovateParser()
        result = parser.parse_mr(mr_info)

        assert result.is_renovate is True

    def test_detect_non_renovate_mr(self) -> None:
        """Test that non-Renovate MRs are correctly identified."""
        mr_info = MergeRequestInfo(
            iid=42,
            title="Fix bug in authentication",
            description="Regular fix",
            source_branch="feature/auth-fix",
            target_branch="main",
            author_username="developer",
            state="opened",
            web_url="https://gitlab.com/test/project/-/merge_requests/42",
            created_at=datetime.now(),
            updated_at=datetime.now(),
        )

        parser = RenovateParser()
        result = parser.parse_mr(mr_info)

        assert result.is_renovate is False

    def test_parse_renovate_title_single_package(self) -> None:
        """Test parsing single package update from title."""
        mr_info = MergeRequestInfo(
            iid=42,
            title="Update dependency lodash to v5.0.0",
            description="",
            source_branch="renovate/lodash-5.x",
            target_branch="main",
            author_username="renovate-bot",
            state="opened",
            web_url="https://gitlab.com/test/project/-/merge_requests/42",
            created_at=datetime.now(),
            updated_at=datetime.now(),
        )

        parser = RenovateParser()
        result = parser.parse_mr(mr_info)

        assert result.is_renovate is True
        assert len(result.updates) >= 1
        # First update should be lodash
        lodash_update = next((u for u in result.updates if u.name == "lodash"), None)
        assert lodash_update is not None
        assert lodash_update.to_version == "5.0.0"

    def test_parse_renovate_title_with_from_version(self) -> None:
        """Test parsing title with from and to versions."""
        mr_info = MergeRequestInfo(
            iid=42,
            title="Update lodash from 4.17.21 to 5.0.0",
            description="",
            source_branch="renovate/lodash-5.x",
            target_branch="main",
            author_username="renovate-bot",
            state="opened",
            web_url="https://gitlab.com/test/project/-/merge_requests/42",
            created_at=datetime.now(),
            updated_at=datetime.now(),
        )

        parser = RenovateParser()
        result = parser.parse_mr(mr_info)

        assert result.is_renovate is True
        assert len(result.updates) >= 1
        lodash_update = next((u for u in result.updates if u.name == "lodash"), None)
        assert lodash_update is not None
        assert lodash_update.from_version == "4.17.21"
        assert lodash_update.to_version == "5.0.0"


class TestGitLabAnalysisWorkflow:
    """Test full GitLab analysis workflow with mocked API."""

    @pytest.fixture
    def mock_gitlab_client(self) -> MagicMock:
        """Create a mocked GitLab client."""
        client = MagicMock(spec=GitLabClient)

        # Load fixtures
        mr_data = load_fixture("gitlab_mr_renovate.json")
        changes_data = load_fixture("gitlab_mr_changes.json")

        # Create MergeRequestInfo from fixture
        mr_info = MergeRequestInfo(
            iid=mr_data["iid"],
            title=mr_data["title"],
            description=mr_data["description"],
            source_branch=mr_data["source_branch"],
            target_branch=mr_data["target_branch"],
            author_username=mr_data["author"]["username"],
            state=mr_data["state"],
            web_url=mr_data["web_url"],
            created_at=datetime.fromisoformat(mr_data["created_at"].replace("Z", "+00:00")),
            updated_at=datetime.fromisoformat(mr_data["updated_at"].replace("Z", "+00:00")),
            labels=mr_data["labels"],
            has_conflicts=mr_data["has_conflicts"],
            merge_status=mr_data["merge_status"],
        )

        # Create MergeRequestChange objects
        changes = [
            MergeRequestChange(
                old_path=c["old_path"],
                new_path=c["new_path"],
                a_mode=c["a_mode"],
                b_mode=c["b_mode"],
                new_file=c["new_file"],
                renamed_file=c["renamed_file"],
                deleted_file=c["deleted_file"],
                diff=c["diff"],
            )
            for c in changes_data["changes"]
        ]

        client.get_merge_request.return_value = mr_info
        client.get_mr_changes.return_value = changes

        return client

    @pytest.mark.asyncio
    async def test_full_analysis_workflow(self, mock_gitlab_client: MagicMock) -> None:
        """Test complete analysis workflow from MR fetch to result."""
        config = AnalysisConfig(
            post_comment=False,  # Don't actually post
            apply_labels=False,  # Don't actually apply
            use_ai_review=False,
        )

        analyzer = MergeRequestAnalyzer(mock_gitlab_client, config)

        # Run analysis
        result = await analyzer.analyze_mr("mygroup/myproject", 42)

        # Verify MR was fetched
        mock_gitlab_client.get_merge_request.assert_called_once_with("mygroup/myproject", 42)

        # Verify it was identified as Renovate
        assert result.report.merge_request_id == "42"

        # Verify we got an analysis (not skipped)
        assert "Not a Renovate MR" not in result.report.summary

    @pytest.mark.asyncio
    async def test_non_renovate_mr_skipped(self, mock_gitlab_client: MagicMock) -> None:
        """Test that non-Renovate MRs are skipped."""
        # Override to return non-Renovate MR
        mock_gitlab_client.get_merge_request.return_value = MergeRequestInfo(
            iid=99,
            title="Regular feature",
            description="Not a dependency update",
            source_branch="feature/new-thing",
            target_branch="main",
            author_username="developer",
            state="opened",
            web_url="https://gitlab.com/test/project/-/merge_requests/99",
            created_at=datetime.now(),
            updated_at=datetime.now(),
        )

        config = AnalysisConfig(post_comment=False, apply_labels=False)
        analyzer = MergeRequestAnalyzer(mock_gitlab_client, config)

        result = await analyzer.analyze_mr("mygroup/myproject", 99)

        assert "Not a Renovate MR" in result.report.summary


class TestLabelDetermination:
    """Test label determination based on analysis results."""

    def test_labels_for_breaking_changes(self) -> None:
        """Test that breaking changes get appropriate labels."""
        from blastauri.git.label_manager import determine_labels_for_analysis

        labels_add, labels_remove = determine_labels_for_analysis(
            severity=Severity.HIGH,
            breaking_changes_count=3,
            cves_fixed_count=0,
            waf_mitigatable_count=0,
        )

        assert "blastauri:breaking" in labels_add
        assert "blastauri:safe" in labels_remove

    def test_labels_for_security_critical(self) -> None:
        """Test that critical CVEs get security labels."""
        from blastauri.git.label_manager import determine_labels_for_analysis

        labels_add, labels_remove = determine_labels_for_analysis(
            severity=Severity.CRITICAL,
            breaking_changes_count=0,
            cves_fixed_count=2,
            waf_mitigatable_count=1,
        )

        assert "security:critical" in labels_add
        assert "blastauri:waf-available" in labels_add

    def test_labels_for_safe_update(self) -> None:
        """Test that safe updates get safe label."""
        from blastauri.git.label_manager import determine_labels_for_analysis

        labels_add, labels_remove = determine_labels_for_analysis(
            severity=Severity.LOW,
            breaking_changes_count=0,
            cves_fixed_count=0,
            waf_mitigatable_count=0,
        )

        assert "blastauri:safe" in labels_add


class TestCommentGeneration:
    """Test MR comment generation."""

    def test_generate_analysis_comment(self) -> None:
        """Test that analysis comments are properly formatted."""
        from blastauri.core.models import AnalysisReport, Ecosystem, UpgradeImpact
        from blastauri.git.comment_generator import CommentGenerator

        report = AnalysisReport(
            merge_request_id="42",
            repository="mygroup/myproject",
            upgrades=[
                UpgradeImpact(
                    dependency_name="lodash",
                    ecosystem=Ecosystem.NPM,
                    from_version="4.17.21",
                    to_version="5.0.0",
                    is_major_upgrade=True,
                    breaking_changes=[],
                    impacted_locations=[],
                    cves_fixed=[],
                    risk_score=45,
                    severity=Severity.MEDIUM,
                )
            ],
            overall_risk_score=45,
            overall_severity=Severity.MEDIUM,
            summary="1 dependency update analyzed",
            recommendations=["Review breaking changes before merging"],
        )

        generator = CommentGenerator()
        comment = generator.generate_analysis_comment(report)

        # Verify comment structure
        assert "Blastauri" in comment
        assert "lodash" in comment
        assert "4.17.21" in comment
        assert "5.0.0" in comment
        assert "MEDIUM" in comment.upper() or "45" in comment
