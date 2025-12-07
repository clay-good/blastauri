"""Tests for GitLab integration and Renovate MR analysis."""

from datetime import datetime

import pytest

from blastauri.core.models import (
    CVE,
    AnalysisReport,
    BreakingChange,
    BreakingChangeType,
    Ecosystem,
    ImpactedLocation,
    Severity,
    UpgradeImpact,
    UsageLocation,
)
from blastauri.git.comment_generator import (
    CommentConfig,
    CommentGenerator,
    generate_analysis_comment,
)
from blastauri.git.gitlab_client import (
    MergeRequestChange,
    MergeRequestInfo,
)
from blastauri.git.label_manager import (
    BLASTAURI_LABELS,
    SECURITY_LABELS,
    determine_labels_for_analysis,
)
from blastauri.git.renovate_parser import (
    RenovateParser,
    UpdateType,
    is_renovate_branch,
    parse_renovate_mr,
)


class TestRenovateParser:
    """Tests for Renovate MR parsing."""

    @pytest.fixture
    def parser(self) -> RenovateParser:
        """Create a Renovate parser."""
        return RenovateParser()

    @pytest.fixture
    def renovate_mr(self) -> MergeRequestInfo:
        """Create a sample Renovate MR."""
        return MergeRequestInfo(
            iid=123,
            title="Update dependency lodash to v4.17.21",
            description="This PR updates lodash from 4.17.20 to 4.17.21.",
            source_branch="renovate/lodash-4.x",
            target_branch="main",
            author_username="renovate[bot]",
            state="opened",
            web_url="https://gitlab.com/group/project/-/merge_requests/123",
            created_at=datetime.now(),
            updated_at=datetime.now(),
            labels=[],
        )

    @pytest.fixture
    def non_renovate_mr(self) -> MergeRequestInfo:
        """Create a non-Renovate MR."""
        return MergeRequestInfo(
            iid=456,
            title="Add new feature",
            description="This PR adds a new feature.",
            source_branch="feature/new-feature",
            target_branch="main",
            author_username="developer",
            state="opened",
            web_url="https://gitlab.com/group/project/-/merge_requests/456",
            created_at=datetime.now(),
            updated_at=datetime.now(),
            labels=[],
        )

    def test_is_renovate_mr_by_author(
        self, parser: RenovateParser, renovate_mr: MergeRequestInfo
    ) -> None:
        """Test detecting Renovate MR by author."""
        assert parser.is_renovate_mr(renovate_mr) is True

    def test_is_renovate_mr_by_branch(self, parser: RenovateParser) -> None:
        """Test detecting Renovate MR by branch name."""
        mr = MergeRequestInfo(
            iid=789,
            title="Some title",
            description="",
            source_branch="renovate/react-monorepo",
            target_branch="main",
            author_username="some-user",
            state="opened",
            web_url="https://gitlab.com/group/project/-/merge_requests/789",
            created_at=datetime.now(),
            updated_at=datetime.now(),
            labels=[],
        )
        assert parser.is_renovate_mr(mr) is True

    def test_is_not_renovate_mr(
        self, parser: RenovateParser, non_renovate_mr: MergeRequestInfo
    ) -> None:
        """Test non-Renovate MR detection."""
        assert parser.is_renovate_mr(non_renovate_mr) is False

    def test_parse_title_single_update(
        self, parser: RenovateParser, renovate_mr: MergeRequestInfo
    ) -> None:
        """Test parsing single package update from title."""
        result = parser.parse_mr(renovate_mr)

        assert result.is_renovate is True
        assert len(result.updates) >= 1

        update = result.updates[0]
        assert update.name == "lodash"
        assert update.to_version == "4.17.21"

    def test_parse_title_from_to_format(self, parser: RenovateParser) -> None:
        """Test parsing 'from X to Y' title format."""
        mr = MergeRequestInfo(
            iid=100,
            title="Update axios from v0.21.0 to v0.21.4",
            description="",
            source_branch="renovate/axios-0.x",
            target_branch="main",
            author_username="renovate[bot]",
            state="opened",
            web_url="https://gitlab.com/test/-/merge_requests/100",
            created_at=datetime.now(),
            updated_at=datetime.now(),
            labels=[],
        )

        result = parser.parse_mr(mr)

        assert result.is_renovate is True
        assert len(result.updates) >= 1
        assert result.updates[0].from_version == "0.21.0"
        assert result.updates[0].to_version == "0.21.4"

    def test_parse_description_table(self, parser: RenovateParser) -> None:
        """Test parsing update table from description."""
        mr = MergeRequestInfo(
            iid=101,
            title="Update multiple packages",
            description="""
            | Package | From | To | Change |
            |---------|------|-----|--------|
            | lodash | 4.17.20 | 4.17.21 | patch |
            | axios | 0.21.0 | 0.21.4 | patch |
            """,
            source_branch="renovate/multi-update",
            target_branch="main",
            author_username="renovate[bot]",
            state="opened",
            web_url="https://gitlab.com/test/-/merge_requests/101",
            created_at=datetime.now(),
            updated_at=datetime.now(),
            labels=[],
        )

        result = parser.parse_mr(mr)

        assert result.is_renovate is True
        assert len(result.updates) >= 2

    def test_detect_major_update(self, parser: RenovateParser) -> None:
        """Test detecting major version update."""
        mr = MergeRequestInfo(
            iid=102,
            title="Update react to v18.0.0 (major)",
            description="",
            source_branch="renovate/react-18.x",
            target_branch="main",
            author_username="renovate[bot]",
            state="opened",
            web_url="https://gitlab.com/test/-/merge_requests/102",
            created_at=datetime.now(),
            updated_at=datetime.now(),
            labels=[],
        )

        result = parser.parse_mr(mr)

        assert result.update_type == UpdateType.MAJOR

    def test_detect_grouped_update(self, parser: RenovateParser) -> None:
        """Test detecting grouped/monorepo updates."""
        mr = MergeRequestInfo(
            iid=103,
            title="Update react monorepo",
            description="",
            source_branch="renovate/react-monorepo",
            target_branch="main",
            author_username="renovate[bot]",
            state="opened",
            web_url="https://gitlab.com/test/-/merge_requests/103",
            created_at=datetime.now(),
            updated_at=datetime.now(),
            labels=[],
        )

        result = parser.parse_mr(mr)

        assert result.is_grouped is True
        assert result.group_name == "react-monorepo"

    def test_is_renovate_branch_function(self) -> None:
        """Test is_renovate_branch convenience function."""
        assert is_renovate_branch("renovate/lodash") is True
        assert is_renovate_branch("renovate-lodash") is True
        assert is_renovate_branch("feature/new-feature") is False
        assert is_renovate_branch("dependabot/npm/lodash") is False

    def test_detect_ecosystem_from_lockfile(self, parser: RenovateParser) -> None:
        """Test ecosystem detection from changed files."""
        mr = MergeRequestInfo(
            iid=104,
            title="Update dependency",
            description="",
            source_branch="renovate/dep",
            target_branch="main",
            author_username="renovate[bot]",
            state="opened",
            web_url="https://gitlab.com/test/-/merge_requests/104",
            created_at=datetime.now(),
            updated_at=datetime.now(),
            labels=[],
        )

        changes = [
            MergeRequestChange(
                old_path="package-lock.json",
                new_path="package-lock.json",
                a_mode="100644",
                b_mode="100644",
                new_file=False,
                renamed_file=False,
                deleted_file=False,
                diff="...",
            )
        ]

        result = parser.parse_mr(mr, changes)
        # Should detect NPM ecosystem from package-lock.json
        assert result.is_renovate is True


class TestCommentGenerator:
    """Tests for comment generation."""

    @pytest.fixture
    def generator(self) -> CommentGenerator:
        """Create a comment generator."""
        return CommentGenerator()

    @pytest.fixture
    def sample_report(self) -> AnalysisReport:
        """Create a sample analysis report."""
        breaking_change = BreakingChange(
            change_type=BreakingChangeType.REMOVED_FUNCTION,
            description="Function `oldFunc` has been removed",
            old_api="oldFunc",
            new_api="newFunc",
            source="changelog",
        )

        location = UsageLocation(
            file_path="src/app.py",
            line_number=42,
            column=10,
            code_snippet="result = oldFunc(data)",
            usage_type="call",
            symbol="oldFunc",
        )

        impacted = ImpactedLocation(
            location=location,
            breaking_change=breaking_change,
            confidence=0.9,
            suggested_fix="Replace `oldFunc` with `newFunc`",
        )

        cve = CVE(
            id="CVE-2021-44228",
            description="Log4j vulnerability",
            severity=Severity.CRITICAL,
            cvss_score=10.0,
            source="nvd",
        )

        upgrade = UpgradeImpact(
            dependency_name="test-lib",
            ecosystem=Ecosystem.PYPI,
            from_version="1.0.0",
            to_version="2.0.0",
            is_major_upgrade=True,
            breaking_changes=[breaking_change],
            impacted_locations=[impacted],
            cves_fixed=[cve],
            risk_score=75,
            severity=Severity.HIGH,
        )

        return AnalysisReport(
            merge_request_id="123",
            repository="group/project",
            upgrades=[upgrade],
            overall_risk_score=75,
            overall_severity=Severity.HIGH,
            summary="High risk upgrade with breaking changes",
            recommendations=["Review breaking changes", "Run tests"],
        )

    def test_generate_comment_includes_marker(
        self, generator: CommentGenerator, sample_report: AnalysisReport
    ) -> None:
        """Test that comment includes identification marker."""
        comment = generator.generate_analysis_comment(sample_report)

        assert "<!-- blastauri-analysis -->" in comment

    def test_generate_comment_includes_summary(
        self, generator: CommentGenerator, sample_report: AnalysisReport
    ) -> None:
        """Test that comment includes summary section."""
        comment = generator.generate_analysis_comment(sample_report)

        assert "Risk Score" in comment
        assert "75" in comment
        assert "HIGH" in comment

    def test_generate_comment_includes_upgrades(
        self, generator: CommentGenerator, sample_report: AnalysisReport
    ) -> None:
        """Test that comment includes upgrade details."""
        comment = generator.generate_analysis_comment(sample_report)

        assert "test-lib" in comment
        assert "1.0.0" in comment
        assert "2.0.0" in comment

    def test_generate_comment_includes_breaking_changes(
        self, generator: CommentGenerator, sample_report: AnalysisReport
    ) -> None:
        """Test that comment includes breaking changes."""
        comment = generator.generate_analysis_comment(sample_report)

        assert "Breaking Changes" in comment
        assert "oldFunc" in comment

    def test_generate_comment_includes_cves(
        self, generator: CommentGenerator, sample_report: AnalysisReport
    ) -> None:
        """Test that comment includes CVE information."""
        comment = generator.generate_analysis_comment(sample_report)

        assert "CVE-2021-44228" in comment
        assert "CRITICAL" in comment

    def test_generate_comment_includes_recommendations(
        self, generator: CommentGenerator, sample_report: AnalysisReport
    ) -> None:
        """Test that comment includes recommendations."""
        comment = generator.generate_analysis_comment(sample_report)

        assert "Recommendations" in comment
        assert "Review breaking changes" in comment

    def test_generate_comment_with_ai_review(
        self, generator: CommentGenerator, sample_report: AnalysisReport
    ) -> None:
        """Test comment generation with AI review."""
        ai_review = "This upgrade appears safe based on code analysis."
        comment = generator.generate_analysis_comment(sample_report, ai_review)

        assert "AI Analysis" in comment
        assert ai_review in comment

    def test_generate_simple_comment(self, generator: CommentGenerator) -> None:
        """Test simple one-line comment generation."""
        comment = generator.generate_simple_comment(
            risk_score=50,
            severity=Severity.MEDIUM,
            breaking_changes_count=2,
            cves_fixed_count=1,
        )

        assert "<!-- blastauri-analysis -->" in comment
        assert "50" in comment
        assert "Breaking Changes: 2" in comment
        assert "CVEs Fixed: 1" in comment

    def test_custom_config(self) -> None:
        """Test comment generator with custom config."""
        config = CommentConfig(
            marker="<!-- custom-marker -->",
            include_details=False,
            use_collapsible=False,
        )
        generator = CommentGenerator(config)

        report = AnalysisReport(
            merge_request_id="1",
            repository="test",
            overall_risk_score=0,
            overall_severity=Severity.LOW,
        )

        comment = generator.generate_analysis_comment(report)
        assert "<!-- custom-marker -->" in comment


class TestLabelManager:
    """Tests for label management."""

    def test_security_labels_defined(self) -> None:
        """Test that all security labels are defined."""
        assert Severity.CRITICAL in SECURITY_LABELS
        assert Severity.HIGH in SECURITY_LABELS
        assert Severity.MEDIUM in SECURITY_LABELS
        assert Severity.LOW in SECURITY_LABELS

    def test_blastauri_labels_defined(self) -> None:
        """Test that all blastauri labels are defined."""
        assert "breaking" in BLASTAURI_LABELS
        assert "safe" in BLASTAURI_LABELS
        assert "needs-review" in BLASTAURI_LABELS
        assert "waf-available" in BLASTAURI_LABELS

    def test_label_colors(self) -> None:
        """Test that labels have valid colors."""
        for label in SECURITY_LABELS.values():
            assert label.color.startswith("#")
            assert len(label.color) == 7

        for label in BLASTAURI_LABELS.values():
            assert label.color.startswith("#")
            assert len(label.color) == 7

    def test_determine_labels_critical_severity(self) -> None:
        """Test label determination for critical severity."""
        add, remove = determine_labels_for_analysis(
            severity=Severity.CRITICAL,
            breaking_changes_count=5,
            cves_fixed_count=2,
            waf_mitigatable_count=1,
        )

        assert "security:critical" in add
        assert "blastauri:breaking" in add
        assert "blastauri:needs-review" in add
        assert "blastauri:waf-available" in add
        assert "blastauri:safe" in remove

    def test_determine_labels_low_severity_no_breaking(self) -> None:
        """Test label determination for low severity without breaking changes."""
        add, remove = determine_labels_for_analysis(
            severity=Severity.LOW,
            breaking_changes_count=0,
            cves_fixed_count=1,
            waf_mitigatable_count=0,
        )

        assert "security:low" in add
        assert "blastauri:safe" in add
        assert "blastauri:breaking" in remove
        assert "blastauri:needs-review" in remove
        assert "blastauri:waf-available" in remove


class TestMergeRequestInfo:
    """Tests for MergeRequestInfo dataclass."""

    def test_merge_request_info_creation(self) -> None:
        """Test creating MergeRequestInfo."""
        now = datetime.now()
        mr = MergeRequestInfo(
            iid=1,
            title="Test MR",
            description="Description",
            source_branch="feature/test",
            target_branch="main",
            author_username="user",
            state="opened",
            web_url="https://gitlab.com/test/-/merge_requests/1",
            created_at=now,
            updated_at=now,
            labels=["label1", "label2"],
        )

        assert mr.iid == 1
        assert mr.title == "Test MR"
        assert len(mr.labels) == 2

    def test_merge_request_change_creation(self) -> None:
        """Test creating MergeRequestChange."""
        change = MergeRequestChange(
            old_path="old/path.py",
            new_path="new/path.py",
            a_mode="100644",
            b_mode="100644",
            new_file=False,
            renamed_file=True,
            deleted_file=False,
            diff="@@ -1,3 +1,3 @@",
        )

        assert change.old_path == "old/path.py"
        assert change.renamed_file is True


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_parse_renovate_mr_function(self) -> None:
        """Test parse_renovate_mr convenience function."""
        mr = MergeRequestInfo(
            iid=1,
            title="Update lodash to v4.17.21",
            description="",
            source_branch="renovate/lodash",
            target_branch="main",
            author_username="renovate[bot]",
            state="opened",
            web_url="https://gitlab.com/test/-/merge_requests/1",
            created_at=datetime.now(),
            updated_at=datetime.now(),
            labels=[],
        )

        result = parse_renovate_mr(mr)

        assert result.is_renovate is True
        assert len(result.updates) >= 1

    def test_generate_analysis_comment_function(self) -> None:
        """Test generate_analysis_comment convenience function."""
        report = AnalysisReport(
            merge_request_id="1",
            repository="test",
            overall_risk_score=50,
            overall_severity=Severity.MEDIUM,
        )

        comment = generate_analysis_comment(report)

        assert "<!-- blastauri-analysis -->" in comment
        assert "Blastauri" in comment
