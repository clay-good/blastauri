"""Main merge request analyzer orchestrating all analysis components."""

import asyncio
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from blastauri.analysis.ai_reviewer import AIProvider, ai_review_upgrade
from blastauri.analysis.api_diff import ApiDiffAnalyzer
from blastauri.analysis.changelog_parser import (
    ChangelogParser,
    detect_breaking_changes_from_version,
)
from blastauri.analysis.heuristic_analyzer import HeuristicAnalyzer
from blastauri.analysis.impact_calculator import ImpactCalculator
from blastauri.analysis.known_breaking_changes import get_known_breaking_changes
from blastauri.analysis.package_metadata import PackageMetadataAnalyzer
from blastauri.analysis.usage_finder import UsageFinder
from blastauri.core.models import (
    AnalysisReport,
    BreakingChange,
    CVE,
    DependencyUpdate,
    Ecosystem,
    ImpactedLocation,
    Severity,
    UpgradeImpact,
)
from blastauri.cve.aggregator import CveAggregator
from blastauri.cve.waf_patterns import get_waf_pattern_id, is_waf_mitigatable
from blastauri.git.comment_generator import CommentConfig, CommentGenerator
from blastauri.git.gitlab_client import GitLabClient, MergeRequestInfo
from blastauri.git.label_manager import LabelManager, determine_labels_for_analysis
from blastauri.git.renovate_parser import RenovateMRInfo, RenovateParser


@dataclass
class AnalysisConfig:
    """Configuration for MR analysis."""

    # Whether to post comments
    post_comment: bool = True

    # Whether to apply labels
    apply_labels: bool = True

    # Whether to use AI review
    use_ai_review: bool = False

    # AI provider to use
    ai_provider: AIProvider = AIProvider.NONE

    # Severity threshold for failing CI
    severity_threshold: Severity = Severity.HIGH

    # Whether to analyze CVEs
    analyze_cves: bool = True

    # Whether to analyze breaking changes
    analyze_breaking_changes: bool = True

    # Whether to analyze code impact
    analyze_code_impact: bool = True

    # Clone repository for analysis
    clone_for_analysis: bool = True


@dataclass
class AnalysisResult:
    """Result of MR analysis."""

    report: AnalysisReport
    comment_body: Optional[str] = None
    labels_added: list[str] = field(default_factory=list)
    labels_removed: list[str] = field(default_factory=list)
    ai_review: Optional[str] = None
    should_block: bool = False
    error: Optional[str] = None


class MergeRequestAnalyzer:
    """Orchestrates analysis of merge requests."""

    def __init__(
        self,
        gitlab_client: GitLabClient,
        config: Optional[AnalysisConfig] = None,
    ):
        """Initialize the MR analyzer.

        Args:
            gitlab_client: GitLab client instance.
            config: Optional analysis configuration.
        """
        self._client = gitlab_client
        self._config = config or AnalysisConfig()
        self._renovate_parser = RenovateParser()
        self._changelog_parser = ChangelogParser()
        self._impact_calculator = ImpactCalculator()
        self._usage_finder = UsageFinder()
        self._label_manager = LabelManager(gitlab_client)
        self._comment_generator = CommentGenerator()

    async def analyze_mr(
        self,
        project_id: str | int,
        mr_iid: int,
        repository_path: Optional[Path] = None,
    ) -> AnalysisResult:
        """Analyze a merge request.

        Args:
            project_id: Project ID or path.
            mr_iid: Merge request IID.
            repository_path: Optional path to cloned repository.

        Returns:
            Analysis result.
        """
        try:
            # Get MR info
            mr_info = self._client.get_merge_request(project_id, mr_iid)

            # Check if it's a Renovate MR
            renovate_info = self._renovate_parser.parse_mr(mr_info)

            if not renovate_info.is_renovate:
                return AnalysisResult(
                    report=AnalysisReport(
                        merge_request_id=str(mr_iid),
                        repository=str(project_id),
                        summary="Not a Renovate MR - skipping analysis",
                    ),
                )

            # Get MR changes for ecosystem detection
            changes = self._client.get_mr_changes(project_id, mr_iid)
            renovate_info = self._renovate_parser.parse_mr(mr_info, changes)

            # Analyze each update
            upgrades: list[UpgradeImpact] = []

            for update in renovate_info.updates:
                upgrade_impact = await self._analyze_update(
                    update,
                    repository_path,
                )
                upgrades.append(upgrade_impact)

            # Calculate overall metrics
            overall_score, overall_severity = self._impact_calculator.calculate_overall_risk(
                upgrades
            )

            # Generate recommendations
            recommendations = self._generate_recommendations(upgrades, overall_severity)

            # Create report
            report = AnalysisReport(
                merge_request_id=str(mr_iid),
                repository=str(project_id),
                upgrades=upgrades,
                overall_risk_score=overall_score,
                overall_severity=overall_severity,
                summary=self._generate_summary(upgrades, overall_severity),
                recommendations=recommendations,
            )

            # AI review if enabled
            ai_review = None
            if self._config.use_ai_review and self._config.ai_provider != AIProvider.NONE:
                for upgrade in upgrades:
                    if upgrade.severity in (Severity.CRITICAL, Severity.HIGH):
                        review_result = await ai_review_upgrade(
                            upgrade,
                            repository_path or Path.cwd(),
                            self._config.ai_provider,
                        )
                        if review_result.summary:
                            ai_review = review_result.summary
                            break

            # Generate comment
            comment_body = None
            if self._config.post_comment:
                comment_body = self._comment_generator.generate_analysis_comment(
                    report, ai_review
                )

            # Determine labels
            labels_added: list[str] = []
            labels_removed: list[str] = []

            if self._config.apply_labels:
                total_breaking = sum(len(u.breaking_changes) for u in upgrades)
                total_cves = sum(len(u.cves_fixed) for u in upgrades)
                waf_mitigatable = sum(
                    1 for u in upgrades
                    for c in u.cves_fixed
                    if is_waf_mitigatable(c)
                )

                labels_added, labels_removed = determine_labels_for_analysis(
                    overall_severity,
                    total_breaking,
                    total_cves,
                    waf_mitigatable,
                )

            # Determine if should block
            should_block = self._should_block_mr(overall_severity)

            return AnalysisResult(
                report=report,
                comment_body=comment_body,
                labels_added=labels_added,
                labels_removed=labels_removed,
                ai_review=ai_review,
                should_block=should_block,
            )

        except Exception as e:
            return AnalysisResult(
                report=AnalysisReport(
                    merge_request_id=str(mr_iid),
                    repository=str(project_id),
                    summary=f"Analysis failed: {e}",
                ),
                error=str(e),
            )

    async def _analyze_update(
        self,
        update: DependencyUpdate,
        repository_path: Optional[Path],
    ) -> UpgradeImpact:
        """Analyze a single dependency update.

        Uses multiple detection strategies in priority order:
        1. Version analysis (major version = breaking)
        2. Known breaking changes database (curated, reliable)
        3. Package metadata analysis (deprecation, peer deps, engines)
        4. API diff analysis (compares actual exports)
        5. Heuristic analysis (size changes, file removals)
        6. Changelog parsing (fallback, less reliable)

        Args:
            update: Dependency update information.
            repository_path: Optional path to repository.

        Returns:
            Upgrade impact analysis.
        """
        breaking_changes: list[BreakingChange] = []
        impacted_locations: list[ImpactedLocation] = []
        cves_fixed: list[CVE] = []
        seen_descriptions: set[str] = set()

        def add_unique_changes(changes: list[BreakingChange]) -> None:
            """Add changes while avoiding duplicates."""
            for change in changes:
                if change.description not in seen_descriptions:
                    seen_descriptions.add(change.description)
                    breaking_changes.append(change)

        # 1. Detect major version breaking change (always runs, no network)
        version_changes = detect_breaking_changes_from_version(
            update.from_version, update.to_version
        )
        add_unique_changes(version_changes)

        if self._config.analyze_breaking_changes:
            # 2. Check known breaking changes database (most reliable, no network)
            known_changes = get_known_breaking_changes(
                update.ecosystem,
                update.name,
                update.from_version,
                update.to_version,
            )
            add_unique_changes(known_changes)

            # 3. Package metadata analysis (deprecation, peer deps, engines, exports)
            try:
                async with PackageMetadataAnalyzer() as meta_analyzer:
                    metadata_changes = await meta_analyzer.analyze_upgrade(
                        update.ecosystem,
                        update.name,
                        update.from_version,
                        update.to_version,
                    )
                    add_unique_changes(metadata_changes)
            except Exception:
                pass

            # 4. API diff analysis (compares actual package exports)
            try:
                async with ApiDiffAnalyzer() as api_analyzer:
                    api_changes = await api_analyzer.analyze_package(
                        update.ecosystem,
                        update.name,
                        update.from_version,
                        update.to_version,
                    )
                    add_unique_changes(api_changes)
            except Exception:
                pass

            # 5. Heuristic analysis (size, file count, export count changes)
            try:
                async with HeuristicAnalyzer() as heuristic_analyzer:
                    heuristic_result = await heuristic_analyzer.analyze(
                        update.ecosystem,
                        update.name,
                        update.from_version,
                        update.to_version,
                    )
                    add_unique_changes(heuristic_result.breaking_changes)
            except Exception:
                pass

            # 6. Changelog parsing (fallback for anything we missed)
            try:
                async with self._changelog_parser as parser:
                    changelog_changes = await parser.fetch_changelog(
                        update.ecosystem,
                        update.name,
                        update.from_version,
                        update.to_version,
                    )
                    add_unique_changes(changelog_changes)
            except Exception:
                pass

        # Find impacted locations in code
        if self._config.analyze_code_impact and repository_path and breaking_changes:
            impacted_locations = self._usage_finder.find_impacted_locations(
                repository_path,
                update.ecosystem,
                update.name,
                breaking_changes,
            )

        # Check for CVEs fixed
        if self._config.analyze_cves:
            try:
                async with CveAggregator() as aggregator:
                    # Get CVEs for old version
                    old_cves = await aggregator.find_vulnerabilities_for_package(
                        update.ecosystem,
                        update.name,
                        update.from_version,
                    )

                    # Get CVEs for new version
                    new_cves = await aggregator.find_vulnerabilities_for_package(
                        update.ecosystem,
                        update.name,
                        update.to_version,
                    )

                    # CVEs fixed = in old but not in new
                    new_cve_ids = {c.id for c in new_cves}
                    cves_fixed = [c for c in old_cves if c.id not in new_cve_ids]

                    # Mark WAF mitigatable
                    for cve in cves_fixed:
                        cve.is_waf_mitigatable = is_waf_mitigatable(cve)
                        cve.waf_pattern_id = get_waf_pattern_id(cve)

            except Exception:
                # Continue without CVE data if aggregator fails
                pass

        # Calculate impact
        return self._impact_calculator.calculate_upgrade_impact(
            dependency_name=update.name,
            ecosystem=update.ecosystem,
            from_version=update.from_version,
            to_version=update.to_version,
            breaking_changes=breaking_changes,
            impacted_locations=impacted_locations,
            cves_fixed=cves_fixed,
            is_major_upgrade=update.is_major,
        )

    def _generate_summary(
        self,
        upgrades: list[UpgradeImpact],
        severity: Severity,
    ) -> str:
        """Generate a summary for the analysis."""
        if not upgrades:
            return "No dependency updates to analyze."

        total_breaking = sum(len(u.breaking_changes) for u in upgrades)
        total_cves = sum(len(u.cves_fixed) for u in upgrades)

        if severity == Severity.CRITICAL:
            return (
                f"Critical risk detected: {total_breaking} breaking changes found. "
                "Manual review required before merging."
            )
        elif severity == Severity.HIGH:
            return (
                f"High risk: {total_breaking} breaking changes detected. "
                "Review recommended."
            )
        elif severity == Severity.MEDIUM:
            return (
                f"Moderate risk: {total_breaking} breaking changes. "
                f"{total_cves} CVEs would be fixed."
            )
        else:
            if total_cves:
                return f"Low risk upgrade. {total_cves} CVEs would be fixed."
            return "Low risk upgrade. No breaking changes detected."

    def _generate_recommendations(
        self,
        upgrades: list[UpgradeImpact],
        severity: Severity,
    ) -> list[str]:
        """Generate recommendations based on analysis."""
        recommendations: list[str] = []

        if severity in (Severity.CRITICAL, Severity.HIGH):
            recommendations.append(
                "Review all breaking changes before merging"
            )

        # Check for impacted locations
        total_impacted = sum(len(u.impacted_locations) for u in upgrades)
        if total_impacted > 0:
            recommendations.append(
                f"Update {total_impacted} code location(s) affected by breaking changes"
            )

        # Check for CVEs
        critical_cves = []
        for upgrade in upgrades:
            for cve in upgrade.cves_fixed:
                if cve.severity == Severity.CRITICAL:
                    critical_cves.append(cve)

        if critical_cves:
            recommendations.append(
                f"Prioritize this upgrade - fixes {len(critical_cves)} critical CVE(s)"
            )

        # Check for WAF availability
        waf_available = any(
            cve.is_waf_mitigatable
            for upgrade in upgrades
            for cve in upgrade.cves_fixed
        )

        if waf_available and severity in (Severity.CRITICAL, Severity.HIGH):
            recommendations.append(
                "Consider deploying WAF rules while preparing upgrade"
            )

        # Run tests
        if any(u.breaking_changes for u in upgrades):
            recommendations.append(
                "Run full test suite to verify no regressions"
            )

        return recommendations

    def _should_block_mr(self, severity: Severity) -> bool:
        """Determine if MR should be blocked based on severity."""
        severity_order = [
            Severity.LOW,
            Severity.NONE,
            Severity.UNKNOWN,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]

        threshold_idx = severity_order.index(self._config.severity_threshold)
        current_idx = severity_order.index(severity)

        return current_idx >= threshold_idx

    async def apply_analysis_result(
        self,
        project_id: str | int,
        mr_iid: int,
        result: AnalysisResult,
    ) -> None:
        """Apply analysis result to the MR.

        Args:
            project_id: Project ID or path.
            mr_iid: Merge request IID.
            result: Analysis result to apply.
        """
        # Post or update comment
        if result.comment_body and self._config.post_comment:
            existing_note = self._client.find_bot_comment(project_id, mr_iid)

            if existing_note:
                self._client.update_mr_comment(
                    project_id, mr_iid, existing_note, result.comment_body
                )
            else:
                self._client.post_mr_comment(
                    project_id, mr_iid, result.comment_body
                )

        # Apply labels
        if self._config.apply_labels:
            if result.labels_removed:
                self._client.remove_mr_labels(
                    project_id, mr_iid, result.labels_removed
                )
            if result.labels_added:
                # Ensure labels exist first
                for label_name in result.labels_added:
                    # Labels are created by label manager when needed
                    pass
                self._client.add_mr_labels(
                    project_id, mr_iid, result.labels_added
                )


async def analyze_renovate_mr(
    project_id: str | int,
    mr_iid: int,
    gitlab_token: Optional[str] = None,
    repository_path: Optional[Path] = None,
    config: Optional[AnalysisConfig] = None,
) -> AnalysisResult:
    """Convenience function to analyze a Renovate MR.

    Args:
        project_id: GitLab project ID or path.
        mr_iid: Merge request IID.
        gitlab_token: Optional GitLab token.
        repository_path: Optional path to cloned repository.
        config: Optional analysis configuration.

    Returns:
        Analysis result.
    """
    from blastauri.git.gitlab_client import GitLabConfig

    gitlab_config = GitLabConfig.from_env()
    if gitlab_token:
        gitlab_config.private_token = gitlab_token

    client = GitLabClient(gitlab_config)
    analyzer = MergeRequestAnalyzer(client, config)

    return await analyzer.analyze_mr(project_id, mr_iid, repository_path)
