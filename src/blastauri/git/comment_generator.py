"""Analysis comment generator for merge requests."""

from dataclasses import dataclass
from typing import Optional

from blastauri.core.models import (
    AnalysisReport,
    BreakingChange,
    CVE,
    ImpactedLocation,
    Severity,
    UpgradeImpact,
)


@dataclass
class CommentConfig:
    """Configuration for comment generation."""

    # Marker to identify bot comments
    marker: str = "<!-- blastauri-analysis -->"

    # Whether to include detailed breakdowns
    include_details: bool = True

    # Maximum number of impacted locations to show
    max_locations: int = 10

    # Maximum number of breaking changes to show
    max_breaking_changes: int = 10

    # Whether to include CVE information
    include_cves: bool = True

    # Whether to include AI review summary
    include_ai_review: bool = True

    # Whether to collapse sections
    use_collapsible: bool = True


# Severity to emoji mapping
SEVERITY_ICONS = {
    Severity.CRITICAL: "!!",
    Severity.HIGH: "!",
    Severity.MEDIUM: "~",
    Severity.LOW: "-",
    Severity.NONE: "-",
    Severity.UNKNOWN: "?",
}

# Severity to color mapping for labels
SEVERITY_COLORS = {
    Severity.CRITICAL: "#FF0000",
    Severity.HIGH: "#FF6600",
    Severity.MEDIUM: "#FFCC00",
    Severity.LOW: "#00CC00",
    Severity.NONE: "#00CC00",
    Severity.UNKNOWN: "#808080",
}


class CommentGenerator:
    """Generates analysis comments for merge requests."""

    def __init__(self, config: Optional[CommentConfig] = None):
        """Initialize the comment generator.

        Args:
            config: Optional comment configuration.
        """
        self._config = config or CommentConfig()

    def generate_analysis_comment(
        self,
        report: AnalysisReport,
        ai_review: Optional[str] = None,
    ) -> str:
        """Generate a complete analysis comment.

        Args:
            report: Analysis report.
            ai_review: Optional AI review summary.

        Returns:
            Formatted comment body.
        """
        sections: list[str] = []

        # Add marker for identification
        sections.append(self._config.marker)
        sections.append("")

        # Header
        sections.append("## Blastauri Dependency Analysis")
        sections.append("")

        # Summary section
        sections.append(self._generate_summary(report))
        sections.append("")

        # Upgrades section
        if report.upgrades:
            sections.append(self._generate_upgrades_section(report.upgrades))
            sections.append("")

        # CVE section
        if self._config.include_cves:
            cves_fixed = []
            for upgrade in report.upgrades:
                cves_fixed.extend(upgrade.cves_fixed)
            if cves_fixed:
                sections.append(self._generate_cves_section(cves_fixed))
                sections.append("")

        # AI Review section
        if self._config.include_ai_review and ai_review:
            sections.append(self._generate_ai_section(ai_review))
            sections.append("")

        # Recommendations section
        if report.recommendations:
            sections.append(self._generate_recommendations(report.recommendations))
            sections.append("")

        # Footer
        sections.append(self._generate_footer())

        return "\n".join(sections)

    def _generate_summary(self, report: AnalysisReport) -> str:
        """Generate summary section."""
        lines: list[str] = []

        # Overall status badge
        severity_icon = SEVERITY_ICONS.get(report.overall_severity, "?")
        status = self._get_status_text(report.overall_severity)

        lines.append(f"### Status: {status}")
        lines.append("")

        # Key metrics
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Risk Score | **{report.overall_risk_score}/100** |")
        lines.append(f"| Severity | **{report.overall_severity.value.upper()}** |")
        lines.append(f"| Packages Updated | {len(report.upgrades)} |")

        # Count breaking changes and impacted locations
        total_breaking = sum(len(u.breaking_changes) for u in report.upgrades)
        total_impacted = sum(len(u.impacted_locations) for u in report.upgrades)
        total_cves = sum(len(u.cves_fixed) for u in report.upgrades)

        lines.append(f"| Breaking Changes | {total_breaking} |")
        lines.append(f"| Impacted Locations | {total_impacted} |")
        lines.append(f"| CVEs Fixed | {total_cves} |")

        # Summary text
        if report.summary:
            lines.append("")
            lines.append(f"> {report.summary}")

        return "\n".join(lines)

    def _generate_upgrades_section(self, upgrades: list[UpgradeImpact]) -> str:
        """Generate upgrades breakdown section."""
        lines: list[str] = []

        lines.append("### Package Upgrades")
        lines.append("")

        for upgrade in upgrades:
            severity_icon = SEVERITY_ICONS.get(upgrade.severity, "?")
            major_badge = " (MAJOR)" if upgrade.is_major_upgrade else ""

            lines.append(
                f"#### {severity_icon} {upgrade.dependency_name} "
                f"`{upgrade.from_version}` -> `{upgrade.to_version}`{major_badge}"
            )
            lines.append("")

            # Risk score
            lines.append(f"- **Risk Score:** {upgrade.risk_score}/100 ({upgrade.severity.value})")

            # Breaking changes summary
            if upgrade.breaking_changes:
                lines.append(f"- **Breaking Changes:** {len(upgrade.breaking_changes)}")

                if self._config.include_details:
                    lines.append("")
                    lines.append(
                        self._generate_breaking_changes_details(upgrade.breaking_changes)
                    )

            # Impacted locations summary
            if upgrade.impacted_locations:
                files_affected = len(
                    set(loc.location.file_path for loc in upgrade.impacted_locations)
                )
                lines.append(
                    f"- **Impacted Locations:** {len(upgrade.impacted_locations)} "
                    f"in {files_affected} file(s)"
                )

                if self._config.include_details:
                    lines.append("")
                    lines.append(
                        self._generate_impacted_locations_details(upgrade.impacted_locations)
                    )

            # CVEs fixed
            if upgrade.cves_fixed:
                critical = sum(1 for c in upgrade.cves_fixed if c.severity == Severity.CRITICAL)
                high = sum(1 for c in upgrade.cves_fixed if c.severity == Severity.HIGH)

                cve_summary = f"{len(upgrade.cves_fixed)} CVE(s) fixed"
                if critical:
                    cve_summary += f" ({critical} critical)"
                elif high:
                    cve_summary += f" ({high} high)"

                lines.append(f"- **Security:** {cve_summary}")

            lines.append("")

        return "\n".join(lines)

    def _generate_breaking_changes_details(
        self,
        changes: list[BreakingChange],
    ) -> str:
        """Generate breaking changes details."""
        lines: list[str] = []

        if self._config.use_collapsible:
            lines.append("<details>")
            lines.append("<summary>Breaking Changes</summary>")
            lines.append("")

        displayed = changes[: self._config.max_breaking_changes]

        for change in displayed:
            lines.append(f"- **{change.change_type.value}:** {change.description}")

            if change.old_api and change.new_api:
                lines.append(f"  - `{change.old_api}` -> `{change.new_api}`")
            elif change.old_api:
                lines.append(f"  - Removed: `{change.old_api}`")

            if change.migration_guide:
                lines.append(f"  - Migration: {change.migration_guide}")

        if len(changes) > self._config.max_breaking_changes:
            remaining = len(changes) - self._config.max_breaking_changes
            lines.append(f"- ... and {remaining} more")

        if self._config.use_collapsible:
            lines.append("")
            lines.append("</details>")

        return "\n".join(lines)

    def _generate_impacted_locations_details(
        self,
        locations: list[ImpactedLocation],
    ) -> str:
        """Generate impacted locations details."""
        lines: list[str] = []

        if self._config.use_collapsible:
            lines.append("<details>")
            lines.append("<summary>Impacted Locations</summary>")
            lines.append("")

        # Group by file
        by_file: dict[str, list[ImpactedLocation]] = {}
        for loc in locations:
            by_file.setdefault(loc.location.file_path, []).append(loc)

        displayed_files = list(by_file.items())[: self._config.max_locations]

        for file_path, file_locations in displayed_files:
            lines.append(f"**`{file_path}`**")

            for loc in file_locations[:3]:  # Max 3 per file
                lines.append(
                    f"- Line {loc.location.line_number}: `{loc.location.code_snippet[:50]}...`"
                )

                if loc.suggested_fix:
                    lines.append(f"  - Fix: {loc.suggested_fix}")

            if len(file_locations) > 3:
                lines.append(f"- ... and {len(file_locations) - 3} more in this file")

            lines.append("")

        if len(by_file) > self._config.max_locations:
            remaining = len(by_file) - self._config.max_locations
            lines.append(f"... and {remaining} more files")

        if self._config.use_collapsible:
            lines.append("</details>")

        return "\n".join(lines)

    def _generate_cves_section(self, cves: list[CVE]) -> str:
        """Generate CVEs fixed section."""
        lines: list[str] = []

        lines.append("### Security Vulnerabilities Fixed")
        lines.append("")

        # Group by severity
        by_severity: dict[Severity, list[CVE]] = {}
        for cve in cves:
            by_severity.setdefault(cve.severity, []).append(cve)

        # Display in severity order
        severity_order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
        ]

        for severity in severity_order:
            severity_cves = by_severity.get(severity, [])
            if not severity_cves:
                continue

            lines.append(f"**{severity.value.upper()}**")

            for cve in severity_cves:
                score = f" (CVSS: {cve.cvss_score})" if cve.cvss_score else ""
                lines.append(f"- [{cve.id}](https://nvd.nist.gov/vuln/detail/{cve.id}){score}")
                lines.append(f"  - {cve.description[:100]}...")

            lines.append("")

        return "\n".join(lines)

    def _generate_ai_section(self, ai_review: str) -> str:
        """Generate AI review section."""
        lines: list[str] = []

        lines.append("### AI Analysis")
        lines.append("")

        if self._config.use_collapsible:
            lines.append("<details>")
            lines.append("<summary>Show AI Analysis</summary>")
            lines.append("")

        lines.append(ai_review)

        if self._config.use_collapsible:
            lines.append("")
            lines.append("</details>")

        return "\n".join(lines)

    def _generate_recommendations(self, recommendations: list[str]) -> str:
        """Generate recommendations section."""
        lines: list[str] = []

        lines.append("### Recommendations")
        lines.append("")

        for rec in recommendations:
            lines.append(f"- {rec}")

        return "\n".join(lines)

    def _generate_footer(self) -> str:
        """Generate comment footer."""
        return (
            "---\n"
            "*Generated by [Blastauri](https://github.com/clay-good/blastauri) - "
            "Dependency upgrade impact analysis*"
        )

    def _get_status_text(self, severity: Severity) -> str:
        """Get status text for severity."""
        if severity == Severity.CRITICAL:
            return "CRITICAL - Manual Review Required"
        elif severity == Severity.HIGH:
            return "HIGH RISK - Review Recommended"
        elif severity == Severity.MEDIUM:
            return "MODERATE RISK - Review Suggested"
        elif severity == Severity.LOW:
            return "LOW RISK - Safe to Merge"
        else:
            return "SAFE - No Issues Detected"

    def generate_simple_comment(
        self,
        risk_score: int,
        severity: Severity,
        breaking_changes_count: int,
        cves_fixed_count: int,
    ) -> str:
        """Generate a simple one-line comment.

        Args:
            risk_score: Risk score.
            severity: Overall severity.
            breaking_changes_count: Number of breaking changes.
            cves_fixed_count: Number of CVEs fixed.

        Returns:
            Simple comment text.
        """
        icon = SEVERITY_ICONS.get(severity, "?")
        status = self._get_status_text(severity)

        parts = [
            self._config.marker,
            f"**Blastauri Analysis:** {status}",
            f"Risk Score: {risk_score}/100",
        ]

        if breaking_changes_count:
            parts.append(f"Breaking Changes: {breaking_changes_count}")

        if cves_fixed_count:
            parts.append(f"CVEs Fixed: {cves_fixed_count}")

        return " | ".join(parts)


def generate_analysis_comment(
    report: AnalysisReport,
    ai_review: Optional[str] = None,
    config: Optional[CommentConfig] = None,
) -> str:
    """Convenience function to generate an analysis comment.

    Args:
        report: Analysis report.
        ai_review: Optional AI review summary.
        config: Optional comment configuration.

    Returns:
        Formatted comment body.
    """
    generator = CommentGenerator(config)
    return generator.generate_analysis_comment(report, ai_review)
