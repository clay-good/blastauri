"""Impact calculator for computing upgrade risk scores."""

from dataclasses import dataclass
from typing import Optional

from blastauri.core.models import (
    BreakingChange,
    BreakingChangeType,
    CVE,
    Ecosystem,
    ImpactedLocation,
    Severity,
    UpgradeImpact,
)


@dataclass
class RiskScoreWeights:
    """Weights for risk score calculation."""

    # Impacted locations scoring (0-30 points)
    max_location_points: int = 30
    locations_threshold_high: int = 20  # 20+ locations = max points
    locations_threshold_medium: int = 10  # 10+ locations = 2/3 max
    locations_threshold_low: int = 5  # 5+ locations = 1/3 max

    # Breaking change severity scoring (0-30 points)
    max_breaking_change_points: int = 30
    removed_function_weight: int = 8
    removed_class_weight: int = 10
    removed_module_weight: int = 10
    changed_signature_weight: int = 6
    renamed_export_weight: int = 5
    changed_default_weight: int = 4
    changed_behavior_weight: int = 5
    deprecated_weight: int = 2
    major_version_weight: int = 3

    # Major version upgrade points (0-20 points)
    max_major_version_points: int = 20

    # CVE deduction (-10 points)
    cve_deduction: int = 10


@dataclass
class BreakingChangeSeverity:
    """Severity classification for a breaking change."""

    change: BreakingChange
    severity: Severity
    points: int
    explanation: str


class ImpactCalculator:
    """Calculates risk scores and severity for dependency upgrades."""

    def __init__(self, weights: Optional[RiskScoreWeights] = None):
        """Initialize the impact calculator.

        Args:
            weights: Optional custom weights for scoring.
        """
        self._weights = weights or RiskScoreWeights()

    def calculate_upgrade_impact(
        self,
        dependency_name: str,
        ecosystem: Ecosystem,
        from_version: str,
        to_version: str,
        breaking_changes: list[BreakingChange],
        impacted_locations: list[ImpactedLocation],
        cves_fixed: list[CVE],
        is_major_upgrade: bool,
    ) -> UpgradeImpact:
        """Calculate the full impact of a dependency upgrade.

        Args:
            dependency_name: Name of the dependency.
            ecosystem: Package ecosystem.
            from_version: Current version.
            to_version: Target version.
            breaking_changes: Detected breaking changes.
            impacted_locations: Code locations impacted.
            cves_fixed: CVEs that would be fixed.
            is_major_upgrade: Whether this is a major version bump.

        Returns:
            Complete upgrade impact analysis.
        """
        # Calculate component scores
        location_score = self._calculate_location_score(impacted_locations)
        breaking_score = self._calculate_breaking_change_score(breaking_changes)
        major_score = self._calculate_major_version_score(is_major_upgrade)
        cve_deduction = self._calculate_cve_deduction(cves_fixed)

        # Combine scores
        raw_score = location_score + breaking_score + major_score - cve_deduction
        risk_score = max(0, min(100, raw_score))

        # Determine severity from score
        severity = self._score_to_severity(risk_score)

        return UpgradeImpact(
            dependency_name=dependency_name,
            ecosystem=ecosystem,
            from_version=from_version,
            to_version=to_version,
            is_major_upgrade=is_major_upgrade,
            breaking_changes=breaking_changes,
            impacted_locations=impacted_locations,
            cves_fixed=cves_fixed,
            risk_score=risk_score,
            severity=severity,
        )

    def _calculate_location_score(
        self,
        impacted_locations: list[ImpactedLocation],
    ) -> int:
        """Calculate score based on impacted locations.

        Args:
            impacted_locations: List of impacted code locations.

        Returns:
            Score between 0 and max_location_points.
        """
        w = self._weights
        count = len(impacted_locations)

        if count == 0:
            return 0
        elif count >= w.locations_threshold_high:
            return w.max_location_points
        elif count >= w.locations_threshold_medium:
            return int(w.max_location_points * 2 / 3)
        elif count >= w.locations_threshold_low:
            return int(w.max_location_points / 3)
        else:
            # Scale linearly for small counts
            return int(count * (w.max_location_points / 3) / w.locations_threshold_low)

    def _calculate_breaking_change_score(
        self,
        breaking_changes: list[BreakingChange],
    ) -> int:
        """Calculate score based on breaking changes.

        Args:
            breaking_changes: List of breaking changes.

        Returns:
            Score between 0 and max_breaking_change_points.
        """
        if not breaking_changes:
            return 0

        w = self._weights
        total_weight = 0

        for change in breaking_changes:
            total_weight += self._get_change_weight(change.change_type)

        # Cap at maximum
        return min(total_weight, w.max_breaking_change_points)

    def _get_change_weight(self, change_type: BreakingChangeType) -> int:
        """Get weight for a breaking change type.

        Args:
            change_type: Type of breaking change.

        Returns:
            Weight value.
        """
        w = self._weights

        weights_map = {
            BreakingChangeType.REMOVED_FUNCTION: w.removed_function_weight,
            BreakingChangeType.REMOVED_CLASS: w.removed_class_weight,
            BreakingChangeType.REMOVED_MODULE: w.removed_module_weight,
            BreakingChangeType.CHANGED_SIGNATURE: w.changed_signature_weight,
            BreakingChangeType.RENAMED_EXPORT: w.renamed_export_weight,
            BreakingChangeType.CHANGED_DEFAULT: w.changed_default_weight,
            BreakingChangeType.CHANGED_BEHAVIOR: w.changed_behavior_weight,
            BreakingChangeType.DEPRECATED: w.deprecated_weight,
            BreakingChangeType.MAJOR_VERSION: w.major_version_weight,
        }

        return weights_map.get(change_type, 3)

    def _calculate_major_version_score(self, is_major: bool) -> int:
        """Calculate score for major version upgrade.

        Args:
            is_major: Whether upgrade is a major version bump.

        Returns:
            Score (0 or max_major_version_points).
        """
        return self._weights.max_major_version_points if is_major else 0

    def _calculate_cve_deduction(self, cves_fixed: list[CVE]) -> int:
        """Calculate deduction for CVEs that would be fixed.

        Args:
            cves_fixed: List of CVEs fixed by upgrade.

        Returns:
            Deduction amount (positive number).
        """
        if not cves_fixed:
            return 0

        # Deduct more for critical/high CVEs
        deduction = 0
        for cve in cves_fixed:
            if cve.severity in (Severity.CRITICAL, Severity.HIGH):
                deduction += self._weights.cve_deduction
            else:
                deduction += self._weights.cve_deduction // 2

        return deduction

    def _score_to_severity(self, score: int) -> Severity:
        """Convert risk score to severity level.

        Args:
            score: Risk score (0-100).

        Returns:
            Severity level.
        """
        if score >= 80:
            return Severity.CRITICAL
        elif score >= 60:
            return Severity.HIGH
        elif score >= 40:
            return Severity.MEDIUM
        else:
            return Severity.LOW

    def classify_breaking_change(
        self,
        change: BreakingChange,
    ) -> BreakingChangeSeverity:
        """Classify the severity of a single breaking change.

        Args:
            change: Breaking change to classify.

        Returns:
            Severity classification.
        """
        weight = self._get_change_weight(change.change_type)

        # Map weight to severity
        if weight >= 8:
            severity = Severity.CRITICAL
            explanation = "This change removes core functionality and will likely break your code."
        elif weight >= 6:
            severity = Severity.HIGH
            explanation = "This change modifies important APIs and may require code updates."
        elif weight >= 4:
            severity = Severity.MEDIUM
            explanation = "This change affects behavior but may not require immediate updates."
        else:
            severity = Severity.LOW
            explanation = "This change has minimal impact and can be addressed gradually."

        return BreakingChangeSeverity(
            change=change,
            severity=severity,
            points=weight,
            explanation=explanation,
        )

    def calculate_overall_risk(
        self,
        upgrades: list[UpgradeImpact],
    ) -> tuple[int, Severity]:
        """Calculate overall risk from multiple upgrades.

        Args:
            upgrades: List of upgrade impacts.

        Returns:
            Tuple of (overall_score, overall_severity).
        """
        if not upgrades:
            return 0, Severity.LOW

        # Use highest risk among upgrades
        max_score = max(u.risk_score for u in upgrades)
        max_severity = self._score_to_severity(max_score)

        # Also consider cumulative impact
        total_locations = sum(len(u.impacted_locations) for u in upgrades)
        total_breaking = sum(len(u.breaking_changes) for u in upgrades)

        # Bonus for multiple high-impact upgrades
        critical_count = sum(
            1 for u in upgrades if u.severity in (Severity.CRITICAL, Severity.HIGH)
        )

        if critical_count > 1:
            max_score = min(100, max_score + (critical_count - 1) * 5)
            max_severity = self._score_to_severity(max_score)

        return max_score, max_severity

    def generate_risk_summary(
        self,
        upgrade: UpgradeImpact,
    ) -> str:
        """Generate a human-readable risk summary.

        Args:
            upgrade: Upgrade impact analysis.

        Returns:
            Summary string.
        """
        parts: list[str] = []

        # Header
        parts.append(
            f"Upgrading {upgrade.dependency_name} from {upgrade.from_version} "
            f"to {upgrade.to_version}"
        )

        # Severity and score
        parts.append(f"Risk: {upgrade.severity.value.upper()} (score: {upgrade.risk_score}/100)")

        # Key stats
        if upgrade.is_major_upgrade:
            parts.append("- Major version upgrade")

        if upgrade.breaking_changes:
            parts.append(f"- {len(upgrade.breaking_changes)} breaking change(s) detected")

        if upgrade.impacted_locations:
            files_count = len(set(loc.location.file_path for loc in upgrade.impacted_locations))
            parts.append(
                f"- {len(upgrade.impacted_locations)} code location(s) in {files_count} file(s) affected"
            )

        if upgrade.cves_fixed:
            critical_cves = [c for c in upgrade.cves_fixed if c.severity == Severity.CRITICAL]
            if critical_cves:
                parts.append(f"- Fixes {len(critical_cves)} critical CVE(s)")
            parts.append(f"- Total {len(upgrade.cves_fixed)} CVE(s) fixed")

        return "\n".join(parts)


def calculate_risk_score(
    impacted_locations: list[ImpactedLocation],
    breaking_changes: list[BreakingChange],
    is_major_upgrade: bool,
    cves_fixed: list[CVE],
) -> int:
    """Convenience function to calculate risk score.

    Args:
        impacted_locations: List of impacted locations.
        breaking_changes: List of breaking changes.
        is_major_upgrade: Whether this is a major version bump.
        cves_fixed: CVEs that would be fixed.

    Returns:
        Risk score (0-100).
    """
    calculator = ImpactCalculator()
    impact = calculator.calculate_upgrade_impact(
        dependency_name="",
        ecosystem=Ecosystem.NPM,  # Doesn't affect calculation
        from_version="",
        to_version="",
        breaking_changes=breaking_changes,
        impacted_locations=impacted_locations,
        cves_fixed=cves_fixed,
        is_major_upgrade=is_major_upgrade,
    )
    return impact.risk_score


def classify_severity(risk_score: int) -> Severity:
    """Convenience function to classify severity from score.

    Args:
        risk_score: Risk score (0-100).

    Returns:
        Severity level.
    """
    calculator = ImpactCalculator()
    return calculator._score_to_severity(risk_score)
