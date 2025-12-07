"""WAF rule lifecycle management.

This module tracks WAF rules and manages their lifecycle:
- Tracks which rules are deployed and why
- Detects when rules become obsolete (vulnerability patched)
- Identifies rules ready for promotion (log -> block)
"""

import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from blastauri.core.models import CVE, Dependency
from blastauri.waf.providers.base import WafProviderType


@dataclass
class RuleTrigger:
    """Information about what triggered a WAF rule creation."""

    ecosystem: str
    package: str
    version: str
    detected_at: str


@dataclass
class WafRuleState:
    """State of a single WAF rule."""

    rule_id: str
    cve_ids: list[str]
    created_at: str
    mode: str  # "log" or "block"
    provider: str
    triggered_by: RuleTrigger
    status: str  # "active", "obsolete", "promoted"
    last_triggered: str | None = None
    promoted_at: str | None = None
    notes: str = ""

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "rule_id": self.rule_id,
            "cve_ids": self.cve_ids,
            "created_at": self.created_at,
            "mode": self.mode,
            "provider": self.provider,
            "triggered_by": {
                "ecosystem": self.triggered_by.ecosystem,
                "package": self.triggered_by.package,
                "version": self.triggered_by.version,
                "detected_at": self.triggered_by.detected_at,
            },
            "status": self.status,
            "last_triggered": self.last_triggered,
            "promoted_at": self.promoted_at,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "WafRuleState":
        """Create from dictionary."""
        trigger_data = data.get("triggered_by", {})
        return cls(
            rule_id=data["rule_id"],
            cve_ids=data.get("cve_ids", []),
            created_at=data["created_at"],
            mode=data.get("mode", "log"),
            provider=data.get("provider", "aws"),
            triggered_by=RuleTrigger(
                ecosystem=trigger_data.get("ecosystem", ""),
                package=trigger_data.get("package", ""),
                version=trigger_data.get("version", ""),
                detected_at=trigger_data.get("detected_at", ""),
            ),
            status=data.get("status", "active"),
            last_triggered=data.get("last_triggered"),
            promoted_at=data.get("promoted_at"),
            notes=data.get("notes", ""),
        )


@dataclass
class WafState:
    """Complete WAF state for a repository."""

    version: int
    generated_at: str
    rules: list[WafRuleState]
    provider: str = "aws"
    last_sync: str | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "version": self.version,
            "generated_at": self.generated_at,
            "provider": self.provider,
            "last_sync": self.last_sync,
            "rules": [r.to_dict() for r in self.rules],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "WafState":
        """Create from dictionary."""
        return cls(
            version=data.get("version", 1),
            generated_at=data["generated_at"],
            provider=data.get("provider", "aws"),
            last_sync=data.get("last_sync"),
            rules=[WafRuleState.from_dict(r) for r in data.get("rules", [])],
        )

    @classmethod
    def empty(cls, provider: str = "aws") -> "WafState":
        """Create empty state."""
        return cls(
            version=1,
            generated_at=datetime.utcnow().isoformat() + "Z",
            rules=[],
            provider=provider,
        )

    def get_active_rules(self) -> list[WafRuleState]:
        """Get all active rules."""
        return [r for r in self.rules if r.status == "active"]

    def get_rule_by_id(self, rule_id: str) -> WafRuleState | None:
        """Get a rule by ID."""
        for rule in self.rules:
            if rule.rule_id == rule_id:
                return rule
        return None

    def get_rules_for_cve(self, cve_id: str) -> list[WafRuleState]:
        """Get all rules protecting against a CVE."""
        return [r for r in self.rules if cve_id in r.cve_ids]


@dataclass
class LifecycleChange:
    """A proposed change to WAF rule state."""

    change_type: str  # "add", "remove", "promote"
    rule_id: str
    cve_ids: list[str]
    reason: str
    rule_state: WafRuleState | None = None


@dataclass
class LifecycleAnalysis:
    """Result of lifecycle analysis."""

    new_rules: list[LifecycleChange]
    obsolete_rules: list[LifecycleChange]
    promotion_candidates: list[LifecycleChange]
    unchanged_rules: list[WafRuleState]
    summary: str


class WafLifecycleManager:
    """Manages WAF rule lifecycle.

    Tracks rules, detects obsolete rules, and identifies promotion candidates.
    """

    STATE_FILE_NAME = "waf-state.json"
    STATE_DIR = ".blastauri"
    DEFAULT_PROMOTION_DAYS = 14

    def __init__(
        self,
        repo_path: str,
        provider: WafProviderType = WafProviderType.AWS,
        promotion_days: int = DEFAULT_PROMOTION_DAYS,
    ) -> None:
        """Initialize the lifecycle manager.

        Args:
            repo_path: Path to the repository.
            provider: WAF provider type.
            promotion_days: Days before rules are eligible for promotion.
        """
        self._repo_path = Path(repo_path)
        self._provider = provider
        self._promotion_days = promotion_days
        self._state_path = self._repo_path / self.STATE_DIR / self.STATE_FILE_NAME

    @property
    def state_file_path(self) -> Path:
        """Get the path to the state file."""
        return self._state_path

    def load_state(self) -> WafState:
        """Load WAF state from file.

        Returns:
            Current WAF state or empty state if file doesn't exist.
        """
        if not self._state_path.exists():
            return WafState.empty(self._provider.value)

        try:
            with open(self._state_path) as f:
                data = json.load(f)
            return WafState.from_dict(data)
        except (json.JSONDecodeError, KeyError, TypeError):
            return WafState.empty(self._provider.value)

    def save_state(self, state: WafState) -> None:
        """Save WAF state to file.

        Args:
            state: State to save.
        """
        # Update timestamp
        state.generated_at = datetime.utcnow().isoformat() + "Z"
        state.last_sync = state.generated_at

        # Ensure directory exists
        self._state_path.parent.mkdir(parents=True, exist_ok=True)

        # Write state
        with open(self._state_path, "w") as f:
            json.dump(state.to_dict(), f, indent=2)

    def analyze_lifecycle(
        self,
        current_state: WafState,
        dependencies: list[Dependency],
        detected_cves: list[CVE],
        fixed_versions: dict[str, str],
    ) -> LifecycleAnalysis:
        """Analyze the current lifecycle state.

        Args:
            current_state: Current WAF state.
            dependencies: Current dependencies in the repository.
            detected_cves: CVEs detected in current dependencies.
            fixed_versions: Map of CVE ID to fixed version.

        Returns:
            Analysis with proposed changes.
        """
        new_rules: list[LifecycleChange] = []
        obsolete_rules: list[LifecycleChange] = []
        promotion_candidates: list[LifecycleChange] = []
        unchanged_rules: list[WafRuleState] = []

        # Build lookup of current CVEs
        current_cve_ids = {cve.id for cve in detected_cves}

        # Check existing rules for obsolescence
        for rule in current_state.get_active_rules():
            is_obsolete = self._check_rule_obsolete(
                rule, dependencies, fixed_versions
            )

            if is_obsolete:
                obsolete_rules.append(
                    LifecycleChange(
                        change_type="remove",
                        rule_id=rule.rule_id,
                        cve_ids=rule.cve_ids,
                        reason="Vulnerable package has been patched to a safe version",
                        rule_state=rule,
                    )
                )
            elif self._is_promotion_candidate(rule):
                promotion_candidates.append(
                    LifecycleChange(
                        change_type="promote",
                        rule_id=rule.rule_id,
                        cve_ids=rule.cve_ids,
                        reason=f"Rule has been in log mode for {self._promotion_days}+ days",
                        rule_state=rule,
                    )
                )
            else:
                unchanged_rules.append(rule)

        # Check for new rules needed
        existing_cve_coverage = set()
        for rule in current_state.get_active_rules():
            existing_cve_coverage.update(rule.cve_ids)

        for cve in detected_cves:
            if cve.is_waf_mitigatable and cve.id not in existing_cve_coverage:
                # Find which dependency triggered this
                trigger = self._find_trigger_dependency(cve, dependencies)

                new_rule = WafRuleState(
                    rule_id=f"blastauri-{cve.id.lower().replace('-', '')}",
                    cve_ids=[cve.id],
                    created_at=datetime.utcnow().isoformat() + "Z",
                    mode="log",
                    provider=self._provider.value,
                    triggered_by=trigger,
                    status="active",
                )

                new_rules.append(
                    LifecycleChange(
                        change_type="add",
                        rule_id=new_rule.rule_id,
                        cve_ids=new_rule.cve_ids,
                        reason=f"New WAF-mitigatable vulnerability detected: {cve.id}",
                        rule_state=new_rule,
                    )
                )

        # Generate summary
        summary = self._generate_summary(
            new_rules, obsolete_rules, promotion_candidates, unchanged_rules
        )

        return LifecycleAnalysis(
            new_rules=new_rules,
            obsolete_rules=obsolete_rules,
            promotion_candidates=promotion_candidates,
            unchanged_rules=unchanged_rules,
            summary=summary,
        )

    def _check_rule_obsolete(
        self,
        rule: WafRuleState,
        dependencies: list[Dependency],
        fixed_versions: dict[str, str],
    ) -> bool:
        """Check if a rule is obsolete.

        A rule is obsolete if:
        - The triggering package is no longer in dependencies
        - The triggering package is at a fixed version

        Args:
            rule: Rule to check.
            dependencies: Current dependencies.
            fixed_versions: Map of CVE ID to fixed version.

        Returns:
            True if rule is obsolete.
        """
        trigger = rule.triggered_by

        # Find the package in current dependencies
        matching_dep = None
        for dep in dependencies:
            if (
                dep.name == trigger.package
                and dep.ecosystem.value == trigger.ecosystem
            ):
                matching_dep = dep
                break

        if matching_dep is None:
            # Package no longer in dependencies - rule is obsolete
            return True

        # Check if current version is fixed for all CVEs
        for cve_id in rule.cve_ids:
            fixed_version = fixed_versions.get(cve_id)
            if fixed_version:
                if self._version_is_patched(
                    matching_dep.version, fixed_version
                ):
                    continue
                else:
                    # Not patched yet
                    return False
            else:
                # No fixed version known - assume still vulnerable
                return False

        return True

    def _version_is_patched(
        self,
        current_version: str,
        fixed_version: str,
    ) -> bool:
        """Check if current version is at or above fixed version.

        Simple semver comparison - production would need more sophisticated
        version comparison per ecosystem.

        Args:
            current_version: Current package version.
            fixed_version: Version that fixes the vulnerability.

        Returns:
            True if current version is patched.
        """
        try:
            current_parts = [
                int(p) for p in current_version.split(".")[:3]
                if p.isdigit()
            ]
            fixed_parts = [
                int(p) for p in fixed_version.split(".")[:3]
                if p.isdigit()
            ]

            # Pad to same length
            while len(current_parts) < 3:
                current_parts.append(0)
            while len(fixed_parts) < 3:
                fixed_parts.append(0)

            return current_parts >= fixed_parts
        except (ValueError, AttributeError):
            # If parsing fails, assume not patched
            return False

    def _is_promotion_candidate(self, rule: WafRuleState) -> bool:
        """Check if a rule is ready for promotion.

        A rule is ready for promotion if:
        - It's in log mode
        - It's been active for promotion_days or more

        Args:
            rule: Rule to check.

        Returns:
            True if rule is ready for promotion.
        """
        if rule.mode != "log":
            return False

        try:
            created = datetime.fromisoformat(
                rule.created_at.replace("Z", "+00:00")
            )
            threshold = datetime.now(created.tzinfo) - timedelta(
                days=self._promotion_days
            )
            return created < threshold
        except (ValueError, TypeError):
            return False

    def _find_trigger_dependency(
        self,
        cve: CVE,
        dependencies: list[Dependency],
    ) -> RuleTrigger:
        """Find which dependency triggered a CVE.

        Args:
            cve: CVE to find trigger for.
            dependencies: Current dependencies.

        Returns:
            RuleTrigger with dependency info.
        """
        for affected in cve.affected_packages:
            for dep in dependencies:
                if (
                    dep.name.lower() == affected.name.lower()
                    and dep.ecosystem.value == affected.ecosystem.lower()
                ):
                    return RuleTrigger(
                        ecosystem=dep.ecosystem.value,
                        package=dep.name,
                        version=dep.version,
                        detected_at=datetime.utcnow().isoformat() + "Z",
                    )

        # Fallback - use first affected package
        if cve.affected_packages:
            affected = cve.affected_packages[0]
            return RuleTrigger(
                ecosystem=affected.ecosystem.lower(),
                package=affected.name,
                version="unknown",
                detected_at=datetime.utcnow().isoformat() + "Z",
            )

        return RuleTrigger(
            ecosystem="unknown",
            package="unknown",
            version="unknown",
            detected_at=datetime.utcnow().isoformat() + "Z",
        )

    def _generate_summary(
        self,
        new_rules: list[LifecycleChange],
        obsolete_rules: list[LifecycleChange],
        promotion_candidates: list[LifecycleChange],
        unchanged_rules: list[WafRuleState],
    ) -> str:
        """Generate a summary of lifecycle analysis.

        Args:
            new_rules: New rules to add.
            obsolete_rules: Rules to remove.
            promotion_candidates: Rules ready for promotion.
            unchanged_rules: Unchanged rules.

        Returns:
            Summary string.
        """
        parts = []

        total = (
            len(new_rules)
            + len(obsolete_rules)
            + len(promotion_candidates)
            + len(unchanged_rules)
        )

        parts.append(f"WAF Rule Lifecycle Analysis: {total} total rules")

        if new_rules:
            parts.append(f"  - {len(new_rules)} new rules to add")
        if obsolete_rules:
            parts.append(f"  - {len(obsolete_rules)} obsolete rules to remove")
        if promotion_candidates:
            parts.append(
                f"  - {len(promotion_candidates)} rules ready for promotion"
            )
        if unchanged_rules:
            parts.append(f"  - {len(unchanged_rules)} rules unchanged")

        if not new_rules and not obsolete_rules and not promotion_candidates:
            parts.append("  No changes recommended")

        return "\n".join(parts)

    def apply_changes(
        self,
        state: WafState,
        analysis: LifecycleAnalysis,
    ) -> WafState:
        """Apply lifecycle changes to state.

        Args:
            state: Current state.
            analysis: Analysis with changes to apply.

        Returns:
            Updated state.
        """
        # Add new rules
        for change in analysis.new_rules:
            if change.rule_state:
                state.rules.append(change.rule_state)

        # Mark obsolete rules
        for change in analysis.obsolete_rules:
            rule = state.get_rule_by_id(change.rule_id)
            if rule:
                rule.status = "obsolete"

        # Note: Promotions are suggestions - not automatically applied
        # They require explicit user action

        return state

    def promote_rule(
        self,
        state: WafState,
        rule_id: str,
    ) -> WafRuleState | None:
        """Promote a rule from log to block mode.

        Args:
            state: Current state.
            rule_id: ID of rule to promote.

        Returns:
            Updated rule or None if not found.
        """
        rule = state.get_rule_by_id(rule_id)
        if rule and rule.mode == "log":
            rule.mode = "block"
            rule.promoted_at = datetime.utcnow().isoformat() + "Z"
            rule.status = "promoted"
            return rule
        return None

    def find_obsolete_rules(
        self,
        state: WafState,
        dependencies: list[Dependency],
    ) -> list[WafRuleState]:
        """Find obsolete rules.

        Args:
            state: Current WAF state.
            dependencies: Current dependencies.

        Returns:
            List of obsolete rules.
        """
        obsolete: list[WafRuleState] = []

        for rule in state.get_active_rules():
            trigger = rule.triggered_by

            # Check if triggering package still exists
            found = False
            for dep in dependencies:
                if (
                    dep.name == trigger.package
                    and dep.ecosystem.value == trigger.ecosystem
                ):
                    found = True
                    break

            if not found:
                obsolete.append(rule)

        return obsolete

    def find_promotion_candidates(
        self,
        state: WafState,
        min_days: int | None = None,
    ) -> list[WafRuleState]:
        """Find rules ready for promotion.

        Args:
            state: Current WAF state.
            min_days: Minimum days before promotion (default: promotion_days).

        Returns:
            List of rules ready for promotion.
        """
        if min_days is None:
            min_days = self._promotion_days

        candidates: list[WafRuleState] = []

        for rule in state.get_active_rules():
            if rule.mode != "log":
                continue

            try:
                created = datetime.fromisoformat(
                    rule.created_at.replace("Z", "+00:00")
                )
                threshold = datetime.now(created.tzinfo) - timedelta(days=min_days)
                if created < threshold:
                    candidates.append(rule)
            except (ValueError, TypeError):
                continue

        return candidates

    def get_status_report(self, state: WafState) -> dict:
        """Generate a status report for the WAF state.

        Args:
            state: Current WAF state.

        Returns:
            Status report dictionary.
        """
        active_rules = state.get_active_rules()
        log_rules = [r for r in active_rules if r.mode == "log"]
        block_rules = [r for r in active_rules if r.mode == "block"]
        obsolete_rules = [r for r in state.rules if r.status == "obsolete"]

        # Collect all CVEs covered
        all_cves: set[str] = set()
        for rule in active_rules:
            all_cves.update(rule.cve_ids)

        return {
            "provider": state.provider,
            "last_sync": state.last_sync,
            "total_rules": len(state.rules),
            "active_rules": len(active_rules),
            "log_mode_rules": len(log_rules),
            "block_mode_rules": len(block_rules),
            "obsolete_rules": len(obsolete_rules),
            "cves_covered": sorted(all_cves),
            "rules": [
                {
                    "rule_id": r.rule_id,
                    "cve_ids": r.cve_ids,
                    "mode": r.mode,
                    "status": r.status,
                    "created_at": r.created_at,
                    "package": r.triggered_by.package,
                }
                for r in state.rules
            ],
        }
