"""Fix suggestion generator for breaking changes."""

import re
from dataclasses import dataclass
from typing import Optional

from blastauri.core.models import (
    BreakingChange,
    BreakingChangeType,
    Ecosystem,
    ImpactedLocation,
    UsageLocation,
)


@dataclass
class FixSuggestion:
    """A suggested fix for an impacted location."""

    location: UsageLocation
    original_code: str
    suggested_code: str
    explanation: str
    confidence: float  # 0.0 to 1.0
    is_automated: bool  # Can be auto-applied


@dataclass
class MigrationStep:
    """A step in a migration guide."""

    order: int
    title: str
    description: str
    before_code: Optional[str]
    after_code: Optional[str]
    files_affected: list[str]


class FixGenerator:
    """Generates fix suggestions for breaking changes."""

    def __init__(self):
        """Initialize the fix generator."""
        # Common migration patterns by ecosystem
        self._ecosystem_migrations: dict[Ecosystem, dict[str, str]] = {
            Ecosystem.NPM: {
                # React patterns
                "componentWillMount": "componentDidMount or useEffect",
                "componentWillReceiveProps": "componentDidUpdate or getDerivedStateFromProps",
                "componentWillUpdate": "componentDidUpdate or getSnapshotBeforeUpdate",
                # Express patterns
                "req.param": "req.params or req.query",
                "res.sendfile": "res.sendFile",
                # Lodash patterns
                "_.pluck": "_.map with property name",
                "_.where": "_.filter",
            },
            Ecosystem.PYPI: {
                # Django patterns
                "url(": "path( or re_path(",
                "render_to_response": "render",
                "HttpResponse(mimetype=": "HttpResponse(content_type=",
                # Python 3 patterns
                "dict.iteritems": "dict.items",
                "dict.iterkeys": "dict.keys",
                "dict.itervalues": "dict.values",
                "xrange": "range",
                "raw_input": "input",
            },
            Ecosystem.GO: {
                # Context patterns
                "golang.org/x/net/context": "context (standard library)",
            },
            Ecosystem.RUBYGEMS: {
                # Rails patterns
                "find_all_by_": "where(",
                "find_by_": "find_by(",
                "scoped": "all",
                "attr_accessible": "strong parameters",
            },
        }

    def generate_fix(
        self,
        impacted: ImpactedLocation,
        ecosystem: Ecosystem,
    ) -> FixSuggestion:
        """Generate a fix suggestion for an impacted location.

        Args:
            impacted: The impacted location.
            ecosystem: Package ecosystem.

        Returns:
            Fix suggestion.
        """
        change = impacted.breaking_change
        location = impacted.location

        # Try to generate specific fix based on change type
        if change.old_api and change.new_api:
            return self._generate_rename_fix(impacted, ecosystem)

        if change.change_type == BreakingChangeType.CHANGED_SIGNATURE:
            return self._generate_signature_fix(impacted, ecosystem)

        if change.change_type in (
            BreakingChangeType.REMOVED_FUNCTION,
            BreakingChangeType.REMOVED_CLASS,
            BreakingChangeType.REMOVED_MODULE,
        ):
            return self._generate_removal_fix(impacted, ecosystem)

        if change.change_type == BreakingChangeType.DEPRECATED:
            return self._generate_deprecation_fix(impacted, ecosystem)

        # Default: provide explanation-only fix
        return FixSuggestion(
            location=location,
            original_code=location.code_snippet,
            suggested_code=location.code_snippet,  # No automatic change
            explanation=self._generate_generic_explanation(change),
            confidence=0.3,
            is_automated=False,
        )

    def _generate_rename_fix(
        self,
        impacted: ImpactedLocation,
        ecosystem: Ecosystem,
    ) -> FixSuggestion:
        """Generate fix for a rename operation."""
        change = impacted.breaking_change
        location = impacted.location

        old_api = change.old_api or ""
        new_api = change.new_api or ""

        # Simple text replacement
        suggested_code = location.code_snippet.replace(old_api, new_api)

        # Check if the replacement made a change
        is_automated = suggested_code != location.code_snippet

        return FixSuggestion(
            location=location,
            original_code=location.code_snippet,
            suggested_code=suggested_code,
            explanation=f"Replace `{old_api}` with `{new_api}`",
            confidence=0.9 if is_automated else 0.5,
            is_automated=is_automated,
        )

    def _generate_signature_fix(
        self,
        impacted: ImpactedLocation,
        ecosystem: Ecosystem,
    ) -> FixSuggestion:
        """Generate fix for a signature change."""
        change = impacted.breaking_change
        location = impacted.location

        explanation_parts = ["The function signature has changed."]

        if change.old_api:
            explanation_parts.append(f"Old: `{change.old_api}`")
        if change.new_api:
            explanation_parts.append(f"New: `{change.new_api}`")
        if change.migration_guide:
            explanation_parts.append(f"Migration: {change.migration_guide}")

        return FixSuggestion(
            location=location,
            original_code=location.code_snippet,
            suggested_code=location.code_snippet,  # Manual review needed
            explanation=" ".join(explanation_parts),
            confidence=0.5,
            is_automated=False,
        )

    def _generate_removal_fix(
        self,
        impacted: ImpactedLocation,
        ecosystem: Ecosystem,
    ) -> FixSuggestion:
        """Generate fix for removed functionality."""
        change = impacted.breaking_change
        location = impacted.location

        # Check for known migrations
        old_api = change.old_api or location.symbol
        migrations = self._ecosystem_migrations.get(ecosystem, {})

        suggested_alternative = None
        for pattern, replacement in migrations.items():
            if pattern in old_api or pattern in location.code_snippet:
                suggested_alternative = replacement
                break

        if suggested_alternative:
            explanation = f"`{old_api}` has been removed. Use `{suggested_alternative}` instead."
        elif change.new_api:
            explanation = f"`{old_api}` has been removed. Use `{change.new_api}` instead."
            suggested_alternative = change.new_api
        else:
            explanation = f"`{old_api}` has been removed. Find an alternative or remove usage."

        return FixSuggestion(
            location=location,
            original_code=location.code_snippet,
            suggested_code=location.code_snippet,  # Manual review needed
            explanation=explanation,
            confidence=0.4 if suggested_alternative else 0.2,
            is_automated=False,
        )

    def _generate_deprecation_fix(
        self,
        impacted: ImpactedLocation,
        ecosystem: Ecosystem,
    ) -> FixSuggestion:
        """Generate fix for deprecated functionality."""
        change = impacted.breaking_change
        location = impacted.location

        explanation = f"`{location.symbol}` is deprecated."

        if change.new_api:
            explanation += f" Use `{change.new_api}` instead."
        if change.migration_guide:
            explanation += f" {change.migration_guide}"

        return FixSuggestion(
            location=location,
            original_code=location.code_snippet,
            suggested_code=location.code_snippet,
            explanation=explanation,
            confidence=0.6,
            is_automated=False,
        )

    def _generate_generic_explanation(self, change: BreakingChange) -> str:
        """Generate a generic explanation for a breaking change."""
        parts = [f"Breaking change detected: {change.description}"]

        if change.migration_guide:
            parts.append(f"Migration: {change.migration_guide}")

        return " ".join(parts)

    def generate_migration_guide(
        self,
        package_name: str,
        ecosystem: Ecosystem,
        from_version: str,
        to_version: str,
        breaking_changes: list[BreakingChange],
        impacted_locations: list[ImpactedLocation],
    ) -> list[MigrationStep]:
        """Generate a migration guide for an upgrade.

        Args:
            package_name: Package name.
            ecosystem: Package ecosystem.
            from_version: Starting version.
            to_version: Target version.
            breaking_changes: List of breaking changes.
            impacted_locations: List of impacted locations.

        Returns:
            List of migration steps.
        """
        steps: list[MigrationStep] = []
        order = 1

        # Group impacted locations by file
        files_by_change: dict[str, list[ImpactedLocation]] = {}
        for loc in impacted_locations:
            key = str(loc.breaking_change.change_type.value)
            files_by_change.setdefault(key, []).append(loc)

        # Handle renames first (usually safe to auto-apply)
        renames = [
            c for c in breaking_changes
            if c.change_type == BreakingChangeType.RENAMED_EXPORT and c.old_api and c.new_api
        ]

        for change in renames:
            affected_files = self._get_affected_files(change, impacted_locations)
            steps.append(
                MigrationStep(
                    order=order,
                    title=f"Rename `{change.old_api}` to `{change.new_api}`",
                    description=change.description,
                    before_code=change.old_api,
                    after_code=change.new_api,
                    files_affected=affected_files,
                )
            )
            order += 1

        # Handle signature changes
        sig_changes = [
            c for c in breaking_changes
            if c.change_type == BreakingChangeType.CHANGED_SIGNATURE
        ]

        for change in sig_changes:
            affected_files = self._get_affected_files(change, impacted_locations)
            steps.append(
                MigrationStep(
                    order=order,
                    title=f"Update function signature: {change.description[:50]}...",
                    description=change.description,
                    before_code=change.old_api,
                    after_code=change.new_api,
                    files_affected=affected_files,
                )
            )
            order += 1

        # Handle removals
        removals = [
            c for c in breaking_changes
            if c.change_type in (
                BreakingChangeType.REMOVED_FUNCTION,
                BreakingChangeType.REMOVED_CLASS,
                BreakingChangeType.REMOVED_MODULE,
            )
        ]

        for change in removals:
            affected_files = self._get_affected_files(change, impacted_locations)
            title = f"Replace removed {change.change_type.value.replace('removed_', '')}"
            if change.old_api:
                title = f"Replace removed `{change.old_api}`"

            steps.append(
                MigrationStep(
                    order=order,
                    title=title,
                    description=change.description,
                    before_code=change.old_api,
                    after_code=change.new_api or "// TODO: Find alternative",
                    files_affected=affected_files,
                )
            )
            order += 1

        # Handle behavior changes
        behavior_changes = [
            c for c in breaking_changes
            if c.change_type in (
                BreakingChangeType.CHANGED_BEHAVIOR,
                BreakingChangeType.CHANGED_DEFAULT,
            )
        ]

        if behavior_changes:
            affected_files = list(
                set(
                    loc.location.file_path
                    for loc in impacted_locations
                    if loc.breaking_change in behavior_changes
                )
            )
            steps.append(
                MigrationStep(
                    order=order,
                    title="Review behavior changes",
                    description="The following behavior changes may affect your code:\n"
                    + "\n".join(f"- {c.description}" for c in behavior_changes),
                    before_code=None,
                    after_code=None,
                    files_affected=affected_files,
                )
            )
            order += 1

        # Final step: run tests
        steps.append(
            MigrationStep(
                order=order,
                title="Run tests",
                description=f"After completing the migration from {from_version} to {to_version}, "
                f"run your test suite to verify everything works correctly.",
                before_code=None,
                after_code=None,
                files_affected=[],
            )
        )

        return steps

    def _get_affected_files(
        self,
        change: BreakingChange,
        impacted_locations: list[ImpactedLocation],
    ) -> list[str]:
        """Get files affected by a breaking change."""
        return list(
            set(
                loc.location.file_path
                for loc in impacted_locations
                if loc.breaking_change == change
            )
        )

    def generate_fix_diff(
        self,
        fix: FixSuggestion,
    ) -> str:
        """Generate a diff-style representation of a fix.

        Args:
            fix: Fix suggestion.

        Returns:
            Diff-style string.
        """
        if fix.original_code == fix.suggested_code:
            return f"# {fix.explanation}\n# Manual review required"

        lines = [
            f"# {fix.location.file_path}:{fix.location.line_number}",
            f"- {fix.original_code}",
            f"+ {fix.suggested_code}",
        ]

        return "\n".join(lines)


def generate_fixes(
    impacted_locations: list[ImpactedLocation],
    ecosystem: Ecosystem,
) -> list[FixSuggestion]:
    """Convenience function to generate fixes for all impacted locations.

    Args:
        impacted_locations: List of impacted locations.
        ecosystem: Package ecosystem.

    Returns:
        List of fix suggestions.
    """
    generator = FixGenerator()
    return [
        generator.generate_fix(loc, ecosystem)
        for loc in impacted_locations
    ]


def generate_migration_guide(
    package_name: str,
    ecosystem: Ecosystem,
    from_version: str,
    to_version: str,
    breaking_changes: list[BreakingChange],
    impacted_locations: list[ImpactedLocation],
) -> list[MigrationStep]:
    """Convenience function to generate a migration guide.

    Args:
        package_name: Package name.
        ecosystem: Package ecosystem.
        from_version: Starting version.
        to_version: Target version.
        breaking_changes: List of breaking changes.
        impacted_locations: List of impacted locations.

    Returns:
        List of migration steps.
    """
    generator = FixGenerator()
    return generator.generate_migration_guide(
        package_name,
        ecosystem,
        from_version,
        to_version,
        breaking_changes,
        impacted_locations,
    )
