"""Usage finder for locating dependency usage across a codebase."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from blastauri.analysis.static_analyzer import ImportInfo, StaticAnalyzer
from blastauri.core.models import (
    BreakingChange,
    Ecosystem,
    ImpactedLocation,
    UsageLocation,
)


@dataclass
class PackageUsageReport:
    """Report of a package's usage in a codebase."""

    package_name: str
    ecosystem: Ecosystem
    imports: list[ImportInfo] = field(default_factory=list)
    usages: list[UsageLocation] = field(default_factory=list)
    files_analyzed: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def total_imports(self) -> int:
        """Total number of import statements."""
        return len(self.imports)

    @property
    def total_usages(self) -> int:
        """Total number of usage locations."""
        return len(self.usages)

    @property
    def files_with_usage(self) -> int:
        """Number of files with at least one usage."""
        return len(set(u.file_path for u in self.usages))

    @property
    def symbols_used(self) -> set[str]:
        """Set of all symbols used."""
        return {u.symbol for u in self.usages}


class UsageFinder:
    """Finds dependency usage across a codebase."""

    def __init__(
        self,
        static_analyzer: Optional[StaticAnalyzer] = None,
        exclude_patterns: Optional[list[str]] = None,
    ):
        """Initialize the usage finder.

        Args:
            static_analyzer: Optional pre-configured static analyzer.
            exclude_patterns: Glob patterns for files to exclude.
        """
        self._analyzer = static_analyzer or StaticAnalyzer(
            exclude_patterns=exclude_patterns
        )

    def find_package_usage(
        self,
        directory: Path,
        ecosystem: Ecosystem,
        package_name: str,
        symbols: Optional[list[str]] = None,
    ) -> PackageUsageReport:
        """Find all usage of a package in a directory.

        Args:
            directory: Directory to search.
            ecosystem: Package ecosystem.
            package_name: Package name to find.
            symbols: Optional list of specific symbols to find.

        Returns:
            Usage report.
        """
        report = PackageUsageReport(
            package_name=package_name,
            ecosystem=ecosystem,
        )

        # Find all source files
        files = self._analyzer.find_files(directory, ecosystem)
        report.files_analyzed = len(files)

        # Find imports
        try:
            report.imports = self._analyzer.find_all_imports(
                directory, ecosystem, package_name
            )
        except Exception as e:
            report.errors.append(f"Error finding imports: {e}")

        # Find usages
        try:
            report.usages = self._analyzer.find_all_usages(
                directory, ecosystem, package_name, symbols
            )
        except Exception as e:
            report.errors.append(f"Error finding usages: {e}")

        return report

    def find_impacted_locations(
        self,
        directory: Path,
        ecosystem: Ecosystem,
        package_name: str,
        breaking_changes: list[BreakingChange],
    ) -> list[ImpactedLocation]:
        """Find locations impacted by breaking changes.

        Args:
            directory: Directory to search.
            ecosystem: Package ecosystem.
            package_name: Package name.
            breaking_changes: List of breaking changes.

        Returns:
            List of impacted locations.
        """
        impacted: list[ImpactedLocation] = []

        # Extract symbols from breaking changes
        symbols_to_find: set[str] = set()
        symbol_to_changes: dict[str, list[BreakingChange]] = {}

        for change in breaking_changes:
            # Extract symbols from old_api and new_api
            if change.old_api:
                symbol = self._extract_symbol_name(change.old_api)
                if symbol:
                    symbols_to_find.add(symbol)
                    symbol_to_changes.setdefault(symbol, []).append(change)

            # Also look for description-based symbols
            desc_symbols = self._extract_symbols_from_description(change.description)
            for symbol in desc_symbols:
                symbols_to_find.add(symbol)
                symbol_to_changes.setdefault(symbol, []).append(change)

        # Find usages of these symbols
        if symbols_to_find:
            usages = self._analyzer.find_all_usages(
                directory, ecosystem, package_name, list(symbols_to_find)
            )

            for usage in usages:
                # Find matching breaking changes
                matching_changes = symbol_to_changes.get(usage.symbol, [])

                for change in matching_changes:
                    confidence = self._calculate_match_confidence(usage, change)

                    impacted.append(
                        ImpactedLocation(
                            location=usage,
                            breaking_change=change,
                            confidence=confidence,
                            suggested_fix=self._generate_quick_fix(usage, change),
                        )
                    )

        # For breaking changes without specific symbols, warn about all usages
        general_changes = [
            c for c in breaking_changes
            if not c.old_api and not self._extract_symbols_from_description(c.description)
        ]

        if general_changes:
            # Get all package usages
            all_usages = self._analyzer.find_all_usages(
                directory, ecosystem, package_name
            )

            for usage in all_usages:
                for change in general_changes:
                    impacted.append(
                        ImpactedLocation(
                            location=usage,
                            breaking_change=change,
                            confidence=0.3,  # Lower confidence for general warnings
                            suggested_fix=None,
                        )
                    )

        return impacted

    def _extract_symbol_name(self, api_ref: str) -> Optional[str]:
        """Extract a symbol name from an API reference.

        Args:
            api_ref: API reference string.

        Returns:
            Extracted symbol name.
        """
        # Remove common prefixes/suffixes
        api_ref = api_ref.strip()

        # Handle method signatures: func_name(args) -> type
        if "(" in api_ref:
            api_ref = api_ref.split("(")[0]

        # Handle module paths: module.submodule.symbol
        if "." in api_ref:
            api_ref = api_ref.split(".")[-1]

        # Handle type annotations: name: type
        if ":" in api_ref:
            api_ref = api_ref.split(":")[0]

        api_ref = api_ref.strip()

        # Validate it looks like a symbol
        if api_ref and api_ref[0].isalpha():
            return api_ref

        return None

    def _extract_symbols_from_description(self, description: str) -> list[str]:
        """Extract symbol names from a breaking change description.

        Args:
            description: Breaking change description.

        Returns:
            List of extracted symbols.
        """
        import re

        symbols: list[str] = []

        # Look for backtick-quoted identifiers
        backtick_matches = re.findall(r"`(\w+(?:\.\w+)*)`", description)
        symbols.extend(backtick_matches)

        # Look for single-quoted identifiers
        quote_matches = re.findall(r"'(\w+(?:\.\w+)*)'", description)
        symbols.extend(quote_matches)

        # Look for CamelCase class names
        class_matches = re.findall(r"\b([A-Z][a-zA-Z0-9]+)\b", description)
        symbols.extend(class_matches)

        # Deduplicate while preserving order
        seen: set[str] = set()
        unique_symbols: list[str] = []
        for s in symbols:
            # Extract last part if it's a path
            s = s.split(".")[-1]
            if s not in seen:
                seen.add(s)
                unique_symbols.append(s)

        return unique_symbols

    def _calculate_match_confidence(
        self,
        usage: UsageLocation,
        change: BreakingChange,
    ) -> float:
        """Calculate confidence that a usage is impacted by a change.

        Args:
            usage: Usage location.
            change: Breaking change.

        Returns:
            Confidence score between 0.0 and 1.0.
        """
        confidence = 0.5  # Base confidence

        # Exact symbol match in old_api
        if change.old_api:
            old_symbol = self._extract_symbol_name(change.old_api)
            if old_symbol and old_symbol == usage.symbol:
                confidence += 0.3

        # Usage type matches change type
        if change.change_type.value.startswith("removed"):
            confidence += 0.1
        elif change.change_type.value == "changed_signature":
            if usage.usage_type == "call":
                confidence += 0.2

        # Code snippet contains related terms
        snippet_lower = usage.code_snippet.lower()
        if change.old_api and change.old_api.lower() in snippet_lower:
            confidence += 0.1

        return min(1.0, confidence)

    def _generate_quick_fix(
        self,
        usage: UsageLocation,
        change: BreakingChange,
    ) -> Optional[str]:
        """Generate a quick fix suggestion.

        Args:
            usage: Usage location.
            change: Breaking change.

        Returns:
            Fix suggestion or None.
        """
        # If there's a new API, suggest replacing
        if change.old_api and change.new_api:
            return f"Replace `{change.old_api}` with `{change.new_api}`"

        # If there's a migration guide, use it
        if change.migration_guide:
            return change.migration_guide

        # Generic suggestions based on change type
        if change.change_type.value.startswith("removed"):
            return f"Remove usage of `{usage.symbol}` or find alternative"
        elif change.change_type.value == "changed_signature":
            return f"Review and update arguments to `{usage.symbol}`"
        elif change.change_type.value == "deprecated":
            return f"`{usage.symbol}` is deprecated, consider updating"

        return None


def find_dependency_usages(
    directory: Path,
    ecosystem: Ecosystem,
    package_name: str,
    exclude_patterns: Optional[list[str]] = None,
) -> PackageUsageReport:
    """Convenience function to find dependency usages.

    Args:
        directory: Directory to search.
        ecosystem: Package ecosystem.
        package_name: Package name.
        exclude_patterns: Glob patterns to exclude.

    Returns:
        Usage report.
    """
    finder = UsageFinder(exclude_patterns=exclude_patterns)
    return finder.find_package_usage(directory, ecosystem, package_name)


def find_impacted_code(
    directory: Path,
    ecosystem: Ecosystem,
    package_name: str,
    breaking_changes: list[BreakingChange],
    exclude_patterns: Optional[list[str]] = None,
) -> list[ImpactedLocation]:
    """Convenience function to find impacted code locations.

    Args:
        directory: Directory to search.
        ecosystem: Package ecosystem.
        package_name: Package name.
        breaking_changes: List of breaking changes.
        exclude_patterns: Glob patterns to exclude.

    Returns:
        List of impacted locations.
    """
    finder = UsageFinder(exclude_patterns=exclude_patterns)
    return finder.find_impacted_locations(
        directory, ecosystem, package_name, breaking_changes
    )
