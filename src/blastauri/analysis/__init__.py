"""Upgrade impact analysis engine.

This module provides the primary differentiating feature of blastauri:
detecting breaking changes and predicting upgrade impact.

Components:
- changelog_parser: Parse changelogs for breaking changes
- api_diff: Compare package exports between versions (TypeScript, Python)
- known_breaking_changes: Curated database of breaking changes for popular packages
- static_analyzer: Tree-sitter based static analysis for Python, JS, Go, Ruby
- usage_finder: Find dependency usage locations in codebase
- impact_calculator: Calculate risk scores and severity
- fix_generator: Generate fix suggestions and migration guides
- ai_reviewer: Optional AI-assisted review using Claude or Augment
"""

from blastauri.analysis.ai_reviewer import (
    AIProvider,
    AIReviewResult,
    AugmentReviewer,
    BaseAIReviewer,
    ClaudeReviewer,
    NoOpReviewer,
    ai_review_upgrade,
    get_ai_reviewer,
)
from blastauri.analysis.changelog_parser import (
    ChangelogEntry,
    ChangelogParser,
    ChangelogSource,
    detect_breaking_changes_from_version,
    is_major_version_upgrade,
)
from blastauri.analysis.fix_generator import (
    FixGenerator,
    FixSuggestion,
    MigrationStep,
    generate_fixes,
    generate_migration_guide,
)
from blastauri.analysis.impact_calculator import (
    BreakingChangeSeverity,
    ImpactCalculator,
    RiskScoreWeights,
    calculate_risk_score,
    classify_severity,
)
from blastauri.analysis.static_analyzer import (
    BaseLanguageAnalyzer,
    GoAnalyzer,
    ImportInfo,
    JavaScriptAnalyzer,
    PythonAnalyzer,
    RubyAnalyzer,
    StaticAnalyzer,
    UsageType,
)
from blastauri.analysis.usage_finder import (
    PackageUsageReport,
    UsageFinder,
    find_dependency_usages,
    find_impacted_code,
)
from blastauri.analysis.api_diff import (
    ApiDiff,
    ApiDiffAnalyzer,
    ApiExport,
    analyze_api_diff,
)
from blastauri.analysis.known_breaking_changes import (
    KnownBreakingChange,
    get_all_packages_with_known_changes,
    get_known_breaking_changes,
)
from blastauri.analysis.package_metadata import (
    MaintenanceStatus,
    PackageMetadata,
    PackageMetadataAnalyzer,
    PackageSignal,
    RiskSignal,
    analyze_package_metadata,
)
from blastauri.analysis.heuristic_analyzer import (
    HeuristicAnalyzer,
    HeuristicResult,
    PackageStats,
    analyze_with_heuristics,
)

__all__ = [
    # AI Reviewer
    "AIProvider",
    "AIReviewResult",
    "AugmentReviewer",
    "BaseAIReviewer",
    "ClaudeReviewer",
    "NoOpReviewer",
    "ai_review_upgrade",
    "get_ai_reviewer",
    # Changelog Parser
    "ChangelogEntry",
    "ChangelogParser",
    "ChangelogSource",
    "detect_breaking_changes_from_version",
    "is_major_version_upgrade",
    # Fix Generator
    "FixGenerator",
    "FixSuggestion",
    "MigrationStep",
    "generate_fixes",
    "generate_migration_guide",
    # Impact Calculator
    "BreakingChangeSeverity",
    "ImpactCalculator",
    "RiskScoreWeights",
    "calculate_risk_score",
    "classify_severity",
    # Static Analyzer
    "BaseLanguageAnalyzer",
    "GoAnalyzer",
    "ImportInfo",
    "JavaScriptAnalyzer",
    "PythonAnalyzer",
    "RubyAnalyzer",
    "StaticAnalyzer",
    "UsageType",
    # Usage Finder
    "PackageUsageReport",
    "UsageFinder",
    "find_dependency_usages",
    "find_impacted_code",
    # API Diff
    "ApiDiff",
    "ApiDiffAnalyzer",
    "ApiExport",
    "analyze_api_diff",
    # Known Breaking Changes
    "KnownBreakingChange",
    "get_all_packages_with_known_changes",
    "get_known_breaking_changes",
    # Package Metadata
    "MaintenanceStatus",
    "PackageMetadata",
    "PackageMetadataAnalyzer",
    "PackageSignal",
    "RiskSignal",
    "analyze_package_metadata",
    # Heuristic Analyzer
    "HeuristicAnalyzer",
    "HeuristicResult",
    "PackageStats",
    "analyze_with_heuristics",
]
