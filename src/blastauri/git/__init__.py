"""Git platform integrations for GitLab and GitHub.

This module provides integration with GitLab and GitHub for analyzing
Renovate merge requests and Dependabot pull requests.

Components:
- gitlab_client: GitLab API client for MRs, comments, labels
- github_client: GitHub API client for PRs, comments, labels
- renovate_parser: Renovate MR detection and parsing
- dependabot_parser: Dependabot and Renovate PR detection for GitHub
- comment_generator: Analysis comment generation with markdown formatting
- label_manager: Severity label application and management
- mr_analyzer: GitLab MR analysis orchestrator
- pr_analyzer: GitHub PR analysis orchestrator
"""

from blastauri.git.comment_generator import (
    CommentConfig,
    CommentGenerator,
    generate_analysis_comment,
)
from blastauri.git.dependabot_parser import (
    BotType,
    DependabotParser,
    DependencyPRInfo,
    is_dependabot_branch,
    is_dependency_bot_branch,
    parse_dependency_pr,
)
from blastauri.git.github_client import (
    GitHubClient,
    GitHubConfig,
    PullRequestFile,
    PullRequestInfo,
    RepositoryLabel,
)
from blastauri.git.gitlab_client import (
    GitLabClient,
    GitLabConfig,
    MergeRequestChange,
    MergeRequestDiff,
    MergeRequestInfo,
    ProjectLabel,
)
from blastauri.git.label_manager import (
    BLASTAURI_LABELS,
    SECURITY_LABELS,
    LabelDefinition,
    LabelManager,
    determine_labels_for_analysis,
)
from blastauri.git.mr_analyzer import (
    AnalysisConfig,
    AnalysisResult,
    MergeRequestAnalyzer,
    analyze_renovate_mr,
)
from blastauri.git.pr_analyzer import (
    PRAnalysisConfig,
    PRAnalysisResult,
    PullRequestAnalyzer,
    analyze_github_pr,
)
from blastauri.git.mr_creator import (
    FileChange,
    MrCreationConfig,
    MrCreationResult,
    MrCreator,
    WafMrCreator,
)
from blastauri.git.renovate_parser import (
    RenovateMRInfo,
    RenovateParser,
    UpdateType,
    is_renovate_branch,
    parse_renovate_mr,
)

__all__ = [
    # Comment Generator
    "CommentConfig",
    "CommentGenerator",
    "generate_analysis_comment",
    # Dependabot Parser
    "BotType",
    "DependabotParser",
    "DependencyPRInfo",
    "is_dependabot_branch",
    "is_dependency_bot_branch",
    "parse_dependency_pr",
    # GitHub Client
    "GitHubClient",
    "GitHubConfig",
    "PullRequestFile",
    "PullRequestInfo",
    "RepositoryLabel",
    # GitLab Client
    "GitLabClient",
    "GitLabConfig",
    "MergeRequestChange",
    "MergeRequestDiff",
    "MergeRequestInfo",
    "ProjectLabel",
    # Label Manager
    "BLASTAURI_LABELS",
    "SECURITY_LABELS",
    "LabelDefinition",
    "LabelManager",
    "determine_labels_for_analysis",
    # MR Analyzer (GitLab)
    "AnalysisConfig",
    "AnalysisResult",
    "MergeRequestAnalyzer",
    "analyze_renovate_mr",
    # PR Analyzer (GitHub)
    "PRAnalysisConfig",
    "PRAnalysisResult",
    "PullRequestAnalyzer",
    "analyze_github_pr",
    # MR Creator
    "FileChange",
    "MrCreationConfig",
    "MrCreationResult",
    "MrCreator",
    "WafMrCreator",
    # Renovate Parser
    "RenovateMRInfo",
    "RenovateParser",
    "UpdateType",
    "is_renovate_branch",
    "parse_renovate_mr",
]
