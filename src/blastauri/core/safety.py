"""Safety guardrails for blastauri operations.

This module enforces that blastauri operates in a read-only, advisory capacity.
All operations are designed to INFORM developers, not to automatically change code.

Principles:
1. NEVER modify source code in repositories directly
2. NEVER auto-merge any MR/PR
3. NEVER commit to protected branches (main, master, production)
4. Only CREATE new MRs/PRs for human review
5. Only ADD comments and labels (metadata, not code)
6. All WAF changes require human approval via MR/PR workflow

This file serves as both documentation and runtime verification.
"""

from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class OperationType(str, Enum):
    """Types of operations blastauri can perform."""

    # Read-only operations (always safe)
    READ_FILE = "read_file"
    SCAN_DEPENDENCIES = "scan_dependencies"
    QUERY_CVE_DATABASE = "query_cve_database"
    ANALYZE_MR = "analyze_mr"
    GENERATE_REPORT = "generate_report"

    # Metadata operations (non-code, reversible)
    POST_COMMENT = "post_comment"
    ADD_LABEL = "add_label"
    REMOVE_LABEL = "remove_label"

    # Local write operations (user's machine only)
    WRITE_LOCAL_FILE = "write_local_file"
    WRITE_CONFIG = "write_config"

    # MR/PR creation (requires human review)
    CREATE_MR_BRANCH = "create_mr_branch"
    CREATE_MR = "create_mr"


# Operations that are ALWAYS allowed
ALWAYS_ALLOWED_OPERATIONS = {
    OperationType.READ_FILE,
    OperationType.SCAN_DEPENDENCIES,
    OperationType.QUERY_CVE_DATABASE,
    OperationType.ANALYZE_MR,
    OperationType.GENERATE_REPORT,
}

# Operations that modify metadata only (not source code)
METADATA_OPERATIONS = {
    OperationType.POST_COMMENT,
    OperationType.ADD_LABEL,
    OperationType.REMOVE_LABEL,
}

# Operations that write to local filesystem only
LOCAL_WRITE_OPERATIONS = {
    OperationType.WRITE_LOCAL_FILE,
    OperationType.WRITE_CONFIG,
}

# Operations that create MRs for human review
MR_CREATION_OPERATIONS = {
    OperationType.CREATE_MR_BRANCH,
    OperationType.CREATE_MR,
}

# Protected branches that should NEVER be directly modified
PROTECTED_BRANCHES = {
    "main",
    "master",
    "production",
    "prod",
    "release",
    "stable",
    "develop",  # Some teams protect develop too
}


@dataclass
class SafetyCheck:
    """Result of a safety check."""

    allowed: bool
    reason: str
    operation: OperationType


class SafetyGuard:
    """Enforces safety guardrails for all blastauri operations.

    This class is intentionally restrictive. Any new operation types
    must be explicitly added and reviewed.
    """

    def __init__(self, allow_mr_creation: bool = True):
        """Initialize the safety guard.

        Args:
            allow_mr_creation: Whether to allow MR/PR creation operations.
                              Even when True, MRs are created for human review only.
        """
        self._allow_mr_creation = allow_mr_creation

    def check_operation(
        self,
        operation: OperationType,
        target_branch: str | None = None,
    ) -> SafetyCheck:
        """Check if an operation is allowed.

        Args:
            operation: The operation to check.
            target_branch: Target branch for MR operations.

        Returns:
            SafetyCheck result.
        """
        # Always allow read operations
        if operation in ALWAYS_ALLOWED_OPERATIONS:
            return SafetyCheck(
                allowed=True,
                reason="Read-only operation, always allowed",
                operation=operation,
            )

        # Metadata operations are allowed (they don't change code)
        if operation in METADATA_OPERATIONS:
            return SafetyCheck(
                allowed=True,
                reason="Metadata operation (comment/label), does not modify code",
                operation=operation,
            )

        # Local write operations are allowed (user's machine)
        if operation in LOCAL_WRITE_OPERATIONS:
            return SafetyCheck(
                allowed=True,
                reason="Local filesystem write, does not affect remote repositories",
                operation=operation,
            )

        # MR creation operations require explicit enablement
        if operation in MR_CREATION_OPERATIONS:
            if not self._allow_mr_creation:
                return SafetyCheck(
                    allowed=False,
                    reason="MR/PR creation disabled in this context",
                    operation=operation,
                )

            # Never allow targeting protected branches directly
            if target_branch and target_branch.lower() in PROTECTED_BRANCHES:
                return SafetyCheck(
                    allowed=False,
                    reason=f"Cannot target protected branch '{target_branch}' directly",
                    operation=operation,
                )

            return SafetyCheck(
                allowed=True,
                reason="MR/PR creation allowed (requires human review before merge)",
                operation=operation,
            )

        # Unknown operations are not allowed
        return SafetyCheck(
            allowed=False,
            reason=f"Unknown operation type: {operation}",
            operation=operation,
        )

    def check_branch_name(self, branch_name: str) -> SafetyCheck:
        """Check if a branch name is safe to create.

        Blastauri only creates branches with specific prefixes.

        Args:
            branch_name: Branch name to check.

        Returns:
            SafetyCheck result.
        """
        allowed_prefixes = (
            "blastauri/",
            "blastauri-waf/",
            "waf/",
        )

        if branch_name.startswith(allowed_prefixes):
            return SafetyCheck(
                allowed=True,
                reason="Branch follows blastauri naming convention",
                operation=OperationType.CREATE_MR_BRANCH,
            )

        return SafetyCheck(
            allowed=False,
            reason=f"Branch '{branch_name}' does not follow blastauri naming convention",
            operation=OperationType.CREATE_MR_BRANCH,
        )

    def check_file_path(self, file_path: str, repository_root: str | None = None) -> SafetyCheck:
        """Check if a file path is safe to write (WAF operations).

        Blastauri only writes WAF-related files.

        Args:
            file_path: File path to check.
            repository_root: Repository root for relative path calculation.

        Returns:
            SafetyCheck result.
        """
        path = Path(file_path)

        # Only allow Terraform and state files in specific directories
        allowed_patterns = [
            "terraform/waf/",
            "waf/",
            ".blastauri/",
        ]

        allowed_extensions = {
            ".tf",      # Terraform
            ".tfvars",  # Terraform variables
            ".json",    # State files
            ".yml",     # Config files
            ".yaml",    # Config files
        }

        path_str = str(path)
        if repository_root:
            try:
                path_str = str(path.relative_to(repository_root))
            except ValueError:
                pass

        # Check if path matches allowed patterns
        matches_pattern = any(pattern in path_str for pattern in allowed_patterns)
        has_allowed_extension = path.suffix.lower() in allowed_extensions

        if matches_pattern and has_allowed_extension:
            return SafetyCheck(
                allowed=True,
                reason="WAF configuration file in allowed directory",
                operation=OperationType.WRITE_LOCAL_FILE,
            )

        return SafetyCheck(
            allowed=False,
            reason=f"File path '{file_path}' is not in allowed WAF directories",
            operation=OperationType.WRITE_LOCAL_FILE,
        )


# Global safety guard instance
_safety_guard: SafetyGuard | None = None


def get_safety_guard() -> SafetyGuard:
    """Get the global safety guard instance."""
    global _safety_guard
    if _safety_guard is None:
        _safety_guard = SafetyGuard()
    return _safety_guard


def assert_operation_allowed(
    operation: OperationType,
    target_branch: str | None = None,
) -> None:
    """Assert that an operation is allowed, raise if not.

    Args:
        operation: Operation to check.
        target_branch: Target branch for MR operations.

    Raises:
        PermissionError: If operation is not allowed.
    """
    guard = get_safety_guard()
    result = guard.check_operation(operation, target_branch)

    if not result.allowed:
        raise PermissionError(
            f"Operation not allowed: {operation.value}. Reason: {result.reason}"
        )


# Human-readable summary for documentation
SAFETY_SUMMARY = """
BLASTAURI SAFETY GUARANTEES
============================

This tool is designed to be ADVISORY ONLY. It helps developers make informed
decisions without making automatic changes that could break their code.

What blastauri DOES:
- Analyzes MRs/PRs and provides breaking change information
- Posts comments with analysis results (metadata only)
- Adds labels to help triage (metadata only)
- Generates WAF Terraform files locally for review
- Creates separate MRs/PRs for WAF changes (requires human approval)

What blastauri NEVER does:
- Modify source code in any repository
- Auto-merge any MR/PR
- Commit directly to main/master/production branches
- Make changes without human review
- Execute WAF rules without terraform apply (which YOU run)

All actions are reversible:
- Comments can be edited/deleted
- Labels can be removed
- WAF MRs can be closed without merging
- Local Terraform files can be deleted

The tool is designed to REDUCE developer fatigue by surfacing
relevant information, not by making autonomous decisions.
"""
