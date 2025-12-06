"""MR/PR creator for WAF updates.

This module handles creating merge requests (GitLab) and
pull requests (GitHub) for WAF rule changes.
"""

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional, Protocol, Union


class GitLabClientProtocol(Protocol):
    """Protocol for GitLab client methods needed by MR creator."""

    async def create_branch(
        self,
        project_id: str,
        branch_name: str,
        ref: str,
    ) -> None:
        """Create a new branch."""
        ...

    async def create_file(
        self,
        project_id: str,
        file_path: str,
        branch: str,
        content: str,
        commit_message: str,
    ) -> None:
        """Create or update a file."""
        ...

    async def update_file(
        self,
        project_id: str,
        file_path: str,
        branch: str,
        content: str,
        commit_message: str,
    ) -> None:
        """Update an existing file."""
        ...

    async def create_merge_request(
        self,
        project_id: str,
        source_branch: str,
        target_branch: str,
        title: str,
        description: str,
    ) -> dict:
        """Create a merge request."""
        ...


class GitHubClientProtocol(Protocol):
    """Protocol for GitHub client methods needed by PR creator."""

    async def create_branch(
        self,
        repo: str,
        branch_name: str,
        ref: str,
    ) -> None:
        """Create a new branch."""
        ...

    async def create_or_update_file(
        self,
        repo: str,
        file_path: str,
        branch: str,
        content: str,
        commit_message: str,
    ) -> None:
        """Create or update a file."""
        ...

    async def create_pull_request(
        self,
        repo: str,
        head: str,
        base: str,
        title: str,
        body: str,
    ) -> dict:
        """Create a pull request."""
        ...


@dataclass
class FileChange:
    """A file to be committed."""

    path: str
    content: str
    commit_message: str


@dataclass
class MrCreationResult:
    """Result of MR/PR creation."""

    success: bool
    mr_url: Optional[str] = None
    mr_iid: Optional[int] = None
    branch_name: Optional[str] = None
    error: Optional[str] = None


@dataclass
class MrCreationConfig:
    """Configuration for MR creation."""

    target_branch: str = "main"
    branch_prefix: str = "blastauri/waf"
    auto_merge: bool = False
    labels: list[str] = field(default_factory=lambda: ["blastauri", "waf"])
    assignees: list[str] = field(default_factory=list)
    reviewers: list[str] = field(default_factory=list)


class MrCreator:
    """Creates merge requests for WAF updates.

    Works with both GitLab and GitHub clients.
    """

    def __init__(self, config: Optional[MrCreationConfig] = None) -> None:
        """Initialize the MR creator.

        Args:
            config: Creation configuration.
        """
        self._config = config or MrCreationConfig()

    def generate_branch_name(self, prefix: str = "") -> str:
        """Generate a unique branch name.

        Args:
            prefix: Optional prefix for the branch name.

        Returns:
            Branch name string.
        """
        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        base = prefix or self._config.branch_prefix
        return f"{base}-{timestamp}"

    async def create_gitlab_mr(
        self,
        client: GitLabClientProtocol,
        project_id: str,
        title: str,
        description: str,
        files: list[FileChange],
    ) -> MrCreationResult:
        """Create a GitLab merge request.

        Args:
            client: GitLab client.
            project_id: GitLab project ID.
            title: MR title.
            description: MR description.
            files: Files to commit.

        Returns:
            MrCreationResult with outcome.
        """
        branch_name = self.generate_branch_name()

        try:
            # Create branch from target
            await client.create_branch(
                project_id,
                branch_name,
                self._config.target_branch,
            )

            # Commit all files
            for file_change in files:
                await client.create_file(
                    project_id,
                    file_change.path,
                    branch_name,
                    file_change.content,
                    file_change.commit_message,
                )

            # Create MR
            mr_result = await client.create_merge_request(
                project_id,
                branch_name,
                self._config.target_branch,
                title,
                description,
            )

            return MrCreationResult(
                success=True,
                mr_url=mr_result.get("web_url"),
                mr_iid=mr_result.get("iid"),
                branch_name=branch_name,
            )

        except Exception as e:
            return MrCreationResult(
                success=False,
                branch_name=branch_name,
                error=str(e),
            )

    async def create_github_pr(
        self,
        client: GitHubClientProtocol,
        repo: str,
        title: str,
        description: str,
        files: list[FileChange],
    ) -> MrCreationResult:
        """Create a GitHub pull request.

        Args:
            client: GitHub client.
            repo: Repository name (owner/repo).
            title: PR title.
            description: PR description.
            files: Files to commit.

        Returns:
            MrCreationResult with outcome.
        """
        branch_name = self.generate_branch_name()

        try:
            # Create branch from target
            await client.create_branch(
                repo,
                branch_name,
                self._config.target_branch,
            )

            # Commit all files
            for file_change in files:
                await client.create_or_update_file(
                    repo,
                    file_change.path,
                    branch_name,
                    file_change.content,
                    file_change.commit_message,
                )

            # Create PR
            pr_result = await client.create_pull_request(
                repo,
                branch_name,
                self._config.target_branch,
                title,
                description,
            )

            return MrCreationResult(
                success=True,
                mr_url=pr_result.get("html_url"),
                mr_iid=pr_result.get("number"),
                branch_name=branch_name,
            )

        except Exception as e:
            return MrCreationResult(
                success=False,
                branch_name=branch_name,
                error=str(e),
            )

    def generate_waf_update_title(
        self,
        new_rules: int = 0,
        removed_rules: int = 0,
        promoted_rules: int = 0,
    ) -> str:
        """Generate MR title for WAF update.

        Args:
            new_rules: Number of new rules added.
            removed_rules: Number of rules removed.
            promoted_rules: Number of rules promoted.

        Returns:
            MR title string.
        """
        parts = []

        if new_rules:
            parts.append(f"add {new_rules} rule(s)")
        if removed_rules:
            parts.append(f"remove {removed_rules} rule(s)")
        if promoted_rules:
            parts.append(f"promote {promoted_rules} rule(s)")

        if not parts:
            return "chore(waf): update WAF configuration"

        return f"chore(waf): {', '.join(parts)}"

    def generate_waf_update_description(
        self,
        new_rules: list[dict],
        removed_rules: list[dict],
        promoted_rules: list[dict],
        terraform_files: list[str],
    ) -> str:
        """Generate MR description for WAF update.

        Args:
            new_rules: List of new rule info dicts.
            removed_rules: List of removed rule info dicts.
            promoted_rules: List of promoted rule info dicts.
            terraform_files: List of Terraform files changed.

        Returns:
            MR description in markdown.
        """
        lines = []
        lines.append("## WAF Rule Update")
        lines.append("")
        lines.append(
            "This merge request was automatically generated by Blastauri "
            "to update WAF rules based on detected vulnerabilities."
        )
        lines.append("")

        if new_rules:
            lines.append("### New Rules")
            lines.append("")
            lines.append("| Rule ID | CVEs | Package | Reason |")
            lines.append("|---------|------|---------|--------|")
            for rule in new_rules:
                cves = ", ".join(rule.get("cve_ids", []))
                package = rule.get("package", "unknown")
                reason = rule.get("reason", "New vulnerability detected")
                lines.append(f"| {rule['rule_id']} | {cves} | {package} | {reason} |")
            lines.append("")

        if removed_rules:
            lines.append("### Removed Rules")
            lines.append("")
            lines.append("The following rules are obsolete and will be removed:")
            lines.append("")
            lines.append("| Rule ID | CVEs | Reason |")
            lines.append("|---------|------|--------|")
            for rule in removed_rules:
                cves = ", ".join(rule.get("cve_ids", []))
                reason = rule.get("reason", "Vulnerability patched")
                lines.append(f"| {rule['rule_id']} | {cves} | {reason} |")
            lines.append("")

        if promoted_rules:
            lines.append("### Promoted Rules")
            lines.append("")
            lines.append(
                "The following rules have been promoted from `log` to `block` mode:"
            )
            lines.append("")
            lines.append("| Rule ID | CVEs | Days Active |")
            lines.append("|---------|------|-------------|")
            for rule in promoted_rules:
                cves = ", ".join(rule.get("cve_ids", []))
                days = rule.get("days_active", "14+")
                lines.append(f"| {rule['rule_id']} | {cves} | {days} |")
            lines.append("")

        lines.append("### Changed Files")
        lines.append("")
        for filename in terraform_files:
            lines.append(f"- `{filename}`")
        lines.append("- `.blastauri/waf-state.json`")
        lines.append("")

        lines.append("### Review Checklist")
        lines.append("")
        lines.append("Before merging, please verify:")
        lines.append("")
        lines.append("- [ ] WAF rule patterns are appropriate for the vulnerabilities")
        lines.append("- [ ] Terraform syntax is valid (`terraform validate`)")
        lines.append("- [ ] Rules have been tested in a staging environment")
        lines.append("- [ ] No legitimate traffic will be blocked")
        lines.append("")

        lines.append("### How to Test")
        lines.append("")
        lines.append("```bash")
        lines.append("# Validate Terraform")
        lines.append("cd terraform/waf && terraform init && terraform validate")
        lines.append("")
        lines.append("# Plan changes")
        lines.append("terraform plan")
        lines.append("```")
        lines.append("")

        lines.append("---")
        lines.append(
            "*Generated by [Blastauri](https://github.com/clay-good/blastauri)*"
        )

        return "\n".join(lines)

    def collect_terraform_files(
        self,
        terraform_dir: Path,
        state_file: Path,
    ) -> list[FileChange]:
        """Collect Terraform and state files for commit.

        Args:
            terraform_dir: Directory containing Terraform files.
            state_file: Path to WAF state file.

        Returns:
            List of FileChange objects.
        """
        changes: list[FileChange] = []

        # Collect Terraform files
        if terraform_dir.exists():
            for tf_file in terraform_dir.glob("*.tf"):
                content = tf_file.read_text()
                relative_path = str(tf_file)
                changes.append(
                    FileChange(
                        path=relative_path,
                        content=content,
                        commit_message=f"chore(waf): update {tf_file.name}",
                    )
                )

        # Collect state file
        if state_file.exists():
            content = state_file.read_text()
            changes.append(
                FileChange(
                    path=str(state_file),
                    content=content,
                    commit_message="chore(waf): update WAF state",
                )
            )

        return changes


class WafMrCreator(MrCreator):
    """Specialized MR creator for WAF updates."""

    def __init__(
        self,
        repo_path: str,
        terraform_dir: str = "terraform/waf",
        config: Optional[MrCreationConfig] = None,
    ) -> None:
        """Initialize the WAF MR creator.

        Args:
            repo_path: Path to the repository.
            terraform_dir: Relative path to Terraform directory.
            config: Creation configuration.
        """
        super().__init__(config)
        self._repo_path = Path(repo_path)
        self._terraform_dir = terraform_dir

    async def create_waf_mr(
        self,
        client: Union[GitLabClientProtocol, GitHubClientProtocol],
        project_id: str,
        new_rules: list[dict],
        removed_rules: list[dict],
        promoted_rules: list[dict],
        platform: str = "gitlab",
    ) -> MrCreationResult:
        """Create MR for WAF updates.

        Args:
            client: Git platform client.
            project_id: Project/repo identifier.
            new_rules: List of new rule info dicts.
            removed_rules: List of removed rule info dicts.
            promoted_rules: List of promoted rule info dicts.
            platform: "gitlab" or "github".

        Returns:
            MrCreationResult with outcome.
        """
        # Generate title and description
        title = self.generate_waf_update_title(
            new_rules=len(new_rules),
            removed_rules=len(removed_rules),
            promoted_rules=len(promoted_rules),
        )

        terraform_dir = self._repo_path / self._terraform_dir
        state_file = self._repo_path / ".blastauri" / "waf-state.json"

        # Get list of terraform files
        terraform_files = []
        if terraform_dir.exists():
            terraform_files = [
                f"{self._terraform_dir}/{f.name}"
                for f in terraform_dir.glob("*.tf")
            ]
        terraform_files.append(".blastauri/waf-state.json")

        description = self.generate_waf_update_description(
            new_rules=new_rules,
            removed_rules=removed_rules,
            promoted_rules=promoted_rules,
            terraform_files=terraform_files,
        )

        # Collect files to commit
        files = self.collect_terraform_files(terraform_dir, state_file)

        if not files:
            return MrCreationResult(
                success=False,
                error="No files to commit",
            )

        # Create MR based on platform
        if platform == "gitlab":
            return await self.create_gitlab_mr(
                client=client,  # type: ignore
                project_id=project_id,
                title=title,
                description=description,
                files=files,
            )
        else:
            return await self.create_github_pr(
                client=client,  # type: ignore
                repo=project_id,
                title=title,
                description=description,
                files=files,
            )
