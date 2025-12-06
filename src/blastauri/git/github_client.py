"""GitHub API client for pull request operations."""

import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from github import Auth, Github
from github.PullRequest import PullRequest
from github.Repository import Repository


@dataclass
class GitHubConfig:
    """Configuration for GitHub client."""

    token: Optional[str] = None
    base_url: str = "https://api.github.com"

    @classmethod
    def from_env(cls) -> "GitHubConfig":
        """Create config from environment variables."""
        return cls(
            token=os.environ.get("GITHUB_TOKEN"),
            base_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
        )


@dataclass
class PullRequestInfo:
    """Information about a pull request."""

    number: int
    title: str
    body: str
    head_branch: str
    base_branch: str
    author_login: str
    state: str
    html_url: str
    created_at: datetime
    updated_at: datetime
    labels: list[str] = field(default_factory=list)
    mergeable: Optional[bool] = None
    merged: bool = False


@dataclass
class PullRequestFile:
    """A file changed in a pull request."""

    filename: str
    status: str  # added, removed, modified, renamed
    additions: int
    deletions: int
    changes: int
    patch: Optional[str] = None
    previous_filename: Optional[str] = None


@dataclass
class RepositoryLabel:
    """A repository label."""

    name: str
    color: str
    description: str = ""


class GitHubClient:
    """Client for GitHub API operations."""

    def __init__(self, config: Optional[GitHubConfig] = None):
        """Initialize the GitHub client.

        Args:
            config: GitHub configuration. If None, reads from environment.
        """
        self._config = config or GitHubConfig.from_env()
        self._gh: Optional[Github] = None

    def _get_client(self) -> Github:
        """Get or create the GitHub client."""
        if self._gh is None:
            if self._config.token:
                auth = Auth.Token(self._config.token)
                if self._config.base_url != "https://api.github.com":
                    self._gh = Github(
                        auth=auth,
                        base_url=self._config.base_url,
                    )
                else:
                    self._gh = Github(auth=auth)
            else:
                self._gh = Github()

        return self._gh

    def get_repository(self, repo_full_name: str) -> Repository:
        """Get a GitHub repository.

        Args:
            repo_full_name: Repository full name (e.g., "owner/repo").

        Returns:
            GitHub repository object.
        """
        gh = self._get_client()
        return gh.get_repo(repo_full_name)

    def get_pull_request(
        self,
        repo_full_name: str,
        pr_number: int,
    ) -> PullRequestInfo:
        """Get pull request information.

        Args:
            repo_full_name: Repository full name.
            pr_number: Pull request number.

        Returns:
            Pull request information.
        """
        repo = self.get_repository(repo_full_name)
        pr = repo.get_pull(pr_number)

        return PullRequestInfo(
            number=pr.number,
            title=pr.title,
            body=pr.body or "",
            head_branch=pr.head.ref,
            base_branch=pr.base.ref,
            author_login=pr.user.login if pr.user else "",
            state=pr.state,
            html_url=pr.html_url,
            created_at=pr.created_at,
            updated_at=pr.updated_at,
            labels=[label.name for label in pr.labels],
            mergeable=pr.mergeable,
            merged=pr.merged,
        )

    def get_pr_files(
        self,
        repo_full_name: str,
        pr_number: int,
    ) -> list[PullRequestFile]:
        """Get files changed in a pull request.

        Args:
            repo_full_name: Repository full name.
            pr_number: Pull request number.

        Returns:
            List of changed files.
        """
        repo = self.get_repository(repo_full_name)
        pr = repo.get_pull(pr_number)
        files = pr.get_files()

        return [
            PullRequestFile(
                filename=f.filename,
                status=f.status,
                additions=f.additions,
                deletions=f.deletions,
                changes=f.changes,
                patch=f.patch,
                previous_filename=f.previous_filename,
            )
            for f in files
        ]

    def get_pr_diff(
        self,
        repo_full_name: str,
        pr_number: int,
    ) -> str:
        """Get the diff for a pull request.

        Args:
            repo_full_name: Repository full name.
            pr_number: Pull request number.

        Returns:
            Diff as string.
        """
        repo = self.get_repository(repo_full_name)
        pr = repo.get_pull(pr_number)

        # Get diff via comparison
        comparison = repo.compare(pr.base.sha, pr.head.sha)
        return comparison.diff_url

    def get_file_content(
        self,
        repo_full_name: str,
        file_path: str,
        ref: str = "main",
    ) -> str:
        """Get file content from repository.

        Args:
            repo_full_name: Repository full name.
            file_path: Path to file in repository.
            ref: Branch, tag, or commit SHA.

        Returns:
            File content as string.
        """
        repo = self.get_repository(repo_full_name)
        try:
            content = repo.get_contents(file_path, ref=ref)
            if isinstance(content, list):
                return ""  # Directory
            return content.decoded_content.decode("utf-8")
        except Exception:
            return ""

    def post_pr_comment(
        self,
        repo_full_name: str,
        pr_number: int,
        body: str,
    ) -> int:
        """Post a comment on a pull request.

        Args:
            repo_full_name: Repository full name.
            pr_number: Pull request number.
            body: Comment body.

        Returns:
            Comment ID.
        """
        repo = self.get_repository(repo_full_name)
        pr = repo.get_pull(pr_number)
        comment = pr.create_issue_comment(body)
        return comment.id

    def update_pr_comment(
        self,
        repo_full_name: str,
        comment_id: int,
        body: str,
    ) -> None:
        """Update an existing pull request comment.

        Args:
            repo_full_name: Repository full name.
            comment_id: Comment ID to update.
            body: New comment body.
        """
        repo = self.get_repository(repo_full_name)
        comment = repo.get_issue_comment(comment_id)
        comment.edit(body)

    def delete_pr_comment(
        self,
        repo_full_name: str,
        comment_id: int,
    ) -> None:
        """Delete a pull request comment.

        Args:
            repo_full_name: Repository full name.
            comment_id: Comment ID to delete.
        """
        repo = self.get_repository(repo_full_name)
        comment = repo.get_issue_comment(comment_id)
        comment.delete()

    def find_bot_comment(
        self,
        repo_full_name: str,
        pr_number: int,
        marker: str = "<!-- blastauri-analysis -->",
    ) -> Optional[int]:
        """Find an existing bot comment by marker.

        Args:
            repo_full_name: Repository full name.
            pr_number: Pull request number.
            marker: HTML comment marker to find.

        Returns:
            Comment ID if found, None otherwise.
        """
        repo = self.get_repository(repo_full_name)
        pr = repo.get_pull(pr_number)
        comments = pr.get_issue_comments()

        for comment in comments:
            if marker in (comment.body or ""):
                return comment.id

        return None

    def get_repository_labels(
        self,
        repo_full_name: str,
    ) -> list[RepositoryLabel]:
        """Get all labels for a repository.

        Args:
            repo_full_name: Repository full name.

        Returns:
            List of repository labels.
        """
        repo = self.get_repository(repo_full_name)
        labels = repo.get_labels()

        return [
            RepositoryLabel(
                name=label.name,
                color=label.color,
                description=label.description or "",
            )
            for label in labels
        ]

    def create_label(
        self,
        repo_full_name: str,
        name: str,
        color: str,
        description: str = "",
    ) -> RepositoryLabel:
        """Create a repository label.

        Args:
            repo_full_name: Repository full name.
            name: Label name.
            color: Label color (hex format without #).
            description: Label description.

        Returns:
            Created label.
        """
        repo = self.get_repository(repo_full_name)
        # Remove # from color if present
        color = color.lstrip("#")
        label = repo.create_label(name=name, color=color, description=description)

        return RepositoryLabel(
            name=label.name,
            color=label.color,
            description=label.description or "",
        )

    def ensure_label_exists(
        self,
        repo_full_name: str,
        name: str,
        color: str,
        description: str = "",
    ) -> RepositoryLabel:
        """Ensure a label exists, creating it if necessary.

        Args:
            repo_full_name: Repository full name.
            name: Label name.
            color: Label color.
            description: Label description.

        Returns:
            The label (existing or newly created).
        """
        labels = self.get_repository_labels(repo_full_name)
        for label in labels:
            if label.name == name:
                return label

        return self.create_label(repo_full_name, name, color, description)

    def add_pr_labels(
        self,
        repo_full_name: str,
        pr_number: int,
        labels: list[str],
    ) -> None:
        """Add labels to a pull request.

        Args:
            repo_full_name: Repository full name.
            pr_number: Pull request number.
            labels: List of label names to add.
        """
        repo = self.get_repository(repo_full_name)
        pr = repo.get_pull(pr_number)
        issue = repo.get_issue(pr_number)

        for label in labels:
            issue.add_to_labels(label)

    def remove_pr_labels(
        self,
        repo_full_name: str,
        pr_number: int,
        labels: list[str],
    ) -> None:
        """Remove labels from a pull request.

        Args:
            repo_full_name: Repository full name.
            pr_number: Pull request number.
            labels: List of label names to remove.
        """
        repo = self.get_repository(repo_full_name)
        issue = repo.get_issue(pr_number)

        current_labels = {label.name for label in issue.labels}

        for label in labels:
            if label in current_labels:
                try:
                    issue.remove_from_labels(label)
                except Exception:
                    pass  # Label might not exist

    def create_branch(
        self,
        repo_full_name: str,
        branch_name: str,
        ref: str = "main",
    ) -> None:
        """Create a new branch.

        Args:
            repo_full_name: Repository full name.
            branch_name: Name for the new branch.
            ref: Reference to create branch from.
        """
        repo = self.get_repository(repo_full_name)
        source = repo.get_branch(ref)
        repo.create_git_ref(
            ref=f"refs/heads/{branch_name}",
            sha=source.commit.sha,
        )

    def create_file(
        self,
        repo_full_name: str,
        file_path: str,
        branch: str,
        content: str,
        commit_message: str,
    ) -> None:
        """Create a new file in the repository.

        Args:
            repo_full_name: Repository full name.
            file_path: Path for the new file.
            branch: Branch to create file on.
            content: File content.
            commit_message: Commit message.
        """
        repo = self.get_repository(repo_full_name)
        repo.create_file(
            path=file_path,
            message=commit_message,
            content=content,
            branch=branch,
        )

    def update_file(
        self,
        repo_full_name: str,
        file_path: str,
        branch: str,
        content: str,
        commit_message: str,
    ) -> None:
        """Update an existing file in the repository.

        Args:
            repo_full_name: Repository full name.
            file_path: Path to the file.
            branch: Branch to update file on.
            content: New file content.
            commit_message: Commit message.
        """
        repo = self.get_repository(repo_full_name)
        contents = repo.get_contents(file_path, ref=branch)

        if isinstance(contents, list):
            raise ValueError(f"{file_path} is a directory")

        repo.update_file(
            path=file_path,
            message=commit_message,
            content=content,
            sha=contents.sha,
            branch=branch,
        )

    def create_pull_request(
        self,
        repo_full_name: str,
        head_branch: str,
        base_branch: str,
        title: str,
        body: str = "",
        labels: Optional[list[str]] = None,
    ) -> PullRequestInfo:
        """Create a new pull request.

        Args:
            repo_full_name: Repository full name.
            head_branch: Source branch name.
            base_branch: Target branch name.
            title: PR title.
            body: PR body.
            labels: Optional list of labels.

        Returns:
            Created pull request info.
        """
        repo = self.get_repository(repo_full_name)
        pr = repo.create_pull(
            title=title,
            body=body,
            head=head_branch,
            base=base_branch,
        )

        if labels:
            issue = repo.get_issue(pr.number)
            for label in labels:
                issue.add_to_labels(label)

        return PullRequestInfo(
            number=pr.number,
            title=pr.title,
            body=pr.body or "",
            head_branch=pr.head.ref,
            base_branch=pr.base.ref,
            author_login=pr.user.login if pr.user else "",
            state=pr.state,
            html_url=pr.html_url,
            created_at=pr.created_at,
            updated_at=pr.updated_at,
            labels=labels or [],
        )

    def get_check_runs(
        self,
        repo_full_name: str,
        pr_number: int,
    ) -> list[dict[str, Any]]:
        """Get check runs for a pull request.

        Args:
            repo_full_name: Repository full name.
            pr_number: Pull request number.

        Returns:
            List of check run information.
        """
        repo = self.get_repository(repo_full_name)
        pr = repo.get_pull(pr_number)
        commit = repo.get_commit(pr.head.sha)
        check_runs = commit.get_check_runs()

        return [
            {
                "name": run.name,
                "status": run.status,
                "conclusion": run.conclusion,
                "url": run.html_url,
            }
            for run in check_runs
        ]

    def get_workflow_runs(
        self,
        repo_full_name: str,
        branch: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Get workflow runs for a repository.

        Args:
            repo_full_name: Repository full name.
            branch: Optional branch filter.

        Returns:
            List of workflow run information.
        """
        repo = self.get_repository(repo_full_name)

        if branch:
            runs = repo.get_workflow_runs(branch=branch)
        else:
            runs = repo.get_workflow_runs()

        return [
            {
                "id": run.id,
                "name": run.name,
                "status": run.status,
                "conclusion": run.conclusion,
                "url": run.html_url,
                "created_at": run.created_at,
            }
            for run in runs[:10]  # Limit to 10 most recent
        ]
