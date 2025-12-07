"""GitLab API client for merge request operations."""

import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import gitlab
import gitlab.exceptions
from gitlab.v4.objects import Project

from blastauri.errors import (
    GitLabAccessDeniedError,
    GitLabAuthenticationError,
    GitLabNotFoundError,
    GitLabRateLimitError,
    NetworkError,
)


@dataclass
class GitLabConfig:
    """Configuration for GitLab client."""

    url: str = "https://gitlab.com"
    private_token: str | None = None
    oauth_token: str | None = None
    job_token: str | None = None

    @classmethod
    def from_env(cls) -> "GitLabConfig":
        """Create config from environment variables."""
        return cls(
            url=os.environ.get("GITLAB_URL", "https://gitlab.com"),
            private_token=os.environ.get("GITLAB_PRIVATE_TOKEN"),
            oauth_token=os.environ.get("GITLAB_OAUTH_TOKEN"),
            job_token=os.environ.get("CI_JOB_TOKEN"),
        )


@dataclass
class MergeRequestInfo:
    """Information about a merge request."""

    iid: int
    title: str
    description: str
    source_branch: str
    target_branch: str
    author_username: str
    state: str
    web_url: str
    created_at: datetime
    updated_at: datetime
    labels: list[str] = field(default_factory=list)
    has_conflicts: bool = False
    merge_status: str = ""


@dataclass
class MergeRequestDiff:
    """Diff information for a merge request."""

    old_path: str
    new_path: str
    diff: str
    new_file: bool
    renamed_file: bool
    deleted_file: bool


@dataclass
class MergeRequestChange:
    """File change in a merge request."""

    old_path: str
    new_path: str
    a_mode: str
    b_mode: str
    new_file: bool
    renamed_file: bool
    deleted_file: bool
    diff: str


@dataclass
class ProjectLabel:
    """A project label."""

    name: str
    color: str
    description: str = ""


class GitLabClient:
    """Client for GitLab API operations."""

    def __init__(self, config: GitLabConfig | None = None):
        """Initialize the GitLab client.

        Args:
            config: GitLab configuration. If None, reads from environment.
        """
        self._config = config or GitLabConfig.from_env()
        self._gl: gitlab.Gitlab | None = None

    def _get_client(self) -> gitlab.Gitlab:
        """Get or create the GitLab client."""
        if self._gl is None:
            # Determine authentication method
            if self._config.private_token:
                self._gl = gitlab.Gitlab(
                    self._config.url,
                    private_token=self._config.private_token,
                )
            elif self._config.oauth_token:
                self._gl = gitlab.Gitlab(
                    self._config.url,
                    oauth_token=self._config.oauth_token,
                )
            elif self._config.job_token:
                self._gl = gitlab.Gitlab(
                    self._config.url,
                    job_token=self._config.job_token,
                )
            else:
                # Unauthenticated access
                self._gl = gitlab.Gitlab(self._config.url)

            try:
                self._gl.auth()
            except gitlab.exceptions.GitlabAuthenticationError as e:
                raise GitLabAuthenticationError() from e
            except gitlab.exceptions.GitlabConnectionError as e:
                raise NetworkError("GitLab", e) from e

        return self._gl

    def _handle_gitlab_error(
        self,
        error: Exception,
        project_id: str | int = "",
        mr_iid: int | None = None,
    ) -> None:
        """Convert GitLab library exceptions to user-friendly errors.

        Args:
            error: The original exception.
            project_id: Project ID or path for context.
            mr_iid: Merge request IID for context.

        Raises:
            GitLabAuthenticationError: For 401 errors.
            GitLabAccessDeniedError: For 403 errors.
            GitLabNotFoundError: For 404 errors.
            GitLabRateLimitError: For 429 errors.
            NetworkError: For connection errors.
        """
        project_str = str(project_id) if project_id else ""

        if isinstance(error, gitlab.exceptions.GitlabAuthenticationError):
            raise GitLabAuthenticationError() from error

        if isinstance(error, gitlab.exceptions.GitlabConnectionError):
            raise NetworkError("GitLab", error) from error

        if isinstance(error, gitlab.exceptions.GitlabHttpError):
            status_code = getattr(error, "response_code", 0)
            if status_code == 401:
                raise GitLabAuthenticationError() from error
            if status_code == 403:
                raise GitLabAccessDeniedError(project_str) from error
            if status_code == 404:
                raise GitLabNotFoundError(project_str, mr_iid) from error
            if status_code == 429:
                # Try to get retry-after header
                retry_after = None
                if hasattr(error, "response_headers"):
                    retry_after = error.response_headers.get("retry-after")
                    if retry_after:
                        retry_after = int(retry_after)
                raise GitLabRateLimitError(retry_after) from error

        if isinstance(error, gitlab.exceptions.GitlabGetError):
            raise GitLabNotFoundError(project_str, mr_iid) from error

        # Re-raise unknown errors
        raise error

    def get_project(self, project_id: str | int) -> Project:
        """Get a GitLab project.

        Args:
            project_id: Project ID or path (e.g., "group/project").

        Returns:
            GitLab project object.

        Raises:
            GitLabAuthenticationError: If authentication fails.
            GitLabAccessDeniedError: If access is denied.
            GitLabNotFoundError: If the project is not found.
            NetworkError: If connection fails.
        """
        try:
            gl = self._get_client()
            return gl.projects.get(project_id)
        except gitlab.exceptions.GitlabError as e:
            self._handle_gitlab_error(e, project_id)
            raise  # Should not reach here

    def get_merge_request(
        self,
        project_id: str | int,
        mr_iid: int,
    ) -> MergeRequestInfo:
        """Get merge request information.

        Args:
            project_id: Project ID or path.
            mr_iid: Merge request IID.

        Returns:
            Merge request information.

        Raises:
            GitLabAuthenticationError: If authentication fails.
            GitLabAccessDeniedError: If access is denied.
            GitLabNotFoundError: If the MR is not found.
            NetworkError: If connection fails.
        """
        try:
            project = self.get_project(project_id)
            mr = project.mergerequests.get(mr_iid)
        except gitlab.exceptions.GitlabError as e:
            self._handle_gitlab_error(e, project_id, mr_iid)
            raise  # Should not reach here

        return MergeRequestInfo(
            iid=mr.iid,
            title=mr.title,
            description=mr.description or "",
            source_branch=mr.source_branch,
            target_branch=mr.target_branch,
            author_username=mr.author.get("username", "") if mr.author else "",
            state=mr.state,
            web_url=mr.web_url,
            created_at=datetime.fromisoformat(mr.created_at.replace("Z", "+00:00")),
            updated_at=datetime.fromisoformat(mr.updated_at.replace("Z", "+00:00")),
            labels=list(mr.labels) if mr.labels else [],
            has_conflicts=mr.has_conflicts if hasattr(mr, "has_conflicts") else False,
            merge_status=mr.merge_status if hasattr(mr, "merge_status") else "",
        )

    def get_mr_diff(
        self,
        project_id: str | int,
        mr_iid: int,
    ) -> list[MergeRequestDiff]:
        """Get merge request diffs.

        Args:
            project_id: Project ID or path.
            mr_iid: Merge request IID.

        Returns:
            List of diffs.
        """
        project = self.get_project(project_id)
        mr = project.mergerequests.get(mr_iid)
        diffs = mr.diffs.list(get_all=True)

        result: list[MergeRequestDiff] = []
        for diff_version in diffs:
            diff_detail = mr.diffs.get(diff_version.id)
            for d in diff_detail.diffs:
                result.append(
                    MergeRequestDiff(
                        old_path=d.get("old_path", ""),
                        new_path=d.get("new_path", ""),
                        diff=d.get("diff", ""),
                        new_file=d.get("new_file", False),
                        renamed_file=d.get("renamed_file", False),
                        deleted_file=d.get("deleted_file", False),
                    )
                )

        return result

    def get_mr_changes(
        self,
        project_id: str | int,
        mr_iid: int,
    ) -> list[MergeRequestChange]:
        """Get merge request file changes.

        Args:
            project_id: Project ID or path.
            mr_iid: Merge request IID.

        Returns:
            List of file changes.
        """
        project = self.get_project(project_id)
        mr = project.mergerequests.get(mr_iid)
        changes = mr.changes()

        result: list[MergeRequestChange] = []
        for change in changes.get("changes", []):
            result.append(
                MergeRequestChange(
                    old_path=change.get("old_path", ""),
                    new_path=change.get("new_path", ""),
                    a_mode=change.get("a_mode", ""),
                    b_mode=change.get("b_mode", ""),
                    new_file=change.get("new_file", False),
                    renamed_file=change.get("renamed_file", False),
                    deleted_file=change.get("deleted_file", False),
                    diff=change.get("diff", ""),
                )
            )

        return result

    def get_file_content(
        self,
        project_id: str | int,
        file_path: str,
        ref: str = "main",
    ) -> str:
        """Get file content from repository.

        Args:
            project_id: Project ID or path.
            file_path: Path to file in repository.
            ref: Branch, tag, or commit SHA.

        Returns:
            File content as string.
        """
        project = self.get_project(project_id)
        try:
            f = project.files.get(file_path=file_path, ref=ref)
            return f.decode().decode("utf-8")
        except gitlab.exceptions.GitlabGetError:
            return ""

    def post_mr_comment(
        self,
        project_id: str | int,
        mr_iid: int,
        body: str,
    ) -> int:
        """Post a comment on a merge request.

        Args:
            project_id: Project ID or path.
            mr_iid: Merge request IID.
            body: Comment body.

        Returns:
            Note ID of the created comment.
        """
        project = self.get_project(project_id)
        mr = project.mergerequests.get(mr_iid)
        note = mr.notes.create({"body": body})
        return note.id

    def update_mr_comment(
        self,
        project_id: str | int,
        mr_iid: int,
        note_id: int,
        body: str,
    ) -> None:
        """Update an existing merge request comment.

        Args:
            project_id: Project ID or path.
            mr_iid: Merge request IID.
            note_id: Note ID to update.
            body: New comment body.
        """
        project = self.get_project(project_id)
        mr = project.mergerequests.get(mr_iid)
        note = mr.notes.get(note_id)
        note.body = body
        note.save()

    def delete_mr_comment(
        self,
        project_id: str | int,
        mr_iid: int,
        note_id: int,
    ) -> None:
        """Delete a merge request comment.

        Args:
            project_id: Project ID or path.
            mr_iid: Merge request IID.
            note_id: Note ID to delete.
        """
        project = self.get_project(project_id)
        mr = project.mergerequests.get(mr_iid)
        note = mr.notes.get(note_id)
        note.delete()

    def find_bot_comment(
        self,
        project_id: str | int,
        mr_iid: int,
        marker: str = "<!-- blastauri-analysis -->",
    ) -> int | None:
        """Find an existing bot comment by marker.

        Args:
            project_id: Project ID or path.
            mr_iid: Merge request IID.
            marker: HTML comment marker to find.

        Returns:
            Note ID if found, None otherwise.
        """
        project = self.get_project(project_id)
        mr = project.mergerequests.get(mr_iid)
        notes = mr.notes.list(get_all=True)

        for note in notes:
            if marker in note.body:
                return note.id

        return None

    def get_project_labels(
        self,
        project_id: str | int,
    ) -> list[ProjectLabel]:
        """Get all labels for a project.

        Args:
            project_id: Project ID or path.

        Returns:
            List of project labels.
        """
        project = self.get_project(project_id)
        labels = project.labels.list(get_all=True)

        return [
            ProjectLabel(
                name=label.name,
                color=label.color,
                description=label.description or "",
            )
            for label in labels
        ]

    def create_label(
        self,
        project_id: str | int,
        name: str,
        color: str,
        description: str = "",
    ) -> ProjectLabel:
        """Create a project label.

        Args:
            project_id: Project ID or path.
            name: Label name.
            color: Label color (hex format, e.g., "#FF0000").
            description: Label description.

        Returns:
            Created label.
        """
        project = self.get_project(project_id)
        label = project.labels.create({
            "name": name,
            "color": color,
            "description": description,
        })

        return ProjectLabel(
            name=label.name,
            color=label.color,
            description=label.description or "",
        )

    def ensure_label_exists(
        self,
        project_id: str | int,
        name: str,
        color: str,
        description: str = "",
    ) -> ProjectLabel:
        """Ensure a label exists, creating it if necessary.

        Args:
            project_id: Project ID or path.
            name: Label name.
            color: Label color.
            description: Label description.

        Returns:
            The label (existing or newly created).
        """
        labels = self.get_project_labels(project_id)
        for label in labels:
            if label.name == name:
                return label

        return self.create_label(project_id, name, color, description)

    def add_mr_labels(
        self,
        project_id: str | int,
        mr_iid: int,
        labels: list[str],
    ) -> None:
        """Add labels to a merge request.

        Args:
            project_id: Project ID or path.
            mr_iid: Merge request IID.
            labels: List of label names to add.
        """
        project = self.get_project(project_id)
        mr = project.mergerequests.get(mr_iid)

        current_labels = set(mr.labels) if mr.labels else set()
        new_labels = current_labels | set(labels)

        mr.labels = list(new_labels)
        mr.save()

    def remove_mr_labels(
        self,
        project_id: str | int,
        mr_iid: int,
        labels: list[str],
    ) -> None:
        """Remove labels from a merge request.

        Args:
            project_id: Project ID or path.
            mr_iid: Merge request IID.
            labels: List of label names to remove.
        """
        project = self.get_project(project_id)
        mr = project.mergerequests.get(mr_iid)

        current_labels = set(mr.labels) if mr.labels else set()
        new_labels = current_labels - set(labels)

        mr.labels = list(new_labels)
        mr.save()

    def create_branch(
        self,
        project_id: str | int,
        branch_name: str,
        ref: str = "main",
    ) -> None:
        """Create a new branch.

        Args:
            project_id: Project ID or path.
            branch_name: Name for the new branch.
            ref: Reference to create branch from.
        """
        project = self.get_project(project_id)
        project.branches.create({
            "branch": branch_name,
            "ref": ref,
        })

    def create_file(
        self,
        project_id: str | int,
        file_path: str,
        branch: str,
        content: str,
        commit_message: str,
    ) -> None:
        """Create a new file in the repository.

        Args:
            project_id: Project ID or path.
            file_path: Path for the new file.
            branch: Branch to create file on.
            content: File content.
            commit_message: Commit message.
        """
        project = self.get_project(project_id)
        project.files.create({
            "file_path": file_path,
            "branch": branch,
            "content": content,
            "commit_message": commit_message,
        })

    def update_file(
        self,
        project_id: str | int,
        file_path: str,
        branch: str,
        content: str,
        commit_message: str,
    ) -> None:
        """Update an existing file in the repository.

        Args:
            project_id: Project ID or path.
            file_path: Path to the file.
            branch: Branch to update file on.
            content: New file content.
            commit_message: Commit message.
        """
        project = self.get_project(project_id)
        f = project.files.get(file_path=file_path, ref=branch)
        f.content = content
        f.save(branch=branch, commit_message=commit_message)

    def create_merge_request(
        self,
        project_id: str | int,
        source_branch: str,
        target_branch: str,
        title: str,
        description: str = "",
        labels: list[str] | None = None,
        remove_source_branch: bool = True,
    ) -> MergeRequestInfo:
        """Create a new merge request.

        Args:
            project_id: Project ID or path.
            source_branch: Source branch name.
            target_branch: Target branch name.
            title: MR title.
            description: MR description.
            labels: Optional list of labels.
            remove_source_branch: Remove source branch on merge.

        Returns:
            Created merge request info.
        """
        project = self.get_project(project_id)
        mr = project.mergerequests.create({
            "source_branch": source_branch,
            "target_branch": target_branch,
            "title": title,
            "description": description,
            "labels": labels or [],
            "remove_source_branch": remove_source_branch,
        })

        return MergeRequestInfo(
            iid=mr.iid,
            title=mr.title,
            description=mr.description or "",
            source_branch=mr.source_branch,
            target_branch=mr.target_branch,
            author_username=mr.author.get("username", "") if mr.author else "",
            state=mr.state,
            web_url=mr.web_url,
            created_at=datetime.fromisoformat(mr.created_at.replace("Z", "+00:00")),
            updated_at=datetime.fromisoformat(mr.updated_at.replace("Z", "+00:00")),
            labels=list(mr.labels) if mr.labels else [],
        )

    def get_mr_approvals(
        self,
        project_id: str | int,
        mr_iid: int,
    ) -> dict[str, Any]:
        """Get merge request approval status.

        Args:
            project_id: Project ID or path.
            mr_iid: Merge request IID.

        Returns:
            Approval status dictionary.
        """
        project = self.get_project(project_id)
        mr = project.mergerequests.get(mr_iid)

        try:
            approvals = mr.approvals.get()
            return {
                "approved": approvals.approved,
                "approvals_required": approvals.approvals_required,
                "approvals_left": approvals.approvals_left,
                "approved_by": [
                    a.get("user", {}).get("username", "")
                    for a in approvals.approved_by
                ],
            }
        except Exception:
            return {
                "approved": False,
                "approvals_required": 0,
                "approvals_left": 0,
                "approved_by": [],
            }

    def get_pipeline_status(
        self,
        project_id: str | int,
        mr_iid: int,
    ) -> str | None:
        """Get the latest pipeline status for an MR.

        Args:
            project_id: Project ID or path.
            mr_iid: Merge request IID.

        Returns:
            Pipeline status or None.
        """
        project = self.get_project(project_id)
        mr = project.mergerequests.get(mr_iid)
        pipelines = mr.pipelines.list(per_page=1)

        if pipelines:
            return pipelines[0].status

        return None
