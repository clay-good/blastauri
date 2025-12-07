"""Custom exceptions for blastauri with user-friendly error messages."""



class BlastauriError(Exception):
    """Base exception with user-friendly message and optional hint.

    Attributes:
        message: The main error message.
        hint: Optional hint for resolving the error.
    """

    def __init__(self, message: str, hint: str = "") -> None:
        """Initialize the exception.

        Args:
            message: The main error message.
            hint: Optional hint for resolving the error.
        """
        self.message = message
        self.hint = hint
        super().__init__(message)

    def __str__(self) -> str:
        """Return string representation."""
        if self.hint:
            return f"{self.message}\nHint: {self.hint}"
        return self.message


class AuthenticationError(BlastauriError):
    """Authentication failed - missing or invalid credentials."""

    pass


class GitLabAuthenticationError(AuthenticationError):
    """GitLab authentication failed."""

    def __init__(
        self,
        message: str = "GitLab authentication failed",
        hint: str = "Set GITLAB_TOKEN or GITLAB_PRIVATE_TOKEN environment variable with 'api' scope.",
    ) -> None:
        super().__init__(message, hint)


class GitHubAuthenticationError(AuthenticationError):
    """GitHub authentication failed."""

    def __init__(
        self,
        message: str = "GitHub authentication failed",
        hint: str = "Set GITHUB_TOKEN environment variable with 'repo' scope.",
    ) -> None:
        super().__init__(message, hint)


class AccessDeniedError(BlastauriError):
    """Access denied - insufficient permissions."""

    pass


class GitLabAccessDeniedError(AccessDeniedError):
    """GitLab access denied."""

    def __init__(
        self,
        project: str = "",
        message: str = "",
        hint: str = "",
    ) -> None:
        if not message:
            message = f"GitLab access denied for project '{project}'" if project else "GitLab access denied"
        if not hint:
            hint = "Verify your token has 'api' scope and you have access to the project."
        super().__init__(message, hint)


class GitHubAccessDeniedError(AccessDeniedError):
    """GitHub access denied."""

    def __init__(
        self,
        repo: str = "",
        message: str = "",
        hint: str = "",
    ) -> None:
        if not message:
            message = f"GitHub access denied for repository '{repo}'" if repo else "GitHub access denied"
        if not hint:
            hint = "Verify your token has 'repo' scope and you have access to the repository."
        super().__init__(message, hint)


class NotFoundError(BlastauriError):
    """Resource not found."""

    pass


class GitLabNotFoundError(NotFoundError):
    """GitLab project or MR not found."""

    def __init__(
        self,
        project: str = "",
        mr_iid: int | None = None,
        message: str = "",
        hint: str = "",
    ) -> None:
        if not message:
            if project and mr_iid:
                message = f"GitLab MR !{mr_iid} not found in project '{project}'"
            elif project:
                message = f"GitLab project '{project}' not found"
            else:
                message = "GitLab resource not found"
        if not hint:
            hint = "Verify the project path and MR IID are correct."
        super().__init__(message, hint)


class GitHubNotFoundError(NotFoundError):
    """GitHub repository or PR not found."""

    def __init__(
        self,
        repo: str = "",
        pr_number: int | None = None,
        message: str = "",
        hint: str = "",
    ) -> None:
        if not message:
            if repo and pr_number:
                message = f"GitHub PR #{pr_number} not found in repository '{repo}'"
            elif repo:
                message = f"GitHub repository '{repo}' not found"
            else:
                message = "GitHub resource not found"
        if not hint:
            hint = "Verify the repository (owner/repo) and PR number are correct."
        super().__init__(message, hint)


class RateLimitError(BlastauriError):
    """API rate limit exceeded."""

    def __init__(
        self,
        service: str,
        retry_after: int | None = None,
        message: str = "",
        hint: str = "",
    ) -> None:
        if not message:
            if retry_after:
                message = f"{service} rate limit exceeded. Retry after {retry_after} seconds."
            else:
                message = f"{service} rate limit exceeded."
        super().__init__(message, hint)


class GitLabRateLimitError(RateLimitError):
    """GitLab API rate limit exceeded."""

    def __init__(
        self,
        retry_after: int | None = None,
        message: str = "",
        hint: str = "Wait before retrying or use a token with higher limits.",
    ) -> None:
        super().__init__("GitLab", retry_after, message, hint)


class GitHubRateLimitError(RateLimitError):
    """GitHub API rate limit exceeded."""

    def __init__(
        self,
        retry_after: int | None = None,
        authenticated: bool = True,
        message: str = "",
        hint: str = "",
    ) -> None:
        if not hint:
            if authenticated:
                hint = "Wait before retrying or check your rate limit status at https://api.github.com/rate_limit"
            else:
                hint = "Authenticate with GITHUB_TOKEN to increase limit from 60 to 5000 requests/hour."
        super().__init__("GitHub", retry_after, message, hint)


class NvdRateLimitError(RateLimitError):
    """NVD API rate limit exceeded."""

    def __init__(
        self,
        retry_after: int | None = None,
        message: str = "",
        hint: str = "Set NVD_API_KEY for higher rate limits (free at https://nvd.nist.gov/developers/request-an-api-key).",
    ) -> None:
        super().__init__("NVD", retry_after, message, hint)


class ConfigurationError(BlastauriError):
    """Invalid configuration."""

    pass


class MissingTokenError(ConfigurationError):
    """Required token is missing."""

    def __init__(
        self,
        token_name: str,
        message: str = "",
        hint: str = "",
    ) -> None:
        if not message:
            message = f"Required environment variable {token_name} is not set"
        if not hint:
            hint = f"Set {token_name} in your environment or CI/CD variables."
        super().__init__(message, hint)


class NetworkError(BlastauriError):
    """Network connectivity issue."""

    def __init__(
        self,
        service: str,
        original_error: Exception | None = None,
        message: str = "",
        hint: str = "",
    ) -> None:
        if not message:
            message = f"Failed to reach {service}"
            if original_error:
                message += f": {original_error}"
        if not hint:
            hint = "Check your internet connection and firewall settings."
        super().__init__(message, hint)


class ParseError(BlastauriError):
    """Failed to parse response or file."""

    pass


class DiffParseError(ParseError):
    """Failed to parse lockfile diff."""

    def __init__(
        self,
        filename: str = "",
        message: str = "",
        hint: str = "",
    ) -> None:
        if not message:
            message = f"Failed to parse diff for {filename}" if filename else "Failed to parse diff"
        if not hint:
            hint = "Ensure the diff is in unified diff format."
        super().__init__(message, hint)


class UnsupportedEcosystemError(BlastauriError):
    """Unsupported package ecosystem."""

    def __init__(
        self,
        ecosystem: str,
        message: str = "",
        hint: str = "",
    ) -> None:
        if not message:
            message = f"Unsupported package ecosystem: {ecosystem}"
        if not hint:
            hint = "Supported ecosystems: npm, pypi, go, maven, cargo, composer, rubygems."
        super().__init__(message, hint)


class AnalysisError(BlastauriError):
    """Error during dependency analysis."""

    pass


class WafError(BlastauriError):
    """Error during WAF rule generation or management."""

    pass
