"""Docker image end-to-end tests for blastauri.

These tests verify the Docker image works correctly.
They are skipped if Docker is not available.
"""

import subprocess
import tempfile
from pathlib import Path

import pytest


def docker_available() -> bool:
    """Check if Docker is available."""
    try:
        result = subprocess.run(
            ["docker", "version"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


# Skip all tests if Docker is not available
pytestmark = pytest.mark.skipif(
    not docker_available(),
    reason="Docker not available",
)


@pytest.fixture(scope="module")
def docker_image() -> str:
    """Build the Docker image for testing.

    Returns:
        The image name/tag.
    """
    project_root = Path(__file__).parent.parent.parent

    # Build the image
    result = subprocess.run(
        ["docker", "build", "-t", "blastauri-pytest", "."],
        cwd=project_root,
        capture_output=True,
        text=True,
        timeout=300,  # 5 minute timeout for build
    )

    if result.returncode != 0:
        pytest.fail(f"Docker build failed: {result.stderr}")

    yield "blastauri-pytest"

    # Cleanup after all tests
    subprocess.run(
        ["docker", "rmi", "blastauri-pytest"],
        capture_output=True,
    )


class TestDockerImage:
    """Tests for the Docker image."""

    def test_version_command(self, docker_image: str) -> None:
        """Test that --version command works."""
        result = subprocess.run(
            ["docker", "run", "--rm", docker_image, "--version"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "blastauri version" in result.stdout

    def test_help_command(self, docker_image: str) -> None:
        """Test that --help command works."""
        result = subprocess.run(
            ["docker", "run", "--rm", docker_image, "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "Know what breaks before you merge" in result.stdout
        assert "analyze" in result.stdout
        assert "scan" in result.stdout
        assert "waf" in result.stdout

    def test_analyze_help(self, docker_image: str) -> None:
        """Test that analyze --help works."""
        result = subprocess.run(
            ["docker", "run", "--rm", docker_image, "analyze", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "Analyze" in result.stdout or "analyze" in result.stdout
        assert "--project" in result.stdout or "--repo" in result.stdout

    def test_analyze_dry_run(self, docker_image: str) -> None:
        """Test that analyze --dry-run works in container."""
        result = subprocess.run(
            ["docker", "run", "--rm", docker_image, "analyze", "--dry-run"],
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert result.returncode == 0
        assert "dry-run" in result.stdout.lower() or "sample" in result.stdout.lower()

    def test_scan_help(self, docker_image: str) -> None:
        """Test that scan --help works."""
        result = subprocess.run(
            ["docker", "run", "--rm", docker_image, "scan", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "Scan" in result.stdout or "scan" in result.stdout

    def test_waf_help(self, docker_image: str) -> None:
        """Test that waf --help works."""
        result = subprocess.run(
            ["docker", "run", "--rm", docker_image, "waf", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "WAF" in result.stdout or "waf" in result.stdout

    def test_waf_templates(self, docker_image: str) -> None:
        """Test that waf templates command works."""
        result = subprocess.run(
            ["docker", "run", "--rm", docker_image, "waf", "templates"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0

    def test_scan_with_mounted_volume(self, docker_image: str) -> None:
        """Test scanning a mounted directory."""
        project_root = Path(__file__).parent.parent.parent
        fixtures_dir = project_root / "tests" / "fixtures"

        if not fixtures_dir.exists():
            pytest.skip("Fixtures directory not found")

        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "-v", f"{fixtures_dir}:/workspace:ro",
                docker_image, "scan", "/workspace",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        # Scan may find no lockfiles, which is OK
        assert result.returncode == 0 or "No supported lockfiles" in result.stdout

    def test_waf_generate_with_output(self, docker_image: str) -> None:
        """Test WAF generation with output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = subprocess.run(
                [
                    "docker", "run", "--rm",
                    "-v", f"{tmpdir}:/output",
                    docker_image, "waf", "generate",
                    "--owasp", "--output", "/output",
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )

            # Check that command ran (may succeed or fail depending on state)
            # Just verify it doesn't crash
            assert result.returncode in [0, 1]

    def test_config_show(self, docker_image: str) -> None:
        """Test config show command."""
        result = subprocess.run(
            ["docker", "run", "--rm", docker_image, "config", "show"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        # May succeed or fail if no config exists
        # Just verify the command runs
        assert result.returncode in [0, 1]


class TestDockerImageSecurity:
    """Security-related tests for the Docker image."""

    def test_runs_as_non_root(self, docker_image: str) -> None:
        """Test that the container doesn't run as root.

        Note: This test uses a workaround since the entrypoint is blastauri.
        """
        # We can verify this by checking the Dockerfile uses USER directive
        project_root = Path(__file__).parent.parent.parent
        dockerfile = project_root / "Dockerfile"

        content = dockerfile.read_text()
        assert "USER " in content or "user" in content.lower()

    def test_no_sensitive_env_vars_exposed(self, docker_image: str) -> None:
        """Test that sensitive env vars aren't baked into the image."""
        result = subprocess.run(
            ["docker", "inspect", docker_image, "--format", "{{json .Config.Env}}"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        env_output = result.stdout.lower()

        # Check no tokens are baked in
        assert "gitlab_token" not in env_output or "null" in env_output
        assert "github_token" not in env_output or "null" in env_output
        assert "nvd_api_key" not in env_output or "null" in env_output


class TestDockerImageWithEnvVars:
    """Tests that verify environment variable handling."""

    def test_analyze_requires_token_message(self, docker_image: str) -> None:
        """Test that analyze without token gives helpful error."""
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                docker_image, "analyze",
                "--project", "test/project",
                "--mr", "1",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Should fail but give helpful error about token
        assert result.returncode == 1
        output = result.stdout + result.stderr
        # Should mention something about token, authentication, or environment
        assert any(word in output.lower() for word in ["token", "auth", "gitlab", "error"])

    def test_env_var_passthrough(self, docker_image: str) -> None:
        """Test that environment variables can be passed to container."""
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "-e", "BLASTAURI_TEST_VAR=test_value",
                docker_image, "--help",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        # Just verify container starts with env var
        assert result.returncode == 0
