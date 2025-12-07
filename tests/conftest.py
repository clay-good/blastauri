"""Pytest configuration and fixtures for blastauri tests."""

import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def fixtures_dir() -> Path:
    """Return the path to the test fixtures directory."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def lockfiles_dir(fixtures_dir: Path) -> Path:
    """Return the path to the lockfiles fixtures directory."""
    return fixtures_dir / "lockfiles"


@pytest.fixture
def cve_responses_dir(fixtures_dir: Path) -> Path:
    """Return the path to the CVE responses fixtures directory."""
    return fixtures_dir / "cve_responses"


@pytest.fixture
def changelogs_dir(fixtures_dir: Path) -> Path:
    """Return the path to the changelogs fixtures directory."""
    return fixtures_dir / "changelogs"


@pytest.fixture
def codebases_dir(fixtures_dir: Path) -> Path:
    """Return the path to the sample codebases fixtures directory."""
    return fixtures_dir / "codebases"


@pytest.fixture
def sample_package_lock(lockfiles_dir: Path, temp_dir: Path) -> Path:
    """Create a sample package-lock.json file."""
    content = """{
  "name": "sample-project",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "sample-project",
      "version": "1.0.0",
      "dependencies": {
        "lodash": "^4.17.21",
        "express": "^4.18.2"
      },
      "devDependencies": {
        "jest": "^29.7.0"
      }
    },
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
    },
    "node_modules/express": {
      "version": "4.18.2",
      "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz"
    },
    "node_modules/jest": {
      "version": "29.7.0",
      "resolved": "https://registry.npmjs.org/jest/-/jest-29.7.0.tgz",
      "dev": true
    }
  }
}"""
    file_path = temp_dir / "package-lock.json"
    file_path.write_text(content)
    return file_path


@pytest.fixture
def sample_requirements_txt(temp_dir: Path) -> Path:
    """Create a sample requirements.txt file."""
    content = """# Production dependencies
requests==2.31.0
pydantic>=2.5.0,<3.0.0
httpx~=0.27.0

# Development dependencies
-e git+https://github.com/example/repo.git#egg=example
pytest>=8.0.0
"""
    file_path = temp_dir / "requirements.txt"
    file_path.write_text(content)
    return file_path


@pytest.fixture
def sample_go_mod(temp_dir: Path) -> Path:
    """Create a sample go.mod file."""
    content = """module github.com/example/myproject

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/stretchr/testify v1.8.4 // indirect
)

replace github.com/old/module => github.com/new/module v1.0.0
"""
    file_path = temp_dir / "go.mod"
    file_path.write_text(content)
    return file_path


@pytest.fixture
def sample_config(temp_dir: Path) -> Path:
    """Create a sample .blastauri.yml configuration file."""
    content = """version: 1
platform: gitlab

analysis:
  ai_provider: none
  severity_threshold: low

waf:
  provider: aws
  mode: log

scanner:
  ecosystems:
    - npm
    - pypi
  exclude_dev: false
"""
    file_path = temp_dir / ".blastauri.yml"
    file_path.write_text(content)
    return file_path


@pytest.fixture
def env_with_tokens(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set up environment variables for testing."""
    monkeypatch.setenv("GITLAB_TOKEN", "test-gitlab-token")
    monkeypatch.setenv("GITHUB_TOKEN", "test-github-token")
    monkeypatch.setenv("NVD_API_KEY", "test-nvd-key")


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove sensitive environment variables for testing."""
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("NVD_API_KEY", raising=False)
