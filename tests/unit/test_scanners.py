"""Tests for dependency scanners."""

from pathlib import Path

import pytest

from blastauri.core.models import Ecosystem
from blastauri.scanners import (
    CargoScanner,
    ComposerScanner,
    GoScanner,
    MavenScanner,
    NpmScanner,
    PipScanner,
    RubyScanner,
    ScannerRegistry,
    detect_ecosystems,
    register_default_scanners,
    scan_repository,
)


class TestNpmScanner:
    """Tests for NPM scanner."""

    @pytest.fixture
    def scanner(self) -> NpmScanner:
        """Create NPM scanner instance."""
        return NpmScanner()

    def test_ecosystem(self, scanner: NpmScanner) -> None:
        """Test that scanner returns correct ecosystem."""
        assert scanner.ecosystem == Ecosystem.NPM

    def test_lockfile_patterns(self, scanner: NpmScanner) -> None:
        """Test that scanner has correct lockfile patterns."""
        assert "package-lock.json" in scanner.lockfile_patterns
        assert "yarn.lock" in scanner.lockfile_patterns
        assert "pnpm-lock.yaml" in scanner.lockfile_patterns

    def test_parse_package_lock(
        self, scanner: NpmScanner, lockfiles_dir: Path
    ) -> None:
        """Test parsing package-lock.json."""
        deps = scanner.parse_lockfile(lockfiles_dir / "package-lock.json")

        assert len(deps) >= 5

        names = {d.name for d in deps}
        assert "lodash" in names
        assert "express" in names
        assert "axios" in names
        assert "jest" in names
        assert "typescript" in names

        lodash = next(d for d in deps if d.name == "lodash")
        assert lodash.version == "4.17.21"
        assert lodash.ecosystem == Ecosystem.NPM
        assert lodash.is_dev is False

        jest = next(d for d in deps if d.name == "jest")
        assert jest.is_dev is True

    def test_parse_yarn_lock(
        self, scanner: NpmScanner, lockfiles_dir: Path
    ) -> None:
        """Test parsing yarn.lock."""
        deps = scanner.parse_lockfile(lockfiles_dir / "yarn.lock")

        assert len(deps) >= 5

        names = {d.name for d in deps}
        assert "lodash" in names
        assert "express" in names
        assert "axios" in names

    def test_parse_pnpm_lock(
        self, scanner: NpmScanner, lockfiles_dir: Path
    ) -> None:
        """Test parsing pnpm-lock.yaml."""
        deps = scanner.parse_lockfile(lockfiles_dir / "pnpm-lock.yaml")

        assert len(deps) >= 5

        names = {d.name for d in deps}
        assert "lodash" in names
        assert "express" in names


class TestPipScanner:
    """Tests for Python/pip scanner."""

    @pytest.fixture
    def scanner(self) -> PipScanner:
        """Create pip scanner instance."""
        return PipScanner()

    def test_ecosystem(self, scanner: PipScanner) -> None:
        """Test that scanner returns correct ecosystem."""
        assert scanner.ecosystem == Ecosystem.PYPI

    def test_parse_requirements_txt(
        self, scanner: PipScanner, lockfiles_dir: Path
    ) -> None:
        """Test parsing requirements.txt."""
        deps = scanner.parse_lockfile(lockfiles_dir / "requirements.txt")

        assert len(deps) >= 5

        names = {d.name for d in deps}
        assert "requests" in names
        assert "pydantic" in names
        assert "httpx" in names

        requests_dep = next(d for d in deps if d.name == "requests")
        assert requests_dep.version == "2.31.0"
        assert requests_dep.ecosystem == Ecosystem.PYPI

    def test_parse_pipfile_lock(
        self, scanner: PipScanner, lockfiles_dir: Path
    ) -> None:
        """Test parsing Pipfile.lock."""
        deps = scanner.parse_lockfile(lockfiles_dir / "Pipfile.lock")

        assert len(deps) >= 3

        names = {d.name for d in deps}
        assert "requests" in names
        assert "pydantic" in names

        pytest_dep = next((d for d in deps if d.name == "pytest"), None)
        if pytest_dep:
            assert pytest_dep.is_dev is True

    def test_parse_poetry_lock(
        self, scanner: PipScanner, lockfiles_dir: Path
    ) -> None:
        """Test parsing poetry.lock."""
        deps = scanner.parse_lockfile(lockfiles_dir / "poetry.lock")

        assert len(deps) >= 3

        names = {d.name for d in deps}
        assert "requests" in names
        assert "pydantic" in names


class TestGoScanner:
    """Tests for Go scanner."""

    @pytest.fixture
    def scanner(self) -> GoScanner:
        """Create Go scanner instance."""
        return GoScanner()

    def test_ecosystem(self, scanner: GoScanner) -> None:
        """Test that scanner returns correct ecosystem."""
        assert scanner.ecosystem == Ecosystem.GO

    def test_parse_go_mod(
        self, scanner: GoScanner, lockfiles_dir: Path
    ) -> None:
        """Test parsing go.mod."""
        deps = scanner.parse_lockfile(lockfiles_dir / "go.mod")

        assert len(deps) >= 3

        names = {d.name for d in deps}
        assert "github.com/gin-gonic/gin" in names
        assert "github.com/stretchr/testify" in names
        assert "github.com/spf13/cobra" in names

        gin_dep = next(d for d in deps if d.name == "github.com/gin-gonic/gin")
        assert gin_dep.version == "1.9.1"
        assert gin_dep.is_direct is True

    def test_parse_go_sum(
        self, scanner: GoScanner, lockfiles_dir: Path
    ) -> None:
        """Test parsing go.sum."""
        deps = scanner.parse_lockfile(lockfiles_dir / "go.sum")

        assert len(deps) >= 5

        names = {d.name for d in deps}
        assert "github.com/gin-gonic/gin" in names


class TestRubyScanner:
    """Tests for Ruby scanner."""

    @pytest.fixture
    def scanner(self) -> RubyScanner:
        """Create Ruby scanner instance."""
        return RubyScanner()

    def test_ecosystem(self, scanner: RubyScanner) -> None:
        """Test that scanner returns correct ecosystem."""
        assert scanner.ecosystem == Ecosystem.RUBYGEMS

    def test_parse_gemfile_lock(
        self, scanner: RubyScanner, lockfiles_dir: Path
    ) -> None:
        """Test parsing Gemfile.lock."""
        deps = scanner.parse_lockfile(lockfiles_dir / "Gemfile.lock")

        assert len(deps) >= 5

        names = {d.name for d in deps}
        assert "rails" in names
        assert "rack" in names
        assert "activesupport" in names

        rails_dep = next(d for d in deps if d.name == "rails")
        assert rails_dep.version == "7.1.2"
        assert rails_dep.is_direct is True


class TestMavenScanner:
    """Tests for Maven scanner."""

    @pytest.fixture
    def scanner(self) -> MavenScanner:
        """Create Maven scanner instance."""
        return MavenScanner()

    def test_ecosystem(self, scanner: MavenScanner) -> None:
        """Test that scanner returns correct ecosystem."""
        assert scanner.ecosystem == Ecosystem.MAVEN

    def test_parse_pom_xml(
        self, scanner: MavenScanner, lockfiles_dir: Path
    ) -> None:
        """Test parsing pom.xml."""
        deps = scanner.parse_lockfile(lockfiles_dir / "pom.xml")

        assert len(deps) >= 4

        names = {d.name for d in deps}
        assert "org.springframework:spring-core" in names
        assert "com.fasterxml.jackson.core:jackson-databind" in names
        assert "org.apache.logging.log4j:log4j-core" in names

        spring_dep = next(d for d in deps if "spring-core" in d.name)
        assert spring_dep.version == "6.1.2"

        junit_dep = next(d for d in deps if "junit" in d.name)
        assert junit_dep.is_dev is True


class TestCargoScanner:
    """Tests for Cargo scanner."""

    @pytest.fixture
    def scanner(self) -> CargoScanner:
        """Create Cargo scanner instance."""
        return CargoScanner()

    def test_ecosystem(self, scanner: CargoScanner) -> None:
        """Test that scanner returns correct ecosystem."""
        assert scanner.ecosystem == Ecosystem.CARGO

    def test_parse_cargo_lock(
        self, scanner: CargoScanner, lockfiles_dir: Path
    ) -> None:
        """Test parsing Cargo.lock."""
        deps = scanner.parse_lockfile(lockfiles_dir / "Cargo.lock")

        assert len(deps) >= 4

        names = {d.name for d in deps}
        assert "serde" in names
        assert "serde_json" in names
        assert "tokio" in names
        assert "reqwest" in names

        serde_dep = next(d for d in deps if d.name == "serde")
        assert serde_dep.version == "1.0.193"


class TestComposerScanner:
    """Tests for Composer scanner."""

    @pytest.fixture
    def scanner(self) -> ComposerScanner:
        """Create Composer scanner instance."""
        return ComposerScanner()

    def test_ecosystem(self, scanner: ComposerScanner) -> None:
        """Test that scanner returns correct ecosystem."""
        assert scanner.ecosystem == Ecosystem.COMPOSER

    def test_parse_composer_lock(
        self, scanner: ComposerScanner, lockfiles_dir: Path
    ) -> None:
        """Test parsing composer.lock."""
        deps = scanner.parse_lockfile(lockfiles_dir / "composer.lock")

        assert len(deps) >= 4

        names = {d.name for d in deps}
        assert "laravel/framework" in names
        assert "guzzlehttp/guzzle" in names
        assert "monolog/monolog" in names
        assert "phpunit/phpunit" in names

        laravel_dep = next(d for d in deps if d.name == "laravel/framework")
        assert laravel_dep.version == "10.38.2"
        assert laravel_dep.is_dev is False

        phpunit_dep = next(d for d in deps if d.name == "phpunit/phpunit")
        assert phpunit_dep.is_dev is True


class TestScannerRegistry:
    """Tests for scanner registry."""

    def test_default_scanners_registered(self) -> None:
        """Test that default scanners are registered."""
        register_default_scanners()
        scanners = ScannerRegistry.get_all()

        assert len(scanners) == 7

        ecosystems = {s.ecosystem for s in scanners}
        assert Ecosystem.NPM in ecosystems
        assert Ecosystem.PYPI in ecosystems
        assert Ecosystem.GO in ecosystems
        assert Ecosystem.RUBYGEMS in ecosystems
        assert Ecosystem.MAVEN in ecosystems
        assert Ecosystem.CARGO in ecosystems
        assert Ecosystem.COMPOSER in ecosystems

    def test_get_for_ecosystem(self) -> None:
        """Test getting scanner by ecosystem."""
        register_default_scanners()

        npm_scanner = ScannerRegistry.get_for_ecosystem(Ecosystem.NPM)
        assert npm_scanner is not None
        assert npm_scanner.ecosystem == Ecosystem.NPM

    def test_get_for_file(self) -> None:
        """Test getting scanner for a file."""
        register_default_scanners()

        scanner = ScannerRegistry.get_for_file(Path("package-lock.json"))
        assert scanner is not None
        assert scanner.ecosystem == Ecosystem.NPM

        scanner = ScannerRegistry.get_for_file(Path("requirements.txt"))
        assert scanner is not None
        assert scanner.ecosystem == Ecosystem.PYPI


class TestDetectEcosystems:
    """Tests for ecosystem detection."""

    def test_detect_npm(self, temp_dir: Path) -> None:
        """Test detecting NPM ecosystem."""
        (temp_dir / "package.json").write_text("{}")

        ecosystems = detect_ecosystems(temp_dir)
        assert Ecosystem.NPM in ecosystems

    def test_detect_python(self, temp_dir: Path) -> None:
        """Test detecting Python ecosystem."""
        (temp_dir / "requirements.txt").write_text("")

        ecosystems = detect_ecosystems(temp_dir)
        assert Ecosystem.PYPI in ecosystems

    def test_detect_multiple(self, temp_dir: Path) -> None:
        """Test detecting multiple ecosystems."""
        (temp_dir / "package.json").write_text("{}")
        (temp_dir / "requirements.txt").write_text("")
        (temp_dir / "go.mod").write_text("module test")

        ecosystems = detect_ecosystems(temp_dir)
        assert Ecosystem.NPM in ecosystems
        assert Ecosystem.PYPI in ecosystems
        assert Ecosystem.GO in ecosystems


class TestScanRepository:
    """Tests for full repository scanning."""

    def test_scan_repository(self, lockfiles_dir: Path) -> None:
        """Test scanning a repository with multiple lockfiles."""
        register_default_scanners()
        result = scan_repository(lockfiles_dir)

        assert len(result.dependencies) > 0
        assert len(result.lockfiles_scanned) > 0
        assert result.repository_path == str(lockfiles_dir.resolve())

    def test_scan_with_ecosystem_filter(self, lockfiles_dir: Path) -> None:
        """Test scanning with ecosystem filter."""
        register_default_scanners()
        result = scan_repository(lockfiles_dir, ecosystems=[Ecosystem.NPM])

        ecosystems = {d.ecosystem for d in result.dependencies}
        assert Ecosystem.NPM in ecosystems
        assert Ecosystem.PYPI not in ecosystems

    def test_scan_excludes_patterns(self, temp_dir: Path) -> None:
        """Test that exclude patterns work."""
        register_default_scanners()

        node_modules = temp_dir / "node_modules" / "test"
        node_modules.mkdir(parents=True)
        (node_modules / "package-lock.json").write_text('{"lockfileVersion": 3, "packages": {}}')

        (temp_dir / "package-lock.json").write_text('{"lockfileVersion": 3, "packages": {}}')

        result = scan_repository(temp_dir)

        assert "node_modules" not in " ".join(result.lockfiles_scanned)
