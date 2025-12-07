"""Base scanner interface for dependency parsing."""

from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import ClassVar

from blastauri.core.models import Dependency, Ecosystem, ScanResult
from blastauri.utils.logging import get_logger

logger = get_logger(__name__)


class BaseScanner(ABC):
    """Abstract base class for dependency scanners.

    All ecosystem-specific scanners must inherit from this class and implement
    the abstract methods.
    """

    lockfile_patterns: ClassVar[list[str]] = []
    """Glob patterns for lockfiles this scanner can parse."""

    @property
    @abstractmethod
    def ecosystem(self) -> Ecosystem:
        """Return the ecosystem this scanner handles."""
        ...

    @abstractmethod
    def parse_lockfile(self, path: Path) -> list[Dependency]:
        """Parse a single lockfile and return dependencies.

        Args:
            path: Path to the lockfile.

        Returns:
            List of dependencies found in the lockfile.

        Raises:
            ValueError: If the file format is invalid.
            FileNotFoundError: If the file does not exist.
        """
        ...

    def can_parse(self, path: Path) -> bool:
        """Check if this scanner can parse the given file.

        Args:
            path: Path to check.

        Returns:
            True if this scanner can parse the file.
        """
        filename = path.name
        for pattern in self.lockfile_patterns:
            if pattern.startswith("*"):
                if filename.endswith(pattern[1:]):
                    return True
            elif filename == pattern:
                return True
        return False

    def scan_directory(
        self,
        directory: str | Path,
        exclude_patterns: list[str] | None = None,
    ) -> ScanResult:
        """Scan a directory for lockfiles and parse all dependencies.

        Args:
            directory: Directory to scan (string or Path).
            exclude_patterns: Patterns to exclude from scanning.

        Returns:
            ScanResult containing all found dependencies.
        """
        if exclude_patterns is None:
            exclude_patterns = ["node_modules", "vendor", ".git", "__pycache__", ".venv", "venv"]

        dependencies: list[Dependency] = []
        lockfiles_scanned: list[str] = []
        errors: list[str] = []

        directory = Path(directory).resolve()

        for pattern in self.lockfile_patterns:
            for lockfile in directory.rglob(pattern):
                if self._should_exclude(lockfile, directory, exclude_patterns):
                    continue

                relative_path = str(lockfile.relative_to(directory))
                logger.debug("Scanning %s", relative_path)

                try:
                    deps = self.parse_lockfile(lockfile)
                    for dep in deps:
                        dep.location = relative_path
                    dependencies.extend(deps)
                    lockfiles_scanned.append(relative_path)
                except Exception as e:
                    error_msg = f"Error parsing {relative_path}: {e}"
                    logger.warning(error_msg)
                    errors.append(error_msg)

        return ScanResult(
            dependencies=dependencies,
            lockfiles_scanned=lockfiles_scanned,
            scan_timestamp=datetime.utcnow(),
            errors=errors,
            repository_path=str(directory),
        )

    def _should_exclude(
        self,
        path: Path,
        base_dir: Path,
        exclude_patterns: list[str],
    ) -> bool:
        """Check if a path should be excluded from scanning.

        Args:
            path: Path to check.
            base_dir: Base directory for relative path calculation.
            exclude_patterns: Patterns to exclude.

        Returns:
            True if the path should be excluded.
        """
        try:
            relative = path.relative_to(base_dir)
            parts = relative.parts
            for pattern in exclude_patterns:
                if pattern in parts:
                    return True
        except ValueError:
            pass
        return False


class ScannerRegistry:
    """Registry for scanner instances."""

    _scanners: ClassVar[list[BaseScanner]] = []

    @classmethod
    def register(cls, scanner: BaseScanner) -> None:
        """Register a scanner instance.

        Args:
            scanner: Scanner to register.
        """
        cls._scanners.append(scanner)

    @classmethod
    def get_all(cls) -> list[BaseScanner]:
        """Get all registered scanners.

        Returns:
            List of all registered scanners.
        """
        return cls._scanners.copy()

    @classmethod
    def get_for_ecosystem(cls, ecosystem: Ecosystem) -> BaseScanner | None:
        """Get scanner for a specific ecosystem.

        Args:
            ecosystem: Ecosystem to get scanner for.

        Returns:
            Scanner for the ecosystem or None.
        """
        for scanner in cls._scanners:
            if scanner.ecosystem == ecosystem:
                return scanner
        return None

    @classmethod
    def get_for_file(cls, path: Path) -> BaseScanner | None:
        """Get scanner that can parse a specific file.

        Args:
            path: Path to the file.

        Returns:
            Scanner that can parse the file or None.
        """
        for scanner in cls._scanners:
            if scanner.can_parse(path):
                return scanner
        return None

    @classmethod
    def clear(cls) -> None:
        """Clear all registered scanners."""
        cls._scanners.clear()


def scan_repository(
    directory: Path,
    ecosystems: list[Ecosystem] | None = None,
    exclude_patterns: list[str] | None = None,
) -> ScanResult:
    """Scan a repository for all dependencies.

    Args:
        directory: Directory to scan.
        ecosystems: Specific ecosystems to scan (None for all).
        exclude_patterns: Patterns to exclude from scanning.

    Returns:
        Combined ScanResult from all scanners.
    """
    all_dependencies: list[Dependency] = []
    all_lockfiles: list[str] = []
    all_errors: list[str] = []

    scanners = ScannerRegistry.get_all()

    for scanner in scanners:
        if ecosystems is not None and scanner.ecosystem not in ecosystems:
            continue

        result = scanner.scan_directory(directory, exclude_patterns)
        all_dependencies.extend(result.dependencies)
        all_lockfiles.extend(result.lockfiles_scanned)
        all_errors.extend(result.errors)

    return ScanResult(
        dependencies=all_dependencies,
        lockfiles_scanned=all_lockfiles,
        scan_timestamp=datetime.utcnow(),
        errors=all_errors,
        repository_path=str(directory.resolve()),
    )
