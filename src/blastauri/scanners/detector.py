"""Ecosystem detection for automatic scanner selection."""

from pathlib import Path

from blastauri.core.models import Ecosystem
from blastauri.scanners.base import BaseScanner, ScannerRegistry
from blastauri.utils.logging import get_logger

logger = get_logger(__name__)

ECOSYSTEM_FILES: dict[Ecosystem, list[str]] = {
    Ecosystem.NPM: [
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        ".npmrc",
    ],
    Ecosystem.PYPI: [
        "requirements.txt",
        "requirements-dev.txt",
        "Pipfile",
        "Pipfile.lock",
        "pyproject.toml",
        "poetry.lock",
        "setup.py",
        "setup.cfg",
    ],
    Ecosystem.GO: [
        "go.mod",
        "go.sum",
    ],
    Ecosystem.RUBYGEMS: [
        "Gemfile",
        "Gemfile.lock",
        ".ruby-version",
    ],
    Ecosystem.MAVEN: [
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
    ],
    Ecosystem.CARGO: [
        "Cargo.toml",
        "Cargo.lock",
    ],
    Ecosystem.COMPOSER: [
        "composer.json",
        "composer.lock",
    ],
}


def detect_ecosystems(directory: Path) -> list[Ecosystem]:
    """Detect which ecosystems are present in a directory.

    Args:
        directory: Directory to scan.

    Returns:
        List of detected ecosystems.
    """
    detected: list[Ecosystem] = []
    directory = directory.resolve()

    for ecosystem, indicator_files in ECOSYSTEM_FILES.items():
        for filename in indicator_files:
            if (directory / filename).exists():
                if ecosystem not in detected:
                    detected.append(ecosystem)
                    logger.debug("Detected %s ecosystem via %s", ecosystem.value, filename)
                break

    return detected


def get_scanners_for_directory(directory: Path) -> list[BaseScanner]:
    """Get scanners for all detected ecosystems in a directory.

    Args:
        directory: Directory to analyze.

    Returns:
        List of scanner instances for detected ecosystems.
    """
    ecosystems = detect_ecosystems(directory)
    scanners: list[BaseScanner] = []

    for ecosystem in ecosystems:
        scanner = ScannerRegistry.get_for_ecosystem(ecosystem)
        if scanner:
            scanners.append(scanner)

    return scanners


def get_all_scanners() -> list[BaseScanner]:
    """Get all registered scanners.

    Returns:
        List of all scanner instances.
    """
    return ScannerRegistry.get_all()


def register_default_scanners() -> None:
    """Register all default scanner implementations."""
    from blastauri.scanners.cargo import CargoScanner
    from blastauri.scanners.composer import ComposerScanner
    from blastauri.scanners.go import GoScanner
    from blastauri.scanners.maven import MavenScanner
    from blastauri.scanners.npm import NpmScanner
    from blastauri.scanners.pip import PipScanner
    from blastauri.scanners.ruby import RubyScanner

    ScannerRegistry.clear()

    ScannerRegistry.register(NpmScanner())
    ScannerRegistry.register(PipScanner())
    ScannerRegistry.register(GoScanner())
    ScannerRegistry.register(RubyScanner())
    ScannerRegistry.register(MavenScanner())
    ScannerRegistry.register(CargoScanner())
    ScannerRegistry.register(ComposerScanner())

    logger.debug("Registered %d scanners", len(ScannerRegistry.get_all()))
