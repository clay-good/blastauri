"""Dependency scanners for various ecosystems."""

from blastauri.scanners.base import (
    BaseScanner,
    ScannerRegistry,
    scan_repository,
)
from blastauri.scanners.cargo import CargoScanner
from blastauri.scanners.composer import ComposerScanner
from blastauri.scanners.detector import (
    detect_ecosystems,
    get_all_scanners,
    get_scanners_for_directory,
    register_default_scanners,
)
from blastauri.scanners.go import GoScanner
from blastauri.scanners.maven import MavenScanner
from blastauri.scanners.npm import NpmScanner
from blastauri.scanners.pip import PipScanner
from blastauri.scanners.ruby import RubyScanner

__all__ = [
    "BaseScanner",
    "CargoScanner",
    "ComposerScanner",
    "GoScanner",
    "MavenScanner",
    "NpmScanner",
    "PipScanner",
    "RubyScanner",
    "ScannerRegistry",
    "detect_ecosystems",
    "get_all_scanners",
    "get_scanners_for_directory",
    "register_default_scanners",
    "scan_repository",
]

register_default_scanners()
