"""Static analyzer using tree-sitter for code analysis."""

import fnmatch
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import ClassVar

from blastauri.core.models import Ecosystem, UsageLocation


class UsageType(str, Enum):
    """Types of dependency usage."""

    IMPORT = "import"
    CALL = "call"
    ATTRIBUTE = "attribute"
    DECORATOR = "decorator"
    TYPE_ANNOTATION = "type_annotation"
    INSTANTIATION = "instantiation"


@dataclass
class ImportInfo:
    """Information about an import statement."""

    module: str
    names: list[str]
    alias: str | None
    is_from_import: bool
    line_number: int
    file_path: str


# Default patterns to exclude from analysis
DEFAULT_EXCLUDE_PATTERNS = [
    "node_modules/**",
    "vendor/**",
    ".git/**",
    "__pycache__/**",
    "*.pyc",
    ".venv/**",
    "venv/**",
    "env/**",
    ".env/**",
    "dist/**",
    "build/**",
    ".next/**",
    "coverage/**",
    ".pytest_cache/**",
    ".mypy_cache/**",
    ".ruff_cache/**",
    "*.min.js",
    "*.bundle.js",
]


class BaseLanguageAnalyzer(ABC):
    """Base class for language-specific analyzers."""

    # File extensions this analyzer handles
    file_extensions: ClassVar[list[str]] = []

    # Ecosystem this analyzer is for
    ecosystem: ClassVar[Ecosystem]

    def __init__(self):
        """Initialize the analyzer."""
        self._tree_sitter_available = self._check_tree_sitter()

    def _check_tree_sitter(self) -> bool:
        """Check if tree-sitter is available."""
        try:
            import tree_sitter  # noqa: F401
            return True
        except ImportError:
            return False

    def can_analyze(self, file_path: Path) -> bool:
        """Check if this analyzer can handle the file.

        Args:
            file_path: Path to the file.

        Returns:
            True if this analyzer handles the file type.
        """
        return file_path.suffix.lower() in self.file_extensions

    @abstractmethod
    def find_imports(self, file_path: Path, content: str) -> list[ImportInfo]:
        """Find all imports in a file.

        Args:
            file_path: Path to the file.
            content: File content.

        Returns:
            List of import information.
        """
        pass

    @abstractmethod
    def find_usages(
        self,
        file_path: Path,
        content: str,
        symbol: str,
        import_info: ImportInfo,
    ) -> list[UsageLocation]:
        """Find all usages of a symbol in a file.

        Args:
            file_path: Path to the file.
            content: File content.
            symbol: Symbol to find.
            import_info: Import information for context.

        Returns:
            List of usage locations.
        """
        pass


class PythonAnalyzer(BaseLanguageAnalyzer):
    """Analyzer for Python code."""

    file_extensions: ClassVar[list[str]] = [".py", ".pyi"]
    ecosystem: ClassVar[Ecosystem] = Ecosystem.PYPI

    def find_imports(self, file_path: Path, content: str) -> list[ImportInfo]:
        """Find all imports in a Python file."""
        imports: list[ImportInfo] = []
        lines = content.split("\n")

        # Track multi-line imports
        in_multiline = False
        multiline_buffer = ""
        multiline_start = 0

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()

            # Handle multi-line imports
            if in_multiline:
                multiline_buffer += " " + stripped
                if ")" in stripped:
                    in_multiline = False
                    self._parse_import_line(
                        multiline_buffer, multiline_start, str(file_path), imports
                    )
                    multiline_buffer = ""
                continue

            # Skip comments and empty lines
            if stripped.startswith("#") or not stripped:
                continue

            # Check for multi-line import start
            if stripped.startswith(("import ", "from ")) and "(" in stripped and ")" not in stripped:
                in_multiline = True
                multiline_buffer = stripped
                multiline_start = line_num
                continue

            # Regular import line
            if stripped.startswith(("import ", "from ")):
                self._parse_import_line(stripped, line_num, str(file_path), imports)

        return imports

    def _parse_import_line(
        self,
        line: str,
        line_num: int,
        file_path: str,
        imports: list[ImportInfo],
    ) -> None:
        """Parse a single import line."""
        # from X import Y, Z
        from_match = re.match(
            r"from\s+([\w.]+)\s+import\s+(.+)", line
        )
        if from_match:
            module = from_match.group(1)
            names_part = from_match.group(2).strip()

            # Handle parenthesized imports
            names_part = re.sub(r"[()]", "", names_part)

            names: list[str] = []
            alias = None

            for name in names_part.split(","):
                name = name.strip()
                if not name:
                    continue

                # Handle aliases
                if " as " in name:
                    real_name, alias_name = name.split(" as ")
                    names.append(real_name.strip())
                    alias = alias_name.strip()
                else:
                    names.append(name)

            if names:
                imports.append(
                    ImportInfo(
                        module=module,
                        names=names,
                        alias=alias,
                        is_from_import=True,
                        line_number=line_num,
                        file_path=file_path,
                    )
                )
            return

        # import X, Y
        import_match = re.match(r"import\s+(.+)", line)
        if import_match:
            modules_part = import_match.group(1)

            for module in modules_part.split(","):
                module = module.strip()
                if not module:
                    continue

                alias = None
                if " as " in module:
                    real_module, alias = module.split(" as ")
                    module = real_module.strip()
                    alias = alias.strip()

                imports.append(
                    ImportInfo(
                        module=module,
                        names=[],
                        alias=alias,
                        is_from_import=False,
                        line_number=line_num,
                        file_path=file_path,
                    )
                )

    def find_usages(
        self,
        file_path: Path,
        content: str,
        symbol: str,
        import_info: ImportInfo,
    ) -> list[UsageLocation]:
        """Find all usages of a symbol in a Python file."""
        usages: list[UsageLocation] = []
        lines = content.split("\n")

        # Determine the name to search for
        if import_info.alias:
            search_name = import_info.alias
        elif import_info.is_from_import and symbol in import_info.names:
            search_name = symbol
        else:
            search_name = import_info.module.split(".")[-1]

        # Patterns to find
        patterns = [
            # Function calls: symbol(...) or symbol.method(...)
            (rf"\b({re.escape(search_name)})\s*\(", UsageType.CALL),
            (rf"\b({re.escape(search_name)})\.\w+\s*\(", UsageType.CALL),
            # Attribute access: symbol.attr
            (rf"\b({re.escape(search_name)})\.\w+(?!\s*\()", UsageType.ATTRIBUTE),
            # Decorators: @symbol
            (rf"@({re.escape(search_name)})\b", UsageType.DECORATOR),
            # Type annotations: -> symbol or : symbol
            (rf"(?:->|:)\s*({re.escape(search_name)})\b", UsageType.TYPE_ANNOTATION),
            # Instantiation: symbol(...) where symbol is CamelCase
            (rf"\b({re.escape(search_name)})\s*\(", UsageType.INSTANTIATION),
        ]

        for line_num, line in enumerate(lines, 1):
            # Skip the import line itself
            if line_num == import_info.line_number:
                continue

            for pattern, usage_type in patterns:
                for match in re.finditer(pattern, line):
                    column = match.start(1)

                    # Get code snippet with context
                    snippet_start = max(0, column - 20)
                    snippet_end = min(len(line), column + len(search_name) + 30)
                    snippet = line[snippet_start:snippet_end].strip()

                    usages.append(
                        UsageLocation(
                            file_path=str(file_path),
                            line_number=line_num,
                            column=column,
                            code_snippet=snippet,
                            usage_type=usage_type.value,
                            symbol=symbol,
                        )
                    )
                    break  # Only record first match per pattern per line

        return usages


class JavaScriptAnalyzer(BaseLanguageAnalyzer):
    """Analyzer for JavaScript/TypeScript code."""

    file_extensions: ClassVar[list[str]] = [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]
    ecosystem: ClassVar[Ecosystem] = Ecosystem.NPM

    def find_imports(self, file_path: Path, content: str) -> list[ImportInfo]:
        """Find all imports in a JavaScript/TypeScript file."""
        imports: list[ImportInfo] = []
        lines = content.split("\n")

        # Track multi-line imports
        in_multiline = False
        multiline_buffer = ""
        multiline_start = 0

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()

            # Handle multi-line imports
            if in_multiline:
                multiline_buffer += " " + stripped
                if "from" in stripped.lower() or stripped.endswith(";"):
                    in_multiline = False
                    self._parse_import_line(
                        multiline_buffer, multiline_start, str(file_path), imports
                    )
                    multiline_buffer = ""
                continue

            # Skip comments
            if stripped.startswith("//") or stripped.startswith("/*"):
                continue

            # ES6 imports
            if stripped.startswith("import "):
                if "{" in stripped and "}" not in stripped:
                    in_multiline = True
                    multiline_buffer = stripped
                    multiline_start = line_num
                else:
                    self._parse_import_line(stripped, line_num, str(file_path), imports)

            # CommonJS require
            elif "require(" in stripped:
                self._parse_require_line(stripped, line_num, str(file_path), imports)

        return imports

    def _parse_import_line(
        self,
        line: str,
        line_num: int,
        file_path: str,
        imports: list[ImportInfo],
    ) -> None:
        """Parse an ES6 import statement."""
        # import X from 'module'
        default_match = re.match(
            r"import\s+(\w+)\s+from\s+['\"](.+?)['\"]", line
        )
        if default_match:
            imports.append(
                ImportInfo(
                    module=default_match.group(2),
                    names=[default_match.group(1)],
                    alias=None,
                    is_from_import=True,
                    line_number=line_num,
                    file_path=file_path,
                )
            )
            return

        # import { X, Y as Z } from 'module'
        named_match = re.match(
            r"import\s+\{([^}]+)\}\s+from\s+['\"](.+?)['\"]", line
        )
        if named_match:
            names_part = named_match.group(1)
            module = named_match.group(2)

            names: list[str] = []
            alias = None

            for name in names_part.split(","):
                name = name.strip()
                if not name:
                    continue

                if " as " in name:
                    real_name, alias_name = name.split(" as ")
                    names.append(real_name.strip())
                    alias = alias_name.strip()
                else:
                    names.append(name)

            if names:
                imports.append(
                    ImportInfo(
                        module=module,
                        names=names,
                        alias=alias,
                        is_from_import=True,
                        line_number=line_num,
                        file_path=file_path,
                    )
                )
            return

        # import * as X from 'module'
        star_match = re.match(
            r"import\s+\*\s+as\s+(\w+)\s+from\s+['\"](.+?)['\"]", line
        )
        if star_match:
            imports.append(
                ImportInfo(
                    module=star_match.group(2),
                    names=["*"],
                    alias=star_match.group(1),
                    is_from_import=True,
                    line_number=line_num,
                    file_path=file_path,
                )
            )

    def _parse_require_line(
        self,
        line: str,
        line_num: int,
        file_path: str,
        imports: list[ImportInfo],
    ) -> None:
        """Parse a CommonJS require statement."""
        # const X = require('module')
        require_match = re.match(
            r"(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*['\"](.+?)['\"]", line
        )
        if require_match:
            imports.append(
                ImportInfo(
                    module=require_match.group(2),
                    names=[require_match.group(1)],
                    alias=None,
                    is_from_import=False,
                    line_number=line_num,
                    file_path=file_path,
                )
            )
            return

        # const { X, Y } = require('module')
        destructure_match = re.match(
            r"(?:const|let|var)\s+\{([^}]+)\}\s*=\s*require\s*\(\s*['\"](.+?)['\"]", line
        )
        if destructure_match:
            names_part = destructure_match.group(1)
            module = destructure_match.group(2)

            names = [n.strip().split(":")[0].strip() for n in names_part.split(",") if n.strip()]

            if names:
                imports.append(
                    ImportInfo(
                        module=module,
                        names=names,
                        alias=None,
                        is_from_import=False,
                        line_number=line_num,
                        file_path=file_path,
                    )
                )

    def find_usages(
        self,
        file_path: Path,
        content: str,
        symbol: str,
        import_info: ImportInfo,
    ) -> list[UsageLocation]:
        """Find all usages of a symbol in a JavaScript/TypeScript file."""
        usages: list[UsageLocation] = []
        lines = content.split("\n")

        # Determine the name to search for
        if import_info.alias:
            search_name = import_info.alias
        elif import_info.names and symbol in import_info.names:
            search_name = symbol
        elif import_info.names:
            search_name = import_info.names[0]
        else:
            search_name = import_info.module.split("/")[-1]

        patterns = [
            # Function calls
            (rf"\b({re.escape(search_name)})\s*\(", UsageType.CALL),
            (rf"\b({re.escape(search_name)})\.\w+\s*\(", UsageType.CALL),
            # Property access
            (rf"\b({re.escape(search_name)})\.\w+(?!\s*\()", UsageType.ATTRIBUTE),
            # JSX component usage
            (rf"<({re.escape(search_name)})\b", UsageType.INSTANTIATION),
            # new instantiation
            (rf"\bnew\s+({re.escape(search_name)})\s*\(", UsageType.INSTANTIATION),
            # Type annotations (TypeScript)
            (rf":\s*({re.escape(search_name)})\b", UsageType.TYPE_ANNOTATION),
        ]

        for line_num, line in enumerate(lines, 1):
            if line_num == import_info.line_number:
                continue

            for pattern, usage_type in patterns:
                for match in re.finditer(pattern, line):
                    column = match.start(1)

                    snippet_start = max(0, column - 20)
                    snippet_end = min(len(line), column + len(search_name) + 30)
                    snippet = line[snippet_start:snippet_end].strip()

                    usages.append(
                        UsageLocation(
                            file_path=str(file_path),
                            line_number=line_num,
                            column=column,
                            code_snippet=snippet,
                            usage_type=usage_type.value,
                            symbol=symbol,
                        )
                    )
                    break

        return usages


class GoAnalyzer(BaseLanguageAnalyzer):
    """Analyzer for Go code."""

    file_extensions: ClassVar[list[str]] = [".go"]
    ecosystem: ClassVar[Ecosystem] = Ecosystem.GO

    def find_imports(self, file_path: Path, content: str) -> list[ImportInfo]:
        """Find all imports in a Go file."""
        imports: list[ImportInfo] = []
        lines = content.split("\n")

        in_import_block = False

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()

            # Single import
            single_match = re.match(r'import\s+"(.+)"', stripped)
            if single_match:
                module = single_match.group(1)
                imports.append(
                    ImportInfo(
                        module=module,
                        names=[module.split("/")[-1]],
                        alias=None,
                        is_from_import=True,
                        line_number=line_num,
                        file_path=str(file_path),
                    )
                )
                continue

            # Import block start
            if stripped == "import (" or stripped.startswith("import ("):
                in_import_block = True
                continue

            # Import block end
            if in_import_block and stripped == ")":
                in_import_block = False
                continue

            # Import within block
            if in_import_block:
                # Aliased import
                alias_match = re.match(r'(\w+)\s+"(.+)"', stripped)
                if alias_match:
                    alias = alias_match.group(1)
                    module = alias_match.group(2)
                    imports.append(
                        ImportInfo(
                            module=module,
                            names=[module.split("/")[-1]],
                            alias=alias,
                            is_from_import=True,
                            line_number=line_num,
                            file_path=str(file_path),
                        )
                    )
                    continue

                # Regular import
                regular_match = re.match(r'"(.+)"', stripped)
                if regular_match:
                    module = regular_match.group(1)
                    imports.append(
                        ImportInfo(
                            module=module,
                            names=[module.split("/")[-1]],
                            alias=None,
                            is_from_import=True,
                            line_number=line_num,
                            file_path=str(file_path),
                        )
                    )

        return imports

    def find_usages(
        self,
        file_path: Path,
        content: str,
        symbol: str,
        import_info: ImportInfo,
    ) -> list[UsageLocation]:
        """Find all usages of a symbol in a Go file."""
        usages: list[UsageLocation] = []
        lines = content.split("\n")

        # In Go, package name is used as prefix
        if import_info.alias:
            search_name = import_info.alias
        else:
            search_name = import_info.module.split("/")[-1]

        patterns = [
            # Package function call: pkg.Function(...)
            (rf"\b({re.escape(search_name)})\.(\w+)\s*\(", UsageType.CALL),
            # Package type usage: pkg.Type
            (rf"\b({re.escape(search_name)})\.([A-Z]\w*)", UsageType.TYPE_ANNOTATION),
            # Package constant/variable: pkg.CONST
            (rf"\b({re.escape(search_name)})\.(\w+)(?!\s*\()", UsageType.ATTRIBUTE),
        ]

        for line_num, line in enumerate(lines, 1):
            if line_num == import_info.line_number:
                continue

            for pattern, usage_type in patterns:
                for match in re.finditer(pattern, line):
                    column = match.start(1)
                    matched_symbol = match.group(2) if match.lastindex >= 2 else symbol

                    snippet_start = max(0, column - 20)
                    snippet_end = min(len(line), column + len(search_name) + 30)
                    snippet = line[snippet_start:snippet_end].strip()

                    usages.append(
                        UsageLocation(
                            file_path=str(file_path),
                            line_number=line_num,
                            column=column,
                            code_snippet=snippet,
                            usage_type=usage_type.value,
                            symbol=matched_symbol,
                        )
                    )
                    break

        return usages


class RubyAnalyzer(BaseLanguageAnalyzer):
    """Analyzer for Ruby code."""

    file_extensions: ClassVar[list[str]] = [".rb", ".rake", ".gemspec"]
    ecosystem: ClassVar[Ecosystem] = Ecosystem.RUBYGEMS

    def find_imports(self, file_path: Path, content: str) -> list[ImportInfo]:
        """Find all requires in a Ruby file."""
        imports: list[ImportInfo] = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()

            # require 'gem_name'
            require_match = re.match(r"require\s+['\"](.+?)['\"]", stripped)
            if require_match:
                module = require_match.group(1)
                imports.append(
                    ImportInfo(
                        module=module,
                        names=[module.split("/")[-1].replace("-", "_")],
                        alias=None,
                        is_from_import=True,
                        line_number=line_num,
                        file_path=str(file_path),
                    )
                )
                continue

            # require_relative 'path'
            require_rel_match = re.match(r"require_relative\s+['\"](.+?)['\"]", stripped)
            if require_rel_match:
                module = require_rel_match.group(1)
                imports.append(
                    ImportInfo(
                        module=module,
                        names=[],
                        alias=None,
                        is_from_import=True,
                        line_number=line_num,
                        file_path=str(file_path),
                    )
                )

        return imports

    def find_usages(
        self,
        file_path: Path,
        content: str,
        symbol: str,
        import_info: ImportInfo,
    ) -> list[UsageLocation]:
        """Find all usages in a Ruby file."""
        usages: list[UsageLocation] = []
        lines = content.split("\n")

        # Convert gem name to module name (e.g., active_support -> ActiveSupport)
        module_name = "".join(w.title() for w in symbol.replace("-", "_").split("_"))

        patterns = [
            # Class/module reference
            (rf"\b({re.escape(module_name)})\b", UsageType.TYPE_ANNOTATION),
            # Method call on module
            (rf"\b({re.escape(module_name)})\.(\w+)", UsageType.CALL),
            # include/extend
            (rf"(?:include|extend)\s+({re.escape(module_name)})", UsageType.CALL),
        ]

        for line_num, line in enumerate(lines, 1):
            if line_num == import_info.line_number:
                continue

            for pattern, usage_type in patterns:
                for match in re.finditer(pattern, line):
                    column = match.start(1)

                    snippet_start = max(0, column - 20)
                    snippet_end = min(len(line), column + len(module_name) + 30)
                    snippet = line[snippet_start:snippet_end].strip()

                    usages.append(
                        UsageLocation(
                            file_path=str(file_path),
                            line_number=line_num,
                            column=column,
                            code_snippet=snippet,
                            usage_type=usage_type.value,
                            symbol=symbol,
                        )
                    )
                    break

        return usages


class StaticAnalyzer:
    """Main static analyzer that coordinates language-specific analyzers."""

    def __init__(
        self,
        exclude_patterns: list[str] | None = None,
    ):
        """Initialize the static analyzer.

        Args:
            exclude_patterns: Glob patterns for files/directories to exclude.
        """
        self._exclude_patterns = exclude_patterns or DEFAULT_EXCLUDE_PATTERNS
        self._analyzers: dict[Ecosystem, BaseLanguageAnalyzer] = {
            Ecosystem.PYPI: PythonAnalyzer(),
            Ecosystem.NPM: JavaScriptAnalyzer(),
            Ecosystem.GO: GoAnalyzer(),
            Ecosystem.RUBYGEMS: RubyAnalyzer(),
        }

    def get_analyzer(self, ecosystem: Ecosystem) -> BaseLanguageAnalyzer | None:
        """Get the analyzer for an ecosystem.

        Args:
            ecosystem: Target ecosystem.

        Returns:
            Language analyzer or None.
        """
        return self._analyzers.get(ecosystem)

    def should_exclude(self, file_path: Path, base_path: Path) -> bool:
        """Check if a file should be excluded.

        Args:
            file_path: File to check.
            base_path: Base directory for relative path calculation.

        Returns:
            True if file should be excluded.
        """
        try:
            relative_path = file_path.relative_to(base_path)
        except ValueError:
            relative_path = file_path

        path_str = str(relative_path)

        for pattern in self._exclude_patterns:
            if fnmatch.fnmatch(path_str, pattern):
                return True
            # Also check each path component
            for part in relative_path.parts:
                if fnmatch.fnmatch(part, pattern.replace("**", "*")):
                    return True

        return False

    def find_files(
        self,
        directory: Path,
        ecosystem: Ecosystem,
    ) -> list[Path]:
        """Find all files for an ecosystem in a directory.

        Args:
            directory: Directory to search.
            ecosystem: Target ecosystem.

        Returns:
            List of file paths.
        """
        analyzer = self._analyzers.get(ecosystem)
        if not analyzer:
            return []

        files: list[Path] = []

        for ext in analyzer.file_extensions:
            for file_path in directory.rglob(f"*{ext}"):
                if file_path.is_file() and not self.should_exclude(file_path, directory):
                    files.append(file_path)

        return files

    def find_all_imports(
        self,
        directory: Path,
        ecosystem: Ecosystem,
        package_name: str,
    ) -> list[ImportInfo]:
        """Find all imports of a package in a directory.

        Args:
            directory: Directory to search.
            ecosystem: Package ecosystem.
            package_name: Package name to find.

        Returns:
            List of import information.
        """
        analyzer = self._analyzers.get(ecosystem)
        if not analyzer:
            return []

        all_imports: list[ImportInfo] = []
        files = self.find_files(directory, ecosystem)

        # Normalize package name for comparison
        normalized_package = self._normalize_package_name(package_name, ecosystem)

        for file_path in files:
            try:
                content = file_path.read_text(encoding="utf-8")
                imports = analyzer.find_imports(file_path, content)

                # Filter for matching package
                for imp in imports:
                    normalized_module = self._normalize_package_name(imp.module, ecosystem)
                    if self._module_matches_package(normalized_module, normalized_package, ecosystem):
                        all_imports.append(imp)

            except (OSError, UnicodeDecodeError):
                continue

        return all_imports

    def find_all_usages(
        self,
        directory: Path,
        ecosystem: Ecosystem,
        package_name: str,
        symbols: list[str] | None = None,
    ) -> list[UsageLocation]:
        """Find all usages of a package in a directory.

        Args:
            directory: Directory to search.
            ecosystem: Package ecosystem.
            package_name: Package name.
            symbols: Optional list of specific symbols to find.

        Returns:
            List of usage locations.
        """
        analyzer = self._analyzers.get(ecosystem)
        if not analyzer:
            return []

        # First find all imports
        all_imports = self.find_all_imports(directory, ecosystem, package_name)

        all_usages: list[UsageLocation] = []

        for import_info in all_imports:
            file_path = Path(import_info.file_path)
            try:
                content = file_path.read_text(encoding="utf-8")

                # Find usages for each imported symbol
                search_symbols = symbols or import_info.names or [package_name]

                for symbol in search_symbols:
                    usages = analyzer.find_usages(file_path, content, symbol, import_info)
                    all_usages.extend(usages)

            except (OSError, UnicodeDecodeError):
                continue

        return all_usages

    def _normalize_package_name(self, name: str, ecosystem: Ecosystem) -> str:
        """Normalize package name for comparison.

        Args:
            name: Package name.
            ecosystem: Package ecosystem.

        Returns:
            Normalized name.
        """
        if ecosystem == Ecosystem.PYPI:
            # Python packages: normalize underscores, hyphens, case
            return name.lower().replace("-", "_").replace(".", "_")
        elif ecosystem == Ecosystem.NPM:
            # NPM: case-sensitive, but handle scoped packages
            return name.lstrip("@").replace("/", "__")
        elif ecosystem == Ecosystem.GO:
            # Go: use last path component
            return name.split("/")[-1]
        elif ecosystem == Ecosystem.RUBYGEMS:
            # Ruby: normalize hyphens to underscores
            return name.lower().replace("-", "_")
        return name.lower()

    def _module_matches_package(
        self,
        module: str,
        package: str,
        ecosystem: Ecosystem,
    ) -> bool:
        """Check if a module matches a package.

        Args:
            module: Import module name.
            package: Package name.
            ecosystem: Package ecosystem.

        Returns:
            True if they match.
        """
        # Exact match
        if module == package:
            return True

        # Prefix match for submodules
        if module.startswith(f"{package}_") or module.startswith(f"{package}__"):
            return True

        # For Go, match on path suffix
        if ecosystem == Ecosystem.GO:
            return module.endswith(f"/{package}") or module == package

        return False
