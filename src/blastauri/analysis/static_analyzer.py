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
    UNKNOWN = "unknown"


@dataclass
class ImportInfo:
    """Information about an import statement."""

    module: str
    names: list[str]
    alias: str | None
    is_from_import: bool
    line_number: int
    file_path: str


@dataclass
class CallGraphNode:
    """Node in the call graph (function or method)."""

    name: str
    file_path: str
    start_line: int
    end_line: int
    is_external: bool = False
    
    @property
    def id(self) -> str:
        """Unique identifier for the node."""
        return f"{self.file_path}:{self.name}"


@dataclass
class CallGraphEdge:
    """Edge in the call graph (function call)."""

    source: str  # Name of the caller function
    target: str  # Name of the called function
    line_number: int
    file_path: str


class CallGraph:
    """Represents the call graph of the codebase."""

    def __init__(self) -> None:
        """Initialize the call graph."""
        self.nodes: dict[str, CallGraphNode] = {}
        self.edges: list[CallGraphEdge] = []

    def add_node(self, node: CallGraphNode) -> None:
        """Add a node to the graph."""
        self.nodes[node.id] = node

    def add_edge(self, edge: CallGraphEdge) -> None:
        """Add an edge to the graph."""
        self.edges.append(edge)



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

    @abstractmethod
    def extract_call_graph_nodes(
        self,
        file_path: Path,
        content: str,
    ) -> list[CallGraphNode]:
        """Extract function/method definitions from a file.

        Args:
            file_path: Path to the file.
            content: File content.

        Returns:
            List of call graph nodes (function/method definitions).
        """
        pass

    @abstractmethod
    def extract_call_graph_edges(
        self,
        file_path: Path,
        content: str,
        nodes: list[CallGraphNode],
    ) -> list[CallGraphEdge]:
        """Extract function calls from a file.

        Args:
            file_path: Path to the file.
            content: File content.
            nodes: List of known nodes to identify callers.

        Returns:
            List of call graph edges (function calls).
        """
        pass


class PythonAnalyzer(BaseLanguageAnalyzer):
    """Analyzer for Python code."""

    file_extensions: ClassVar[list[str]] = [".py", ".pyi"]
    ecosystem: ClassVar[Ecosystem] = Ecosystem.PYPI

    def __init__(self):
        """Initialize Python analyzer with tree-sitter."""
        super().__init__()
        if self._tree_sitter_available:
            from tree_sitter import Language, Parser
            import tree_sitter_python

            self.language = Language(tree_sitter_python.language())
            self.parser = Parser(self.language)
        else:
            self.language = None
            self.parser = None

    def find_imports(self, file_path: Path, content: str) -> list[ImportInfo]:
        """Find all imports in a Python file using AST if available."""
        if self._tree_sitter_available and self.parser:
            return self._find_imports_ast(file_path, content)
        return self._find_imports_regex(file_path, content)

    def extract_call_graph_nodes(self, file_path: Path, content: str) -> list[CallGraphNode]:
        """Extract function/method definitions using AST."""
        if not self._tree_sitter_available or not self.parser:
            return []
            
        return self._find_definitions_ast(file_path, content)

    def extract_call_graph_edges(
        self, file_path: Path, content: str, nodes: list[CallGraphNode]
    ) -> list[CallGraphEdge]:
        """Extract function calls within defined nodes."""
        if not self._tree_sitter_available or not self.parser:
            return []

        return self._find_calls_ast(file_path, content, nodes)

    def _find_imports_ast(self, file_path: Path, content: str) -> list[ImportInfo]:
        """Find imports using tree-sitter AST."""
        from tree_sitter import Query, QueryCursor

        imports: list[ImportInfo] = []
        tree = self.parser.parse(bytes(content, "utf8"))

        query = Query(self.language, """
            (import_statement
                name: (dotted_name) @import_name)
            
            (import_statement
                name: (aliased_import
                    name: (dotted_name) @import_name
                    alias: (identifier) @import_alias))

            (import_from_statement
                module_name: (dotted_name) @from_module
                name: (dotted_name) @from_name)

            (import_from_statement
                module_name: (dotted_name) @from_module
                name: (aliased_import
                    name: (dotted_name) @from_name
                    alias: (identifier) @from_alias))
            
            (import_from_statement
                module_name: (relative_import) @from_relative
                name: (dotted_name) @from_name)
        """)

        cursor = QueryCursor(query)
        matches = cursor.matches(tree.root_node)

        # We need to aggregate matches by statement line number sometimes, 
        # but ImportInfo is per "imported symbol".
        # Actually our ImportInfo structure assumes one entry per symbol? 
        # "names: list[str]".
        # BaseLanguageAnalyzer.ImportInfo:
        # module: str (e.g. "json")
        # names: list[str] (e.g. ["load"])
        # alias: str | None
        
        # So we can emit one ImportInfo per captured symbol.
        
        for match_id, captures_dict in matches:
            module = None
            name = None
            alias = None
            line = 0

            # Helper to get text
            def get_text(node):
                return content[node.start_byte:node.end_byte]

            if "import_name" in captures_dict:
                # import X [as Y], Z
                # Each match is for one name
                node = captures_dict["import_name"][0]
                module = get_text(node)
                line = node.start_point[0] + 1
                if "import_alias" in captures_dict:
                    alias = get_text(captures_dict["import_alias"][0])

                imports.append(ImportInfo(
                    module=module,
                    names=[], # For plain import, names is usually empty in this model?
                              # Wait, _find_imports_regex uses names=[] for "import X"
                    alias=alias,
                    is_from_import=False,
                    line_number=line,
                    file_path=str(file_path)
                ))
            
            elif "from_module" in captures_dict or "from_relative" in captures_dict:
                # from X import Y
                if "from_module" in captures_dict:
                    module_node = captures_dict["from_module"][0]
                    module = get_text(module_node)
                else:
                    module_node = captures_dict["from_relative"][0]
                    module = get_text(module_node) # e.g. "." or ".."
                
                line = module_node.start_point[0] + 1

                if "from_name" in captures_dict:
                    # Capture name is typically dotted_name e.g. "load" (identifier inside dotted_name) or "a.b"
                    name_node = captures_dict["from_name"][0]
                    name = get_text(name_node)
                    
                    if "from_alias" in captures_dict:
                        alias = get_text(captures_dict["from_alias"][0])
                        
                    imports.append(ImportInfo(
                        module=module,
                        names=[name],
                        alias=alias,
                        is_from_import=True,
                        line_number=line,
                        file_path=str(file_path)
                    ))

        return imports

    def _find_definitions_ast(self, file_path: Path, content: str) -> list[CallGraphNode]:
        """Find function/class definitions."""
        from tree_sitter import Query, QueryCursor
        nodes: list[CallGraphNode] = []
        tree = self.parser.parse(bytes(content, "utf8"))
        
        query = Query(self.language, """
            (function_definition
                name: (identifier) @name) @func
        """)
        
        cursor = QueryCursor(query)
        matches = cursor.matches(tree.root_node)
        
        for match_id, captures_dict in matches:
            for capture_name, captured_nodes in captures_dict.items():
                for node in captured_nodes:
                    if capture_name == "name":
                        # node is the (identifier) containing the name
                        func_name = content[node.start_byte:node.end_byte]
                        func_def = node.parent
                        if not func_def:
                            continue
                            
                        # Default is simple function name
                        full_name = func_name
                        
                        # Check for class context
                        # Structure: function_definition -> block -> class_definition
                        parent = func_def.parent
                        if parent and parent.type == "block":
                            grandparent = parent.parent
                            if grandparent and grandparent.type == "class_definition":
                                # Find class name
                                # class_definition has child field 'name'
                                class_name_node = grandparent.child_by_field_name("name")
                                if class_name_node:
                                     class_name = content[class_name_node.start_byte:class_name_node.end_byte]
                                     full_name = f"{class_name}.{func_name}"

                        nodes.append(CallGraphNode(
                            name=full_name,
                            file_path=str(file_path),
                            start_line=func_def.start_point[0] + 1,
                            end_line=func_def.end_point[0] + 1
                        ))
        return nodes

    def _find_calls_ast(
        self, file_path: Path, content: str, nodes: list[CallGraphNode]
    ) -> list[CallGraphEdge]:
        """Find function calls inside definitions."""
        from tree_sitter import Query, QueryCursor

        edges: list[CallGraphEdge] = []
        tree = self.parser.parse(bytes(content, "utf8"))

        # Query for simple function calls and attribute calls (like yaml.load())
        # We need to capture both the object and the method for attribute calls
        query = Query(self.language, """
            (call
                function: (identifier) @func_name) @call_simple

            (call
                function: (attribute
                    object: (identifier) @attr_obj
                    attribute: (identifier) @attr_method)) @call_attr
        """)

        cursor = QueryCursor(query)
        matches = cursor.matches(tree.root_node)

        for match_id, captures_dict in matches:
            callee_name = None
            line_number = None

            if "func_name" in captures_dict:
                # Simple call: foo()
                node = captures_dict["func_name"][0]
                callee_name = content[node.start_byte:node.end_byte]
                line_number = node.start_point[0] + 1
            elif "attr_obj" in captures_dict and "attr_method" in captures_dict:
                # Attribute call: obj.method() -> capture as "obj.method"
                obj_node = captures_dict["attr_obj"][0]
                method_node = captures_dict["attr_method"][0]
                obj_name = content[obj_node.start_byte:obj_node.end_byte]
                method_name = content[method_node.start_byte:method_node.end_byte]
                callee_name = f"{obj_name}.{method_name}"
                line_number = method_node.start_point[0] + 1

            if callee_name and line_number:
                # Find which function owns this call
                caller_name = "<main>"
                for func_node in nodes:
                    if func_node.start_line <= line_number <= func_node.end_line:
                        caller_name = func_node.id
                        break

                edges.append(CallGraphEdge(
                    source=caller_name,
                    target=callee_name,
                    line_number=line_number,
                    file_path=str(file_path)
                ))

        return edges

    def _find_imports_regex(self, file_path: Path, content: str) -> list[ImportInfo]:
        """Find all imports in a Python file using regex (legacy)."""
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
        if self._tree_sitter_available and self.parser:
            return self._find_usages_ast(file_path, content, symbol, import_info)
        return self._find_usages_regex(file_path, content, symbol, import_info)

    def _find_usages_regex(
        self,
        file_path: Path,
        content: str,
        symbol: str,
        import_info: ImportInfo,
    ) -> list[UsageLocation]:
        """Find usages using Regex (Legacy)."""
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

    def _find_usages_ast(
        self,
        file_path: Path,
        content: str,
        symbol: str,
        import_info: ImportInfo,
    ) -> list[UsageLocation]:
        """Find usages using AST."""
        from tree_sitter import Query, QueryCursor

        usages: list[UsageLocation] = []
        tree = self.parser.parse(bytes(content, "utf8"))

        # Determine the local name of the symbol
        if import_info.alias:
            search_name = import_info.alias
        elif import_info.is_from_import and symbol in import_info.names:
            search_name = symbol
        elif import_info.names and symbol in import_info.names:
             search_name = symbol
        else:
             # import json -> search_name = json
            search_name = import_info.module.split(".")[-1]

        # Query to find identifiers with usage context
        query = Query(self.language, """
            (call function: (identifier) @call_func)
            (call function: (attribute object: (identifier) @call_obj))
            (attribute object: (identifier) @attr_obj)
            (decorator (identifier) @decorator)
            (decorator (call function: (identifier) @dec_call))
            (type (identifier) @type)
            (identifier) @ident
        """)

        cursor = QueryCursor(query)
        matches = cursor.matches(tree.root_node)

        visited_ranges = set()

        for match_id, captures_dict in matches:
             for capture_name, captured_nodes in captures_dict.items():
                for node in captured_nodes:
                    node_range = (node.start_byte, node.end_byte)
                    if node_range in visited_ranges:
                        continue
                    
                    found_name = content[node.start_byte:node.end_byte]
                    if found_name != search_name:
                        continue

                    line_num = node.start_point[0] + 1
                    if line_num == import_info.line_number:
                        continue

                    usage_type = UsageType.UNKNOWN
                    
                    if capture_name == "call_func":
                        usage_type = UsageType.CALL
                        visited_ranges.add(node_range)
                    elif capture_name == "call_obj":
                         usage_type = UsageType.CALL
                         visited_ranges.add(node_range)
                    elif capture_name == "attr_obj":
                        usage_type = UsageType.ATTRIBUTE
                        visited_ranges.add(node_range)
                    elif capture_name == "decorator" or capture_name == "dec_call":
                        usage_type = UsageType.DECORATOR
                        visited_ranges.add(node_range)
                    elif capture_name == "type":
                        usage_type = UsageType.TYPE_ANNOTATION
                        visited_ranges.add(node_range)
                    elif capture_name == "ident":
                        # Fallback
                        parent = node.parent
                        if parent:
                            if parent.type == "call":
                                usage_type = UsageType.CALL
                            elif parent.type == "attribute":
                                usage_type = UsageType.ATTRIBUTE
                            elif parent.type in ["type", "type_alias", "typed_parameter"]:
                                usage_type = UsageType.TYPE_ANNOTATION
                            elif parent.type == "decorator":
                                usage_type = UsageType.DECORATOR
                        
                        visited_ranges.add(node_range)

                    line = content.splitlines()[line_num - 1]
                    snippet = line.strip()

                    usages.append(UsageLocation(
                        file_path=str(file_path),
                        line_number=line_num,
                        column=node.start_point[1],
                        code_snippet=snippet,
                        usage_type=usage_type.value,
                        symbol=symbol
                    ))

        return usages


class JavaScriptAnalyzer(BaseLanguageAnalyzer):
    """Analyzer for JavaScript/TypeScript code."""

    file_extensions: ClassVar[list[str]] = [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]
    ecosystem: ClassVar[Ecosystem] = Ecosystem.NPM

    def __init__(self):
        """Initialize JavaScript analyzer with tree-sitter."""
        super().__init__()
        if self._tree_sitter_available:
            from tree_sitter import Language, Parser
            import tree_sitter_javascript
            
            # Note: For strict TypeScript support we would need tree_sitter_typescript
            # But tree_sitter_javascript handles most TS syntax gracefully for basic analysis
            self.language = Language(tree_sitter_javascript.language())
            self.parser = Parser(self.language)
        else:
            self.language = None
            self.parser = None

    def find_imports(self, file_path: Path, content: str) -> list[ImportInfo]:
        """Find all imports in a JavaScript/TypeScript file using AST if available."""
        if self._tree_sitter_available and self.parser:
            return self._find_imports_ast(file_path, content)
        return self._find_imports_regex(file_path, content)

    def extract_call_graph_nodes(self, file_path: Path, content: str) -> list[CallGraphNode]:
        """Extract function/method definitions using AST."""
        if not self._tree_sitter_available or not self.parser:
            return []
            
        return self._find_definitions_ast(file_path, content)

    def extract_call_graph_edges(
        self, file_path: Path, content: str, nodes: list[CallGraphNode]
    ) -> list[CallGraphEdge]:
        """Extract function calls within defined nodes."""
        if not self._tree_sitter_available or not self.parser:
            return []

        return self._find_calls_ast(file_path, content, nodes)

    def _find_imports_ast(self, file_path: Path, content: str) -> list[ImportInfo]:
        """Find imports using tree-sitter AST."""
        from tree_sitter import Query, QueryCursor

        imports: list[ImportInfo] = []
        tree = self.parser.parse(bytes(content, "utf8"))

        def get_text(node) -> str:
            return content[node.start_byte:node.end_byte]

        # Query for ES6 imports
        query = Query(self.language, """
            (import_statement
                source: (string) @source)

            (import_statement
                (import_clause
                    (identifier) @default_import)
                source: (string) @default_source)

            (import_statement
                (import_clause
                    (named_imports
                        (import_specifier
                            name: (identifier) @named_import
                            alias: (identifier)? @named_alias)))
                source: (string) @named_source)

            (import_statement
                (import_clause
                    (namespace_import
                        (identifier) @namespace_alias))
                source: (string) @namespace_source)
        """)

        cursor = QueryCursor(query)
        matches = cursor.matches(tree.root_node)

        for match_id, captures_dict in matches:
            # Extract the source module
            source_node = None
            for key in ["source", "default_source", "named_source", "namespace_source"]:
                if key in captures_dict:
                    source_node = captures_dict[key][0]
                    break

            if not source_node:
                continue

            # Get module name (strip quotes)
            module_text = get_text(source_node)
            module = module_text.strip("'\"")
            line = source_node.start_point[0] + 1

            # Handle different import types
            if "default_import" in captures_dict:
                # import X from 'module'
                default_name = get_text(captures_dict["default_import"][0])
                imports.append(ImportInfo(
                    module=module,
                    names=[default_name],
                    alias=None,
                    is_from_import=True,
                    line_number=line,
                    file_path=str(file_path),
                ))
            elif "named_import" in captures_dict:
                # import { X, Y as Z } from 'module'
                named_nodes = captures_dict["named_import"]
                alias_nodes = captures_dict.get("named_alias", [])

                for i, name_node in enumerate(named_nodes):
                    name = get_text(name_node)
                    alias = None
                    if i < len(alias_nodes):
                        alias = get_text(alias_nodes[i])

                    imports.append(ImportInfo(
                        module=module,
                        names=[name],
                        alias=alias,
                        is_from_import=True,
                        line_number=line,
                        file_path=str(file_path),
                    ))
            elif "namespace_alias" in captures_dict:
                # import * as X from 'module'
                alias = get_text(captures_dict["namespace_alias"][0])
                imports.append(ImportInfo(
                    module=module,
                    names=["*"],
                    alias=alias,
                    is_from_import=True,
                    line_number=line,
                    file_path=str(file_path),
                ))
            else:
                # Side-effect import: import 'module'
                imports.append(ImportInfo(
                    module=module,
                    names=[],
                    alias=None,
                    is_from_import=True,
                    line_number=line,
                    file_path=str(file_path),
                ))

        # Also handle CommonJS require() statements
        require_query = Query(self.language, """
            (variable_declarator
                name: (identifier) @var_name
                value: (call_expression
                    function: (identifier) @require_fn
                    arguments: (arguments (string) @require_path)))

            (variable_declarator
                name: (object_pattern
                    (shorthand_property_identifier_pattern) @destructured_name)
                value: (call_expression
                    function: (identifier) @require_fn2
                    arguments: (arguments (string) @require_path2)))
        """)

        require_cursor = QueryCursor(require_query)
        require_matches = require_cursor.matches(tree.root_node)

        for match_id, captures_dict in require_matches:
            # Check for require function
            require_fn = captures_dict.get("require_fn", captures_dict.get("require_fn2", []))
            if not require_fn:
                continue

            fn_name = get_text(require_fn[0])
            if fn_name != "require":
                continue

            # Get the path
            path_node = captures_dict.get("require_path", captures_dict.get("require_path2", []))
            if not path_node:
                continue

            module_text = get_text(path_node[0])
            module = module_text.strip("'\"")
            line = path_node[0].start_point[0] + 1

            if "var_name" in captures_dict:
                # const X = require('module') - X is an alias for the whole module
                var_name = get_text(captures_dict["var_name"][0])
                imports.append(ImportInfo(
                    module=module,
                    names=[],  # Empty - no specific symbols imported
                    alias=var_name,  # The variable is an alias for the whole module
                    is_from_import=False,
                    line_number=line,
                    file_path=str(file_path),
                ))
            elif "destructured_name" in captures_dict:
                # const { X, Y } = require('module')
                for name_node in captures_dict["destructured_name"]:
                    name = get_text(name_node)
                    imports.append(ImportInfo(
                        module=module,
                        names=[name],
                        alias=None,
                        is_from_import=False,
                        line_number=line,
                        file_path=str(file_path),
                    ))

        return imports
    
    def _find_definitions_ast(self, file_path: Path, content: str) -> list[CallGraphNode]:
        """Find function/class/method definitions."""
        from tree_sitter import Query, QueryCursor

        nodes: list[CallGraphNode] = []
        tree = self.parser.parse(bytes(content, "utf8"))
        
        # Query for various JS function definitions
        query = Query(self.language, """
            (function_declaration
                name: (identifier) @name) @func
            (class_declaration
                name: (identifier) @class_name
                body: (class_body
                    (method_definition
                        name: (property_identifier) @method_name) @method))
            (variable_declarator
                name: (identifier) @var_name
                value: (arrow_function) @arrow)
            (variable_declarator
                name: (identifier) @var_name
                value: (function_expression) @anon_func)
        """)
        
        cursor = QueryCursor(query)
        matches = cursor.matches(tree.root_node)
        
        for match_id, captures_dict in matches:
            for capture_name, captured_nodes in captures_dict.items():
                for node in captured_nodes:
                    name = ""
                    def_node = None
                    
                    if capture_name == "name": # function definition
                        name = content[node.start_byte:node.end_byte]
                        def_node = node.parent
                    elif capture_name == "method_name":
                        name = content[node.start_byte:node.end_byte]
                        def_node = node.parent
                    elif capture_name == "var_name":
                        # For arrow functions or anonymous functions assigned to vars
                        name = content[node.start_byte:node.end_byte]
                        # The parent's sibling (value) is the function body
                        def_node = node.parent
                        
                    if name and def_node:
                        nodes.append(CallGraphNode(
                            name=name,
                            file_path=str(file_path),
                            start_line=def_node.start_point[0] + 1,
                            end_line=def_node.end_point[0] + 1
                        ))
                
        return nodes

    def _find_calls_ast(
        self, file_path: Path, content: str, nodes: list[CallGraphNode]
    ) -> list[CallGraphEdge]:
        """Find function calls inside definitions."""
        from tree_sitter import Query, QueryCursor

        edges: list[CallGraphEdge] = []
        tree = self.parser.parse(bytes(content, "utf8"))

        # Query for simple function calls and member expression calls
        query = Query(self.language, """
            (call_expression
                function: (identifier) @func_name) @call_simple

            (call_expression
                function: (member_expression
                    object: (identifier) @member_obj
                    property: (property_identifier) @member_prop)) @call_member
        """)

        cursor = QueryCursor(query)
        matches = cursor.matches(tree.root_node)

        for match_id, captures_dict in matches:
            callee_name = None
            line_number = None

            if "func_name" in captures_dict:
                # Simple call: foo()
                node = captures_dict["func_name"][0]
                callee_name = content[node.start_byte:node.end_byte]
                line_number = node.start_point[0] + 1
            elif "member_obj" in captures_dict and "member_prop" in captures_dict:
                # Member call: obj.method() -> capture as "obj.method"
                obj_node = captures_dict["member_obj"][0]
                prop_node = captures_dict["member_prop"][0]
                obj_name = content[obj_node.start_byte:obj_node.end_byte]
                prop_name = content[prop_node.start_byte:prop_node.end_byte]
                callee_name = f"{obj_name}.{prop_name}"
                line_number = prop_node.start_point[0] + 1

            if callee_name and line_number:
                caller_name = "<root>"
                for func_node in nodes:
                    if func_node.start_line <= line_number <= func_node.end_line:
                        caller_name = func_node.id
                        break

                edges.append(CallGraphEdge(
                    source=caller_name,
                    target=callee_name,
                    line_number=line_number,
                    file_path=str(file_path)
                ))

        return edges

    def _find_imports_regex(self, file_path: Path, content: str) -> list[ImportInfo]:
        """Find all imports in a JavaScript/TypeScript file using regex (legacy)."""
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

    def extract_call_graph_nodes(self, file_path: Path, content: str) -> list[CallGraphNode]:
        """Extract function definitions from Go file (not yet implemented)."""
        # Go call graph extraction requires tree-sitter-go
        # For now, return empty list
        return []

    def extract_call_graph_edges(
        self, file_path: Path, content: str, nodes: list[CallGraphNode]
    ) -> list[CallGraphEdge]:
        """Extract function calls from Go file (not yet implemented)."""
        return []


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

    def extract_call_graph_nodes(self, file_path: Path, content: str) -> list[CallGraphNode]:
        """Extract function definitions from Ruby file (not yet implemented)."""
        # Ruby call graph extraction requires tree-sitter-ruby
        # For now, return empty list
        return []

    def extract_call_graph_edges(
        self, file_path: Path, content: str, nodes: list[CallGraphNode]
    ) -> list[CallGraphEdge]:
        """Extract function calls from Ruby file (not yet implemented)."""
        return []


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
