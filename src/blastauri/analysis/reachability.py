"""Core engine for Reachability Analysis."""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from blastauri.analysis.static_analyzer import CallGraph, ImportInfo, StaticAnalyzer
from blastauri.analysis.vulnerability_kb import VulnerabilitySignature
from blastauri.core.models import Ecosystem

logger = logging.getLogger(__name__)


@dataclass
class ReachabilityResult:
    """Result of a reachability analysis."""

    is_reachable: bool
    status: str  # REACHABLE, POTENTIALLY_REACHABLE, UNREACHABLE, UNKNOWN
    call_trace: list[str] = field(default_factory=list)


class ReachabilityAnalyzer:
    """Analyzes the call graph to determine if vulnerable functions are reachable."""

    def __init__(self, static_analyzer: StaticAnalyzer):
        self.static_analyzer = static_analyzer
        self.call_graph = CallGraph()
        self.file_imports: dict[str, list[ImportInfo]] = {}  # file_path -> list[ImportInfo]
        self.module_map: dict[str, str] = {}     # module_name (stem) -> file_path

    def build_graph(self, file_paths: list[Path]) -> None:
        """Build the full call graph from a list of files."""
        logger.debug("Building call graph from %d files", len(file_paths))

        # 1. First pass: Collect all definitions and imports
        for file_path in file_paths:
            ecosystem = self._guess_ecosystem(file_path)
            if not ecosystem:
                continue

            analyzer = self.static_analyzer.get_analyzer(ecosystem)
            if not analyzer:
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except (OSError, IOError) as e:
                logger.warning("Could not read file %s: %s", file_path, e)
                continue
            
            # Store imports for resolution
            imports = analyzer.find_imports(file_path, content)
            self.file_imports[str(file_path)] = imports

            # Map module name - use stem for simple lookup
            # Note: This can cause collisions if multiple files have the same stem
            # (e.g., src/utils.py and lib/utils.py). For now, last one wins.
            # A more robust solution would use full path or track conflicts.
            stem = file_path.stem
            if stem not in self.module_map:
                self.module_map[stem] = str(file_path)
            # If collision, keep the first one found (more predictable behavior)
            
            # Extract nodes (definitions)
            nodes = analyzer.extract_call_graph_nodes(file_path, content)
            for node in nodes:
                self.call_graph.add_node(node)
                
        # 2. Second pass: Extract edges (calls) and resolve them
        for file_path in file_paths:
            ecosystem = self._guess_ecosystem(file_path)
            if not ecosystem:
                continue
            analyzer = self.static_analyzer.get_analyzer(ecosystem)
            if not analyzer:
                continue

            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except (OSError, IOError):
                continue
            
            # We need the nodes for this file to correctly identify callers
            # Inefficient lookup, but fine for MVP
            file_nodes = [n for n in self.call_graph.nodes.values() if n.file_path == str(file_path)]
            
            edges = analyzer.extract_call_graph_edges(file_path, content, file_nodes)
            
            for edge in edges:
                self.call_graph.add_edge(edge)

        logger.debug(
            "Call graph built: %d nodes, %d edges",
            len(self.call_graph.nodes),
            len(self.call_graph.edges),
        )

    def analyze_vulnerability(self, signature: VulnerabilitySignature) -> ReachabilityResult:
        """Check if a specific vulnerability signature is reachable."""
        logger.debug(
            "Analyzing reachability for %s (symbols: %s)",
            signature.cve_id,
            signature.vulnerable_symbols,
        )

        # 1. Identify Sinks (Vulnerable Functions)
        sinks = signature.vulnerable_symbols
        
        # We need to find "Sink Nodes" in our graph OR "External Calls" that match the sink.
        # Since we don't model external libraries as full nodes often, we look at edges that point to external things.
        
        sink_edges = []
        for edge in self.call_graph.edges:
            # Resolve the call name using imports
            resolved_name = self._resolve_symbol(edge.target, edge.file_path)
            
            for sink in sinks:
                if self._matches_sink(resolved_name, sink):
                    sink_edges.append(edge)
        
        if not sink_edges:
            logger.debug("No calls to vulnerable symbols found - UNREACHABLE")
            return ReachabilityResult(
                is_reachable=False,
                status="UNREACHABLE",
                call_trace=[]
            )

        logger.debug("Found %d calls to vulnerable symbols", len(sink_edges))
            
        # 2. Transitive Reachability (BFS from User Entry Points to Sinks?)
        # Actually easier: BFS backwards from Sinks to any Public/Entry Node?
        # Or BFS from all nodes to Sinks.
        
        # Let's find if ANY path exists from a "Root" (User function) to a Sink Edge.
        # A Sink Edge is (Caller -> Sink).
        # So we need to see if Caller is reachable from entry points.
        # For simplicity, let's assume ALL defined functions in user code are potential entry points 
        # (unless we do strict main/api detection).
        # BUT, to show a trace, we need to connect them.
        
        # Ideally: Is there a path Call A -> Call B -> ... -> Sink Edge?
        # The 'source' of Sink Edge is a node in our graph.
        
        visited = set()
        queue = [] 
        
        # We start from the functions that make the bad call
        for edge in sink_edges:
            queue.append((edge.source, [f"{edge.source} calls {edge.target} ({signature.package_name})"]))
            visited.add(edge.source)
            
        # Perform Reverse BFS to find a chain up to a top-level function
        # We need a reverse graph: TargetNodeID -> [SourceNodeIDs]
        # To build this, we must resolve the target of every edge in the graph.
        
        reverse_graph: dict[str, list[str]] = {}
        
        for edge in self.call_graph.edges:
            # edge.source is already a Node ID (thanks to static_analyzer update)
            # edge.target is a raw string (e.g. "helper" or "yaml.load")
            
            # Try to resolve target to a Node ID
            target_id = self._resolve_call_to_id(edge.target, edge.file_path)
            
            if target_id:
                if target_id not in reverse_graph:
                    reverse_graph[target_id] = []
                reverse_graph[target_id].append(edge.source)
            
            # Also keep raw name for internal calls? 
            # If "helper" calls "helper" (recursion) or intra-file without qualification.
            # _resolve_call_to_id should handle intra-file resolution too.
            
        while queue:
            current_func_id, trace = queue.pop(0)

            # Check if this function is an entry point
            # Heuristic: If it has no callers in our known graph, it's a potential root.
            # Or if it's "main" or in a controller file.
            # Also: if all callers are already visited (cycle), treat as entry point.

            callers = reverse_graph.get(current_func_id, [])

            # Filter to callers we haven't visited yet
            unvisited_callers = [c for c in callers if c not in visited]

            if not callers or not unvisited_callers:
                # No callers within the graph (internal code), OR
                # All callers have been visited (we're at the top of a cycle).
                # This is an entry point.
                display_name = current_func_id.split(":")[-1]
                full_trace = [f"Entry point {display_name}"] + trace
                logger.debug("Found reachable path from entry point: %s", display_name)
                return ReachabilityResult(
                    is_reachable=True,
                    status="REACHABLE",
                    call_trace=full_trace
                )

            for caller_id in unvisited_callers:
                visited.add(caller_id)
                display_caller = caller_id.split(":")[-1]
                display_current = current_func_id.split(":")[-1]

                new_trace = [f"{display_caller} calls {display_current}"] + trace
                queue.append((caller_id, new_trace))
                    
        # If we exhausted the queue without finding an entry point, it means:
        # - The vulnerable function IS called somewhere in the code
        # - BUT that calling code is not reachable from any entry point
        # - This is dead/isolated code - the vulnerability is NOT reachable

        # Return UNREACHABLE since we confirmed the call exists but found no path
        # from an entry point to that call
        first_edge = sink_edges[0]
        logger.debug(
            "Vulnerable call found but no entry point reachable - dead code: %s",
            first_edge.source,
        )
        return ReachabilityResult(
            is_reachable=False,
            status="UNREACHABLE",
            call_trace=[f"Dead code: {first_edge.source} calls {first_edge.target} (no entry point found)"]
        )

    def _resolve_call_to_id(self, call_name: str, context_file: str) -> str | None:
        """Resolve a call string to a Node ID (filepath:funcname)."""
        # 1. Resolve to fully qualified name (module.func)
        qualified_name = self._resolve_symbol(call_name, context_file)
        
        # 2. Split into module and function
        # e.g. "utils.helper" -> module="utils", func="helper"
        # e.g. "helper" (if local) -> need to check if local
        
        parts = qualified_name.split(".")
        
        # Check if it's a known module
        potential_module = parts[0]
        if potential_module in self.module_map:
            # e.g. "utils.helper"
            if len(parts) > 1:
                module_path = self.module_map[potential_module]
                func_name = ".".join(parts[1:])
                return f"{module_path}:{func_name}"
        
        # Handle Local Call (within same file)
        # If qualified_name is just "helper", and we are in "fileA.py"
        # And "fileA:helper" exists.
        
        if len(parts) == 1:
            candidate_id = f"{context_file}:{qualified_name}"
            if candidate_id in self.call_graph.nodes:
                return candidate_id
        
        # Handle "transitive_main.py" importing "helper" from "utils"
        # _resolve_symbol returns "utils.helper".
        # parts=['utils', 'helper']
        # self.module_map['utils'] exists? Yes.
        # Returns path:helper.
        
        return None

    def _resolve_symbol(self, symbol_name: str, file_path: str) -> str:
        """Resolve a symbol name to its fully qualified name using imports."""
        imports = self.file_imports.get(file_path, [])

        # Case 1: symbol is "yaml.load" or "_.template" -> base.method format
        # Case 2: symbol is "load" and we have "from yaml import load"
        # Case 3: symbol is "template" and we have "const { template } = require('lodash')"

        parts = symbol_name.split(".")
        base = parts[0]
        remainder = ".".join(parts[1:]) if len(parts) > 1 else ""

        for imp in imports:
            # Check aliased imports: "import yaml as y" -> y.load becomes yaml.load
            # Also handles: "import * as lodash" -> lodash.template becomes lodash.template
            if imp.alias == base:
                real_module = imp.module
                return f"{real_module}.{remainder}" if remainder else real_module

            # Check from imports for Python: "from yaml import load" -> load becomes yaml.load
            # For JS default imports: "import _ from 'lodash'" -> _.template becomes lodash.template
            # JS default imports have names=[imported_name] where imported_name represents the module
            if imp.is_from_import and base in imp.names:
                # If there's a remainder (e.g., _.template), the base is like an alias
                # and we want: module.remainder (lodash.template)
                if remainder:
                    return f"{imp.module}.{remainder}"
                # If no remainder (e.g., just "load" from "from yaml import load")
                # we want: module.symbol (yaml.load)
                check_name = imp.names[0]
                if imp.alias and imp.alias == base:
                    return f"{imp.module}.{check_name}"
                elif not imp.alias and check_name == base:
                    return f"{imp.module}.{check_name}"

            # Check for CommonJS destructured requires: const { template } = require('lodash')
            # In this case, is_from_import=False but names contains the destructured symbols
            # "template" should become "lodash.template"
            if not imp.is_from_import and imp.names and base in imp.names:
                # This is a destructured import, resolve it like a from import
                return f"{imp.module}.{base}"

            # Check for non-from imports: "import yaml" -> yaml.load stays yaml.load
            if not imp.is_from_import and imp.module == base:
                return symbol_name  # Already qualified

        return symbol_name

    def _matches_sink(self, call_name: str, sink_name: str) -> bool:
        """Check if a call name matches a sink name.

        Args:
            call_name: The resolved call name from user code (e.g., "yaml.load")
            sink_name: The vulnerable symbol from the signature (e.g., "yaml.load")

        Returns:
            True if the call matches the vulnerable sink.
        """
        # Exact match (most reliable)
        if call_name == sink_name:
            return True

        # Normalized comparison (handle different module path formats)
        # e.g., "pyyaml.yaml.load" should match "yaml.load"
        call_parts = call_name.split(".")
        sink_parts = sink_name.split(".")

        # If call is more qualified than sink, check if sink is a suffix
        # e.g., call="pyyaml.yaml.load", sink="yaml.load" -> match
        if len(call_parts) >= len(sink_parts):
            if call_parts[-len(sink_parts):] == sink_parts:
                return True

        # If sink is more qualified, check if call matches the method part
        # BUT only if call has been resolved to include the module
        # e.g., call="yaml.load", sink="pyyaml.yaml.load" -> match
        if len(sink_parts) > len(call_parts) and len(call_parts) >= 2:
            if sink_parts[-len(call_parts):] == call_parts:
                return True

        # REMOVED: Bare suffix match that caused false positives
        # Previously: if sink_name.endswith("." + call_name) matched ANY "load" to "yaml.load"
        # Now we only match if the call has been resolved to include module context

        return False

    def _guess_ecosystem(self, path: Path) -> Ecosystem | None:
        if path.suffix == ".py":
            return Ecosystem.PYPI
        if path.suffix in [".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"]:
            return Ecosystem.NPM
        # Add others as needed
        return None
