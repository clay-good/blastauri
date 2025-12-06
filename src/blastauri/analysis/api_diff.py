"""API diff analysis for detecting breaking changes without changelogs.

This module provides multiple strategies for detecting breaking changes:
1. TypeScript/JavaScript: Parse .d.ts files from npm packages
2. Python: Parse type stubs or use ast to analyze module exports
3. Generic: Compare export names between versions using registry metadata
"""

import ast
import json
import re
import tempfile
import tarfile
from dataclasses import dataclass, field
from enum import Enum
from io import BytesIO
from pathlib import Path
from typing import Optional

import httpx

from blastauri.core.models import BreakingChange, BreakingChangeType, Ecosystem
from blastauri.utils.logging import get_logger

logger = get_logger(__name__)


class ApiChangeType(str, Enum):
    """Types of API changes detected."""

    EXPORT_REMOVED = "export_removed"
    EXPORT_ADDED = "export_added"
    SIGNATURE_CHANGED = "signature_changed"
    TYPE_CHANGED = "type_changed"
    DEFAULT_CHANGED = "default_changed"
    PARAMETER_REMOVED = "parameter_removed"
    PARAMETER_ADDED_REQUIRED = "parameter_added_required"
    RETURN_TYPE_CHANGED = "return_type_changed"


@dataclass
class ApiExport:
    """Represents an exported API element."""

    name: str
    kind: str  # function, class, constant, type
    signature: Optional[str] = None
    parameters: list[str] = field(default_factory=list)
    return_type: Optional[str] = None
    is_default: bool = False


@dataclass
class ApiDiff:
    """Differences between two API versions."""

    removed: list[ApiExport] = field(default_factory=list)
    added: list[ApiExport] = field(default_factory=list)
    changed: list[tuple[ApiExport, ApiExport]] = field(default_factory=list)


class ApiDiffAnalyzer:
    """Analyzes API differences between package versions."""

    def __init__(self, http_client: Optional[httpx.AsyncClient] = None):
        """Initialize the API diff analyzer.

        Args:
            http_client: Optional HTTP client for fetching packages.
        """
        self._http_client = http_client
        self._owns_client = False

    async def __aenter__(self) -> "ApiDiffAnalyzer":
        """Async context manager entry."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(timeout=60.0)
            self._owns_client = True
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        if self._owns_client and self._http_client:
            await self._http_client.aclose()

    async def analyze_npm_package(
        self,
        package_name: str,
        from_version: str,
        to_version: str,
    ) -> list[BreakingChange]:
        """Analyze breaking changes in npm package by comparing type definitions.

        Args:
            package_name: NPM package name.
            from_version: Old version.
            to_version: New version.

        Returns:
            List of detected breaking changes.
        """
        if not self._http_client:
            return []

        try:
            # Get exports from both versions
            old_exports = await self._fetch_npm_exports(package_name, from_version)
            new_exports = await self._fetch_npm_exports(package_name, to_version)

            if not old_exports and not new_exports:
                return []

            # Compare exports
            diff = self._compare_exports(old_exports, new_exports)
            return self._diff_to_breaking_changes(diff, "npm_api_diff")

        except Exception as e:
            logger.debug(f"Failed to analyze npm package {package_name}: {e}")
            return []

    async def _fetch_npm_exports(
        self,
        package_name: str,
        version: str,
    ) -> list[ApiExport]:
        """Fetch exports from an npm package.

        Args:
            package_name: Package name.
            version: Package version.

        Returns:
            List of API exports.
        """
        if not self._http_client:
            return []

        exports: list[ApiExport] = []

        try:
            # First, try to get package.json exports field
            response = await self._http_client.get(
                f"https://registry.npmjs.org/{package_name}/{version}",
            )
            response.raise_for_status()
            pkg_data = response.json()

            # Check for TypeScript types
            types_entry = pkg_data.get("types") or pkg_data.get("typings")

            # Get tarball URL
            tarball_url = pkg_data.get("dist", {}).get("tarball")
            if not tarball_url:
                return exports

            # Download and extract type definitions
            tarball_response = await self._http_client.get(tarball_url)
            tarball_response.raise_for_status()

            with tempfile.TemporaryDirectory() as tmpdir:
                # Extract tarball
                with tarfile.open(
                    fileobj=BytesIO(tarball_response.content), mode="r:gz"
                ) as tar:
                    tar.extractall(tmpdir, filter="data")

                pkg_dir = Path(tmpdir) / "package"

                # Parse type definitions if available
                if types_entry:
                    types_path = pkg_dir / types_entry
                    if types_path.exists():
                        exports.extend(self._parse_typescript_dts(types_path))

                # Also check for index.d.ts
                for dts_file in pkg_dir.glob("**/*.d.ts"):
                    exports.extend(self._parse_typescript_dts(dts_file))

                # If no TypeScript, try parsing JavaScript for exports
                if not exports:
                    main_entry = pkg_data.get("main", "index.js")
                    main_path = pkg_dir / main_entry
                    if main_path.exists():
                        exports.extend(self._parse_js_exports(main_path))

        except Exception as e:
            logger.debug(f"Failed to fetch npm exports for {package_name}@{version}: {e}")

        return exports

    def _parse_typescript_dts(self, file_path: Path) -> list[ApiExport]:
        """Parse TypeScript declaration file for exports.

        Args:
            file_path: Path to .d.ts file.

        Returns:
            List of API exports.
        """
        exports: list[ApiExport] = []

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")

            # Parse export declarations
            # export function name(params): returnType
            func_pattern = r"export\s+(?:declare\s+)?function\s+(\w+)\s*(<[^>]*>)?\s*\(([^)]*)\)\s*:\s*([^;{]+)"
            for match in re.finditer(func_pattern, content):
                name = match.group(1)
                params = match.group(3).strip()
                return_type = match.group(4).strip()

                param_list = [p.strip().split(":")[0].strip() for p in params.split(",") if p.strip()]

                exports.append(ApiExport(
                    name=name,
                    kind="function",
                    signature=f"{name}({params}): {return_type}",
                    parameters=param_list,
                    return_type=return_type,
                ))

            # export class Name
            class_pattern = r"export\s+(?:declare\s+)?(?:abstract\s+)?class\s+(\w+)"
            for match in re.finditer(class_pattern, content):
                exports.append(ApiExport(
                    name=match.group(1),
                    kind="class",
                ))

            # export interface Name
            interface_pattern = r"export\s+(?:declare\s+)?interface\s+(\w+)"
            for match in re.finditer(interface_pattern, content):
                exports.append(ApiExport(
                    name=match.group(1),
                    kind="type",
                ))

            # export type Name
            type_pattern = r"export\s+(?:declare\s+)?type\s+(\w+)"
            for match in re.finditer(type_pattern, content):
                exports.append(ApiExport(
                    name=match.group(1),
                    kind="type",
                ))

            # export const/let/var name
            const_pattern = r"export\s+(?:declare\s+)?(?:const|let|var)\s+(\w+)"
            for match in re.finditer(const_pattern, content):
                exports.append(ApiExport(
                    name=match.group(1),
                    kind="constant",
                ))

            # export default
            if re.search(r"export\s+default\s+", content):
                exports.append(ApiExport(
                    name="default",
                    kind="default",
                    is_default=True,
                ))

        except Exception as e:
            logger.debug(f"Failed to parse TypeScript file {file_path}: {e}")

        return exports

    def _parse_js_exports(self, file_path: Path) -> list[ApiExport]:
        """Parse JavaScript file for exports (CommonJS and ESM).

        Args:
            file_path: Path to JavaScript file.

        Returns:
            List of API exports.
        """
        exports: list[ApiExport] = []

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")

            # ESM exports
            # export { name1, name2 }
            named_exports = re.findall(r"export\s*\{\s*([^}]+)\s*\}", content)
            for export_block in named_exports:
                for name in export_block.split(","):
                    name = name.strip().split(" as ")[0].strip()
                    if name:
                        exports.append(ApiExport(name=name, kind="unknown"))

            # export function/class/const
            for match in re.finditer(r"export\s+(?:function|class|const|let|var)\s+(\w+)", content):
                exports.append(ApiExport(name=match.group(1), kind="unknown"))

            # CommonJS: module.exports = { ... }
            cjs_match = re.search(r"module\.exports\s*=\s*\{([^}]+)\}", content)
            if cjs_match:
                for name in cjs_match.group(1).split(","):
                    name = name.strip().split(":")[0].strip()
                    if name and not name.startswith("//"):
                        exports.append(ApiExport(name=name, kind="unknown"))

            # CommonJS: exports.name = ...
            for match in re.finditer(r"exports\.(\w+)\s*=", content):
                exports.append(ApiExport(name=match.group(1), kind="unknown"))

        except Exception as e:
            logger.debug(f"Failed to parse JavaScript file {file_path}: {e}")

        return exports

    async def analyze_pypi_package(
        self,
        package_name: str,
        from_version: str,
        to_version: str,
    ) -> list[BreakingChange]:
        """Analyze breaking changes in PyPI package by comparing module exports.

        Args:
            package_name: PyPI package name.
            from_version: Old version.
            to_version: New version.

        Returns:
            List of detected breaking changes.
        """
        if not self._http_client:
            return []

        try:
            old_exports = await self._fetch_pypi_exports(package_name, from_version)
            new_exports = await self._fetch_pypi_exports(package_name, to_version)

            if not old_exports and not new_exports:
                return []

            diff = self._compare_exports(old_exports, new_exports)
            return self._diff_to_breaking_changes(diff, "pypi_api_diff")

        except Exception as e:
            logger.debug(f"Failed to analyze PyPI package {package_name}: {e}")
            return []

    async def _fetch_pypi_exports(
        self,
        package_name: str,
        version: str,
    ) -> list[ApiExport]:
        """Fetch exports from a PyPI package.

        Args:
            package_name: Package name.
            version: Package version.

        Returns:
            List of API exports.
        """
        if not self._http_client:
            return []

        exports: list[ApiExport] = []

        try:
            # Get package info
            response = await self._http_client.get(
                f"https://pypi.org/pypi/{package_name}/{version}/json",
            )
            response.raise_for_status()
            data = response.json()

            # Find wheel or sdist URL
            urls = data.get("urls", [])
            wheel_url = None
            sdist_url = None

            for url_info in urls:
                if url_info.get("packagetype") == "bdist_wheel":
                    wheel_url = url_info.get("url")
                    break
                elif url_info.get("packagetype") == "sdist":
                    sdist_url = url_info.get("url")

            download_url = wheel_url or sdist_url
            if not download_url:
                return exports

            # Download and extract
            pkg_response = await self._http_client.get(download_url)
            pkg_response.raise_for_status()

            with tempfile.TemporaryDirectory() as tmpdir:
                if download_url.endswith(".whl"):
                    # Wheel is a zip file
                    import zipfile
                    with zipfile.ZipFile(BytesIO(pkg_response.content)) as zf:
                        zf.extractall(tmpdir)
                else:
                    # sdist is a tarball
                    with tarfile.open(
                        fileobj=BytesIO(pkg_response.content), mode="r:gz"
                    ) as tar:
                        tar.extractall(tmpdir, filter="data")

                # Find Python files and parse for exports
                pkg_dir = Path(tmpdir)

                # Look for __init__.py files
                for init_file in pkg_dir.glob("**/__init__.py"):
                    # Skip test directories
                    if "test" in str(init_file).lower():
                        continue
                    exports.extend(self._parse_python_exports(init_file))

                # Look for .pyi stub files
                for stub_file in pkg_dir.glob("**/*.pyi"):
                    exports.extend(self._parse_python_exports(stub_file))

        except Exception as e:
            logger.debug(f"Failed to fetch PyPI exports for {package_name}@{version}: {e}")

        return exports

    def _parse_python_exports(self, file_path: Path) -> list[ApiExport]:
        """Parse Python file for public exports with type annotations.

        Args:
            file_path: Path to Python file.

        Returns:
            List of API exports with signatures and types.
        """
        exports: list[ApiExport] = []

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(content)

            # Check for __all__
            all_exports: Optional[list[str]] = None
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name) and target.id == "__all__":
                            if isinstance(node.value, ast.List):
                                all_exports = [
                                    elt.value
                                    for elt in node.value.elts
                                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                                ]

            # Parse top-level definitions
            for node in ast.iter_child_nodes(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    # Skip private functions
                    if node.name.startswith("_") and not node.name.startswith("__"):
                        continue
                    # If __all__ exists, only include listed items
                    if all_exports is not None and node.name not in all_exports:
                        continue

                    # Extract parameters with types
                    params_with_types = self._extract_function_params(node)
                    param_names = [p.split(":")[0].strip() for p in params_with_types]

                    # Extract return type
                    return_type = self._annotation_to_string(node.returns) if node.returns else None

                    # Build signature
                    signature = f"{node.name}({', '.join(params_with_types)})"
                    if return_type:
                        signature += f" -> {return_type}"

                    exports.append(ApiExport(
                        name=node.name,
                        kind="function",
                        signature=signature,
                        parameters=param_names,
                        return_type=return_type,
                    ))

                elif isinstance(node, ast.ClassDef):
                    if node.name.startswith("_"):
                        continue
                    if all_exports is not None and node.name not in all_exports:
                        continue

                    # Extract class methods for more detailed comparison
                    class_signature = self._extract_class_signature(node)

                    exports.append(ApiExport(
                        name=node.name,
                        kind="class",
                        signature=class_signature,
                    ))

                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            if target.id.startswith("_"):
                                continue
                            if all_exports is not None and target.id not in all_exports:
                                continue
                            exports.append(ApiExport(
                                name=target.id,
                                kind="constant",
                            ))

                elif isinstance(node, ast.AnnAssign):
                    # Type-annotated assignments: name: Type = value
                    if isinstance(node.target, ast.Name):
                        name = node.target.id
                        if name.startswith("_"):
                            continue
                        if all_exports is not None and name not in all_exports:
                            continue
                        type_str = self._annotation_to_string(node.annotation)
                        exports.append(ApiExport(
                            name=name,
                            kind="constant",
                            signature=f"{name}: {type_str}" if type_str else name,
                            return_type=type_str,
                        ))

        except SyntaxError:
            # File might be Python 2 or have syntax errors
            pass
        except Exception as e:
            logger.debug(f"Failed to parse Python file {file_path}: {e}")

        return exports

    def _extract_function_params(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
        """Extract function parameters with their type annotations.

        Args:
            node: Function definition AST node.

        Returns:
            List of parameter strings with types (e.g., "name: str", "count: int = 0").
        """
        params = []
        args = node.args

        # Calculate defaults offset
        num_args = len(args.args)
        num_defaults = len(args.defaults)
        defaults_start = num_args - num_defaults

        for i, arg in enumerate(args.args):
            param_str = arg.arg

            # Add type annotation if present
            if arg.annotation:
                type_str = self._annotation_to_string(arg.annotation)
                if type_str:
                    param_str = f"{arg.arg}: {type_str}"

            # Add default value indicator if present
            if i >= defaults_start:
                default_idx = i - defaults_start
                default_val = args.defaults[default_idx]
                default_repr = self._default_to_string(default_val)
                if default_repr:
                    param_str = f"{param_str} = {default_repr}"

            params.append(param_str)

        # Handle *args
        if args.vararg:
            vararg_str = f"*{args.vararg.arg}"
            if args.vararg.annotation:
                type_str = self._annotation_to_string(args.vararg.annotation)
                if type_str:
                    vararg_str = f"*{args.vararg.arg}: {type_str}"
            params.append(vararg_str)

        # Handle keyword-only args
        for i, arg in enumerate(args.kwonlyargs):
            param_str = arg.arg
            if arg.annotation:
                type_str = self._annotation_to_string(arg.annotation)
                if type_str:
                    param_str = f"{arg.arg}: {type_str}"
            if i < len(args.kw_defaults) and args.kw_defaults[i] is not None:
                default_repr = self._default_to_string(args.kw_defaults[i])
                if default_repr:
                    param_str = f"{param_str} = {default_repr}"
            params.append(param_str)

        # Handle **kwargs
        if args.kwarg:
            kwarg_str = f"**{args.kwarg.arg}"
            if args.kwarg.annotation:
                type_str = self._annotation_to_string(args.kwarg.annotation)
                if type_str:
                    kwarg_str = f"**{args.kwarg.arg}: {type_str}"
            params.append(kwarg_str)

        return params

    def _extract_class_signature(self, node: ast.ClassDef) -> str:
        """Extract class signature including bases and key methods.

        Args:
            node: Class definition AST node.

        Returns:
            String representation of class signature.
        """
        # Extract base classes
        bases = []
        for base in node.bases:
            base_str = self._annotation_to_string(base)
            if base_str:
                bases.append(base_str)

        sig = f"class {node.name}"
        if bases:
            sig += f"({', '.join(bases)})"

        # Extract public methods
        methods = []
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not item.name.startswith("_") or item.name in ("__init__", "__call__", "__iter__", "__next__"):
                    params = self._extract_function_params(item)
                    return_type = self._annotation_to_string(item.returns) if item.returns else None
                    method_sig = f"{item.name}({', '.join(params)})"
                    if return_type:
                        method_sig += f" -> {return_type}"
                    methods.append(method_sig)

        if methods:
            sig += f" [{len(methods)} methods: {', '.join(m.split('(')[0] for m in methods[:5])}]"

        return sig

    def _annotation_to_string(self, annotation: ast.expr | None) -> Optional[str]:
        """Convert AST annotation node to string representation.

        Args:
            annotation: AST annotation node.

        Returns:
            String representation of the type annotation.
        """
        if annotation is None:
            return None

        try:
            if isinstance(annotation, ast.Name):
                return annotation.id
            elif isinstance(annotation, ast.Constant):
                return repr(annotation.value)
            elif isinstance(annotation, ast.Attribute):
                value = self._annotation_to_string(annotation.value)
                return f"{value}.{annotation.attr}" if value else annotation.attr
            elif isinstance(annotation, ast.Subscript):
                value = self._annotation_to_string(annotation.value)
                slice_str = self._annotation_to_string(annotation.slice)
                return f"{value}[{slice_str}]" if value and slice_str else None
            elif isinstance(annotation, ast.Tuple):
                elements = [self._annotation_to_string(e) for e in annotation.elts]
                if all(elements):
                    return ", ".join(elements)
            elif isinstance(annotation, ast.BinOp):
                # Handle Union types with | operator (Python 3.10+)
                if isinstance(annotation.op, ast.BitOr):
                    left = self._annotation_to_string(annotation.left)
                    right = self._annotation_to_string(annotation.right)
                    if left and right:
                        return f"{left} | {right}"
            elif isinstance(annotation, ast.List):
                elements = [self._annotation_to_string(e) for e in annotation.elts]
                if all(elements):
                    return f"[{', '.join(elements)}]"
            # For complex annotations, use ast.unparse if available (Python 3.9+)
            try:
                return ast.unparse(annotation)
            except (AttributeError, ValueError):
                pass
        except Exception:
            pass

        return None

    def _default_to_string(self, default: ast.expr) -> Optional[str]:
        """Convert default value AST node to string representation.

        Args:
            default: AST node for default value.

        Returns:
            String representation of default value (simplified).
        """
        try:
            if isinstance(default, ast.Constant):
                if default.value is None:
                    return "None"
                elif isinstance(default.value, str):
                    return f"'{default.value}'" if len(default.value) < 20 else "'...'"
                elif isinstance(default.value, (int, float, bool)):
                    return repr(default.value)
            elif isinstance(default, ast.Name):
                return default.id
            elif isinstance(default, ast.List):
                return "[]" if not default.elts else "[...]"
            elif isinstance(default, ast.Dict):
                return "{}" if not default.keys else "{...}"
            elif isinstance(default, ast.Tuple):
                return "()" if not default.elts else "(...)"
            elif isinstance(default, ast.Call):
                func_name = self._annotation_to_string(default.func)
                return f"{func_name}(...)" if func_name else "..."
            # For Python 3.9+
            try:
                unp = ast.unparse(default)
                return unp if len(unp) < 30 else "..."
            except (AttributeError, ValueError):
                pass
        except Exception:
            pass
        return "..."

    def _compare_exports(
        self,
        old_exports: list[ApiExport],
        new_exports: list[ApiExport],
    ) -> ApiDiff:
        """Compare two sets of exports to find differences.

        Args:
            old_exports: Exports from old version.
            new_exports: Exports from new version.

        Returns:
            API diff.
        """
        old_by_name = {e.name: e for e in old_exports}
        new_by_name = {e.name: e for e in new_exports}

        old_names = set(old_by_name.keys())
        new_names = set(new_by_name.keys())

        removed = [old_by_name[name] for name in old_names - new_names]
        added = [new_by_name[name] for name in new_names - old_names]

        # Check for signature changes in common exports
        changed: list[tuple[ApiExport, ApiExport]] = []
        for name in old_names & new_names:
            old_exp = old_by_name[name]
            new_exp = new_by_name[name]

            # Check for parameter changes
            if old_exp.parameters != new_exp.parameters:
                changed.append((old_exp, new_exp))
            elif old_exp.return_type != new_exp.return_type:
                changed.append((old_exp, new_exp))
            elif old_exp.kind != new_exp.kind:
                changed.append((old_exp, new_exp))

        return ApiDiff(removed=removed, added=added, changed=changed)

    def _diff_to_breaking_changes(
        self,
        diff: ApiDiff,
        source: str,
    ) -> list[BreakingChange]:
        """Convert API diff to breaking changes.

        Args:
            diff: API diff.
            source: Source identifier.

        Returns:
            List of breaking changes.
        """
        changes: list[BreakingChange] = []

        # Removed exports are breaking
        for export in diff.removed:
            if export.kind == "function":
                change_type = BreakingChangeType.REMOVED_FUNCTION
            elif export.kind == "class":
                change_type = BreakingChangeType.REMOVED_CLASS
            elif export.kind == "type":
                change_type = BreakingChangeType.REMOVED_MODULE
            else:
                change_type = BreakingChangeType.REMOVED_FUNCTION

            changes.append(BreakingChange(
                change_type=change_type,
                description=f"Removed {export.kind}: {export.name}",
                old_api=export.name,
                source=source,
            ))

        # Signature changes are breaking
        for old_exp, new_exp in diff.changed:
            if old_exp.parameters != new_exp.parameters:
                # Check if parameters were removed (breaking) vs added (potentially breaking)
                old_params = set(old_exp.parameters)
                new_params = set(new_exp.parameters)

                removed_params = old_params - new_params
                if removed_params:
                    changes.append(BreakingChange(
                        change_type=BreakingChangeType.CHANGED_SIGNATURE,
                        description=f"Removed parameter(s) from {old_exp.name}: {', '.join(removed_params)}",
                        old_api=f"{old_exp.name}({', '.join(old_exp.parameters)})",
                        new_api=f"{new_exp.name}({', '.join(new_exp.parameters)})",
                        source=source,
                    ))

            if old_exp.return_type and new_exp.return_type and old_exp.return_type != new_exp.return_type:
                changes.append(BreakingChange(
                    change_type=BreakingChangeType.CHANGED_SIGNATURE,
                    description=f"Return type changed for {old_exp.name}: {old_exp.return_type} -> {new_exp.return_type}",
                    old_api=old_exp.return_type,
                    new_api=new_exp.return_type,
                    source=source,
                ))

        return changes

    async def analyze_package(
        self,
        ecosystem: Ecosystem,
        package_name: str,
        from_version: str,
        to_version: str,
    ) -> list[BreakingChange]:
        """Analyze breaking changes for any supported ecosystem.

        Args:
            ecosystem: Package ecosystem.
            package_name: Package name.
            from_version: Old version.
            to_version: New version.

        Returns:
            List of detected breaking changes.
        """
        if ecosystem == Ecosystem.NPM:
            return await self.analyze_npm_package(package_name, from_version, to_version)
        elif ecosystem == Ecosystem.PYPI:
            return await self.analyze_pypi_package(package_name, from_version, to_version)
        else:
            # Other ecosystems not yet supported
            return []


async def analyze_api_diff(
    ecosystem: Ecosystem,
    package_name: str,
    from_version: str,
    to_version: str,
) -> list[BreakingChange]:
    """Convenience function to analyze API diff.

    Args:
        ecosystem: Package ecosystem.
        package_name: Package name.
        from_version: Old version.
        to_version: New version.

    Returns:
        List of detected breaking changes.
    """
    async with ApiDiffAnalyzer() as analyzer:
        return await analyzer.analyze_package(
            ecosystem, package_name, from_version, to_version
        )
