"""Unit tests for the Reachability Analyzer."""

import pytest
from pathlib import Path
from tempfile import TemporaryDirectory

from blastauri.analysis.reachability import ReachabilityAnalyzer, ReachabilityResult
from blastauri.analysis.static_analyzer import StaticAnalyzer
from blastauri.analysis.vulnerability_kb import VulnerabilitySignature, VulnerabilityKB
from blastauri.core.models import Ecosystem


@pytest.fixture
def static_analyzer():
    return StaticAnalyzer()


@pytest.fixture
def reachability_analyzer(static_analyzer):
    return ReachabilityAnalyzer(static_analyzer)


@pytest.fixture
def yaml_vulnerability():
    """Vulnerability signature for PyYAML's unsafe load."""
    return VulnerabilitySignature(
        cve_id="CVE-2017-18342",
        package_name="pyyaml",
        ecosystem="pypi",
        vulnerable_version_range="<5.4",
        vulnerable_symbols=["yaml.load"]
    )


@pytest.fixture
def lodash_vulnerability():
    """Vulnerability signature for lodash template injection."""
    return VulnerabilitySignature(
        cve_id="CVE-2021-23337",
        package_name="lodash",
        ecosystem="npm",
        vulnerable_version_range="<4.17.21",
        vulnerable_symbols=["_.template", "lodash.template"]
    )


class TestReachabilityAnalyzerPython:
    """Test reachability analysis for Python code."""

    def test_direct_vulnerable_call_is_reachable(self, reachability_analyzer, yaml_vulnerability):
        """Test that directly calling yaml.load is detected as reachable."""
        with TemporaryDirectory() as tmpdir:
            # Create a file that directly calls yaml.load
            unsafe_file = Path(tmpdir) / "unsafe.py"
            unsafe_file.write_text("""
import yaml

def parse_config(data):
    return yaml.load(data)

if __name__ == "__main__":
    parse_config("foo: bar")
""")

            reachability_analyzer.build_graph([unsafe_file])
            result = reachability_analyzer.analyze_vulnerability(yaml_vulnerability)

            assert result.is_reachable is True
            assert result.status == "REACHABLE"
            assert len(result.call_trace) > 0

    def test_safe_function_is_unreachable(self, reachability_analyzer, yaml_vulnerability):
        """Test that calling yaml.safe_load does NOT trigger the vulnerability."""
        with TemporaryDirectory() as tmpdir:
            safe_file = Path(tmpdir) / "safe.py"
            safe_file.write_text("""
import yaml

def parse_config_safe(data):
    return yaml.safe_load(data)

if __name__ == "__main__":
    parse_config_safe("foo: bar")
""")

            reachability_analyzer.build_graph([safe_file])
            result = reachability_analyzer.analyze_vulnerability(yaml_vulnerability)

            assert result.is_reachable is False
            assert result.status == "UNREACHABLE"

    def test_transitive_call_is_reachable(self, reachability_analyzer, yaml_vulnerability):
        """Test that transitive calls through helper functions are detected."""
        with TemporaryDirectory() as tmpdir:
            # Create a helper module that calls yaml.load
            helper_file = Path(tmpdir) / "utils.py"
            helper_file.write_text("""
import yaml

def helper(data):
    return yaml.load(data)
""")

            # Create a main file that calls the helper
            main_file = Path(tmpdir) / "main.py"
            main_file.write_text("""
from utils import helper

def app_controller():
    helper("foo: bar")

if __name__ == "__main__":
    app_controller()
""")

            reachability_analyzer.build_graph([helper_file, main_file])
            result = reachability_analyzer.analyze_vulnerability(yaml_vulnerability)

            assert result.is_reachable is True
            assert result.status == "REACHABLE"

    def test_unused_import_is_unreachable(self, reachability_analyzer, yaml_vulnerability):
        """Test that importing but not using a vulnerable function is unreachable."""
        with TemporaryDirectory() as tmpdir:
            unused_file = Path(tmpdir) / "unused.py"
            unused_file.write_text("""
import yaml

def do_something():
    # yaml is imported but yaml.load is never called
    print("Hello, world!")
""")

            reachability_analyzer.build_graph([unused_file])
            result = reachability_analyzer.analyze_vulnerability(yaml_vulnerability)

            assert result.is_reachable is False
            assert result.status == "UNREACHABLE"

    def test_aliased_import_is_detected(self, reachability_analyzer, yaml_vulnerability):
        """Test that aliased imports are correctly resolved."""
        with TemporaryDirectory() as tmpdir:
            aliased_file = Path(tmpdir) / "aliased.py"
            aliased_file.write_text("""
import yaml as y

def parse_config(data):
    return y.load(data)
""")

            reachability_analyzer.build_graph([aliased_file])
            result = reachability_analyzer.analyze_vulnerability(yaml_vulnerability)

            assert result.is_reachable is True
            assert result.status == "REACHABLE"

    def test_from_import_is_detected(self, reachability_analyzer, yaml_vulnerability):
        """Test that 'from X import Y' style imports are detected."""
        with TemporaryDirectory() as tmpdir:
            from_import_file = Path(tmpdir) / "from_import.py"
            from_import_file.write_text("""
from yaml import load

def parse_config(data):
    return load(data)
""")

            reachability_analyzer.build_graph([from_import_file])
            result = reachability_analyzer.analyze_vulnerability(yaml_vulnerability)

            assert result.is_reachable is True
            assert result.status == "REACHABLE"

    def test_class_method_call_is_detected(self, reachability_analyzer, yaml_vulnerability):
        """Test that calls within class methods are detected."""
        with TemporaryDirectory() as tmpdir:
            class_file = Path(tmpdir) / "class_example.py"
            class_file.write_text("""
import yaml

class ConfigParser:
    def parse(self, data):
        return yaml.load(data)
""")

            reachability_analyzer.build_graph([class_file])
            result = reachability_analyzer.analyze_vulnerability(yaml_vulnerability)

            assert result.is_reachable is True
            assert result.status == "REACHABLE"


class TestReachabilityAnalyzerJavaScript:
    """Test reachability analysis for JavaScript code."""

    def test_lodash_template_is_reachable(self, reachability_analyzer, lodash_vulnerability):
        """Test that lodash.template usage is detected."""
        with TemporaryDirectory() as tmpdir:
            js_file = Path(tmpdir) / "app.js"
            js_file.write_text("""
const _ = require('lodash');

function renderTemplate(data) {
    const compiled = _.template('<%= name %>');
    return compiled(data);
}

module.exports = { renderTemplate };
""")

            reachability_analyzer.build_graph([js_file])
            result = reachability_analyzer.analyze_vulnerability(lodash_vulnerability)

            assert result.is_reachable is True
            assert result.status == "REACHABLE"

    def test_es6_import_is_detected(self, reachability_analyzer, lodash_vulnerability):
        """Test that ES6 imports are correctly analyzed."""
        with TemporaryDirectory() as tmpdir:
            es6_file = Path(tmpdir) / "app.mjs"
            es6_file.write_text("""
import _ from 'lodash';

export function renderTemplate(data) {
    return _.template('<%= name %>')(data);
}
""")

            reachability_analyzer.build_graph([es6_file])
            result = reachability_analyzer.analyze_vulnerability(lodash_vulnerability)

            assert result.is_reachable is True
            assert result.status == "REACHABLE"

    def test_safe_lodash_function_is_unreachable(self, reachability_analyzer, lodash_vulnerability):
        """Test that using safe lodash functions doesn't trigger vulnerability."""
        with TemporaryDirectory() as tmpdir:
            safe_file = Path(tmpdir) / "safe.js"
            safe_file.write_text("""
const _ = require('lodash');

function safeOperation(arr) {
    return _.map(arr, x => x * 2);
}

module.exports = { safeOperation };
""")

            reachability_analyzer.build_graph([safe_file])
            result = reachability_analyzer.analyze_vulnerability(lodash_vulnerability)

            assert result.is_reachable is False
            assert result.status == "UNREACHABLE"


class TestCallGraphBuilding:
    """Test call graph construction."""

    def test_build_graph_extracts_nodes(self, reachability_analyzer):
        """Test that function definitions are extracted as nodes."""
        with TemporaryDirectory() as tmpdir:
            file = Path(tmpdir) / "example.py"
            file.write_text("""
def foo():
    pass

def bar():
    foo()

class MyClass:
    def method(self):
        pass
""")

            reachability_analyzer.build_graph([file])

            # Check nodes were created
            assert len(reachability_analyzer.call_graph.nodes) >= 3
            node_names = [n.name for n in reachability_analyzer.call_graph.nodes.values()]
            assert "foo" in node_names
            assert "bar" in node_names
            assert "MyClass.method" in node_names

    def test_build_graph_extracts_edges(self, reachability_analyzer):
        """Test that function calls are extracted as edges."""
        with TemporaryDirectory() as tmpdir:
            file = Path(tmpdir) / "example.py"
            file.write_text("""
def helper():
    pass

def main():
    helper()
""")

            reachability_analyzer.build_graph([file])

            # Check edges were created
            assert len(reachability_analyzer.call_graph.edges) >= 1
            edge_targets = [e.target for e in reachability_analyzer.call_graph.edges]
            assert "helper" in edge_targets


class TestSymbolResolution:
    """Test symbol resolution in the reachability analyzer."""

    def test_resolve_simple_import(self, reachability_analyzer):
        """Test resolving a simple 'import X' pattern."""
        with TemporaryDirectory() as tmpdir:
            file = Path(tmpdir) / "test.py"
            file.write_text("""
import yaml
yaml.load(data)
""")

            reachability_analyzer.build_graph([file])

            # Check imports were recorded
            assert str(file) in reachability_analyzer.file_imports
            imports = reachability_analyzer.file_imports[str(file)]
            assert len(imports) >= 1
            assert imports[0].module == "yaml"

    def test_resolve_from_import(self, reachability_analyzer):
        """Test resolving a 'from X import Y' pattern."""
        with TemporaryDirectory() as tmpdir:
            file = Path(tmpdir) / "test.py"
            file.write_text("""
from yaml import load
load(data)
""")

            reachability_analyzer.build_graph([file])

            imports = reachability_analyzer.file_imports[str(file)]
            assert len(imports) >= 1
            assert imports[0].module == "yaml"
            assert "load" in imports[0].names


class TestVulnerabilityKB:
    """Test the vulnerability knowledge base."""

    def test_kb_loads_signatures(self):
        """Test that the KB loads signatures from the JSON file."""
        kb = VulnerabilityKB()

        # Should have at least the pyyaml signature
        assert len(kb.signatures) > 0

        pyyaml_sigs = [s for s in kb.signatures if s.package_name == "pyyaml"]
        assert len(pyyaml_sigs) > 0
        assert pyyaml_sigs[0].cve_id == "CVE-2017-18342"
        assert "yaml.load" in pyyaml_sigs[0].vulnerable_symbols

    def test_kb_get_signatures_for_package(self):
        """Test getting signatures for a specific package."""
        kb = VulnerabilityKB()

        sigs = kb.get_signatures_for_package("pyyaml", Ecosystem.PYPI)
        assert len(sigs) > 0
        assert all(s.package_name.lower() == "pyyaml" for s in sigs)

    def test_kb_returns_empty_for_unknown_package(self):
        """Test that unknown packages return empty list."""
        kb = VulnerabilityKB()

        sigs = kb.get_signatures_for_package("nonexistent-package-12345", Ecosystem.PYPI)
        assert sigs == []


class TestReachabilityResult:
    """Test the ReachabilityResult dataclass."""

    def test_result_defaults(self):
        """Test default values for ReachabilityResult."""
        result = ReachabilityResult(
            is_reachable=False,
            status="UNKNOWN"
        )

        assert result.is_reachable is False
        assert result.status == "UNKNOWN"
        assert result.call_trace == []

    def test_result_with_trace(self):
        """Test ReachabilityResult with a call trace."""
        result = ReachabilityResult(
            is_reachable=True,
            status="REACHABLE",
            call_trace=["main() calls helper()", "helper() calls yaml.load()"]
        )

        assert result.is_reachable is True
        assert len(result.call_trace) == 2


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_file_list(self, reachability_analyzer, yaml_vulnerability):
        """Test handling of empty file list."""
        reachability_analyzer.build_graph([])
        result = reachability_analyzer.analyze_vulnerability(yaml_vulnerability)

        assert result.is_reachable is False
        assert result.status == "UNREACHABLE"

    def test_nonexistent_file(self, reachability_analyzer, yaml_vulnerability):
        """Test handling of nonexistent files."""
        reachability_analyzer.build_graph([Path("/nonexistent/file.py")])
        result = reachability_analyzer.analyze_vulnerability(yaml_vulnerability)

        assert result.is_reachable is False

    def test_empty_vulnerability_symbols(self, reachability_analyzer):
        """Test handling of vulnerability with no symbols."""
        empty_vuln = VulnerabilitySignature(
            cve_id="CVE-TEST-EMPTY",
            package_name="test-package",
            ecosystem="pypi",
            vulnerable_version_range="*",
            vulnerable_symbols=[]
        )

        with TemporaryDirectory() as tmpdir:
            file = Path(tmpdir) / "test.py"
            file.write_text("import test_package")

            reachability_analyzer.build_graph([file])
            result = reachability_analyzer.analyze_vulnerability(empty_vuln)

            assert result.is_reachable is False
            assert result.status == "UNREACHABLE"

    def test_binary_file_is_skipped(self, reachability_analyzer, yaml_vulnerability):
        """Test that binary files don't cause errors."""
        with TemporaryDirectory() as tmpdir:
            binary_file = Path(tmpdir) / "binary.py"
            binary_file.write_bytes(b"\x00\x01\x02\x03\xff\xfe")

            # Should not raise an exception
            reachability_analyzer.build_graph([binary_file])
            result = reachability_analyzer.analyze_vulnerability(yaml_vulnerability)

            assert result.is_reachable is False


class TestIntegrationWithVulnerableApp:
    """Integration tests using the vulnerable_app test fixtures."""

    def test_vulnerable_app_unsafe(self, static_analyzer):
        """Test that tests/vulnerable_app/unsafe.py is detected as reachable."""
        vulnerable_app_dir = Path(__file__).parent.parent / "vulnerable_app"
        if not vulnerable_app_dir.exists():
            pytest.skip("vulnerable_app directory not found")

        unsafe_file = vulnerable_app_dir / "unsafe.py"
        if not unsafe_file.exists():
            pytest.skip("unsafe.py not found")

        reachability = ReachabilityAnalyzer(static_analyzer)
        reachability.build_graph([unsafe_file])

        vuln = VulnerabilitySignature(
            cve_id="CVE-2017-18342",
            package_name="pyyaml",
            ecosystem="pypi",
            vulnerable_version_range="<5.4",
            vulnerable_symbols=["yaml.load"]
        )

        result = reachability.analyze_vulnerability(vuln)
        assert result.is_reachable is True

    def test_vulnerable_app_safe(self, static_analyzer):
        """Test that tests/vulnerable_app/safe.py is detected as unreachable."""
        vulnerable_app_dir = Path(__file__).parent.parent / "vulnerable_app"
        if not vulnerable_app_dir.exists():
            pytest.skip("vulnerable_app directory not found")

        safe_file = vulnerable_app_dir / "safe.py"
        if not safe_file.exists():
            pytest.skip("safe.py not found")

        reachability = ReachabilityAnalyzer(static_analyzer)
        reachability.build_graph([safe_file])

        vuln = VulnerabilitySignature(
            cve_id="CVE-2017-18342",
            package_name="pyyaml",
            ecosystem="pypi",
            vulnerable_version_range="<5.4",
            vulnerable_symbols=["yaml.load"]
        )

        result = reachability.analyze_vulnerability(vuln)
        assert result.is_reachable is False

    def test_vulnerable_app_transitive(self, static_analyzer):
        """Test that transitive calls through utils are detected."""
        vulnerable_app_dir = Path(__file__).parent.parent / "vulnerable_app"
        if not vulnerable_app_dir.exists():
            pytest.skip("vulnerable_app directory not found")

        transitive_main = vulnerable_app_dir / "transitive_main.py"
        utils_file = vulnerable_app_dir / "utils.py"

        if not transitive_main.exists() or not utils_file.exists():
            pytest.skip("transitive test files not found")

        reachability = ReachabilityAnalyzer(static_analyzer)
        reachability.build_graph([transitive_main, utils_file])

        vuln = VulnerabilitySignature(
            cve_id="CVE-2017-18342",
            package_name="pyyaml",
            ecosystem="pypi",
            vulnerable_version_range="<5.4",
            vulnerable_symbols=["yaml.load"]
        )

        result = reachability.analyze_vulnerability(vuln)
        assert result.is_reachable is True


class TestJavaScriptASTWalkers:
    """Comprehensive tests for JavaScript AST walkers."""

    def test_destructured_require(self, reachability_analyzer, lodash_vulnerability):
        """Test destructured CommonJS require statements."""
        with TemporaryDirectory() as tmpdir:
            js_file = Path(tmpdir) / "destructured.js"
            js_file.write_text("""
const { template, merge } = require('lodash');

function renderTemplate(data) {
    return template('<%= name %>')(data);
}

module.exports = { renderTemplate };
""")

            reachability_analyzer.build_graph([js_file])
            result = reachability_analyzer.analyze_vulnerability(lodash_vulnerability)

            assert result.is_reachable is True
            assert result.status == "REACHABLE"

    def test_named_es6_imports(self, reachability_analyzer, lodash_vulnerability):
        """Test named ES6 imports."""
        with TemporaryDirectory() as tmpdir:
            js_file = Path(tmpdir) / "named.mjs"
            js_file.write_text("""
import { template } from 'lodash';

export function renderTemplate(data) {
    return template('<%= name %>')(data);
}
""")

            reachability_analyzer.build_graph([js_file])
            result = reachability_analyzer.analyze_vulnerability(lodash_vulnerability)

            assert result.is_reachable is True

    def test_namespace_import(self, reachability_analyzer, lodash_vulnerability):
        """Test namespace ES6 imports (import * as)."""
        with TemporaryDirectory() as tmpdir:
            js_file = Path(tmpdir) / "namespace.mjs"
            js_file.write_text("""
import * as lodash from 'lodash';

export function renderTemplate(data) {
    return lodash.template('<%= name %>')(data);
}
""")

            reachability_analyzer.build_graph([js_file])
            result = reachability_analyzer.analyze_vulnerability(lodash_vulnerability)

            assert result.is_reachable is True

    def test_arrow_function_definitions(self, reachability_analyzer):
        """Test that arrow functions are extracted as nodes."""
        with TemporaryDirectory() as tmpdir:
            js_file = Path(tmpdir) / "arrows.js"
            js_file.write_text("""
const helper = () => {
    console.log("helper");
};

const processor = (data) => {
    return data.map(x => x * 2);
};

function main() {
    helper();
    processor([1, 2, 3]);
}
""")

            reachability_analyzer.build_graph([js_file])

            # Check nodes were created for arrow functions
            node_names = [n.name for n in reachability_analyzer.call_graph.nodes.values()]
            assert "helper" in node_names
            assert "processor" in node_names
            assert "main" in node_names

    def test_class_methods_in_js(self, reachability_analyzer):
        """Test that class methods are extracted in JavaScript."""
        with TemporaryDirectory() as tmpdir:
            js_file = Path(tmpdir) / "class.js"
            js_file.write_text("""
class MyService {
    constructor() {
        this.data = [];
    }

    process(item) {
        return item.toUpperCase();
    }

    async fetchData() {
        return await fetch('/api/data');
    }
}

module.exports = MyService;
""")

            reachability_analyzer.build_graph([js_file])

            node_names = [n.name for n in reachability_analyzer.call_graph.nodes.values()]
            # Method names should be captured
            assert "process" in node_names or "MyService.process" in node_names


class TestCycleDetection:
    """Test that the analyzer handles cycles correctly."""

    def test_recursive_function(self, reachability_analyzer, yaml_vulnerability):
        """Test handling of recursive function calls."""
        with TemporaryDirectory() as tmpdir:
            file = Path(tmpdir) / "recursive.py"
            file.write_text("""
import yaml

def recursive_parser(data, depth=0):
    if depth > 10:
        return None
    result = yaml.load(data)
    return recursive_parser(result, depth + 1)
""")

            reachability_analyzer.build_graph([file])
            result = reachability_analyzer.analyze_vulnerability(yaml_vulnerability)

            # Should detect reachability despite recursion
            assert result.is_reachable is True
            assert result.status == "REACHABLE"

    def test_mutual_recursion(self, reachability_analyzer, yaml_vulnerability):
        """Test handling of mutually recursive functions."""
        with TemporaryDirectory() as tmpdir:
            file = Path(tmpdir) / "mutual.py"
            file.write_text("""
import yaml

def func_a(data):
    return func_b(data)

def func_b(data):
    if data:
        return func_a(data[1:])
    return yaml.load(data)
""")

            reachability_analyzer.build_graph([file])
            result = reachability_analyzer.analyze_vulnerability(yaml_vulnerability)

            # Should still detect reachability
            assert result.is_reachable is True

    def test_complex_call_chain(self, reachability_analyzer, yaml_vulnerability):
        """Test complex call chains don't cause infinite loops."""
        with TemporaryDirectory() as tmpdir:
            file = Path(tmpdir) / "complex.py"
            file.write_text("""
import yaml

def entry_point():
    step1()

def step1():
    step2()
    step3()

def step2():
    step3()

def step3():
    step4()

def step4():
    parser()

def parser():
    return yaml.load("{}")
""")

            reachability_analyzer.build_graph([file])
            result = reachability_analyzer.analyze_vulnerability(yaml_vulnerability)

            assert result.is_reachable is True
            # Should have a call trace
            assert len(result.call_trace) > 0


class TestImportOnlyScenarios:
    """Test scenarios where package is imported but never used."""

    def test_import_no_usage(self, reachability_analyzer, yaml_vulnerability):
        """Test package imported but never called."""
        with TemporaryDirectory() as tmpdir:
            file = Path(tmpdir) / "import_only.py"
            file.write_text("""
import yaml

# yaml is imported but never used
def process_data(data):
    return data.upper()

def main():
    print(process_data("hello"))
""")

            reachability_analyzer.build_graph([file])
            result = reachability_analyzer.analyze_vulnerability(yaml_vulnerability)

            assert result.is_reachable is False
            assert result.status == "UNREACHABLE"

    def test_from_import_no_usage(self, reachability_analyzer, yaml_vulnerability):
        """Test from-import but symbol never called."""
        with TemporaryDirectory() as tmpdir:
            file = Path(tmpdir) / "from_import_only.py"
            file.write_text("""
from yaml import load

# load is imported but never called
def process_data(data):
    return {"result": data}
""")

            reachability_analyzer.build_graph([file])
            result = reachability_analyzer.analyze_vulnerability(yaml_vulnerability)

            assert result.is_reachable is False

    def test_import_different_function(self, reachability_analyzer, yaml_vulnerability):
        """Test that using safe functions from same module doesn't trigger."""
        with TemporaryDirectory() as tmpdir:
            file = Path(tmpdir) / "safe_import.py"
            file.write_text("""
import yaml

def parse_safe(data):
    # Using safe_load instead of load
    return yaml.safe_load(data)

def dump_data(data):
    return yaml.dump(data)
""")

            reachability_analyzer.build_graph([file])
            result = reachability_analyzer.analyze_vulnerability(yaml_vulnerability)

            assert result.is_reachable is False

    def test_conditional_import(self, reachability_analyzer, yaml_vulnerability):
        """Test conditionally imported and used packages."""
        with TemporaryDirectory() as tmpdir:
            file = Path(tmpdir) / "conditional.py"
            file.write_text("""
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

def parse_config(data):
    if HAS_YAML:
        return yaml.load(data)
    return None
""")

            reachability_analyzer.build_graph([file])
            result = reachability_analyzer.analyze_vulnerability(yaml_vulnerability)

            # Should still detect as reachable since the call exists in code
            assert result.is_reachable is True


class TestMultiFileProjects:
    """Test reachability analysis across multiple files."""

    def test_deep_transitive_chain(self, reachability_analyzer, yaml_vulnerability):
        """Test reachability through multiple file hops."""
        with TemporaryDirectory() as tmpdir:
            # Create a chain: main -> service -> parser -> yaml.load
            main_file = Path(tmpdir) / "main.py"
            main_file.write_text("""
from service import process

def main():
    process("data")

if __name__ == "__main__":
    main()
""")

            service_file = Path(tmpdir) / "service.py"
            service_file.write_text("""
from parser import parse

def process(data):
    return parse(data)
""")

            parser_file = Path(tmpdir) / "parser.py"
            parser_file.write_text("""
import yaml

def parse(data):
    return yaml.load(data)
""")

            reachability_analyzer.build_graph([main_file, service_file, parser_file])
            result = reachability_analyzer.analyze_vulnerability(yaml_vulnerability)

            assert result.is_reachable is True

    def test_isolated_vulnerable_file(self, reachability_analyzer, yaml_vulnerability):
        """Test vulnerable code in file not imported by main."""
        with TemporaryDirectory() as tmpdir:
            main_file = Path(tmpdir) / "main.py"
            main_file.write_text("""
from utils import helper

def main():
    helper()
""")

            utils_file = Path(tmpdir) / "utils.py"
            utils_file.write_text("""
def helper():
    return "safe"
""")

            # This file is NOT imported by main
            vulnerable_file = Path(tmpdir) / "deprecated.py"
            vulnerable_file.write_text("""
import yaml

def old_parser(data):
    return yaml.load(data)
""")

            reachability_analyzer.build_graph([main_file, utils_file, vulnerable_file])
            result = reachability_analyzer.analyze_vulnerability(yaml_vulnerability)

            # The vulnerable function exists but is in isolated/dead code
            # It's still "reachable" in the sense that the call exists
            # But the BFS should identify it's not connected to main entry points
            assert result.is_reachable is True  # The call exists in the codebase


class TestVersionRangeChecking:
    """Tests for version range checking in vulnerability KB."""

    def test_parse_version_simple(self):
        """Test parsing simple version strings."""
        from blastauri.analysis.vulnerability_kb import parse_version

        assert parse_version("1.2.3") == (1, 2, 3)
        assert parse_version("5.4") == (5, 4)
        assert parse_version("1") == (1,)
        assert parse_version("0.0.1") == (0, 0, 1)

    def test_parse_version_with_prerelease(self):
        """Test parsing versions with pre-release suffixes."""
        from blastauri.analysis.vulnerability_kb import parse_version

        # Pre-release suffixes are stripped when they follow -/_
        # For versions like "1.0.0.dev1", the .dev1 is treated as a segment
        assert parse_version("2.0-beta9") == (2, 0)
        assert parse_version("1.0.0-alpha") == (1, 0, 0)
        assert parse_version("3.0.0-rc1") == (3, 0, 0)
        # "1.0.0.dev1" -> ".dev1" portion preserved since dot separator, extracts "1"
        assert parse_version("1.0.0.dev1") == (1, 0, 0, 1)

    def test_version_in_range_less_than(self):
        """Test < operator in version ranges."""
        from blastauri.analysis.vulnerability_kb import version_in_range

        assert version_in_range("5.3", "<5.4") is True
        assert version_in_range("5.4", "<5.4") is False
        assert version_in_range("5.5", "<5.4") is False
        assert version_in_range("1.0.0", "<2.0") is True

    def test_version_in_range_less_than_equal(self):
        """Test <= operator in version ranges."""
        from blastauri.analysis.vulnerability_kb import version_in_range

        assert version_in_range("5.3", "<=5.4") is True
        assert version_in_range("5.4", "<=5.4") is True
        assert version_in_range("5.5", "<=5.4") is False

    def test_version_in_range_greater_than(self):
        """Test > operator in version ranges."""
        from blastauri.analysis.vulnerability_kb import version_in_range

        assert version_in_range("2.0", ">1.0") is True
        assert version_in_range("1.0", ">1.0") is False
        assert version_in_range("0.9", ">1.0") is False

    def test_version_in_range_greater_than_equal(self):
        """Test >= operator in version ranges."""
        from blastauri.analysis.vulnerability_kb import version_in_range

        assert version_in_range("2.0", ">=1.0") is True
        assert version_in_range("1.0", ">=1.0") is True
        assert version_in_range("0.9", ">=1.0") is False

    def test_version_in_range_compound(self):
        """Test compound version ranges (>=X,<Y)."""
        from blastauri.analysis.vulnerability_kb import version_in_range

        # Log4j CVE range: >=2.0-beta9,<2.17.0
        assert version_in_range("2.0", ">=2.0,<2.17.0") is True
        assert version_in_range("2.14.1", ">=2.0,<2.17.0") is True
        assert version_in_range("2.17.0", ">=2.0,<2.17.0") is False
        assert version_in_range("1.9", ">=2.0,<2.17.0") is False
        assert version_in_range("2.17.1", ">=2.0,<2.17.0") is False

    def test_version_in_range_not_equal(self):
        """Test != operator in version ranges."""
        from blastauri.analysis.vulnerability_kb import version_in_range

        assert version_in_range("1.0", "!=1.0") is False
        assert version_in_range("1.1", "!=1.0") is True
        assert version_in_range("0.9", "!=1.0") is True

    def test_version_in_range_exact_match(self):
        """Test exact version match."""
        from blastauri.analysis.vulnerability_kb import version_in_range

        assert version_in_range("1.0.0", "1.0.0") is True
        assert version_in_range("1.0.0", "=1.0.0") is True
        assert version_in_range("1.0.0", "==1.0.0") is True
        assert version_in_range("1.0.1", "1.0.0") is False

    def test_version_in_range_empty_inputs(self):
        """Test edge cases with empty inputs."""
        from blastauri.analysis.vulnerability_kb import version_in_range

        assert version_in_range("", "<1.0") is False
        assert version_in_range("1.0", "") is False
        assert version_in_range("", "") is False

    def test_kb_filters_by_version(self):
        """Test that KB filters signatures by version."""
        kb = VulnerabilityKB()

        # PyYAML vulnerable < 5.4
        # Version 5.3 should be vulnerable
        sigs_vulnerable = kb.get_signatures_for_package("pyyaml", Ecosystem.PYPI, "5.3")
        assert len(sigs_vulnerable) > 0

        # Version 5.4 should NOT be vulnerable
        sigs_safe = kb.get_signatures_for_package("pyyaml", Ecosystem.PYPI, "5.4")
        pyyaml_sigs = [s for s in sigs_safe if s.cve_id == "CVE-2017-18342"]
        assert len(pyyaml_sigs) == 0

        # Version 6.0 should NOT be vulnerable
        sigs_newer = kb.get_signatures_for_package("pyyaml", Ecosystem.PYPI, "6.0")
        pyyaml_sigs_newer = [s for s in sigs_newer if s.cve_id == "CVE-2017-18342"]
        assert len(pyyaml_sigs_newer) == 0

    def test_kb_without_version_returns_all(self):
        """Test that KB returns all signatures when version not provided."""
        kb = VulnerabilityKB()

        # Without version, should return all matching signatures
        sigs_all = kb.get_signatures_for_package("pyyaml", Ecosystem.PYPI)
        sigs_with_version = kb.get_signatures_for_package("pyyaml", Ecosystem.PYPI, "5.3")

        # Should return more or equal without version filter
        assert len(sigs_all) >= len(sigs_with_version)

    def test_is_version_vulnerable(self):
        """Test the is_version_vulnerable helper method."""
        kb = VulnerabilityKB()

        # Lodash < 4.17.19 is vulnerable to CVE-2020-8203
        vulnerable = kb.is_version_vulnerable("lodash", Ecosystem.NPM, "4.17.15")
        assert any(s.cve_id == "CVE-2020-8203" for s in vulnerable)

        # Lodash 4.17.21 should NOT have that CVE
        safe = kb.is_version_vulnerable("lodash", Ecosystem.NPM, "4.17.21")
        assert not any(s.cve_id == "CVE-2020-8203" for s in safe)