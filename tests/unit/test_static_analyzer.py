import pytest
from pathlib import Path
from blastauri.analysis.static_analyzer import PythonAnalyzer, ImportInfo, CallGraphNode, CallGraphEdge, UsageType

@pytest.fixture
def python_analyzer():
    return PythonAnalyzer()

def test_find_imports_ast(python_analyzer):
    content = """
import os
import sys as s
from json import load, dump
from . import utils
    """
    imports = python_analyzer.find_imports(Path("test.py"), content)
    
    assert len(imports) == 5
    # import os
    assert imports[0].module == "os"
    
    # import sys as s
    assert imports[1].module == "sys"
    assert imports[1].alias == "s"
    
    # from json import load
    assert imports[2].module == "json"
    assert imports[2].names == ["load"]
    
    # from json import dump
    assert imports[3].module == "json"
    assert imports[3].names == ["dump"]

def test_extract_call_graph_nodes(python_analyzer):
    content = """
def foo():
    pass

class Bar:
    def method(self):
        pass
    """
    nodes = python_analyzer.extract_call_graph_nodes(Path("test.py"), content)
    
    assert len(nodes) == 2
    assert nodes[0].name == "foo"
    assert nodes[0].id == "test.py:foo"
    
    assert nodes[1].name == "Bar.method"
    assert nodes[1].id == "test.py:Bar.method"

def test_extract_call_graph_edges(python_analyzer):
    content = """
def main():
    foo()
    Bar.method()
    """
    nodes = [
        CallGraphNode(name="main", file_path="test.py", start_line=2, end_line=4),
        CallGraphNode(name="foo", file_path="test.py", start_line=10, end_line=11)
    ]
    edges = python_analyzer.extract_call_graph_edges(Path("test.py"), content, nodes)
    
    assert len(edges) == 2
    
    # main calls foo
    assert edges[0].source == "test.py:main"
    assert edges[0].target == "foo"
    
    # main calls Bar.method - captures full attribute expression
    assert edges[1].source == "test.py:main"
    assert edges[1].target == "Bar.method"

def test_find_usages_regex_baseline(python_analyzer):
    content = """
import json
json.load(f)
@json.decorator
def foo(x: json.Type):
    pass
    """
    import_info = ImportInfo(module="json", names=[], alias=None, line_number=2, file_path="test.py", is_from_import=False)
    
    usages = python_analyzer.find_usages(Path("test.py"), content, "json", import_info)
    
    assert len(usages) >= 1
    types = [u.usage_type for u in usages]
    # Expecting calls or attributes
    # Note: Regex might be fuzzy on specific types, but should find something.
    assert UsageType.CALL.value in types or UsageType.ATTRIBUTE.value in types
