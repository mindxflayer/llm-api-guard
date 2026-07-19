import os
import ast
import tempfile
import shutil
import pytest
from scanner.dataflow.callgraph import CallGraph, FunctionRef
from scanner.dataflow.taint import TaintTracker

def test_taint_tracker():
    temp_dir = tempfile.mkdtemp()
    try:
        os.makedirs(os.path.join(temp_dir, "pkg"), exist_ok=True)
        
        b_code = """
def concat_val(target):
    return "concated:" + target
"""
        a_code = """
from .module_b import concat_val
def run_flow(user_input):
    x = user_input
    res = concat_val(x)
    return res
"""
        with open(os.path.join(temp_dir, "pkg", "module_b.py"), "w", encoding="utf-8") as f:
            f.write(b_code)
        with open(os.path.join(temp_dir, "pkg", "module_a.py"), "w", encoding="utf-8") as f:
            f.write(a_code)

        f3_code = """
def final_sink(val):
    return val + "!!!"
"""
        f2_code = """
from .file_3 import final_sink
def middle_helper(data):
    return final_sink(data)
"""
        f1_code = """
from .file_2 import middle_helper
def entrypoint(user_input):
    data = user_input
    return middle_helper(data)
"""
        with open(os.path.join(temp_dir, "pkg", "file_3.py"), "w", encoding="utf-8") as f:
            f.write(f3_code)
        with open(os.path.join(temp_dir, "pkg", "file_2.py"), "w", encoding="utf-8") as f:
            f.write(f2_code)
        with open(os.path.join(temp_dir, "pkg", "file_1.py"), "w", encoding="utf-8") as f:
            f.write(f1_code)

        class_code = """
class DataHolder:
    def __init__(self):
        self.payload = None

    def store(self, value):
        self.payload = value

    def load(self):
        x = self.payload
        return x
"""
        with open(os.path.join(temp_dir, "pkg", "class_model.py"), "w", encoding="utf-8") as f:
            f.write(class_code)

        dict_code = """
def dict_flow(user_input):
    d = {}
    d["payload"] = user_input
    x = d["payload"]
    return x
"""
        with open(os.path.join(temp_dir, "pkg", "dict_flow.py"), "w", encoding="utf-8") as f:
            f.write(dict_code)

        deep_code = """
def h1(x): return h2(x)
def h2(x): return h3(x)
def h3(x): return h4(x)
def h4(x): return h5(x)
def h5(x): return h6(x)
def h6(x): return h7(x)
def h7(x): return h8(x)
def h8(x): return h9(x)
def h9(x): return x
"""
        with open(os.path.join(temp_dir, "pkg", "deep_flow.py"), "w", encoding="utf-8") as f:
            f.write(deep_code)

        cg = CallGraph()
        cg.build(temp_dir)
        tracker = TaintTracker()

        ref_run_flow = FunctionRef("pkg/module_a.py", "run_flow")
        ast_run_flow = cg.get_function_body(ref_run_flow)
        paths = tracker.propagate("user_input", ast_run_flow, cg)
        assert any(
            any(n.scope_name == "concat_val" and n.name == "target" for n in path.nodes)
            for path in paths
        )

        ref_entry = FunctionRef("pkg/file_1.py", "entrypoint")
        ast_entry = cg.get_function_body(ref_entry)
        paths_3 = tracker.propagate("user_input", ast_entry, cg)
        assert any(
            any(n.scope_name == "final_sink" and n.name == "val" for n in path.nodes)
            for path in paths_3
        )

        ref_store = FunctionRef("pkg/class_model.py", "DataHolder.store")
        ast_store = cg.get_function_body(ref_store)
        paths_class = tracker.propagate("value", ast_store, cg)
        assert any(
            any(n.scope_name == "DataHolder.load" and n.name == "x" for n in path.nodes)
            for path in paths_class
        )

        ref_dict = FunctionRef("pkg/dict_flow.py", "dict_flow")
        ast_dict = cg.get_function_body(ref_dict)
        paths_dict = tracker.propagate("user_input", ast_dict, cg)
        assert any(
            any(n.name == "x" for n in path.nodes)
            for path in paths_dict
        )

        ref_h1 = FunctionRef("pkg/deep_flow.py", "h1")
        ast_h1 = cg.get_function_body(ref_h1)
        import sys
        from io import StringIO
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        
        try:
            tracker.propagate("x", ast_h1, cg, max_hops=4)
            captured = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout

        assert "taint tracking hop limit (4) reached from x" in captured

    finally:
        shutil.rmtree(temp_dir)
