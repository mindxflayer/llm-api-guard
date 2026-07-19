import os
import ast
import tempfile
import shutil
import pytest
from scanner.dataflow.callgraph import CallGraph, FunctionRef

def test_call_graph_resolution():
    temp_dir = tempfile.mkdtemp()
    try:
        module_b_content = """
def verify_ok(x):
    return x + 1

class Validator:
    def __init__(self, val):
        self.val = val

    def validate(self, data):
        return data == self.val
"""
        module_a_content = """
from .module_b import verify_ok, Validator

def main_flow(payload):
    result = verify_ok(payload)
    val_obj = Validator(10)
    validation = val_obj.validate(result)
    return validation

def same_file_helper(y):
    return y * 2

def run_helper():
    ans = same_file_helper(5)
    unresolvable_var.method()
    unknown_function()
    return ans
"""
        os.makedirs(os.path.join(temp_dir, "app"), exist_ok=True)
        
        with open(os.path.join(temp_dir, "app", "module_b.py"), "w", encoding="utf-8") as f:
            f.write(module_b_content)
        
        with open(os.path.join(temp_dir, "app", "module_a.py"), "w", encoding="utf-8") as f:
            f.write(module_a_content)

        cg = CallGraph()
        cg.build(temp_dir)

        ref_verify_ok = FunctionRef(file_path="app/module_b.py", name="verify_ok")
        ref_validator_init = FunctionRef(file_path="app/module_b.py", name="Validator.__init__")
        ref_validator_validate = FunctionRef(file_path="app/module_b.py", name="Validator.validate")
        
        ref_main_flow = FunctionRef(file_path="app/module_a.py", name="main_flow")
        ref_same_file_helper = FunctionRef(file_path="app/module_a.py", name="same_file_helper")
        ref_run_helper = FunctionRef(file_path="app/module_a.py", name="run_helper")

        assert ref_verify_ok in cg.definitions
        assert ref_validator_init in cg.definitions
        assert ref_validator_validate in cg.definitions
        assert ref_main_flow in cg.definitions
        assert ref_same_file_helper in cg.definitions
        assert ref_run_helper in cg.definitions

        body_node = cg.get_function_body(ref_verify_ok)
        assert isinstance(body_node, (ast.FunctionDef, ast.AsyncFunctionDef))
        assert body_node.name == "verify_ok"

        calls_in_main_flow = cg.calls.get(ref_main_flow, [])
        
        verify_call = next((c for c in calls_in_main_flow if isinstance(c.node.func, ast.Name) and c.node.func.id == "verify_ok"), None)
        assert verify_call is not None
        assert verify_call.callee == ref_verify_ok

        validator_call = next((c for c in calls_in_main_flow if isinstance(c.node.func, ast.Name) and c.node.func.id == "Validator"), None)
        assert validator_call is not None
        assert validator_call.callee == ref_validator_init

        validate_call = next((c for c in calls_in_main_flow if isinstance(c.node.func, ast.Attribute) and c.node.func.attr == "validate"), None)
        assert validate_call is not None
        assert validate_call.callee is None

        calls_in_run_helper = cg.calls.get(ref_run_helper, [])
        
        same_file_call = next((c for c in calls_in_run_helper if isinstance(c.node.func, ast.Name) and c.node.func.id == "same_file_helper"), None)
        assert same_file_call is not None
        assert same_file_call.callee == ref_same_file_helper

        unresolvable_call = next((c for c in calls_in_run_helper if isinstance(c.node.func, ast.Attribute) and c.node.func.attr == "method"), None)
        assert unresolvable_call is not None
        assert unresolvable_call.callee is None

        unknown_call = next((c for c in calls_in_run_helper if isinstance(c.node.func, ast.Name) and c.node.func.id == "unknown_function"), None)
        assert unknown_call is not None
        assert unknown_call.callee is None

    finally:
        shutil.rmtree(temp_dir)
