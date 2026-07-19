import os
import ast
import logging
from scanner.core import Plugin, Finding
from scanner.dataflow.callgraph import CallGraph, FunctionRef
from scanner.dataflow.taint import TaintTracker

def is_request_access(val_node) -> bool:
    if isinstance(val_node, ast.Attribute):
        if isinstance(val_node.value, ast.Name) and val_node.value.id == "request":
            return True
    elif isinstance(val_node, ast.Subscript):
        if isinstance(val_node.value, ast.Attribute) and isinstance(val_node.value.value, ast.Name) and val_node.value.value.id == "request":
            return True
        if isinstance(val_node.value, ast.Name) and val_node.value.id == "request":
            return True
    elif isinstance(val_node, ast.Call):
        if isinstance(val_node.func, ast.Attribute):
            if isinstance(val_node.func.value, ast.Attribute) and isinstance(val_node.func.value.value, ast.Name) and val_node.func.value.value.id == "request":
                return True
            if isinstance(val_node.func.value, ast.Name) and val_node.func.value.id == "request":
                return True
    return False

def contains_request_param(val_node, request_vars=None) -> bool:
    for sub in ast.walk(val_node):
        if is_request_access(sub):
            return True
        if request_vars and isinstance(sub, ast.Name) and sub.id in request_vars:
            return True
    return False

def is_concatenation_or_fstring(expr) -> bool:
    if isinstance(expr, ast.JoinedStr):
        return True
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        return True
    return False

def references_tainted(expr, target_name) -> bool:
    return any(isinstance(n, ast.Name) and n.id == target_name for n in ast.walk(expr))

def check_sink_in_func(file_path, func_name, tainted_name, cg) -> bool:
    func_ref = FunctionRef(file_path, func_name)
    body = cg.get_function_body(func_ref)
    if not body:
        return False

    for stmt in ast.walk(body):
        if isinstance(stmt, ast.Assign):
            if is_concatenation_or_fstring(stmt.value) and references_tainted(stmt.value, tainted_name):
                for target_node in stmt.targets:
                    target_names = []
                    if isinstance(target_node, ast.Name):
                        target_names.append(target_node.id)
                    elif isinstance(target_node, ast.Subscript) and isinstance(target_node.value, ast.Name):
                        target_names.append(target_node.value.id)
                        if isinstance(target_node.slice, ast.Constant):
                            target_names.append(str(target_node.slice.value))
                    if any(any(x in name.lower() for x in ("prompt", "messages", "completion", "chat")) for name in target_names):
                        return True

        if isinstance(stmt, ast.Call):
            call_name = ""
            if isinstance(stmt.func, ast.Name):
                call_name = stmt.func.id
            elif isinstance(stmt.func, ast.Attribute):
                call_name = stmt.func.attr
            if any(x in call_name.lower() for x in ("prompt", "messages", "completion", "chat", "predict", "generate", "llm")):
                for arg in stmt.args:
                    if is_concatenation_or_fstring(arg) and references_tainted(arg, tainted_name):
                        return True
                for kw in stmt.keywords:
                    if is_concatenation_or_fstring(kw.value) and references_tainted(kw.value, tainted_name):
                        return True
    return False

def resolve_decorator_is_handler(dec, filepath, cg, target_dir) -> bool:
    func = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        obj_name = func.value.id
        resolved = cg._resolve_name_source(obj_name, filepath)
        if resolved:
            src_file, src_name = resolved
            full_src_path = os.path.join(target_dir, src_file)
            if os.path.exists(full_src_path):
                try:
                    with open(full_src_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    src_tree = ast.parse(content)
                except Exception:
                    return False
                for stmt in src_tree.body:
                    if isinstance(stmt, ast.Assign):
                        for tgt in stmt.targets:
                            if isinstance(tgt, ast.Name) and tgt.id == src_name:
                                val = stmt.value
                                if isinstance(val, ast.Call):
                                    call_name = ""
                                    if isinstance(val.func, ast.Name):
                                        call_name = val.func.id
                                    elif isinstance(val.func, ast.Attribute):
                                        call_name = val.func.attr
                                    if call_name in ("Flask", "FastAPI", "APIRouter", "Django"):
                                        return True
                src_imports = cg.imports.get(src_file, {})
                if src_name in src_imports:
                    imp_info = src_imports[src_name]
                    if imp_info[0] == "from_module":
                        module_name = imp_info[1]
                        if any(f in module_name.lower() for f in ("flask", "fastapi", "django")):
                            return True
    return False

class PromptInjectionFlow(Plugin):

    name = "prompt_injection_flow"
    severity = "high"
    owasp_ref = "LLM01"

    def run(self, target: str) -> list[Finding]:
        findings = []
        if not os.path.exists(target):
            return findings

        cg = CallGraph()
        cg.build(target)
        tracker = TaintTracker()

        for ref, node in cg.definitions.items():
            if not isinstance(node, ast.FunctionDef):
                continue

            filepath = os.path.join(target, ref.file_path)
            is_handler = False
            if any(arg.arg == "request" for arg in node.args.args):
                is_handler = True

            for dec in node.decorator_list:
                if resolve_decorator_is_handler(dec, ref.file_path, cg, target):
                    is_handler = True
                    break
                
                dec_name = ""
                if isinstance(dec, ast.Attribute):
                    dec_name = dec.attr
                elif isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                    dec_name = dec.func.attr
                elif isinstance(dec, ast.Name):
                    dec_name = dec.id
                elif isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name):
                    dec_name = dec.func.id

                if dec_name in ("route", "post", "get", "put", "delete", "patch"):
                    print(f"handler detection fell back to name-matching for {node.name} — could not resolve decorator import")
                    logging.warning(f"handler detection fell back to name-matching for {node.name} — could not resolve decorator import")
                    is_handler = True
                    break

            if not is_handler:
                continue

            request_vars = set()
            for arg in node.args.args:
                if arg.arg != "self":
                    request_vars.add(arg.arg)

            for stmt in node.body:
                if isinstance(stmt, ast.Assign):
                    for target_node in stmt.targets:
                        if isinstance(target_node, ast.Name):
                            if contains_request_param(stmt.value, request_vars):
                                request_vars.add(target_node.id)

            for src_var in request_vars:
                paths = tracker.propagate(src_var, node, cg)
                found_sink = False
                for path in paths:
                    for path_node in path.nodes:
                        if path_node.kind == "variable":
                            if check_sink_in_func(path_node.file_path, path_node.scope_name, path_node.name, cg):
                                findings.append(Finding(
                                    rule="prompt_injection_flow",
                                    severity=self.severity,
                                    message="Potential prompt injection flow: Request parameter concatenated into LLM call argument",
                                    location=f"{ref.file_path}:{node.lineno}"
                                ))
                                found_sink = True
                                break
                    if found_sink:
                        break
                if found_sink:
                    break

        return findings
