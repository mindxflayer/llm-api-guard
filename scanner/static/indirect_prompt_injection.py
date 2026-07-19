import os
import ast
from scanner.core import Plugin, Finding
from scanner.dataflow.callgraph import CallGraph, FunctionRef
from scanner.dataflow.taint import TaintTracker

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

def is_web_fetch(node) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            if isinstance(sub.func, ast.Attribute):
                val = sub.func.value
                attr = sub.func.attr
                if isinstance(val, ast.Name) and val.id == "requests" and attr in ("get", "post", "put", "delete", "patch", "request"):
                    return True
                if isinstance(val, ast.Attribute) and isinstance(val.value, ast.Name) and val.value.id == "urllib" and val.attr == "request" and attr == "urlopen":
                    return True
            elif isinstance(sub.func, ast.Name):
                if sub.func.id in ("urlopen",):
                    return True
    return False

def is_file_read(node, opened_vars) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
            if sub.func.attr in ("read", "readline", "readlines", "read_text"):
                if isinstance(sub.func.value, ast.Name) and sub.func.value.id in opened_vars:
                    return True
                if isinstance(sub.func.value, ast.Call) and isinstance(sub.func.value.func, ast.Name) and sub.func.value.func.id == "open":
                    return True
                if isinstance(sub.func.value, ast.Call) and isinstance(sub.func.value.func, ast.Attribute) and sub.func.value.func.attr == "open":
                    return True
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) and sub.func.attr == "read_text":
            return True
    return False

def is_rag_search(node) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            func = sub.func
            fn_name = ""
            if isinstance(func, ast.Name):
                fn_name = func.id
            elif isinstance(func, ast.Attribute):
                fn_name = func.attr
            if any(x in fn_name.lower() for x in ("retrieve", "search", "query", "similarity_search")):
                return True
    return False

class IndirectPromptInjection(Plugin):
    name = "indirect_prompt_injection"
    severity = "high"
    owasp_ref = "LLM01"

    def run(self, target: str) -> list[Finding]:
        findings = []
        if not os.path.exists(target):
            return findings
        cg = CallGraph()
        cg.build(target)
        tracker = TaintTracker()
        tool_functions = set()
        for ref, node in cg.definitions.items():
            if isinstance(node, ast.FunctionDef):
                for dec in node.decorator_list:
                    dec_name = ""
                    if isinstance(dec, ast.Name):
                        dec_name = dec.id
                    elif isinstance(dec, ast.Attribute):
                        dec_name = dec.attr
                    elif isinstance(dec, ast.Call):
                        if isinstance(dec.func, ast.Name):
                            dec_name = dec.func.id
                        elif isinstance(dec.func, ast.Attribute):
                            dec_name = dec.func.attr
                    if dec_name == "tool":
                        tool_functions.add(ref)
                        break
        for ref, node in cg.definitions.items():
            if not isinstance(node, ast.FunctionDef):
                continue
            opened_vars = set()
            for child in ast.walk(node):
                if isinstance(child, ast.Assign) and isinstance(child.value, ast.Call):
                    if isinstance(child.value.func, ast.Name) and child.value.func.id == "open":
                        for tgt in child.targets:
                            if isinstance(tgt, ast.Name):
                                opened_vars.add(tgt.id)
                elif isinstance(child, ast.With):
                    for item in child.items:
                        if isinstance(item.context_expr, ast.Call):
                            if isinstance(item.context_expr.func, ast.Name) and item.context_expr.func.id == "open":
                                if item.optional_vars and isinstance(item.optional_vars, ast.Name):
                                    opened_vars.add(item.optional_vars.id)
            indirect_sources = set()
            for stmt in ast.walk(node):
                if isinstance(stmt, ast.Assign):
                    val = stmt.value
                    is_src = False
                    if is_web_fetch(val) or is_file_read(val, opened_vars) or is_rag_search(val):
                        is_src = True
                    if not is_src and isinstance(val, ast.Call):
                        callee_ref = cg.resolve_call(val, ref.file_path, FunctionRef(ref.file_path, ref.name))
                        if callee_ref:
                            if callee_ref in tool_functions:
                                is_src = True
                            else:
                                if any(x in callee_ref.name.lower() for x in ("retrieve", "search", "query", "similarity_search")):
                                    is_src = True
                    if is_src:
                        for tgt in stmt.targets:
                            if isinstance(tgt, ast.Name):
                                indirect_sources.add(tgt.id)
            for src_var in indirect_sources:
                paths = tracker.propagate(src_var, node, cg)
                found_sink = False
                for path in paths:
                    for path_node in path.nodes:
                        if path_node.kind == "variable":
                            if check_sink_in_func(path_node.file_path, path_node.scope_name, path_node.name, cg):
                                findings.append(Finding(
                                    rule="indirect_prompt_injection",
                                    severity=self.severity,
                                    message="Potential indirect prompt injection: Untrusted input from tool/fetch/RAG/file reaches LLM execution",
                                    location=f"{ref.file_path}:{node.lineno}"
                                ))
                                found_sink = True
                                break
                    if found_sink:
                        break
                if found_sink:
                    break
        return findings
