import os
import ast
from scanner.core import Plugin, Finding
from scanner.dataflow.callgraph import CallGraph, FunctionRef

def is_exception_raising_validator(callee_body) -> bool:
    callee_params = {arg.arg for arg in callee_body.args.args}
    for node in ast.walk(callee_body):
        if isinstance(node, ast.If):
            test_names = {n.id for n in ast.walk(node.test) if isinstance(n, ast.Name)}
            if test_names.intersection(callee_params):
                for child in ast.walk(node):
                    if isinstance(child, ast.Raise):
                        return True
    return False

def returns_boolean(callee_body) -> bool:
    for node in ast.walk(callee_body):
        if isinstance(node, ast.Return):
            val = node.value
            if isinstance(val, ast.Constant) and isinstance(val.value, bool):
                return True
            if isinstance(val, ast.Compare):
                return True
    return False

def is_call_used_in_conditional(caller_def, call_node) -> bool:
    for node in ast.walk(caller_def):
        if isinstance(node, ast.If):
            if any(child is call_node for child in ast.walk(node.test)):
                return True
                
    assigned_vars = set()
    for node in ast.walk(caller_def):
        if isinstance(node, ast.Assign):
            if node.value is call_node:
                for tgt in node.targets:
                    if isinstance(tgt, ast.Name):
                        assigned_vars.add(tgt.id)
    
    if assigned_vars:
        for node in ast.walk(caller_def):
            if isinstance(node, ast.If):
                test_vars = {n.id for n in ast.walk(node.test) if isinstance(n, ast.Name)}
                if test_vars.intersection(assigned_vars):
                    return True
    return False

def is_validation_library_call(call_node, filepath, cg) -> bool:
    func = call_node.func
    if isinstance(func, ast.Attribute):
        if func.attr in ("model_validate", "validate", "load"):
            return True
            
    if isinstance(func, ast.Name):
        name = func.id
        if name in ("Validator", "Schema") or name.endswith("Model") or name.endswith("Validator") or name.endswith("Schema"):
            return True
        resolved = cg._resolve_name_source(name, filepath)
        if resolved:
            src_file, src_name = resolved
            if src_name in ("Validator", "Schema") or src_name.endswith("Model") or src_name.endswith("Validator") or src_name.endswith("Schema"):
                return True
                
    return False

class ExcessiveAgency(Plugin):

    name = "excessive_agency"
    severity = "high"
    owasp_ref = "LLM08"

    def run(self, target: str) -> list[Finding]:
        findings = []
        if not os.path.exists(target):
            return findings

        cg = CallGraph()
        cg.build(target)

        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in ('.git', 'node_modules', 'venv', '__pycache__')]
            for file in files:
                if not file.endswith(".py"):
                    continue
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    tree = ast.parse(content, filename=filepath)
                except Exception:
                    continue

                rel_filepath = os.path.relpath(filepath, target).replace("\\", "/")
                tool_functions = set()

                for sub in ast.walk(tree):
                    if isinstance(sub, ast.Assign):
                        for target_node in sub.targets:
                            if isinstance(target_node, ast.Name) and target_node.id in ("tools", "functions"):
                                if isinstance(sub.value, ast.List):
                                    for elt in sub.value.elts:
                                        if isinstance(elt, ast.Name):
                                            tool_functions.add(elt.id)
                                        elif isinstance(elt, ast.Dict):
                                            for k, v in zip(elt.keys, elt.values):
                                                if isinstance(k, ast.Constant) and k.value == "function" and isinstance(v, ast.Name):
                                                    tool_functions.add(v.id)
                    elif isinstance(sub, ast.Call):
                        for kw in sub.keywords:
                            if kw.arg in ("tools", "functions"):
                                if isinstance(kw.value, ast.List):
                                    for elt in kw.value.elts:
                                        if isinstance(elt, ast.Name):
                                            tool_functions.add(elt.id)

                for sub in ast.walk(tree):
                    if isinstance(sub, ast.FunctionDef):
                        is_tool = False
                        for dec in sub.decorator_list:
                            dec_name = ""
                            if isinstance(dec, ast.Name):
                                dec_name = dec.id
                            elif isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name):
                                dec_name = dec.func.id
                            if dec_name in ("tool", "function_tool"):
                                is_tool = True
                                break
                        if sub.name in tool_functions:
                            is_tool = True

                        if not is_tool:
                            continue

                        has_validation = False
                        for body_node in ast.walk(sub):
                            if isinstance(body_node, ast.Call):
                                if is_validation_library_call(body_node, filepath, cg):
                                    has_validation = True
                                    break
                                
                                callee_ref = cg.resolve_call(body_node, filepath, FunctionRef(file_path=rel_filepath, name=sub.name))
                                if callee_ref:
                                    callee_body = cg.get_function_body(callee_ref)
                                    if callee_body:
                                        if is_exception_raising_validator(callee_body):
                                            has_validation = True
                                            break
                                        if returns_boolean(callee_body) and is_call_used_in_conditional(sub, body_node):
                                            has_validation = True
                                            break

                        if has_validation:
                            continue

                        params = {arg.arg for arg in sub.args.args}
                        has_danger = False
                        for body_node in ast.walk(sub):
                            if isinstance(body_node, ast.Call):
                                if isinstance(body_node.func, ast.Name) and body_node.func.id == "open":
                                    if body_node.args:
                                        arg0 = body_node.args[0]
                                        if not isinstance(arg0, ast.Constant):
                                            for name_node in ast.walk(arg0):
                                                if isinstance(name_node, ast.Name) and name_node.id in params:
                                                    has_danger = True
                                                    break
                                call_name = ""
                                if isinstance(body_node.func, ast.Name):
                                    call_name = body_node.func.id
                                elif isinstance(body_node.func, ast.Attribute):
                                    call_name = body_node.func.attr
                                if call_name in ("system", "run", "Popen", "call", "check_output", "subprocess"):
                                    for arg in body_node.args:
                                        if not isinstance(arg, ast.Constant):
                                            for name_node in ast.walk(arg):
                                                if isinstance(name_node, ast.Name) and name_node.id in params:
                                                    has_danger = True
                                                    break
                                    for kw in body_node.keywords:
                                        if not isinstance(kw.value, ast.Constant):
                                            for name_node in ast.walk(kw.value):
                                                if isinstance(name_node, ast.Name) and name_node.id in params:
                                                    has_danger = True
                                                    break

                        if has_danger:
                            findings.append(Finding(
                                rule="excessive_agency",
                                severity=self.severity,
                                message="Tool performing broad operation (open/subprocess) with param-derived inputs without validation",
                                location=f"{os.path.relpath(filepath, target)}:{sub.lineno}"
                            ))
        return findings
