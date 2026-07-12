import os
import ast
from scanner.core import Plugin, Finding

class PromptInjectionFlow(Plugin):

    name = "prompt_injection_flow"
    severity = "high"
    owasp_ref = "LLM01"

    def run(self, target: str) -> list[Finding]:
        findings = []
        if not os.path.exists(target):
            return findings

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

                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        is_handler = False
                        if any(arg.arg == "request" for arg in node.args.args):
                            is_handler = True
                        for dec in node.decorator_list:
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
                                is_handler = True
                                break
                        if not is_handler:
                            continue

                        request_vars = set()

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

                        def contains_request_param(val_node) -> bool:
                            for sub in ast.walk(val_node):
                                if is_request_access(sub):
                                    return True
                                if isinstance(sub, ast.Name) and sub.id in request_vars:
                                    return True
                            return False

                        for stmt in node.body:
                            if isinstance(stmt, ast.Assign):
                                for target_node in stmt.targets:
                                    if isinstance(target_node, ast.Name):
                                        if contains_request_param(stmt.value):
                                            request_vars.add(target_node.id)

                            def is_concatenation_or_fstring(expr) -> bool:
                                if isinstance(expr, ast.JoinedStr):
                                    return True
                                if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
                                    return True
                                return False

                            if isinstance(stmt, ast.Assign):
                                has_concatenation = is_concatenation_or_fstring(stmt.value) and contains_request_param(stmt.value)
                                if has_concatenation:
                                    for target_node in stmt.targets:
                                        target_names = []
                                        if isinstance(target_node, ast.Name):
                                            target_names.append(target_node.id)
                                        elif isinstance(target_node, ast.Subscript) and isinstance(target_node.value, ast.Name):
                                            target_names.append(target_node.value.id)
                                            if isinstance(target_node.slice, ast.Constant):
                                                target_names.append(str(target_node.slice.value))
                                        if any(any(x in name.lower() for x in ("prompt", "messages", "completion", "chat")) for name in target_names):
                                            findings.append(Finding(
                                                rule="prompt_injection_flow",
                                                severity=self.severity,
                                                message="Potential prompt injection flow from request parameter into prompt string construction",
                                                location=f"{os.path.relpath(filepath, target)}:{stmt.lineno}"
                                            ))
                                            break

                            for sub in ast.walk(stmt):
                                if isinstance(sub, ast.Call):
                                    call_name = ""
                                    if isinstance(sub.func, ast.Name):
                                        call_name = sub.func.id
                                    elif isinstance(sub.func, ast.Attribute):
                                        call_name = sub.func.attr
                                    if any(x in call_name.lower() for x in ("prompt", "messages", "completion", "chat", "predict", "generate", "llm")):
                                        for arg in sub.args:
                                            if is_concatenation_or_fstring(arg) and contains_request_param(arg):
                                                findings.append(Finding(
                                                    rule="prompt_injection_flow",
                                                    severity=self.severity,
                                                    message="Potential prompt injection flow: Request parameter concatenated into LLM call argument",
                                                    location=f"{os.path.relpath(filepath, target)}:{sub.lineno}"
                                                ))
                                                break
                                        for kw in sub.keywords:
                                            if is_concatenation_or_fstring(kw.value) and contains_request_param(kw.value):
                                                findings.append(Finding(
                                                    rule="prompt_injection_flow",
                                                    severity=self.severity,
                                                    message="Potential prompt injection flow: Request parameter concatenated into LLM call keyword argument",
                                                    location=f"{os.path.relpath(filepath, target)}:{sub.lineno}"
                                                ))
                                                break
        return findings
