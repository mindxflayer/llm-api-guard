import os
import ast
from scanner.core import Plugin, Finding

class SystemPromptLeak(Plugin):

    name = "system_prompt_leak"
    severity = "high"
    owasp_ref = "LLM06"

    def run(self, target: str) -> list[Finding]:
        findings = []
        if not os.path.exists(target):
            return findings

        flagged_names = ("system_prompt", "system_message", "internal_reasoning", "chain_of_thought")

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

                        flagged_vars = set()

                        for stmt in node.body:
                            if isinstance(stmt, ast.Assign):
                                is_flagged_assignment = False
                                for target_node in stmt.targets:
                                    if isinstance(target_node, ast.Name) and any(x in target_node.id.lower() for x in flagged_names):
                                        is_flagged_assignment = True
                                        flagged_vars.add(target_node.id)

                                if not is_flagged_assignment:
                                    def has_sys_role(val_node) -> bool:
                                        if isinstance(val_node, ast.Dict):
                                            role_idx = -1
                                            for i, k in enumerate(val_node.keys):
                                                if isinstance(k, ast.Constant) and k.value == "role":
                                                    role_idx = i
                                                    break
                                            if role_idx != -1:
                                                v = val_node.values[role_idx]
                                                if isinstance(v, ast.Constant) and v.value == "system":
                                                    return True
                                        elif isinstance(val_node, ast.List):
                                            for elt in val_node.elts:
                                                if has_sys_role(elt):
                                                    return True
                                        return False

                                    if has_sys_role(stmt.value):
                                        for target_node in stmt.targets:
                                            if isinstance(target_node, ast.Name):
                                                flagged_vars.add(target_node.id)

                        def check_returns(body_list):
                            for step in body_list:
                                if isinstance(step, ast.Return):
                                    if step.value:
                                        for sub in ast.walk(step.value):
                                            if isinstance(sub, ast.Name):
                                                if sub.id in flagged_vars or any(x in sub.id.lower() for x in flagged_names):
                                                    return step.lineno
                                            elif isinstance(sub, ast.Attribute):
                                                if any(x in sub.attr.lower() for x in flagged_names):
                                                    return step.lineno
                                elif hasattr(step, "body") and not isinstance(step, ast.FunctionDef):
                                    res_line = check_returns(step.body)
                                    if res_line:
                                        return res_line
                                    if hasattr(step, "handlers"):
                                        for handler in step.handlers:
                                            res_line = check_returns(handler.body)
                                            if res_line:
                                                return res_line
                                    if hasattr(step, "orelse"):
                                        res_line = check_returns(step.orelse)
                                        if res_line:
                                            return res_line
                                    if hasattr(step, "finalbody"):
                                        res_line = check_returns(step.finalbody)
                                        if res_line:
                                            return res_line
                            return None

                        line_number = check_returns(node.body)
                        if line_number:
                            findings.append(Finding(
                                rule="system_prompt_leak",
                                severity=self.severity,
                                message="System prompt or internal reasoning leak detected in route response",
                                location=f"{os.path.relpath(filepath, target)}:{line_number}"
                            ))
        return findings
