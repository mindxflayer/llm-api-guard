import os
import ast
from scanner.core import Plugin, Finding

class MissingInputValidation(Plugin):
    name = "missing_input_validation"
    severity = "medium"
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

                        accesses_request = False
                        for sub in ast.walk(node):
                            if isinstance(sub, ast.Attribute):
                                if isinstance(sub.value, ast.Name) and sub.value.id == "request":
                                    accesses_request = True
                                    break
                            elif isinstance(sub, ast.Subscript):
                                if isinstance(sub.value, ast.Name) and sub.value.id == "request":
                                    accesses_request = True
                                    break
                                if isinstance(sub.value, ast.Attribute) and isinstance(sub.value.value, ast.Name) and sub.value.value.id == "request":
                                    accesses_request = True
                                    break

                        if not accesses_request:
                            continue

                        has_validation = False
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
                            if "validate" in dec_name.lower():
                                has_validation = True
                                break

                        if not has_validation:
                            for sub in ast.walk(node):
                                if isinstance(sub, ast.Call):
                                    call_name = ""
                                    if isinstance(sub.func, ast.Name):
                                        call_name = sub.func.id
                                    elif isinstance(sub.func, ast.Attribute):
                                        call_name = sub.func.attr
                                    if any(x in call_name.lower() for x in ("validate", "pydantic", "marshmallow", "jsonschema", "parse_obj", "model_validate")):
                                        has_validation = True
                                        break
                                elif isinstance(sub, ast.Attribute):
                                    if isinstance(sub.value, ast.Name) and sub.value.id in ("pydantic", "marshmallow", "jsonschema"):
                                        has_validation = True
                                        break

                        if not has_validation:
                            findings.append(Finding(
                                rule="missing_input_validation",
                                severity=self.severity,
                                message="Route handler accesses request parameters directly without validation",
                                location=f"{os.path.relpath(filepath, target)}:{node.lineno}"
                            ))
        return findings
