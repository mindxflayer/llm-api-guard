import os
import ast
from scanner.core import Plugin, Finding

class UnsafeOutputExec(Plugin):
    name = "unsafe_output_exec"
    severity = "high"
    owasp_ref = "LLM02"

    def run(self, target: str) -> list[Finding]:
        findings = []
        if not os.path.exists(target):
            return findings

        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in ('.git', 'node_modules', 'venv', '__pycache__')]
            for file in files:
                if not file.endswith('.py'):
                    continue
                filepath = os.path.join(root, file)
                rel_path = os.path.relpath(filepath, target)
                
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        code = f.read()
                    tree = ast.parse(code)
                except Exception:
                    continue

                visitor = LLMOutputVisitor(rel_path, self.severity)
                visitor.visit(tree)
                findings.extend(visitor.findings)

        return findings

class LLMOutputVisitor(ast.NodeVisitor):
    def __init__(self, rel_path: str, severity: str):
        self.rel_path = rel_path
        self.severity = severity
        self.findings = []
        self.llm_vars = {"response", "completion"}

    def _is_llm_expression(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Attribute):
            if node.attr in ("content", "choices", "text"):
                return True
            return self._is_llm_expression(node.value)
        if isinstance(node, ast.Subscript):
            return self._is_llm_expression(node.value)
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute):
                if node.func.attr in ("content", "choices", "text") or self._is_llm_expression(node.func.value):
                    return True
            return self._is_llm_expression(node.func)
        if isinstance(node, ast.Name):
            if node.id in self.llm_vars or "response" in node.id.lower() or "completion" in node.id.lower():
                return True
        return False

    def visit_Assign(self, node: ast.Assign):
        is_llm = self._is_llm_expression(node.value)
        if isinstance(node.value, ast.Name) and node.value.id in self.llm_vars:
            is_llm = True

        if is_llm:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.llm_vars.add(target.id)
                elif isinstance(target, (ast.Tuple, ast.List)):
                    for elt in target.elts:
                        if isinstance(elt, ast.Name):
                            self.llm_vars.add(elt.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            if node.args:
                arg = node.args[0]
                if self._is_llm_expression(arg):
                    self.findings.append(Finding(
                        rule="unsafe_output_exec",
                        severity=self.severity,
                        message=f"Detected LLM output passed to {node.func.id}()",
                        location=f"{self.rel_path}:{node.lineno}"
                    ))
        self.generic_visit(node)
