import os
import re
import ast
import yaml
import subprocess
from scanner.core import Plugin, Finding
from scanner.entropy import secret_likelihood_score, is_valid_uuid
from scanner.secret_rules.loader import load_ruleset

OPENAI_RE = re.compile(r'sk-[a-zA-Z0-9]{20,}')
AWS_RE = re.compile(r'AKIA[0-9A-Z]{16}')
ENV_LINE_RE = re.compile(r'^\s*([A-Za-z0-9_]+)\s*=\s*(.*)$')
SECRET_KEYWORDS = {"key", "token", "secret", "password", "auth", "credential"}


class SecretAssignmentVisitor(ast.NodeVisitor):
    def __init__(self):
        self.assignments = []

    def visit_Assign(self, node):
        val_str = None
        if hasattr(ast, "Constant") and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            val_str = node.value.value
        elif isinstance(node.value, ast.Str):
            val_str = node.value.s
            
        if val_str is not None:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.assignments.append((target.id, val_str, node.lineno))
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value:
            val_str = None
            if hasattr(ast, "Constant") and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                val_str = node.value.value
            elif isinstance(node.value, ast.Str):
                val_str = node.value.s
            
            if val_str is not None and isinstance(node.target, ast.Name):
                self.assignments.append((node.target.id, val_str, node.lineno))
        self.generic_visit(node)


def is_test_fixture(filepath: str) -> bool:
    normalized = filepath.replace("\\", "/").lower()
    parts = normalized.split("/")
    if "tests" in parts or "fixtures" in parts:
        return True
    filename = os.path.basename(filepath).lower()
    if filename.startswith("test_") or filename.endswith("_test.py"):
        return True
    return False


def should_filter(val: str, filepath: str, threshold: int) -> bool:
    if is_valid_uuid(val):
        return True
    score = secret_likelihood_score(val)
    if is_test_fixture(filepath):
        if score < (threshold + 15):
            return True
    else:
        if score < threshold:
            return True
    return False


def _load_entropy_threshold() -> int:
    config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.yaml")
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if isinstance(data, dict):
                    sec_det = data.get("secret_detection", {})
                    threshold = sec_det.get("entropy_threshold")
                    if threshold is not None:
                        return int(threshold)
        except Exception:
            pass
    return 70


class HardcodedKeys(Plugin):
    name = "hardcoded_keys"
    severity = "critical"
    owasp_ref = "LLM06"

    def __init__(self, full_history: bool = False):
        self.full_history = full_history
        self.threshold = _load_entropy_threshold()
        rules_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "secret_rules", "gitleaks.toml")
        try:
            self.rules = load_ruleset(rules_path)
        except Exception:
            self.rules = []

    def run(self, target: str) -> list[Finding]:
        findings = []
        if not os.path.exists(target):
            return findings

        def is_binary(filepath: str) -> bool:
            try:
                with open(filepath, 'rb') as f:
                    return b'\x00' in f.read(1024)
            except Exception:
                return True

        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d not in ('.git', 'node_modules', 'venv', '__pycache__')]
            for file in files:
                filepath = os.path.join(root, file)
                if is_binary(filepath):
                    continue

                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                except Exception:
                    continue

                lines = content.splitlines()
                is_env_file = file == ".env" or file.endswith(".env")
                reported_lines = set()

                for line_num, line in enumerate(lines, 1):
                    match_found = False

                    for m in OPENAI_RE.finditer(line):
                        findings.append(Finding(
                            rule="openai_key",
                            severity=self.severity,
                            message=f"Potential hardcoded OpenAI API key found: {m.group(0)}",
                            location=f"{os.path.relpath(filepath, target)}:{line_num}",
                            detection_method="regex"
                        ))
                        match_found = True
                        reported_lines.add(line_num)

                    if not match_found:
                        for m in AWS_RE.finditer(line):
                            findings.append(Finding(
                                rule="aws_key",
                                severity=self.severity,
                                message=f"Potential hardcoded AWS Access Key ID found: {m.group(0)}",
                                location=f"{os.path.relpath(filepath, target)}:{line_num}",
                                detection_method="regex"
                            ))
                            match_found = True
                            reported_lines.add(line_num)

                    if not match_found:
                        for rule in self.rules:
                            for m in rule["regex"].finditer(line):
                                val = m.group(1) if m.groups() and m.group(1) else m.group(0)
                                if not should_filter(val, filepath, self.threshold):
                                    findings.append(Finding(
                                        rule=rule["id"],
                                        severity=self.severity,
                                        message=f"Potential hardcoded secret found via ruleset: {rule['description']}",
                                        location=f"{os.path.relpath(filepath, target)}:{line_num}",
                                        detection_method="ruleset"
                                    ))
                                    match_found = True
                                    reported_lines.add(line_num)
                                    break
                            if match_found:
                                break

                    if not match_found and is_env_file:
                        line_stripped = line.strip()
                        if line_stripped and not line_stripped.startswith("#"):
                            m = ENV_LINE_RE.match(line_stripped)
                            if m:
                                val = m.group(2).strip()
                                if len(val) >= 2 and ((val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'"))):
                                    val = val[1:-1]
                                if val and not should_filter(val, filepath, self.threshold):
                                    findings.append(Finding(
                                        rule="entropy_secret",
                                        severity=self.severity,
                                        message=f"Potential secret in env file found: {line_stripped}",
                                        location=f"{os.path.relpath(filepath, target)}:{line_num}",
                                        detection_method="entropy"
                                    ))
                                    reported_lines.add(line_num)

                if filepath.endswith(".py"):
                    try:
                        tree = ast.parse(content)
                        visitor = SecretAssignmentVisitor()
                        visitor.visit(tree)
                        for var_name, val, line_num in visitor.assignments:
                            if line_num not in reported_lines:
                                if any(kw in var_name.lower() for kw in SECRET_KEYWORDS):
                                    if not should_filter(val, filepath, self.threshold):
                                        findings.append(Finding(
                                            rule="entropy_secret",
                                            severity=self.severity,
                                            message=f"Potential secret assigned to variable: {var_name}",
                                            location=f"{os.path.relpath(filepath, target)}:{line_num}",
                                            detection_method="entropy"
                                        ))
                                        reported_lines.add(line_num)
                    except Exception:
                        pass

        if os.path.isdir(os.path.join(target, ".git")):
            cmd = ["git", "log", "-p"]
            if not self.full_history:
                cmd.extend(["-n", "200"])
            try:
                res = subprocess.run(cmd, cwd=target, capture_output=True, text=True, timeout=30, errors="ignore")
                if res.returncode == 0:
                    current_commit = None
                    current_file = None
                    reported_history = set()
                    for line in res.stdout.splitlines():
                        if line.startswith("commit "):
                            current_commit = line.split()[1][:8]
                        elif line.startswith("diff --git "):
                            parts = line.split()
                            if len(parts) >= 4:
                                if parts[3].startswith("b/"):
                                    current_file = parts[3][2:]
                                else:
                                    current_file = parts[3]
                        elif (line.startswith("+") and not line.startswith("+++")) or (line.startswith("-") and not line.startswith("---")):
                            diff_content = line[1:]
                            secret_found = False
                            secret_val = ""
                            secret_rule = ""
                            msg = ""
                            method = "regex"

                            m = OPENAI_RE.search(diff_content)
                            if m:
                                secret_val = m.group(0)
                                secret_rule = "openai_key"
                                msg = f"Potential hardcoded OpenAI API key found in git history: {secret_val}"
                                method = "regex"
                                secret_found = True

                            if not secret_found:
                                m = AWS_RE.search(diff_content)
                                if m:
                                    secret_val = m.group(0)
                                    secret_rule = "aws_key"
                                    msg = f"Potential hardcoded AWS Access Key ID found in git history: {secret_val}"
                                    method = "regex"
                                    secret_found = True

                            if not secret_found:
                                for rule in self.rules:
                                    m = rule["regex"].search(diff_content)
                                    if m:
                                        val = m.group(1) if m.groups() and m.group(1) else m.group(0)
                                        if not should_filter(val, current_file or "", self.threshold):
                                            secret_val = val
                                            secret_rule = rule["id"]
                                            msg = f"Potential hardcoded secret found via ruleset in git history: {rule['description']}"
                                            method = "ruleset"
                                            secret_found = True
                                            break

                            if not secret_found and current_file:
                                is_env = current_file == ".env" or current_file.endswith(".env")
                                if is_env:
                                    line_stripped = diff_content.strip()
                                    if line_stripped and not line_stripped.startswith("#"):
                                        m = ENV_LINE_RE.match(line_stripped)
                                        if m:
                                            val = m.group(2).strip()
                                            if len(val) >= 2 and ((val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'"))):
                                                val = val[1:-1]
                                            if val and not should_filter(val, current_file, self.threshold):
                                                secret_val = val
                                                secret_rule = "entropy_secret"
                                                msg = f"Potential secret in env file found in git history: {line_stripped}"
                                                method = "entropy"
                                                secret_found = True

                                elif current_file.endswith(".py"):
                                    try:
                                        tree = ast.parse(diff_content)
                                        visitor = SecretAssignmentVisitor()
                                        visitor.visit(tree)
                                        for var_name, val, _ in visitor.assignments:
                                            if any(kw in var_name.lower() for kw in SECRET_KEYWORDS):
                                                if not should_filter(val, current_file, self.threshold):
                                                    secret_val = val
                                                    secret_rule = "entropy_secret"
                                                    msg = f"Potential secret assigned to variable in git history: {var_name}"
                                                    method = "entropy"
                                                    secret_found = True
                                                    break
                                    except Exception:
                                        pass

                            if secret_found and current_commit and current_file:
                                history_loc = f"git-history:{current_commit}:{current_file}"
                                history_key = (secret_rule, secret_val, history_loc)
                                if history_key not in reported_history:
                                    reported_history.add(history_key)
                                    exists_in_working = False
                                    for f in findings:
                                        if not f.location.startswith("git-history:") and secret_val in f.message:
                                            exists_in_working = True
                                            break
                                    if not exists_in_working:
                                        findings.append(Finding(
                                            rule=secret_rule,
                                            severity="critical",
                                            message=msg,
                                            location=history_loc,
                                            detection_method=method
                                        ))
            except Exception:
                pass

        return findings
