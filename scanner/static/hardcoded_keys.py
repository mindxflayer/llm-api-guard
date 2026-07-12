import os
import re
import subprocess
from scanner.core import Plugin, Finding

OPENAI_RE = re.compile(r'sk-[a-zA-Z0-9]{20,}')

AWS_RE = re.compile(r'AKIA[0-9A-Z]{16}')
BEARER_RE = re.compile(r'(?i)\bbearer\s+([a-zA-Z0-9_\-\.\~]{15,})')
ENV_RE = re.compile(r'\b[A-Za-z0-9_]+\s*=\s*[\'"]?([a-zA-Z0-9_\-\.\~\@\#\$\%\^\&\*\+\=]{8,})[\'"]?')

class HardcodedKeys(Plugin):
    name = "hardcoded_keys"
    severity = "critical"
    owasp_ref = "LLM06"

    def __init__(self, full_history: bool = False):
        self.full_history = full_history

    def run(self, target: str) -> list[Finding]:
        findings = []
        if not os.path.exists(target):
            return findings

        placeholders = {"your_key_here", "xxx", "placeholder", "your_api_key", "your-key-here", "todo", "replace_me", "<key>", "[key]"}

        def is_placeholder(val: str) -> bool:
            val_clean = val.lower().strip().strip("'\"")
            if any(p in val_clean for p in placeholders):
                return True
            if len(val_clean) < 8:
                return True
            return False

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
                        lines = f.readlines()
                except Exception:
                    continue

                is_env_file = file == ".env" or file.endswith(".env")

                for line_num, line in enumerate(lines, 1):
                    match_found = False

                    for m in OPENAI_RE.finditer(line):
                        findings.append(Finding(
                            rule="openai_key",
                            severity=self.severity,
                            message=f"Potential hardcoded OpenAI API key found: {m.group(0)}",
                            location=f"{os.path.relpath(filepath, target)}:{line_num}"
                        ))
                        match_found = True

                    if not match_found:
                        for m in AWS_RE.finditer(line):
                            findings.append(Finding(
                                rule="aws_key",
                                severity=self.severity,
                                message=f"Potential hardcoded AWS Access Key ID found: {m.group(0)}",
                                location=f"{os.path.relpath(filepath, target)}:{line_num}"
                            ))
                            match_found = True

                    if not match_found:
                        for m in BEARER_RE.finditer(line):
                            token = m.group(1)
                            if not is_placeholder(token):
                                findings.append(Finding(
                                    rule="bearer_token",
                                    severity=self.severity,
                                    message=f"Potential hardcoded Bearer token found: {m.group(0)}",
                                    location=f"{os.path.relpath(filepath, target)}:{line_num}"
                                ))
                                match_found = True

                    if not match_found and is_env_file:
                        m = ENV_RE.search(line)
                        if m:
                            val = m.group(1)
                            if not is_placeholder(val):
                                findings.append(Finding(
                                    rule="env_secret",
                                    severity=self.severity,
                                    message=f"Potential secret in env file found: {m.group(0)}",
                                    location=f"{os.path.relpath(filepath, target)}:{line_num}"
                                ))

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

                            m = OPENAI_RE.search(diff_content)
                            if m:
                                secret_val = m.group(0)
                                secret_rule = "openai_key"
                                msg = f"Potential hardcoded OpenAI API key found in git history: {secret_val}"
                                secret_found = True

                            if not secret_found:
                                m = AWS_RE.search(diff_content)
                                if m:
                                    secret_val = m.group(0)
                                    secret_rule = "aws_key"
                                    msg = f"Potential hardcoded AWS Access Key ID found in git history: {secret_val}"
                                    secret_found = True

                            if not secret_found:
                                m = BEARER_RE.search(diff_content)
                                if m:
                                    token = m.group(1)
                                    if not is_placeholder(token):
                                        secret_val = m.group(0)
                                        secret_rule = "bearer_token"
                                        msg = f"Potential hardcoded Bearer token found in git history: {secret_val}"
                                        secret_found = True

                            if not secret_found and current_file and (current_file == ".env" or current_file.endswith(".env")):
                                m = ENV_RE.search(diff_content)
                                if m:
                                    val = m.group(1)
                                    if not is_placeholder(val):
                                        secret_val = m.group(0)
                                        secret_rule = "env_secret"
                                        msg = f"Potential secret in env file found in git history: {secret_val}"
                                        secret_found = True

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
                                            location=history_loc
                                        ))
            except Exception:
                pass

        return findings
