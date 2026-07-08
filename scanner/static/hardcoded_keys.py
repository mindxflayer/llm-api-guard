import os
import re
from scanner.core import Plugin, Finding

OPENAI_RE = re.compile(r'sk-[a-zA-Z0-9]{20,}')
AWS_RE = re.compile(r'AKIA[0-9A-Z]{16}')
BEARER_RE = re.compile(r'(?i)\bbearer\s+([a-zA-Z0-9_\-\.\~]{15,})')
ENV_RE = re.compile(r'\b[A-Za-z0-9_]+\s*=\s*[\'"]?([a-zA-Z0-9_\-\.\~\@\#\$\%\^\&\*\+\=]{8,})[\'"]?')

class HardcodedKeys(Plugin):
    name = "hardcoded_keys"
    severity = "critical"
    owasp_ref = "LLM06"

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

        return findings
