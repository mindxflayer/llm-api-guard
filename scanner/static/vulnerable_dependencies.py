import os
import re
import json
from packaging.version import parse as parse_version
from scanner.core import Plugin, Finding

class VulnerableDependencies(Plugin):
    name = "vulnerable_dependencies"
    severity = "medium"
    owasp_ref = "LLM05"

    def run(self, target: str) -> list[Finding]:
        findings = []
        if not os.path.exists(target):
            return findings

        targets = [
            "requirements.txt",
            "Pipfile.lock",
            "poetry.lock",
            "pyproject.toml",
            "package.json",
            "package-lock.json"
        ]

        vulnerability_db = {
            "langchain": [
                (lambda v: v < parse_version("0.0.236"), "critical", "CVE-2023-36095: RCE via PALChain.from_math_prompt(llm).run passing LLM-generated code to Python's exec() with no AST validation")
            ],
            "langchain-core": [
                (lambda v: (v < parse_version("0.3.81")) or (parse_version("1.0.0") <= v < parse_version("1.2.5")), "critical", "CVE-2025-68664: Serialization injection vulnerability (LangGrinch) allowing object injection and potential secret leakage")
            ]
        }



        search_paths = []
        if os.path.isdir(target):
            for item in os.listdir(target):
                item_path = os.path.join(target, item)
                if os.path.isfile(item_path) and item in targets:
                    search_paths.append(item_path)
                elif os.path.isdir(item_path) and item not in (".git", "node_modules", "venv", "__pycache__"):
                    for sub_item in os.listdir(item_path):
                        sub_path = os.path.join(item_path, sub_item)
                        if os.path.isfile(sub_path) and sub_item in targets:
                            search_paths.append(sub_path)
        else:
            if os.path.basename(target) in targets:
                search_paths.append(target)

        for path in search_paths:
            filename = os.path.basename(path)
            content = ""
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception:
                continue

            extracted = []

            if filename == "requirements.txt":
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    m = re.match(r'^([a-zA-Z0-9_\-]+)\s*(?:==|>=|<=|~=)\s*([a-zA-Z0-9\.\-\+]+)', line)
                    if m:
                        pkg_name = m.group(1).lower().replace("_", "-")
                        ver = m.group(2)
                        extracted.append((pkg_name, ver))
            elif filename == "Pipfile.lock":
                try:
                    data = json.loads(content)
                    for sec in ("default", "develop"):
                        if sec in data:
                            for pkg, info in data[sec].items():
                                if isinstance(info, dict) and "version" in info:
                                    ver = info["version"].lstrip("=")
                                    extracted.append((pkg.lower().replace("_", "-"), ver))
                except Exception:
                    pass
            elif filename == "poetry.lock":
                blocks = content.split("[[package]]")
                for block in blocks[1:]:
                    name_match = re.search(r'name\s*=\s*"([^"]+)"', block)
                    version_match = re.search(r'version\s*=\s*"([^"]+)"', block)
                    if name_match and version_match:
                        extracted.append((name_match.group(1).lower().replace("_", "-"), version_match.group(2)))
            elif filename == "pyproject.toml":
                for line in content.splitlines():
                    line = line.strip()
                    m = re.match(r'^([a-zA-Z0-9_\-]+)\s*=\s*["\'][\^~=>]*([0-9\.\-]+)["\']', line)
                    if m:
                        extracted.append((m.group(1).lower().replace("_", "-"), m.group(2)))
                    m2 = re.search(r'["\']([a-zA-Z0-9_\-]+)\s*(?:==|>=|<=|~=)\s*([0-9\.\-]+)["\']', line)
                    if m2:
                        extracted.append((m2.group(1).lower().replace("_", "-"), m2.group(2)))
            elif filename == "package.json":
                try:
                    data = json.loads(content)
                    for sec in ("dependencies", "devDependencies"):
                        if sec in data and isinstance(data[sec], dict):
                            for pkg, ver_str in data[sec].items():
                                ver = ver_str.lstrip("^~=>=<")
                                extracted.append((pkg.lower(), ver))
                except Exception:
                    pass
            elif filename == "package-lock.json":
                try:
                    data = json.loads(content)
                    if "dependencies" in data and isinstance(data["dependencies"], dict):
                        for pkg, info in data["dependencies"].items():
                            if isinstance(info, dict) and "version" in info:
                                extracted.append((pkg.lower(), info["version"]))
                    if "packages" in data and isinstance(data["packages"], dict):
                        for pkg_path, info in data["packages"].items():
                            if isinstance(info, dict) and "version" in info:
                                pkg_name = pkg_path.split("node_modules/")[-1].lower()
                                extracted.append((pkg_name, info["version"]))
                except Exception:
                    pass

            for pkg_name, ver in extracted:
                if pkg_name in vulnerability_db:
                    try:
                        v = parse_version(ver)
                    except Exception:
                        continue
                    for checker, sev, desc in vulnerability_db[pkg_name]:
                        if checker(v):
                            findings.append(Finding(
                                rule="vulnerable_dependencies",
                                severity=sev,
                                message=f"{pkg_name}=={ver} contains vulnerability: {desc}",
                                location=f"{os.path.relpath(path, target)}:{pkg_name}=={ver}"
                            ))
                            break
        return findings
