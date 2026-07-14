import os
import re
import json
from packaging.version import parse as parse_version
from scanner.core import Plugin, Finding
from scanner.osv_client import query_osv_batch

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

        to_query = []
        package_sources = {}
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
            ecosystem = "PyPI" if filename in ("requirements.txt", "Pipfile.lock", "poetry.lock", "pyproject.toml") else "npm"
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
                key = (ecosystem, pkg_name, ver)
                if key not in package_sources:
                    package_sources[key] = []
                    to_query.append(key)
                if path not in package_sources[key]:
                    package_sources[key].append(path)

        if not to_query:
            return findings

        osv_results = query_osv_batch(to_query)

        for key, vulns in osv_results.items():
            ecosystem, pkg_name, ver = key
            paths = package_sources.get(key, [])
            for vuln in vulns:
                vuln_id = vuln.get("id", "")
                summary = vuln.get("summary", "")
                severity = "medium"
                sev_list = vuln.get("severity")
                if sev_list:
                    for entry in sev_list:
                        score_val = entry.get("score")
                        if score_val:
                            try:
                                score = float(score_val)
                                if score >= 9.0:
                                    severity = "critical"
                                elif score >= 7.0:
                                    severity = "high"
                                elif score >= 4.0:
                                    severity = "medium"
                                elif score > 0.0:
                                    severity = "low"
                                break
                            except ValueError:
                                pass
                else:
                    db_spec = vuln.get("database_specific")
                    if db_spec and isinstance(db_spec, dict):
                        db_sev = db_spec.get("severity")
                        if isinstance(db_sev, str):
                            db_sev_lower = db_sev.lower()
                            if db_sev_lower in ("critical", "high", "medium", "low"):
                                severity = db_sev_lower
                            elif db_sev_lower == "moderate":
                                severity = "medium"

                priority = "normal"
                keywords = ("rce", "deserialization", "ssrf", "template injection", "pickle", "eval", "exec")
                full_text = f"{vuln_id} {summary}".lower()
                if any(kw in full_text for kw in keywords):
                    priority = "high"

                prefix = "[offline snapshot, may be outdated] " if vuln.get("source") == "offline_snapshot" else ""
                desc = summary if summary else vuln_id
                message = f"{prefix}{pkg_name}=={ver} contains vulnerability: {desc}"

                for path in paths:
                    finding = Finding(
                        rule="vulnerable_dependencies",
                        severity=severity,
                        message=message,
                        location=f"{os.path.relpath(path, target)}:{pkg_name}=={ver}"
                    )
                    finding.priority = priority
                    findings.append(finding)

        findings.sort(key=lambda f: 0 if getattr(f, "priority", "normal") == "high" else 1)
        return findings
