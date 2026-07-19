import os
import shutil
import tempfile
import subprocess
from scanner.core import Runner
from scanner.static.hardcoded_keys import HardcodedKeys
from scanner.static.unsafe_output_exec import UnsafeOutputExec

def test_hardcoded_keys_plugin():
    plugin = HardcodedKeys()
    
    temp_bad = tempfile.mkdtemp()
    try:
        shutil.copy(os.path.join("tests", "samples", "hardcoded_keys", "bad.py"), os.path.join(temp_bad, "bad.py"))
        runner = Runner([plugin])
        findings_bad = runner.run(temp_bad)
        assert len(findings_bad) >= 3
        for finding in findings_bad:
            assert "sk-abcdefghijklmnopqrstuvwxyz0123456789" not in finding.message
            assert "sk-abcdefghijklmnopqrstuvwxyz0123456789" not in finding.location
            assert "AKIA1234567890123456" not in finding.message
            assert "AKIA1234567890123456" not in finding.location
            assert "token-123456789-abcdefg-xyz" not in finding.message
            assert "token-123456789-abcdefg-xyz" not in finding.location
    finally:
        shutil.rmtree(temp_bad)

    temp_good = tempfile.mkdtemp()
    try:
        shutil.copy(os.path.join("tests", "samples", "hardcoded_keys", "good.py"), os.path.join(temp_good, "good.py"))
        runner = Runner([plugin])
        findings_good = runner.run(temp_good)
        assert len(findings_good) == 0
    finally:
        shutil.rmtree(temp_good)

def test_unsafe_output_exec_plugin():
    plugin = UnsafeOutputExec()
    
    temp_bad = tempfile.mkdtemp()
    try:
        shutil.copy(os.path.join("tests", "samples", "unsafe_output_exec", "bad.py"), os.path.join(temp_bad, "bad.py"))
        runner = Runner([plugin])
        findings_bad = runner.run(temp_bad)
        assert len(findings_bad) == 1
        assert findings_bad[0].rule == "unsafe_output_exec"
    finally:
        shutil.rmtree(temp_bad)

    temp_good = tempfile.mkdtemp()
    try:
        shutil.copy(os.path.join("tests", "samples", "unsafe_output_exec", "good.py"), os.path.join(temp_good, "good.py"))
        runner = Runner([plugin])
        findings_good = runner.run(temp_good)
        assert len(findings_good) == 0
    finally:
        shutil.rmtree(temp_good)

def test_prompt_injection_flow_plugin():
    from scanner.static.prompt_injection_flow import PromptInjectionFlow
    plugin = PromptInjectionFlow()
    temp_bad = tempfile.mkdtemp()
    try:
        shutil.copy(os.path.join("tests", "samples", "prompt_injection_flow", "bad.py"), os.path.join(temp_bad, "bad.py"))
        runner = Runner([plugin])
        findings = runner.run(temp_bad)
        assert len(findings) >= 1
        assert any(f.rule == "prompt_injection_flow" for f in findings)
    finally:
        shutil.rmtree(temp_bad)

    temp_good = tempfile.mkdtemp()
    try:
        shutil.copy(os.path.join("tests", "samples", "prompt_injection_flow", "good.py"), os.path.join(temp_good, "good.py"))
        runner = Runner([plugin])
        findings = runner.run(temp_good)
        assert len(findings) == 0
    finally:
        shutil.rmtree(temp_good)

def test_missing_input_validation_plugin():
    from scanner.static.missing_input_validation import MissingInputValidation
    plugin = MissingInputValidation()
    temp_bad = tempfile.mkdtemp()
    try:
        shutil.copy(os.path.join("tests", "samples", "missing_input_validation", "bad.py"), os.path.join(temp_bad, "bad.py"))
        runner = Runner([plugin])
        findings = runner.run(temp_bad)
        assert len(findings) >= 1
        assert any(f.rule == "missing_input_validation" for f in findings)
    finally:
        shutil.rmtree(temp_bad)

    temp_good = tempfile.mkdtemp()
    try:
        shutil.copy(os.path.join("tests", "samples", "missing_input_validation", "good.py"), os.path.join(temp_good, "good.py"))
        runner = Runner([plugin])
        findings = runner.run(temp_good)
        assert len(findings) == 0
    finally:
        shutil.rmtree(temp_good)

def test_system_prompt_leak_plugin():
    from scanner.static.system_prompt_leak import SystemPromptLeak
    plugin = SystemPromptLeak()
    temp_bad = tempfile.mkdtemp()
    try:
        shutil.copy(os.path.join("tests", "samples", "system_prompt_leak", "bad.py"), os.path.join(temp_bad, "bad.py"))
        runner = Runner([plugin])
        findings = runner.run(temp_bad)
        assert len(findings) >= 1
        assert any(f.rule == "system_prompt_leak" for f in findings)
    finally:
        shutil.rmtree(temp_bad)

    temp_good = tempfile.mkdtemp()
    try:
        shutil.copy(os.path.join("tests", "samples", "system_prompt_leak", "good.py"), os.path.join(temp_good, "good.py"))
        runner = Runner([plugin])
        findings = runner.run(temp_good)
        assert len(findings) == 0
    finally:
        shutil.rmtree(temp_good)

def test_excessive_agency_plugin():
    from scanner.static.excessive_agency import ExcessiveAgency
    plugin = ExcessiveAgency()
    temp_bad = tempfile.mkdtemp()
    try:
        shutil.copy(os.path.join("tests", "samples", "excessive_agency", "bad.py"), os.path.join(temp_bad, "bad.py"))
        runner = Runner([plugin])
        findings = runner.run(temp_bad)
        assert len(findings) >= 1
        assert any(f.rule == "excessive_agency" for f in findings)
    finally:
        shutil.rmtree(temp_bad)

    temp_good = tempfile.mkdtemp()
    try:
        shutil.copy(os.path.join("tests", "samples", "excessive_agency", "good.py"), os.path.join(temp_good, "good.py"))
        runner = Runner([plugin])
        findings = runner.run(temp_good)
        assert len(findings) == 0
    finally:
        shutil.rmtree(temp_good)

def test_vulnerable_dependencies_plugin():
    from unittest.mock import patch
    from scanner.static.vulnerable_dependencies import VulnerableDependencies
    plugin = VulnerableDependencies()
    temp_bad = tempfile.mkdtemp()
    mock_bad = {
        ("PyPI", "langchain", "0.0.235"): [
            {"id": "CVE-2023-36095", "summary": "RCE via PALChain", "severity": [{"type": "CVSS_V3", "score": "9.8"}], "ranges": []}
        ]
    }
    try:
        shutil.copy(os.path.join("tests", "samples", "vulnerable_dependencies", "bad_requirements.txt"), os.path.join(temp_bad, "requirements.txt"))
        with patch("scanner.static.vulnerable_dependencies.query_osv_batch", return_value=mock_bad) as mock_q:
            runner = Runner([plugin])
            findings_bad = runner.run(temp_bad)
            assert len(findings_bad) >= 1
            assert any(f.rule == "vulnerable_dependencies" for f in findings_bad)
            mock_q.assert_called_once()
    finally:
        shutil.rmtree(temp_bad)

    temp_good = tempfile.mkdtemp()
    try:
        shutil.copy(os.path.join("tests", "samples", "vulnerable_dependencies", "good_requirements.txt"), os.path.join(temp_good, "requirements.txt"))
        with patch("scanner.static.vulnerable_dependencies.query_osv_batch", return_value={}) as mock_q:
            runner = Runner([plugin])
            findings_good = runner.run(temp_good)
            assert len(findings_good) == 0
            mock_q.assert_called_once()
    finally:
        shutil.rmtree(temp_good)

def test_vulnerable_dependencies_priority():
    from unittest.mock import patch
    from scanner.static.vulnerable_dependencies import VulnerableDependencies
    plugin = VulnerableDependencies()
    temp_bad = tempfile.mkdtemp()
    with open(os.path.join(temp_bad, "requirements.txt"), "w") as f:
        f.write("pkg-a==1.0.0\npkg-b==2.0.0\n")
    mock_results = {
        ("PyPI", "pkg-a", "1.0.0"): [
            {"id": "VULN-A", "summary": "RCE in package", "severity": [{"type": "CVSS_V3", "score": "8.0"}], "ranges": []}
        ],
        ("PyPI", "pkg-b", "2.0.0"): [
            {"id": "VULN-B", "summary": "some generic bug", "severity": [{"type": "CVSS_V3", "score": "5.0"}], "ranges": []}
        ]
    }
    try:
        with patch("scanner.static.vulnerable_dependencies.query_osv_batch", return_value=mock_results):
            runner = Runner([plugin])
            findings = runner.run(temp_bad)
            assert len(findings) == 2
            assert findings[0].location.endswith("pkg-a==1.0.0")
            assert getattr(findings[0], "priority", None) == "high"
            assert findings[1].location.endswith("pkg-b==2.0.0")
            assert getattr(findings[1], "priority", None) == "normal"
    finally:
        shutil.rmtree(temp_bad)

def test_hardcoded_keys_git_history():
    from scanner.static.hardcoded_keys import HardcodedKeys
    plugin = HardcodedKeys()
    temp_dir = tempfile.mkdtemp()
    try:
        subprocess.run(["git", "init"], cwd=temp_dir, capture_output=True, check=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=temp_dir, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=temp_dir, check=True)
        
        file_path = os.path.join(temp_dir, "keys.py")
        with open(file_path, "w") as f:
            f.write('openai_key = "sk-abcdefghijklmnopqrstuvwxyz0123456789"\n')
        
        subprocess.run(["git", "add", "keys.py"], cwd=temp_dir, check=True)
        subprocess.run(["git", "commit", "-m", "add OpenAI secret key"], cwd=temp_dir, check=True)
        
        with open(file_path, "w") as f:
            f.write('openai_key = "placeholder_key"\n')
            
        subprocess.run(["git", "add", "keys.py"], cwd=temp_dir, check=True)
        subprocess.run(["git", "commit", "-m", "remove OpenAI secret key"], cwd=temp_dir, check=True)
        
        runner = Runner([plugin])
        findings = runner.run(temp_dir)
        print("DEBUG FINDINGS:", findings)
        
        history_findings = [f for f in findings if f.location.startswith("git-history:")]
        working_findings = [f for f in findings if not f.location.startswith("git-history:")]
        print("DEBUG HISTORY:", history_findings)
        print("DEBUG WORKING:", working_findings)
        
        assert len(working_findings) == 0
        assert len(history_findings) >= 1
        assert any(f.rule == "openai_key" and f.severity == "critical" for f in history_findings)
    finally:
        import stat
        def make_writable(func, path, exc_info):
            os.chmod(path, stat.S_IWRITE)
            func(path)
        shutil.rmtree(temp_dir, onerror=make_writable)

def test_excessive_agency_sanitize_variable_bypass():
    from scanner.static.excessive_agency import ExcessiveAgency
    plugin = ExcessiveAgency()
    temp_dir = tempfile.mkdtemp()
    try:
        code = """
def tool(func):
    return func

@tool
def read_file(filepath):
    sanitize_but_not_actually_called = True
    with open(filepath, "r") as f:
        return f.read()
"""
        with open(os.path.join(temp_dir, "bad.py"), "w", encoding="utf-8") as f:
            f.write(code)
        findings = plugin.run(temp_dir)
        assert len(findings) >= 1
        assert any(f.rule == "excessive_agency" for f in findings)
    finally:
        shutil.rmtree(temp_dir)

def test_excessive_agency_cross_module_validator():
    from scanner.static.excessive_agency import ExcessiveAgency
    plugin = ExcessiveAgency()
    temp_dir = tempfile.mkdtemp()
    try:
        module_b = """
def verify_ok(x):
    if not isinstance(x, str):
        raise ValueError("Bad input")
    return x
"""
        module_a = """
from .module_b import verify_ok
def tool(func):
    return func

@tool
def read_file(filepath):
    verify_ok(filepath)
    with open(filepath, "r") as f:
        return f.read()
"""
        os.makedirs(os.path.join(temp_dir, "app"), exist_ok=True)
        with open(os.path.join(temp_dir, "app", "module_b.py"), "w", encoding="utf-8") as f:
            f.write(module_b)
        with open(os.path.join(temp_dir, "app", "module_a.py"), "w", encoding="utf-8") as f:
            f.write(module_a)
        findings = plugin.run(temp_dir)
        assert len(findings) == 0
    finally:
        shutil.rmtree(temp_dir)

def test_excessive_agency_regex_regression():
    from scanner.static.excessive_agency import ExcessiveAgency
    plugin = ExcessiveAgency()
    temp_dir = tempfile.mkdtemp()
    try:
        code = """
def tool(func):
    return func

@tool
def read_file(filepath):
    sanitize_input_totally_not_really = "safe"
    with open(filepath, "r") as f:
        return f.read()
"""
        with open(os.path.join(temp_dir, "bad.py"), "w", encoding="utf-8") as f:
            f.write(code)
        findings = plugin.run(temp_dir)
        assert len(findings) >= 1
    finally:
        shutil.rmtree(temp_dir)

def test_excessive_agency_pydantic_library():
    from scanner.static.excessive_agency import ExcessiveAgency
    plugin = ExcessiveAgency()
    temp_dir = tempfile.mkdtemp()
    try:
        code = """
def tool(func):
    return func

class PathModel:
    def __init__(self, filepath):
        self.filepath = filepath

@tool
def read_file(filepath):
    p = PathModel(filepath=filepath)
    with open(filepath, "r") as f:
        return f.read()
"""
        with open(os.path.join(temp_dir, "bad.py"), "w", encoding="utf-8") as f:
            f.write(code)
        findings = plugin.run(temp_dir)
        assert len(findings) == 0
    finally:
        shutil.rmtree(temp_dir)

def test_prompt_injection_flow_3_file_hop():
    from scanner.static.prompt_injection_flow import PromptInjectionFlow
    plugin = PromptInjectionFlow()
    temp_dir = tempfile.mkdtemp()
    try:
        os.makedirs(os.path.join(temp_dir, "app"), exist_ok=True)
        file1 = """
from flask import Flask, request
from .file2 import first_helper

app = Flask(__name__)

@app.post("/chat")
def chat_handler():
    user_input = request.json["text"]
    return first_helper(user_input)
"""
        file2 = """
from .file3 import second_helper
def first_helper(data):
    return second_helper(data)
"""
        file3 = """
def second_helper(payload):
    prompt = f"System prompt: {payload}"
    return llm_call(prompt)

def llm_call(text):
    return text
"""
        with open(os.path.join(temp_dir, "app", "file1.py"), "w", encoding="utf-8") as f:
            f.write(file1)
        with open(os.path.join(temp_dir, "app", "file2.py"), "w", encoding="utf-8") as f:
            f.write(file2)
        with open(os.path.join(temp_dir, "app", "file3.py"), "w", encoding="utf-8") as f:
            f.write(file3)

        findings = plugin.run(temp_dir)
        assert len(findings) >= 1
        assert any(f.rule == "prompt_injection_flow" for f in findings)
    finally:
        shutil.rmtree(temp_dir)

def test_prompt_injection_flow_decorator_resolution():
    from scanner.static.prompt_injection_flow import PromptInjectionFlow
    plugin = PromptInjectionFlow()
    temp_dir = tempfile.mkdtemp()
    try:
        os.makedirs(os.path.join(temp_dir, "app"), exist_ok=True)
        framework = """
class Flask:
    def post(self, route):
        def decorator(f):
            return f
        return decorator
"""
        app_file = """
from .framework import Flask
app = Flask()
"""
        handler = """
from .app_file import app
@app.post("/chat")
def chat_handler(request):
    user_input = request
    prompt = f"User message: {user_input}"
    return llm_generate(prompt)

def llm_generate(text):
    return text
"""
        with open(os.path.join(temp_dir, "app", "framework.py"), "w", encoding="utf-8") as f:
            f.write(framework)
        with open(os.path.join(temp_dir, "app", "app_file.py"), "w", encoding="utf-8") as f:
            f.write(app_file)
        with open(os.path.join(temp_dir, "app", "handler.py"), "w", encoding="utf-8") as f:
            f.write(handler)

        findings = plugin.run(temp_dir)
        assert len(findings) >= 1
    finally:
        shutil.rmtree(temp_dir)

def test_prompt_injection_flow_fallback_warning():
    from scanner.static.prompt_injection_flow import PromptInjectionFlow
    plugin = PromptInjectionFlow()
    temp_dir = tempfile.mkdtemp()
    try:
        code = """
def route(func):
    return func

@route
def chat_handler(request):
    user_input = request
    prompt = f"User message: {user_input}"
    return llm_generate(prompt)

def llm_generate(text):
    return text
"""
        with open(os.path.join(temp_dir, "bad.py"), "w", encoding="utf-8") as f:
            f.write(code)
        
        import sys
        from io import StringIO
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            findings = plugin.run(temp_dir)
            captured = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout

        assert "handler detection fell back to name-matching for chat_handler" in captured
        assert len(findings) >= 1
    finally:
        shutil.rmtree(temp_dir)

def test_prompt_injection_flow_deep_hop_limit():
    from scanner.static.prompt_injection_flow import PromptInjectionFlow
    plugin = PromptInjectionFlow()
    temp_dir = tempfile.mkdtemp()
    try:
        code = """
def h1(request):
    h2(request)

def h2(x): h3(x)
def h3(x): h4(x)
def h4(x): h5(x)
def h5(x): h6(x)
def h6(x): h7(x)
def h7(x): h8(x)
def h8(x): h9(x)
def h9(x):
    prompt = f"User message: {x}"
    return llm_generate(prompt)

def llm_generate(text):
    return text
"""
        with open(os.path.join(temp_dir, "bad.py"), "w", encoding="utf-8") as f:
            f.write(code)

        import sys
        from io import StringIO
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            findings = plugin.run(temp_dir)
            captured = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout

        assert "taint tracking hop limit (8) reached from request" in captured
    finally:
        shutil.rmtree(temp_dir)






