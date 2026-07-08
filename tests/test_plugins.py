import os
import shutil
import tempfile
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


