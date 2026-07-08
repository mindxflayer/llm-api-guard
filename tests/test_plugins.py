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
