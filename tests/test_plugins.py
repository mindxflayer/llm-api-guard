import os
import shutil
import tempfile
from scanner.static.hardcoded_keys import HardcodedKeys
from scanner.static.unsafe_output_exec import UnsafeOutputExec

def test_hardcoded_keys_plugin():
    plugin = HardcodedKeys()
    
    temp_bad = tempfile.mkdtemp()
    try:
        shutil.copy(os.path.join("tests", "samples", "hardcoded_keys", "bad.py"), os.path.join(temp_bad, "bad.py"))
        findings_bad = plugin.run(temp_bad)
        assert len(findings_bad) >= 3
        rules = [f.rule for f in findings_bad]
        assert "openai_key" in rules
        assert "aws_key" in rules
        assert "bearer_token" in rules
    finally:
        shutil.rmtree(temp_bad)

    temp_good = tempfile.mkdtemp()
    try:
        shutil.copy(os.path.join("tests", "samples", "hardcoded_keys", "good.py"), os.path.join(temp_good, "good.py"))
        findings_good = plugin.run(temp_good)
        assert len(findings_good) == 0
    finally:
        shutil.rmtree(temp_good)

def test_unsafe_output_exec_plugin():
    plugin = UnsafeOutputExec()
    
    temp_bad = tempfile.mkdtemp()
    try:
        shutil.copy(os.path.join("tests", "samples", "unsafe_output_exec", "bad.py"), os.path.join(temp_bad, "bad.py"))
        findings_bad = plugin.run(temp_bad)
        assert len(findings_bad) == 1
        assert findings_bad[0].rule == "unsafe_output_exec"
    finally:
        shutil.rmtree(temp_bad)

    temp_good = tempfile.mkdtemp()
    try:
        shutil.copy(os.path.join("tests", "samples", "unsafe_output_exec", "good.py"), os.path.join(temp_good, "good.py"))
        findings_good = plugin.run(temp_good)
        assert len(findings_good) == 0
    finally:
        shutil.rmtree(temp_good)
