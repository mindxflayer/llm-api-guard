import os
import shutil
import tempfile
import pytest
from scanner.core import Plugin, Finding, PluginLoader, Runner

def test_plugin_loader_discovery():
    temp_dir = tempfile.mkdtemp()
    try:
        plugin_code = """
from scanner.core import Plugin, Finding

class DummyPlugin(Plugin):
    name = "dummy_plugin"
    severity = "low"
    owasp_ref = "LLM01"
    
    def run(self, target: str) -> list[Finding]:
        return [Finding("dummy_rule", "low", "Test find", target)]
"""
        plugin_file = os.path.join(temp_dir, "dummy_plugin.py")
        with open(plugin_file, "w") as f:
            f.write(plugin_code)
            
        loader = PluginLoader()
        plugins = loader.load_plugins(temp_dir)
        
        assert len(plugins) == 1
        plugin_cls = plugins[0]
        assert plugin_cls.name == "dummy_plugin"
        assert plugin_cls.severity == "low"
        assert plugin_cls.owasp_ref == "LLM01"
        
        inst = plugin_cls()
        findings = inst.run("test_target")
        assert len(findings) == 1
        assert findings[0].rule == "dummy_rule"
    finally:
        shutil.rmtree(temp_dir)

def test_runner_exception_handling():
    class SuccessPlugin(Plugin):
        name = "success"
        def run(self, target):
            return [Finding("success_rule", "info", "Success msg", target)]
            
    class BrokenPlugin(Plugin):
        name = "broken"
        def run(self, target):
            raise ValueError("Something went wrong inside the plugin")
            
    runner = Runner([SuccessPlugin(), BrokenPlugin()])
    findings = runner.run("test_target")
    
    assert len(findings) == 1
    assert findings[0].rule == "success_rule"
    assert findings[0].location == "test_target"
