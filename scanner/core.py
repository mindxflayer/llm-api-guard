import os
import sys
import yaml
import inspect
import logging
import importlib.util
from abc import ABC, abstractmethod
from dataclasses import dataclass

logger = logging.getLogger("llm-api-guard")

@dataclass
class Finding:
    rule: str
    severity: str
    message: str
    location: str
    suppressed: bool = False
    owasp_ref: str = ""
    priority: str = "normal"

@dataclass
class LiveTarget:
    url: str
    headers: dict = None

class Plugin(ABC):

    name: str = ""
    severity: str = ""
    owasp_ref: str = ""

    @abstractmethod
    def run(self, target: str) -> list[Finding]:
        pass

class PluginLoader:
    def load_plugins(self, directory: str) -> list[type[Plugin]]:
        plugins = []
        if not os.path.exists(directory) or not os.path.isdir(directory):
            logger.warning(f"Plugin directory does not exist or is not a directory: {directory}")
            return plugins

        abs_dir = os.path.abspath(directory)
        if abs_dir not in sys.path:
            sys.path.insert(0, abs_dir)

        try:
            for filename in os.listdir(abs_dir):
                if filename.endswith(".py") and filename != "__init__.py":
                    filepath = os.path.join(abs_dir, filename)
                    module_name = f"scanner.dynamic_plugins.{filename[:-3]}"
                    
                    try:
                        spec = importlib.util.spec_from_file_location(module_name, filepath)
                        if spec is None or spec.loader is None:
                            continue
                        module = importlib.util.module_from_spec(spec)
                        sys.modules[module_name] = module
                        spec.loader.exec_module(module)
                    except Exception as e:
                        logger.error(f"Failed to load plugin module from {filepath}: {e}", exc_info=True)
                        continue

                    for attribute_name in dir(module):
                        attribute = getattr(module, attribute_name)
                        if (
                            inspect.isclass(attribute)
                            and issubclass(attribute, Plugin)
                            and attribute is not Plugin
                        ):
                            plugins.append(attribute)
        finally:
            if abs_dir in sys.path:
                sys.path.remove(abs_dir)

        return plugins

def load_config(path: str) -> dict:
    if not os.path.exists(path):
        raise ValueError(f"Config file not found at: {path}")
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
    except Exception as e:
        raise ValueError(f"Failed to parse config YAML: {e}")

    if not isinstance(data, dict):
        raise ValueError("Invalid config structure: must be a dict")

    if "severity_threshold" not in data:
        raise ValueError("Missing required key: severity_threshold")
    if data["severity_threshold"] not in ("low", "medium", "high", "critical"):
        raise ValueError(f"Invalid severity_threshold: {data['severity_threshold']}")

    if "checks" not in data:
        raise ValueError("Missing required key: checks")
    if not isinstance(data["checks"], dict):
        raise ValueError("checks must be a dictionary")

    for k, v in data["checks"].items():
        if not isinstance(v, bool):
            raise ValueError(f"Check status for {k} must be boolean")

    if "live_checks" not in data:
        raise ValueError("Missing required key: live_checks")
    if not isinstance(data["live_checks"], dict):
        raise ValueError("live_checks must be a dictionary")

    for k, v in data["live_checks"].items():
        if not isinstance(v, bool):
            raise ValueError(f"Check status for {k} must be boolean")

    return data

def filter_findings_by_severity(findings: list[Finding], threshold: str) -> list[Finding]:
    severities = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    threshold_val = severities.get(threshold.lower(), 1)
    
    filtered = []
    for f in findings:
        f_sev = severities.get(f.severity.lower(), 1)
        if f_sev >= threshold_val:
            filtered.append(f)
    return filtered

class Runner:
    def __init__(self, plugins: list, config: dict = None):
        self.plugins = plugins
        self.config = config

    def run(self, target) -> list[Finding]:
        all_findings = []
        checks = None
        
        is_live = False
        if hasattr(target, "url") or (isinstance(target, dict) and "url" in target):
            is_live = True

        if self.config:
            if is_live:
                checks = self.config.get("live_checks", {})
            else:
                checks = self.config.get("checks", {})

        for plugin_item in self.plugins:
            plugin_instance = None
            try:
                if isinstance(plugin_item, type) and issubclass(plugin_item, Plugin):
                    plugin_instance = plugin_item()
                elif isinstance(plugin_item, Plugin):
                    plugin_instance = plugin_item
                else:
                    logger.warning(f"Skipping invalid plugin item: {plugin_item}")
                    continue

                plugin_name = getattr(plugin_instance, "name", plugin_instance.__class__.__name__)
                if checks is not None:
                    if plugin_name not in checks or not checks[plugin_name]:
                        continue

                logger.info(f"Running plugin: {plugin_name}")
                findings = plugin_instance.run(target)
                if findings:
                    from scanner.redact import redact_finding
                    from scanner.baseline import check_inline_suppression
                    for f in findings:
                        if not getattr(f, "owasp_ref", ""):
                            f.owasp_ref = getattr(plugin_instance, "owasp_ref", "")
                        if check_inline_suppression(f, target):
                            f.suppressed = True
                        all_findings.append(redact_finding(f))
            except Exception as e:
                name = getattr(plugin_instance or plugin_item, "name", str(plugin_item))
                logger.exception(f"Plugin {name} failed with an unhandled exception: {e}")
        
        if self.config and "severity_threshold" in self.config:
            all_findings = filter_findings_by_severity(all_findings, self.config["severity_threshold"])

        return all_findings
