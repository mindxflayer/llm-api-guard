import os
import sys
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

class Runner:
    def __init__(self, plugins: list):
        self.plugins = plugins

    def run(self, target: str) -> list[Finding]:
        all_findings = []
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
                logger.info(f"Running plugin: {plugin_name}")
                findings = plugin_instance.run(target)
                if findings:
                    from scanner.redact import redact_finding
                    all_findings.extend([redact_finding(f) for f in findings])
            except Exception as e:
                name = getattr(plugin_instance or plugin_item, "name", str(plugin_item))
                logger.exception(f"Plugin {name} failed with an unhandled exception: {e}")
        
        return all_findings
