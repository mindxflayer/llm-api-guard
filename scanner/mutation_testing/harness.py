import os
import ast
import json
import logging
import tempfile
from scanner.core import PluginLoader, Runner
from scanner.mutation_testing.mutate import (
    rename_identifiers,
    extract_to_helper,
    convert_dict_access_style,
    wrap_in_try_except,
    change_string_formatting_style,
)

logger = logging.getLogger("llm-api-guard")

MUTATION_TRANSFORMS = [
    ("rename_identifiers", rename_identifiers),
    ("extract_to_helper", extract_to_helper),
    ("convert_dict_access_style", convert_dict_access_style),
    ("wrap_in_try_except", wrap_in_try_except),
    ("change_string_formatting_style", change_string_formatting_style),
]

def run_mutation_testing(rule_names: list[str] = None) -> dict:
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    samples_dir = os.path.join(base_dir, "tests", "samples")
    plugins_dir = os.path.join(base_dir, "scanner", "static")

    loader = PluginLoader()
    plugin_classes = loader.load_plugins(plugins_dir)
    plugin_map = {}
    for p in plugin_classes:
        p_name = getattr(p, "name", p.__name__)
        plugin_map[p_name] = p

    if rule_names is None:
        if os.path.exists(samples_dir):
            rule_names = [
                d for d in os.listdir(samples_dir)
                if os.path.isdir(os.path.join(samples_dir, d)) and os.path.exists(os.path.join(samples_dir, d, "bad.py"))
            ]
        else:
            rule_names = []

    report = {
        "summary": {
            "total_rules": 0,
            "total_mutants": 0,
            "total_killed": 0,
            "total_survived": 0,
            "overall_kill_rate": 0.0
        },
        "rules": {}
    }

    grand_total_mutants = 0
    grand_total_killed = 0
    grand_total_survived = 0

    for rule_name in rule_names:
        bad_fixture_path = os.path.join(samples_dir, rule_name, "bad.py")
        if not os.path.exists(bad_fixture_path):
            logger.warning(f"Fixture bad.py for rule '{rule_name}' not found at {bad_fixture_path}")
            continue

        plugin_cls = plugin_map.get(rule_name)
        if not plugin_cls:
            logger.warning(f"Plugin for rule '{rule_name}' not found in static plugins")
            continue

        try:
            with open(bad_fixture_path, "r", encoding="utf-8") as f:
                original_source = f.read()
        except Exception as e:
            logger.error(f"Failed to read fixture {bad_fixture_path}: {e}")
            continue

        rule_report = {
            "kill_rate": 0.0,
            "total_mutants": 0,
            "killed": 0,
            "survived": 0,
            "techniques": {}
        }

        rule_mutants = 0
        rule_killed = 0
        rule_survived = 0

        for tech_name, transform_fn in MUTATION_TRANSFORMS:
            try:
                mutated_source = transform_fn(original_source)
            except Exception as e:
                logger.error(f"Transform {tech_name} failed on rule '{rule_name}': {e}")
                mutated_source = original_source

            is_mutated = (mutated_source != original_source)
            is_valid_python = False
            if is_mutated:
                try:
                    ast.parse(mutated_source)
                    is_valid_python = True
                except Exception:
                    is_valid_python = False

            if not is_mutated or not is_valid_python:
                rule_report["techniques"][tech_name] = {
                    "status": "skipped_noop",
                    "killed": 0,
                    "survived": 0
                }
                continue

            rule_mutants += 1
            grand_total_mutants += 1

            with tempfile.TemporaryDirectory() as temp_dir:
                temp_file = os.path.join(temp_dir, "bad.py")
                with open(temp_file, "w", encoding="utf-8") as f:
                    f.write(mutated_source)

                config = {
                    "severity_threshold": "low",
                    "checks": {rule_name: True}
                }
                runner = Runner([plugin_cls], config=config)
                findings = runner.run(temp_dir)

                killed = any(f.rule == rule_name for f in findings) or (len(findings) > 0)

                if killed:
                    rule_killed += 1
                    grand_total_killed += 1
                    rule_report["techniques"][tech_name] = {
                        "status": "killed",
                        "killed": 1,
                        "survived": 0
                    }
                else:
                    rule_survived += 1
                    grand_total_survived += 1
                    rule_report["techniques"][tech_name] = {
                        "status": "survived",
                        "killed": 0,
                        "survived": 1
                    }

        rule_kill_rate = (rule_killed / rule_mutants * 100.0) if rule_mutants > 0 else 0.0
        rule_report["total_mutants"] = rule_mutants
        rule_report["killed"] = rule_killed
        rule_report["survived"] = rule_survived
        rule_report["kill_rate"] = round(rule_kill_rate, 2)

        report["rules"][rule_name] = rule_report

    overall_kill_rate = (grand_total_killed / grand_total_mutants * 100.0) if grand_total_mutants > 0 else 0.0
    report["summary"] = {
        "total_rules": len(report["rules"]),
        "total_mutants": grand_total_mutants,
        "total_killed": grand_total_killed,
        "total_survived": grand_total_survived,
        "overall_kill_rate": round(overall_kill_rate, 2)
    }

    benchmarks_dir = os.path.join(base_dir, "benchmarks")
    os.makedirs(benchmarks_dir, exist_ok=True)
    report_file = os.path.join(benchmarks_dir, "mutation_report.json")

    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    return report
