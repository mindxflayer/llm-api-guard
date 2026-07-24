import os
import ast
import json
import pytest
from scanner.mutation_testing.mutate import (
    rename_identifiers,
    extract_to_helper,
    convert_dict_access_style,
    wrap_in_try_except,
    change_string_formatting_style
)
from scanner.mutation_testing.harness import run_mutation_testing

def test_rename_identifiers_transform():
    source = "def process(val):\n    res = val + 10\n    return res\n"
    mutated = rename_identifiers(source)
    assert mutated != source
    parsed = ast.parse(mutated)
    assert isinstance(parsed, ast.AST)

def test_extract_to_helper_transform():
    source = "def compute(x):\n    a = x * 2\n    b = a + 5\n    return b\n"
    mutated = extract_to_helper(source)
    assert mutated != source
    parsed = ast.parse(mutated)
    assert isinstance(parsed, ast.AST)

def test_convert_dict_access_style_transform():
    source = "def get_val(data):\n    return data['key']\n"
    mutated = convert_dict_access_style(source)
    assert mutated != source
    parsed = ast.parse(mutated)
    assert isinstance(parsed, ast.AST)

def test_wrap_in_try_except_transform():
    source = "def do_work(x):\n    return x / 2\n"
    mutated = wrap_in_try_except(source)
    assert mutated != source
    parsed = ast.parse(mutated)
    assert isinstance(parsed, ast.AST)

def test_change_string_formatting_style_transform():
    source = "def greet(name):\n    return f'Hello {name}'\n"
    mutated = change_string_formatting_style(source)
    assert mutated != source
    parsed = ast.parse(mutated)
    assert isinstance(parsed, ast.AST)

def test_run_mutation_testing_single_rule():
    report = run_mutation_testing(["prompt_injection_flow"])
    assert "summary" in report
    assert "rules" in report
    assert "prompt_injection_flow" in report["rules"]

    rule_entry = report["rules"]["prompt_injection_flow"]
    assert "kill_rate" in rule_entry
    assert "total_mutants" in rule_entry
    assert "killed" in rule_entry
    assert "survived" in rule_entry
    assert "techniques" in rule_entry

    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    report_file = os.path.join(base_dir, "benchmarks", "mutation_report.json")
    assert os.path.exists(report_file)

    with open(report_file, "r", encoding="utf-8") as f:
        file_json = json.load(f)
    assert file_json["summary"]["total_rules"] == 1
    assert "prompt_injection_flow" in file_json["rules"]
