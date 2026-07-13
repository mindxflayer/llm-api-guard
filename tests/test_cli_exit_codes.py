import pytest
from scanner.core import Finding
from cli import determine_exit_code

def test_no_fail_on_exits_zero():
    findings = [Finding(rule="r1", severity="high", message="m1", location="l1")]
    code, summary = determine_exit_code(findings, fail_on=None)
    assert code == 0
    assert summary == ""

def test_fail_on_severity_exceeds_exits_one():
    findings = [Finding(rule="r1", severity="high", message="m1", location="l1")]
    code, summary = determine_exit_code(findings, fail_on="medium")
    assert code == 1
    assert "failing (exit 1)" in summary

def test_fail_on_severity_below_exits_zero():
    findings = [Finding(rule="r1", severity="medium", message="m1", location="l1")]
    code, summary = determine_exit_code(findings, fail_on="high")
    assert code == 0
    assert "passing (exit 0)" in summary

def test_fail_on_suppressed_ignored():
    findings = [
        Finding(rule="r1", severity="high", message="m1", location="l1", suppressed=True)
    ]
    code, summary = determine_exit_code(findings, fail_on="medium")
    assert code == 0
    assert "passing (exit 0)" in summary

def test_fail_on_new_without_baseline_usage_error():
    findings = []
    code, summary = determine_exit_code(findings, fail_on="high", fail_on_new=True, baseline_provided=False)
    assert code == 1
    assert "Usage error" in summary

def test_fail_on_new_with_baseline():
    baseline_set = {("r1", "l1")}
    findings_matching = [
        Finding(rule="r1", severity="high", message="m1", location="l1", suppressed=True)
    ]
    code, summary = determine_exit_code(
        findings_matching,
        fail_on="high",
        fail_on_new=True,
        baseline_provided=True,
        baseline_set=baseline_set
    )
    assert code == 0
    assert "passing (exit 0)" in summary

    findings_new = [
        Finding(rule="r2", severity="high", message="m2", location="l2")
    ]
    code2, summary2 = determine_exit_code(
        findings_new,
        fail_on="high",
        fail_on_new=True,
        baseline_provided=True,
        baseline_set=baseline_set
    )
    assert code2 == 1
    assert "failing (exit 1)" in summary2
