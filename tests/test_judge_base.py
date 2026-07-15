from scanner.judge.base import NoOpProvider, JudgeResult


def test_noop_provider_returns_default():
    provider = NoOpProvider()
    result = provider.judge({"rule": "test_rule", "message": "Test Finding"})
    assert isinstance(result, JudgeResult)
    assert result.verdict == "needs_human_review"
    assert result.confidence == 0
    assert "disabled" in result.exploit_explanation
    assert result.suggested_fix == ""
    assert result.severity_adjustment is None
