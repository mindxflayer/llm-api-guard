import os
from unittest.mock import MagicMock
from scanner.judge.base import JudgeResult, JudgeProvider
from scanner.judge.cache import cache_key, JudgeCache


def test_cache_key_generation():
    k1 = cache_key("rule1", "snippet1", "context1", "provider1", "model1")
    k2 = cache_key("rule1", "snippet1", "context1", "provider1", "model1")
    assert k1 == k2

    assert k1 != cache_key("rule2", "snippet1", "context1", "provider1", "model1")
    assert k1 != cache_key("rule1", "snippet2", "context1", "provider1", "model1")
    assert k1 != cache_key("rule1", "snippet1", "context2", "provider1", "model1")
    assert k1 != cache_key("rule1", "snippet1", "context1", "provider2", "model1")
    assert k1 != cache_key("rule1", "snippet1", "context1", "provider1", "model2")


def test_cache_get_set_roundtrip():
    cache = JudgeCache()
    key = "test_key_roundtrip_123"
    path = cache._get_path(key)
    if os.path.exists(path):
        os.remove(path)

    assert cache.get(key) is None

    result = JudgeResult(
        verdict="true_positive",
        confidence=90,
        exploit_explanation="Exploit description",
        suggested_fix="Fix code",
        severity_adjustment="medium"
    )

    cache.set(key, result)
    retrieved = cache.get(key)
    assert retrieved is not None
    assert retrieved.verdict == result.verdict
    assert retrieved.confidence == result.confidence
    assert retrieved.exploit_explanation == result.exploit_explanation
    assert retrieved.suggested_fix == result.suggested_fix
    assert retrieved.severity_adjustment == result.severity_adjustment

    if os.path.exists(path):
        os.remove(path)


class DummyMockProvider(JudgeProvider):

    def __init__(self, provider_name, model):
        self.provider_name = provider_name
        self.model = model
        self.mock_judge = MagicMock()

    def judge(self, finding_context: dict) -> JudgeResult:
        return self.mock_judge(finding_context)


def test_cache_mock_provider_call_count():
    cache = JudgeCache()
    provider = DummyMockProvider("mock_prov", "mock_model")
    expected = JudgeResult("true_positive", 80, "exp", "fix")
    provider.mock_judge.return_value = expected

    context = {"rule": "r", "snippet": "snip", "message": "msg"}

    k = cache_key("r", "snip", "msg", "mock_prov", "mock_model")
    path = cache._get_path(k)
    if os.path.exists(path):
        os.remove(path)

    res1 = provider.judge(context)
    assert res1.verdict == "true_positive"
    assert provider.mock_judge.call_count == 1

    res2 = provider.judge(context)
    assert res2.verdict == "true_positive"
    assert provider.mock_judge.call_count == 1

    if os.path.exists(path):
        os.remove(path)


def test_cache_different_provider_or_model():
    cache = JudgeCache()
    context = {"rule": "r", "snippet": "snip", "message": "msg"}

    k1 = cache_key("r", "snip", "msg", "prov_a", "model_x")
    k2 = cache_key("r", "snip", "msg", "prov_b", "model_x")
    k3 = cache_key("r", "snip", "msg", "prov_a", "model_y")

    for k in (k1, k2, k3):
        p = cache._get_path(k)
        if os.path.exists(p):
            os.remove(p)

    provider_a = DummyMockProvider("prov_a", "model_x")
    provider_b = DummyMockProvider("prov_b", "model_x")
    provider_c = DummyMockProvider("prov_a", "model_y")

    r1 = JudgeResult("true_positive", 80, "exp1", "fix1")
    r2 = JudgeResult("false_positive", 20, "exp2", "fix2")
    r3 = JudgeResult("needs_human_review", 50, "exp3", "fix3")

    provider_a.mock_judge.return_value = r1
    provider_b.mock_judge.return_value = r2
    provider_c.mock_judge.return_value = r3

    res_a = provider_a.judge(context)
    assert res_a.verdict == "true_positive"
    assert provider_a.mock_judge.call_count == 1

    res_b = provider_b.judge(context)
    assert res_b.verdict == "false_positive"
    assert provider_b.mock_judge.call_count == 1

    res_c = provider_c.judge(context)
    assert res_c.verdict == "needs_human_review"
    assert provider_c.mock_judge.call_count == 1

    for k in (k1, k2, k3):
        p = cache._get_path(k)
        if os.path.exists(p):
            os.remove(p)
