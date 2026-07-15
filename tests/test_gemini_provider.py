import os
import json
from unittest.mock import MagicMock, patch
from scanner.judge.gemini_provider import GeminiJudgeProvider
from scanner.judge.base import JudgeResult


class MockResponseGemini:

    def __init__(self, text_val):
        self.text = text_val


def test_gemini_provider_success():
    env_name = "TEST_GEMINI_KEY"
    env_val = "ai-test-123"
    os.environ[env_name] = env_val

    try:
        provider = GeminiJudgeProvider(
            model="gemini-1.5",
            api_key_env=env_name,
            timeout_seconds=40,
            max_retries=3
        )

        mock_response = MockResponseGemini(json.dumps({
            "verdict": "false_positive",
            "confidence": 85,
            "exploit_explanation": "gem_exp",
            "suggested_fix": "gem_fix",
            "severity_adjustment": "low"
        }))
        mock_model = MagicMock()
        mock_model.generate_content.return_value = mock_response

        with patch("google.generativeai.GenerativeModel", return_value=mock_model) as mock_model_cls, patch("google.generativeai.configure") as mock_configure:
            res = provider.judge({"rule": "test"})
            mock_configure.assert_called_once_with(api_key=env_val)
            mock_model_cls.assert_called_once_with("gemini-1.5")
            
            assert isinstance(res, JudgeResult)
            assert res.verdict == "false_positive"
            assert res.confidence == 85
            assert res.exploit_explanation == "gem_exp"
            assert res.suggested_fix == "gem_fix"
            assert res.severity_adjustment == "low"

    finally:
        if env_name in os.environ:
            del os.environ[env_name]


def test_gemini_provider_missing_key():
    provider = GeminiJudgeProvider(model="gemini-1.5", api_key_env="NON_EXISTENT_KEY_VAR_123")
    res = provider.judge({"rule": "test"})
    assert isinstance(res, JudgeResult)
    assert res.verdict == "needs_human_review"
    assert res.confidence == 0
    assert "missing" in res.exploit_explanation.lower()


def test_gemini_provider_malformed_response():
    env_name = "TEST_GEMINI_KEY"
    os.environ[env_name] = "dummy"

    try:
        provider = GeminiJudgeProvider(model="gemini-1.5", api_key_env=env_name)
        mock_response = MockResponseGemini("")
        mock_model = MagicMock()
        mock_model.generate_content.return_value = mock_response

        with patch("google.generativeai.GenerativeModel", return_value=mock_model), patch("google.generativeai.configure"):
            res = provider.judge({"rule": "test"})
            assert isinstance(res, JudgeResult)
            assert res.verdict == "needs_human_review"
            assert res.confidence == 0
            assert "empty" in res.exploit_explanation.lower()

    finally:
        if env_name in os.environ:
            del os.environ[env_name]


def test_gemini_provider_api_error():
    env_name = "TEST_GEMINI_KEY"
    os.environ[env_name] = "dummy"

    try:
        provider = GeminiJudgeProvider(model="gemini-1.5", api_key_env=env_name)
        mock_model = MagicMock()
        mock_model.generate_content.side_effect = Exception("Gemini API rate limit exceeded")

        with patch("google.generativeai.GenerativeModel", return_value=mock_model), patch("google.generativeai.configure"):
            res = provider.judge({"rule": "test"})
            assert isinstance(res, JudgeResult)
            assert res.verdict == "needs_human_review"
            assert res.confidence == 0
            assert "rate limit exceeded" in res.exploit_explanation.lower()

    finally:
        if env_name in os.environ:
            del os.environ[env_name]
