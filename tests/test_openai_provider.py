import os
import json
from unittest.mock import MagicMock, patch
from scanner.judge.openai_provider import OpenAIJudgeProvider
from scanner.judge.base import JudgeResult


class MockChoice:

    def __init__(self, msg):
        self.message = msg


class MockMessage:

    def __init__(self, tc):
        self.tool_calls = tc


class MockCall:

    def __init__(self, func):
        self.function = func


class MockFunction:

    def __init__(self, args):
        self.name = "submit_judgment"
        self.arguments = args


class MockResponseOpenAI:

    def __init__(self, choice_data):
        tc = [MockCall(MockFunction(choice_data))]
        self.choices = [MockChoice(MockMessage(tc))]


def test_openai_provider_success():
    env_name = "TEST_OPENAI_KEY"
    env_val = "sk-test-123"
    os.environ[env_name] = env_val

    try:
        provider = OpenAIJudgeProvider(
            model="gpt-4o",
            api_key_env=env_name,
            timeout_seconds=45,
            max_retries=3
        )

        mock_client = MagicMock()
        mock_response = MockResponseOpenAI(json.dumps({
            "verdict": "true_positive",
            "confidence": 95,
            "exploit_explanation": "expos",
            "suggested_fix": "fixos",
            "severity_adjustment": "medium"
        }))
        mock_client.chat.completions.create.return_value = mock_response

        with patch("openai.OpenAI", return_value=mock_client) as mock_openai_cls:
            res = provider.judge({"rule": "test"})
            mock_openai_cls.assert_called_once_with(api_key=env_val, timeout=45, max_retries=3)
            assert isinstance(res, JudgeResult)
            assert res.verdict == "true_positive"
            assert res.confidence == 95
            assert res.severity_adjustment == "medium"

    finally:
        if env_name in os.environ:
            del os.environ[env_name]


def test_openai_provider_missing_key():
    provider = OpenAIJudgeProvider(model="gpt-4o", api_key_env="NON_EXISTENT_KEY_VAR_123")
    res = provider.judge({"rule": "test"})
    assert isinstance(res, JudgeResult)
    assert res.verdict == "needs_human_review"
    assert res.confidence == 0
    assert "missing" in res.exploit_explanation.lower()


def test_openai_provider_malformed_response():
    env_name = "TEST_OPENAI_KEY"
    os.environ[env_name] = "dummy"

    try:
        provider = OpenAIJudgeProvider(model="gpt-4o", api_key_env=env_name)
        mock_client = MagicMock()
        mock_response = MockResponseOpenAI(json.dumps({
            "verdict": "true_positive"
        }))
        mock_client.chat.completions.create.return_value = mock_response

        with patch("openai.OpenAI", return_value=mock_client):
            res = provider.judge({"rule": "test"})
            assert isinstance(res, JudgeResult)
            assert res.verdict == "needs_human_review"
            assert res.confidence == 0
            assert "missing required fields" in res.exploit_explanation.lower()

    finally:
        if env_name in os.environ:
            del os.environ[env_name]


def test_openai_provider_api_error():
    env_name = "TEST_OPENAI_KEY"
    os.environ[env_name] = "dummy"

    try:
        provider = OpenAIJudgeProvider(model="gpt-4o", api_key_env=env_name)
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = Exception("OpenAI API rate limit exceeded")

        with patch("openai.OpenAI", return_value=mock_client):
            res = provider.judge({"rule": "test"})
            assert isinstance(res, JudgeResult)
            assert res.verdict == "needs_human_review"
            assert res.confidence == 0
            assert "rate limit exceeded" in res.exploit_explanation.lower()

    finally:
        if env_name in os.environ:
            del os.environ[env_name]
