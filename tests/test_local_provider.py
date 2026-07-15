import os
import json
from unittest.mock import MagicMock, patch
from scanner.judge.local_openai_compatible_provider import LocalOpenAICompatibleJudgeProvider
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


def test_local_provider_success():
    env_name = "LOCAL_KEY"
    env_val = "bearer-token"
    os.environ[env_name] = env_val

    try:
        provider = LocalOpenAICompatibleJudgeProvider(
            model="llama-3",
            base_url="http://localhost:8000/v1",
            api_key_env=env_name,
            timeout_seconds=20,
            max_retries=1
        )

        mock_client = MagicMock()
        mock_response = MockResponseOpenAI(json.dumps({
            "verdict": "true_positive",
            "confidence": 99,
            "exploit_explanation": "local_exp",
            "suggested_fix": "local_fix",
            "severity_adjustment": "critical"
        }))
        mock_client.chat.completions.create.return_value = mock_response

        with patch("openai.OpenAI", return_value=mock_client) as mock_openai_cls:
            res = provider.judge({"rule": "test"})
            mock_openai_cls.assert_called_once_with(
                api_key=env_val,
                base_url="http://localhost:8000/v1",
                timeout=20,
                max_retries=1
            )
            assert isinstance(res, JudgeResult)
            assert res.verdict == "true_positive"
            assert res.confidence == 99
            assert res.severity_adjustment == "critical"

    finally:
        if env_name in os.environ:
            del os.environ[env_name]


def test_local_provider_no_credentials():
    provider = LocalOpenAICompatibleJudgeProvider(
        model="llama-3",
        base_url="http://localhost:8000/v1"
    )

    mock_client = MagicMock()
    mock_response = MockResponseOpenAI(json.dumps({
        "verdict": "needs_human_review",
        "confidence": 10,
        "exploit_explanation": "local_exp_no_cred",
        "suggested_fix": "local_fix_no_cred"
    }))
    mock_client.chat.completions.create.return_value = mock_response

    with patch("openai.OpenAI", return_value=mock_client) as mock_openai_cls:
        res = provider.judge({"rule": "test"})
        mock_openai_cls.assert_called_once_with(
            api_key="dummy_key",
            base_url="http://localhost:8000/v1",
            timeout=30,
            max_retries=2
        )
        assert isinstance(res, JudgeResult)
        assert res.verdict == "needs_human_review"
        assert res.confidence == 10
