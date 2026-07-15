import os
from unittest.mock import MagicMock, patch
from scanner.judge.anthropic_provider import AnthropicJudgeProvider
from scanner.judge.base import JudgeResult


class MockBlock:

    def __init__(self, block_type, name, input_data):
        self.type = block_type
        self.name = name
        self.input = input_data


class MockResponse:

    def __init__(self, content):
        self.content = content


def test_anthropic_provider_success():
    env_name = "TEST_ANTHROPIC_KEY"
    env_val = "sk-test-123456789"
    os.environ[env_name] = env_val

    try:
        provider = AnthropicJudgeProvider(
            model="claude-sonnet-5",
            api_key_env=env_name,
            timeout_seconds=45,
            max_retries=3
        )

        mock_client = MagicMock()
        mock_response = MockResponse([
            MockBlock("text", None, None),
            MockBlock("tool_use", "submit_judgment", {
                "verdict": "true_positive",
                "confidence": 92,
                "exploit_explanation": "Contains prompt injection payload",
                "suggested_fix": "Implement strict validation schema",
                "severity_adjustment": "high"
            })
        ])
        mock_client.messages.create.return_value = mock_response

        with patch("anthropic.Anthropic", return_value=mock_client) as mock_auth_cls:
            res = provider.judge({"rule": "test", "message": "msg"})
            mock_auth_cls.assert_called_once_with(api_key=env_val, timeout=45, max_retries=3)

            assert isinstance(res, JudgeResult)
            assert res.verdict == "true_positive"
            assert res.confidence == 92
            assert res.exploit_explanation == "Contains prompt injection payload"
            assert res.suggested_fix == "Implement strict validation schema"
            assert res.severity_adjustment == "high"

    finally:
        if env_name in os.environ:
            del os.environ[env_name]


def test_anthropic_provider_custom_api_key_env():
    env_name = "MY_SPECIAL_KEY_VAR"
    env_val = "sk-special-value"
    os.environ[env_name] = env_val

    try:
        provider = AnthropicJudgeProvider(
            model="claude-sonnet-5",
            api_key_env=env_name
        )

        mock_client = MagicMock()
        mock_response = MockResponse([
            MockBlock("tool_use", "submit_judgment", {
                "verdict": "false_positive",
                "confidence": 80,
                "exploit_explanation": "Safe mock snippet",
                "suggested_fix": "None"
            })
        ])
        mock_client.messages.create.return_value = mock_response

        with patch("anthropic.Anthropic", return_value=mock_client) as mock_auth_cls:
            res = provider.judge({"rule": "test"})
            mock_auth_cls.assert_called_once_with(api_key=env_val, timeout=30, max_retries=2)
            assert res.verdict == "false_positive"
            assert res.confidence == 80
            assert res.severity_adjustment is None

    finally:
        if env_name in os.environ:
            del os.environ[env_name]


def test_anthropic_provider_missing_api_key():
    provider = AnthropicJudgeProvider(
        model="claude-sonnet-5",
        api_key_env="NON_EXISTENT_API_KEY_VAR_123"
    )
    res = provider.judge({"rule": "test"})
    assert isinstance(res, JudgeResult)
    assert res.verdict == "needs_human_review"
    assert res.confidence == 0
    assert "missing" in res.exploit_explanation.lower()


def test_anthropic_provider_malformed_response():
    env_name = "TEST_ANTHROPIC_KEY"
    os.environ[env_name] = "dummy_key"

    try:
        provider = AnthropicJudgeProvider(
            model="claude-sonnet-5",
            api_key_env=env_name
        )

        mock_client = MagicMock()
        mock_response = MockResponse([
            MockBlock("tool_use", "submit_judgment", {
                "verdict": "true_positive"
            })
        ])
        mock_client.messages.create.return_value = mock_response

        with patch("anthropic.Anthropic", return_value=mock_client):
            res = provider.judge({"rule": "test"})
            assert isinstance(res, JudgeResult)
            assert res.verdict == "needs_human_review"
            assert res.confidence == 0
            assert "missing required fields" in res.exploit_explanation.lower()

    finally:
        if env_name in os.environ:
            del os.environ[env_name]


def test_anthropic_provider_no_tool_called():
    env_name = "TEST_ANTHROPIC_KEY"
    os.environ[env_name] = "dummy_key"

    try:
        provider = AnthropicJudgeProvider(
            model="claude-sonnet-5",
            api_key_env=env_name
        )

        mock_client = MagicMock()
        mock_response = MockResponse([
            MockBlock("text", None, None)
        ])
        mock_client.messages.create.return_value = mock_response

        with patch("anthropic.Anthropic", return_value=mock_client):
            res = provider.judge({"rule": "test"})
            assert isinstance(res, JudgeResult)
            assert res.verdict == "needs_human_review"
            assert res.confidence == 0
            assert "did not call" in res.exploit_explanation.lower()

    finally:
        if env_name in os.environ:
            del os.environ[env_name]


def test_anthropic_provider_api_error_graceful_handling():
    env_name = "TEST_ANTHROPIC_KEY"
    os.environ[env_name] = "dummy_key"

    try:
        provider = AnthropicJudgeProvider(
            model="claude-sonnet-5",
            api_key_env=env_name
        )

        mock_client = MagicMock()
        mock_client.messages.create.side_effect = Exception("Anthropic API rate limit reached")

        with patch("anthropic.Anthropic", return_value=mock_client):
            res = provider.judge({"rule": "test"})
            assert isinstance(res, JudgeResult)
            assert res.verdict == "needs_human_review"
            assert res.confidence == 0
            assert "rate limit reached" in res.exploit_explanation.lower()

    finally:
        if env_name in os.environ:
            del os.environ[env_name]
