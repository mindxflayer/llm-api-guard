import os
from unittest.mock import MagicMock, patch
from scanner.judge.base import JudgeResult
from scanner.judge.anthropic_provider import AnthropicJudgeProvider
from scanner.judge.openai_provider import OpenAIJudgeProvider
from scanner.judge.gemini_provider import GeminiJudgeProvider
from scanner.judge.local_openai_compatible_provider import LocalOpenAICompatibleJudgeProvider


class MockBlock:

    def __init__(self, block_type, name, input_data):
        self.type = block_type
        self.name = name
        self.input = input_data


class MockResponseAnthropic:

    def __init__(self, content):
        self.content = content


class MockResponseOpenAI:

    def __init__(self, choice_data):
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

        tc = [MockCall(MockFunction(choice_data))]
        msg = MockMessage(tc)
        self.choices = [MockChoice(msg)]


class MockResponseGemini:

    def __init__(self, text_val):
        self.text = text_val


def test_all_providers_shape_parity():
    os.environ["DUMMY_KEY"] = "sk-dummy"
    try:
        anthropic_prov = AnthropicJudgeProvider(model="claude-sonnet", api_key_env="DUMMY_KEY")
        mock_anthropic_client = MagicMock()
        mock_anthropic_client.messages.create.return_value = MockResponseAnthropic([
            MockBlock("tool_use", "submit_judgment", {
                "verdict": "true_positive",
                "confidence": 90,
                "exploit_explanation": "explanation",
                "suggested_fix": "fix",
                "severity_adjustment": "high"
            })
        ])
        with patch("anthropic.Anthropic", return_value=mock_anthropic_client):
            res = anthropic_prov.judge({"rule": "r"})
            assert isinstance(res, JudgeResult)
            assert res.verdict == "true_positive"
            assert res.confidence == 90
            assert res.exploit_explanation == "explanation"
            assert res.suggested_fix == "fix"
            assert res.severity_adjustment == "high"

        openai_prov = OpenAIJudgeProvider(model="gpt-4o", api_key_env="DUMMY_KEY")
        mock_openai_client = MagicMock()
        import json
        mock_openai_client.chat.completions.create.return_value = MockResponseOpenAI(
            json.dumps({
                "verdict": "false_positive",
                "confidence": 80,
                "exploit_explanation": "exp",
                "suggested_fix": "fix2",
                "severity_adjustment": "low"
            })
        )
        with patch("openai.OpenAI", return_value=mock_openai_client):
            res = openai_prov.judge({"rule": "r"})
            assert isinstance(res, JudgeResult)
            assert res.verdict == "false_positive"
            assert res.confidence == 80
            assert res.exploit_explanation == "exp"
            assert res.suggested_fix == "fix2"
            assert res.severity_adjustment == "low"

        gemini_prov = GeminiJudgeProvider(model="gemini-1.5-pro", api_key_env="DUMMY_KEY")
        mock_gemini_response = MockResponseGemini(
            json.dumps({
                "verdict": "needs_human_review",
                "confidence": 50,
                "exploit_explanation": "exp3",
                "suggested_fix": "fix3",
                "severity_adjustment": "medium"
            })
        )
        mock_gemini_model = MagicMock()
        mock_gemini_model.generate_content.return_value = mock_gemini_response
        with patch("google.generativeai.GenerativeModel", return_value=mock_gemini_model), patch("google.generativeai.configure"):
            res = gemini_prov.judge({"rule": "r"})
            assert isinstance(res, JudgeResult)
            assert res.verdict == "needs_human_review"
            assert res.confidence == 50
            assert res.exploit_explanation == "exp3"
            assert res.suggested_fix == "fix3"
            assert res.severity_adjustment == "medium"

        local_prov = LocalOpenAICompatibleJudgeProvider(
            model="llama-3",
            base_url="http://localhost:11434/v1",
            api_key_env="DUMMY_KEY"
        )
        mock_local_client = MagicMock()
        mock_local_client.chat.completions.create.return_value = MockResponseOpenAI(
            json.dumps({
                "verdict": "true_positive",
                "confidence": 95,
                "exploit_explanation": "exp4",
                "suggested_fix": "fix4",
                "severity_adjustment": "unset"
            })
        )
        with patch("openai.OpenAI", return_value=mock_local_client):
            res = local_prov.judge({"rule": "r"})
            assert isinstance(res, JudgeResult)
            assert res.verdict == "true_positive"
            assert res.confidence == 95
            assert res.exploit_explanation == "exp4"
            assert res.suggested_fix == "fix4"
            assert res.severity_adjustment is None

    finally:
        if "DUMMY_KEY" in os.environ:
            del os.environ["DUMMY_KEY"]
