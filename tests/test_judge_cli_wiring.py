import os
import json
import pytest
from unittest.mock import MagicMock, patch
from scanner.core import Runner, Finding
from scanner.judge import build_judge_provider
from scanner.judge.base import NoOpProvider
from scanner.judge.anthropic_provider import AnthropicJudgeProvider
from scanner.judge.openai_provider import OpenAIJudgeProvider

def test_build_judge_provider_none_and_no_llm_verify():
    config = {
        "judge": {
            "enabled": True,
            "provider": "openai",
            "model": "gpt-4",
            "api_key_env": "OPENAI_API_KEY",
        }
    }
    
    p = build_judge_provider(config, {"no_llm_verify": True})
    assert isinstance(p, NoOpProvider)
    
    p = build_judge_provider(config, {"judge_provider": "none"})
    assert isinstance(p, NoOpProvider)

def test_build_judge_provider_override():
    config = {
        "judge": {
            "enabled": True,
            "provider": "openai",
            "model": "gpt-4",
            "api_key_env": "OPENAI_API_KEY",
        }
    }
    p = build_judge_provider(config, {"judge_provider": "anthropic"})
    assert isinstance(p, AnthropicJudgeProvider)
    assert p.model == "gpt-4"

def test_no_llm_verify_prevents_outbound_and_sdk_instantiation():
    config = {
        "judge": {
            "enabled": True,
            "provider": "openai",
            "model": "gpt-4",
            "api_key_env": "OPENAI_API_KEY",
        }
    }
    
    cli_overrides = {"no_llm_verify": True}
    
    with patch("openai.OpenAI") as mock_openai, \
         patch("anthropic.Anthropic") as mock_anthropic, \
         patch("google.generativeai.configure") as mock_gemini:
         
        provider = build_judge_provider(config, cli_overrides)
        assert isinstance(provider, NoOpProvider)
        
        runner = Runner(plugins=[], config=config, judge_provider=provider)
        res = runner.judge_provider.judge({"rule": "test", "snippet": "sk-12345678901234567890"})
        
        assert mock_openai.call_count == 0
        assert mock_anthropic.call_count == 0
        assert mock_gemini.call_count == 0

def test_redact_before_send():
    config = {
        "judge": {
            "enabled": True,
            "provider": "openai",
            "model": "gpt-4",
            "api_key_env": "OPENAI_API_KEY",
        }
    }
    
    cli_overrides = {
        "judge_provider": "openai",
        "redact_before_send": True
    }
    
    os.environ["OPENAI_API_KEY"] = "dummy"
    
    mock_client = MagicMock()
    
    class MockFunction:
        def __init__(self, name, arguments):
            self.name = name
            self.arguments = arguments
            
    class MockToolCall:
        def __init__(self, fn_name, fn_args):
            self.function = MockFunction(fn_name, fn_args)
            self.type = "function"
            
    class MockMessage:
        def __init__(self, tool_calls):
            self.tool_calls = tool_calls
            self.content = None
            
    class MockChoice:
        def __init__(self, message):
            self.message = message
            
    class MockCompletionsResponse:
        def __init__(self, choices):
            self.choices = choices
            
    dummy_args = json.dumps({
        "verdict": "true_positive",
        "confidence": 95,
        "exploit_explanation": "exp",
        "suggested_fix": "fix"
    })
    tool_call = MockToolCall("submit_judgment", dummy_args)
    msg = MockMessage([tool_call])
    choice = MockChoice(msg)
    response = MockCompletionsResponse([choice])
    
    mock_client.chat.completions.create.return_value = response
    
    with patch("openai.OpenAI", return_value=mock_client):
        provider = build_judge_provider(config, cli_overrides)
        assert provider.redact_before_send is True
        
        finding_context = {
            "rule": "test_rule",
            "message": "Context information with secret: sk-12345678901234567890",
            "snippet": "secret = 'sk-12345678901234567890'\n# This is a comment\nx = \"hello world\""
        }
        
        res = provider.judge(finding_context)
        
        called_args = mock_client.chat.completions.create.call_args
        assert called_args is not None
        
        messages = called_args[1]["messages"]
        user_message_content = messages[1]["content"]
        
        assert "sk-12345678901234567890" not in user_message_content
        assert "This is a comment" not in user_message_content
        assert "hello world" not in user_message_content
        assert "[REDACTED_SECRET]" in user_message_content
        assert "[REDACTED_COMMENT]" in user_message_content
        assert "[REDACTED_STRING]" in user_message_content
