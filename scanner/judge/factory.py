from scanner.judge.base import NoOpProvider, JudgeProvider
from scanner.judge.anthropic_provider import AnthropicJudgeProvider
from scanner.judge.openai_provider import OpenAIJudgeProvider
from scanner.judge.gemini_provider import GeminiJudgeProvider
from scanner.judge.local_openai_compatible_provider import LocalOpenAICompatibleJudgeProvider

def build_judge_provider(config: dict, cli_overrides: dict) -> JudgeProvider:
    judge_cfg = config.get("judge", {})
    no_llm_verify = cli_overrides.get("no_llm_verify", False)
    
    provider_name = cli_overrides.get("judge_provider")
    if provider_name is None:
        if no_llm_verify:
            provider_name = "none"
        else:
            provider_name = judge_cfg.get("provider", "none")
    elif no_llm_verify:
        provider_name = "none"
        
    if provider_name == "none":
        return NoOpProvider()
        
    model = cli_overrides.get("judge_model")
    if model is None:
        model = judge_cfg.get("model", "")
        
    base_url = cli_overrides.get("judge_base_url")
    if base_url is None:
        base_url = judge_cfg.get("base_url")
        
    timeout = judge_cfg.get("timeout_seconds", 30)
    max_retries = judge_cfg.get("max_retries", 2)
    api_key_env = judge_cfg.get("api_key_env")
    
    if provider_name == "anthropic":
        env_var = api_key_env or "ANTHROPIC_API_KEY"
        provider = AnthropicJudgeProvider(
            model=model,
            api_key_env=env_var,
            timeout_seconds=timeout,
            max_retries=max_retries
        )
    elif provider_name == "openai":
        env_var = api_key_env or "OPENAI_API_KEY"
        provider = OpenAIJudgeProvider(
            model=model,
            api_key_env=env_var,
            timeout_seconds=timeout,
            max_retries=max_retries
        )
    elif provider_name == "gemini":
        env_var = api_key_env or "GEMINI_API_KEY"
        provider = GeminiJudgeProvider(
            model=model,
            api_key_env=env_var,
            timeout_seconds=timeout,
            max_retries=max_retries
        )
    elif provider_name == "local":
        env_var = api_key_env or "OPENAI_API_KEY"
        provider = LocalOpenAICompatibleJudgeProvider(
            model=model,
            base_url=base_url or "http://localhost:8000/v1",
            api_key_env=env_var,
            timeout_seconds=timeout,
            max_retries=max_retries
        )
    else:
        return NoOpProvider()
        
    redact_before_send = cli_overrides.get("redact_before_send")
    if redact_before_send is None:
        redact_before_send = judge_cfg.get("redact_before_send", False)
    provider.redact_before_send = bool(redact_before_send)
    
    return provider
