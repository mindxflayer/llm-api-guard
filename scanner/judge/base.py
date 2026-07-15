from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class JudgeResult:
    verdict: str
    confidence: int
    exploit_explanation: str
    suggested_fix: str
    severity_adjustment: str | None = None


class JudgeProvider(ABC):

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if "judge" in cls.__dict__:
            orig_judge = cls.judge
            def wrapped_judge(self, finding_context: dict) -> JudgeResult:
                provider_name = getattr(self, "provider_name", "none")
                if provider_name == "none":
                    return orig_judge(self, finding_context)

                model_name = getattr(self, "model", "unknown")
                rule = finding_context.get("rule", "")
                snippet = (
                    finding_context.get("code_snippet") or
                    finding_context.get("snippet") or
                    finding_context.get("transcript") or
                    finding_context.get("context_val") or
                    ""
                )
                context = (
                    finding_context.get("context") or
                    finding_context.get("message") or
                    finding_context.get("location") or
                    ""
                )

                from scanner.judge.cache import cache_key, JudgeCache
                key = cache_key(rule, snippet, context, provider_name, model_name)
                cache = JudgeCache()
                cached_res = cache.get(key)
                if cached_res is not None:
                    return cached_res

                res = orig_judge(self, finding_context)
                if res is not None:
                    if res.verdict == "needs_human_review" and res.confidence == 0:
                        pass
                    else:
                        cache.set(key, res)
                return res

            cls.judge = wrapped_judge

    @abstractmethod
    def judge(self, finding_context: dict) -> JudgeResult:
        pass


class NoOpProvider(JudgeProvider):

    def judge(self, finding_context: dict) -> JudgeResult:
        return JudgeResult(
            verdict="needs_human_review",
            confidence=0,
            exploit_explanation="LLM verification was disabled",
            suggested_fix="",
            severity_adjustment=None
        )
