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
