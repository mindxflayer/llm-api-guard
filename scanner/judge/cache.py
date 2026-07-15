import hashlib
import json
import os
from scanner.judge.base import JudgeResult


def cache_key(rule: str, code_snippet: str, context: str, provider: str, model: str) -> str:
    payload = f"{rule}\n{code_snippet}\n{context}\n{provider}\n{model}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class JudgeCache:

    def __init__(self):
        self.cache_dir = os.path.expanduser("~/.cache/llm-api-guard/judge")
        os.makedirs(self.cache_dir, exist_ok=True)

    def _get_path(self, key: str) -> str:
        return os.path.join(self.cache_dir, f"{key}.json")

    def get(self, key: str) -> JudgeResult | None:
        path = self._get_path(key)
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return JudgeResult(
                verdict=data["verdict"],
                confidence=int(data["confidence"]),
                exploit_explanation=data["exploit_explanation"],
                suggested_fix=data["suggested_fix"],
                severity_adjustment=data.get("severity_adjustment")
            )
        except Exception:
            return None

    def set(self, key: str, result: JudgeResult) -> None:
        path = self._get_path(key)
        try:
            data = {
                "verdict": result.verdict,
                "confidence": result.confidence,
                "exploit_explanation": result.exploit_explanation,
                "suggested_fix": result.suggested_fix,
                "severity_adjustment": result.severity_adjustment
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            pass
