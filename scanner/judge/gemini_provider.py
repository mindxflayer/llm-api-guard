import json
import os
from scanner.judge.base import JudgeProvider, JudgeResult


class GeminiJudgeProvider(JudgeProvider):

    def __init__(self, model: str, api_key_env: str = "GEMINI_API_KEY", timeout_seconds: int = 30, max_retries: int = 2):
        self.model = model
        self.api_key_env = api_key_env
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.provider_name = "gemini"

    def judge(self, finding_context: dict) -> JudgeResult:
        api_key = os.environ.get(self.api_key_env)
        if not api_key:
            return JudgeResult(
                verdict="needs_human_review",
                confidence=0,
                exploit_explanation="Gemini API key is missing from environment",
                suggested_fix=""
            )

        try:
            import google.generativeai as genai
            from google.generativeai.types import GenerationConfig
        except ImportError:
            return JudgeResult(
                verdict="needs_human_review",
                confidence=0,
                exploit_explanation="Google Generative AI SDK is not installed",
                suggested_fix=""
            )

        genai.configure(api_key=api_key)

        prompt = (
            f"Analyze the following security finding context and return a verdict:\n"
            f"Rule: {finding_context.get('rule')}\n"
            f"Message: {finding_context.get('message')}\n"
            f"Location: {finding_context.get('location')}\n"
            f"Context details: {finding_context.get('context_val') or finding_context.get('snippet') or finding_context.get('transcript')}\n"
        )

        schema = {
            "type": "OBJECT",
            "properties": {
                "verdict": {
                    "type": "STRING",
                    "enum": ["true_positive", "false_positive", "needs_human_review"]
                },
                "confidence": {
                    "type": "INTEGER"
                },
                "exploit_explanation": {
                    "type": "STRING"
                },
                "suggested_fix": {
                    "type": "STRING"
                },
                "severity_adjustment": {
                    "type": "STRING",
                    "enum": ["info", "low", "medium", "high", "critical", "unset"]
                }
            },
            "required": ["verdict", "confidence", "exploit_explanation", "suggested_fix"]
        }

        try:
            model = genai.GenerativeModel(self.model)
            config = GenerationConfig(
                response_mime_type="application/json",
                response_schema=schema,
                candidate_count=1
            )
            response = model.generate_content(
                prompt,
                generation_config=config,
                request_options={"timeout": float(self.timeout_seconds)}
            )

            if not response.text:
                return JudgeResult(
                    verdict="needs_human_review",
                    confidence=0,
                    exploit_explanation="Gemini response text was empty",
                    suggested_fix=""
                )

            args = json.loads(response.text)
            verdict = args.get("verdict")
            confidence = args.get("confidence")
            exploit_explanation = args.get("exploit_explanation")
            suggested_fix = args.get("suggested_fix")
            severity_adjustment = args.get("severity_adjustment")

            if severity_adjustment == "unset":
                severity_adjustment = None

            if not verdict or confidence is None or exploit_explanation is None or suggested_fix is None:
                return JudgeResult(
                    verdict="needs_human_review",
                    confidence=0,
                    exploit_explanation="Gemini response was missing required fields",
                    suggested_fix=""
                )

            if verdict not in ("true_positive", "false_positive", "needs_human_review"):
                verdict = "needs_human_review"

            try:
                confidence = int(confidence)
            except (ValueError, TypeError):
                confidence = 0

            return JudgeResult(
                verdict=str(verdict),
                confidence=int(confidence),
                exploit_explanation=str(exploit_explanation),
                suggested_fix=str(suggested_fix),
                severity_adjustment=severity_adjustment
            )

        except Exception as e:
            return JudgeResult(
                verdict="needs_human_review",
                confidence=0,
                exploit_explanation=f"Gemini API call failed: {e}",
                suggested_fix=""
            )
