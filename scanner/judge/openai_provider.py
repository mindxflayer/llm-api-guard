import os
from scanner.judge.base import JudgeProvider, JudgeResult


class OpenAIJudgeProvider(JudgeProvider):

    def __init__(self, model: str, api_key_env: str = "OPENAI_API_KEY", timeout_seconds: int = 30, max_retries: int = 2):
        self.model = model
        self.api_key_env = api_key_env
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries

    def judge(self, finding_context: dict) -> JudgeResult:
        api_key = os.environ.get(self.api_key_env)
        if not api_key:
            return JudgeResult(
                verdict="needs_human_review",
                confidence=0,
                exploit_explanation="OpenAI API key is missing from environment",
                suggested_fix=""
            )

        try:
            from openai import OpenAI
        except ImportError:
            return JudgeResult(
                verdict="needs_human_review",
                confidence=0,
                exploit_explanation="OpenAI SDK is not installed",
                suggested_fix=""
            )

        client = OpenAI(api_key=api_key, timeout=self.timeout_seconds, max_retries=self.max_retries)
        
        prompt = (
            f"Analyze the following security finding context and return a verdict:\n"
            f"Rule: {finding_context.get('rule')}\n"
            f"Message: {finding_context.get('message')}\n"
            f"Location: {finding_context.get('location')}\n"
            f"Context details: {finding_context.get('context_val') or finding_context.get('snippet') or finding_context.get('transcript')}\n"
        )

        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a precise security reviewer judge."},
                    {"role": "user", "content": prompt}
                ],
                tools=[{
                    "type": "function",
                    "function": {
                        "name": "submit_judgment",
                        "description": "Submit a structured security judgment for a finding.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "verdict": {
                                    "type": "string",
                                    "enum": ["true_positive", "false_positive", "needs_human_review"]
                                },
                                "confidence": {
                                    "type": "integer",
                                    "minimum": 0,
                                    "maximum": 100
                                },
                                "exploit_explanation": {
                                    "type": "string"
                                },
                                "suggested_fix": {
                                    "type": "string"
                                },
                                "severity_adjustment": {
                                    "type": "string",
                                    "enum": ["info", "low", "medium", "high", "critical", "unset"]
                                }
                            },
                            "required": ["verdict", "confidence", "exploit_explanation", "suggested_fix"]
                        }
                    }
                }],
                tool_choice={"type": "function", "function": {"name": "submit_judgment"}}
            )

            tc = None
            choice = response.choices[0]
            if choice.message and choice.message.tool_calls:
                for call in choice.message.tool_calls:
                    if call.function and call.function.name == "submit_judgment":
                        tc = call
                        break

            if not tc:
                return JudgeResult(
                    verdict="needs_human_review",
                    confidence=0,
                    exploit_explanation="OpenAI model did not call the submit_judgment function",
                    suggested_fix=""
                )

            import json
            args = json.loads(tc.function.arguments)
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
                    exploit_explanation="OpenAI response was missing required fields",
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
                exploit_explanation=f"OpenAI API call failed: {e}",
                suggested_fix=""
            )
