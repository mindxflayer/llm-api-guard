import logging
from scanner.core import Plugin, Finding
from scanner.live.throttle import ThrottledRequester
from scanner.live.payloads import load_payloads
from scanner.live.streaming import assemble_response

logger = logging.getLogger("llm-api-guard")

class IndirectInjectionProbe(Plugin):
    name = "indirect_injection_probe"
    severity = "high"
    owasp_ref = "LLM01"

    def run(self, target) -> list[Finding]:
        url = target.url if hasattr(target, "url") else target.get("url")
        headers = target.headers if hasattr(target, "headers") else target.get("headers", {})
        if headers is None:
            headers = {}
        config_dct = getattr(self, "config", {}) or {}
        indirect_cfg = config_dct.get("indirect_injection", {})
        fixtures = indirect_cfg.get("fixtures", [])
        if not fixtures:
            logger.warning("indirect_injection_probe enabled but no fixtures configured — skipping")
            return []
        payload_tier = getattr(self, "payload_tier", "basic")
        payloads = load_payloads(tier=payload_tier)
        instruction_payloads = [p for p in payloads if p.get("category") == "instruction_override"]
        if not instruction_payloads:
            instruction_payloads = payloads[:3]
        requester = ThrottledRequester(max_requests=len(fixtures))
        findings = []
        min_conf = getattr(self, "min_confidence", 70)
        judge_prov = getattr(self, "judge_provider", None)
        for idx, fix in enumerate(fixtures):
            fix_type = fix.get("type", "document")
            trigger_field = fix.get("trigger_field", "context")
            payload_item = instruction_payloads[idx % len(instruction_payloads)]
            payload_text = payload_item["payload"]
            req_headers = dict(headers)
            json_body = {}
            if fix_type == "document":
                doc_content = fix.get("content", "")
                final_content = f"{doc_content}\n\n[INSTRUCTION]\n{payload_text}"
                json_body[trigger_field] = final_content
            elif fix_type == "url":
                json_body[trigger_field] = fix.get("url", "")
            elif fix_type == "mock_tool_response":
                mock_val = fix.get("content", "")
                final_content = f"{mock_val}\n\n[INSTRUCTION]\n{payload_text}"
                json_body[trigger_field] = final_content
            try:
                res = requester.post(url, headers=req_headers, json=json_body, stream=True)
            except Exception:
                res = None
            if res is None:
                continue
            response_text = assemble_response(res)
            if judge_prov is None:
                from scanner.judge.base import NoOpProvider
                judge_prov = NoOpProvider()
            finding_context = {
                "rule": "indirect_injection_probe",
                "message": f"Indirect prompt injection compliance detected for fixture index {idx}",
                "location": url,
                "context_val": (
                    f"Target Declared Purpose: {getattr(self, 'target_description', None) or 'A standard conversational LLM endpoint'}\n"
                    f"Attack Intent / Goal: {payload_item.get('intent', '')}\n"
                    f"Response Transcript:\n{response_text}"
                )
            }
            res_judge = judge_prov.judge(finding_context)
            if res_judge and res_judge.verdict == "true_positive" and res_judge.confidence >= min_conf:
                findings.append(Finding(
                    rule="indirect_injection_probe",
                    severity=self.severity,
                    message=res_judge.exploit_explanation,
                    location=url,
                    detection_method="llm_judge"
                ))
        return findings
