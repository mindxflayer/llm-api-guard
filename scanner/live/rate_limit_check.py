from scanner.core import Plugin, Finding
from scanner.live.throttle import ThrottledRequester

class RateLimitCheck(Plugin):
    name = "rate_limit_check"
    severity = "medium"
    owasp_ref = "LLM04"

    def __init__(self, num_requests: int = 15):
        self.num_requests = num_requests

    def run(self, target) -> list[Finding]:
        url = target.url if hasattr(target, "url") else target.get("url")
        headers = target.headers if hasattr(target, "headers") else target.get("headers", {})

        requester = ThrottledRequester(max_requests=self.num_requests)
        has_rate_limit = False
        unreachable = False

        for _ in range(self.num_requests):
            res = requester.get(url, headers=headers)
            if res is None:
                stats = requester.get_stats()
                if stats["requests_failed"] > 0:
                    unreachable = True
                break

            if res.status_code == 429:
                has_rate_limit = True
                break

            for k in res.headers.keys():
                k_lower = k.lower()
                if k_lower.startswith("x-ratelimit-") or k_lower == "retry-after":
                    has_rate_limit = True
                    break
            if has_rate_limit:
                break

        findings = []
        if unreachable:
            findings.append(Finding(
                rule="rate_limit_check",
                severity="low",
                message=f"Target {url} is unreachable / connection failed during rate limit check.",
                location="live-scanning"
            ))
        elif not has_rate_limit:
            findings.append(Finding(
                rule="rate_limit_check",
                severity=self.severity,
                message=f"No rate limiting observed within {self.num_requests} requests at {url}.",
                location="live-scanning"
            ))
        return findings
