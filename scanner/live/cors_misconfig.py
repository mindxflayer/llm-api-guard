from scanner.core import Plugin, Finding
from scanner.live.throttle import ThrottledRequester

class CorsMisconfig(Plugin):
    """
    Plugin to check access control and CORS policy configurations on target LLM APIs.

    Note: CORS misconfiguration is a general web/API security check, not strictly unique
    to LLMs. However, it is especially relevant to LLM APIs that may be exposed to and
    accessed directly from browser-based environments, as it controls which origins are
    permitted to make cross-origin requests.
    """
    name = "cors_misconfig"
    severity = "medium"
    owasp_ref = "LLM02"

    def run(self, target) -> list[Finding]:
        url = target.url if hasattr(target, "url") else target.get("url")
        headers = target.headers if hasattr(target, "headers") else target.get("headers", {})
        if headers is None:
            headers = {}

        req_headers = dict(headers)
        test_origin = "https://evil-test-origin.example.com"
        req_headers["Origin"] = test_origin

        requester = ThrottledRequester(max_requests=1)
        try:
            res = requester.get(url, headers=req_headers)
        except Exception:
            res = None

        findings = []

        if res is None:
            findings.append(Finding(
                rule="cors_misconfig",
                severity="low",
                message=f"Target {url} is unreachable or connection failed during CORS check.",
                location="live-scanning"
            ))
            return findings

        acao = res.headers.get("Access-Control-Allow-Origin")
        acac = res.headers.get("Access-Control-Allow-Credentials")

        if acao is not None:
            if acao == "*":
                if acac == "true":
                    findings.append(Finding(
                        rule="cors_misconfig",
                        severity="high",
                        message=f"CORS misconfiguration at {url}: Wildcard origin allowed with credentials.",
                        location="live-scanning"
                    ))
                else:
                    findings.append(Finding(
                        rule="cors_misconfig",
                        severity="medium",
                        message=f"CORS vulnerability at {url}: Wildcard origin (*) allowed without credentials.",
                        location="live-scanning"
                    ))
            elif acao == test_origin:
                findings.append(Finding(
                    rule="cors_misconfig",
                    severity="high",
                    message=f"CORS misconfiguration at {url}: Arbitrary origin '{test_origin}' reflected and allowed.",
                    location="live-scanning"
                ))

        return findings
