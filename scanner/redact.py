import re
from scanner.core import Finding
from scanner.static.hardcoded_keys import OPENAI_RE, AWS_RE, BEARER_RE, ENV_RE

def redact_secret(value: str) -> str:
    if len(value) < 8:
        return "*" * len(value)
    return value[:3] + "*" * (len(value) - 7) + value[-4:]

def redact_finding(finding: Finding) -> Finding:
    def redact_text(text: str) -> str:
        if not text:
            return text
        text = OPENAI_RE.sub(lambda m: redact_secret(m.group(0)), text)
        text = AWS_RE.sub(lambda m: redact_secret(m.group(0)), text)

        def redact_bearer(m):
            token = m.group(1)
            prefix = m.group(0)[:m.start(1)-m.start(0)]
            return prefix + redact_secret(token)
        text = BEARER_RE.sub(redact_bearer, text)

        def redact_env(m):
            name_eq = m.group(0)[:m.start(1)-m.start(0)]
            val = m.group(1)
            return name_eq + redact_secret(val)
        text = ENV_RE.sub(redact_env, text)

        return text

    return Finding(
        rule=finding.rule,
        severity=finding.severity,
        message=redact_text(finding.message),
        location=redact_text(finding.location),
        suppressed=finding.suppressed
    )
