# llm-api-guard

A plugin-based security scanner for LLM-powered APIs, modeled against the OWASP Top 10 for LLM Applications.

Version 1 targets Python codebases only for static analysis.

**Status:** Early development.

## Updating Secret Rules

The secret scanner ruleset can be periodically updated from the upstream Gitleaks project. To pull the latest rules and update the vendored `scanner/secret_rules/gitleaks.toml`, run:

```bash
python scripts/update_secret_rules.py
```

This script will download the latest rules, validate their syntax, and print a summary of rule changes.
*(Note: Periodically running this via a scheduler or CI/CD cron job is recommended, but not configured by default).*
