# Ground Truth Labels Schema

Each repository label file should be named `<repo_name>.yaml` in this directory.

```yaml
# Schema:
# findings:
#   - rule: string (matches static plugin rule name, e.g. "hardcoded_keys")
#     location: string (file path or file:line matching scanner finding location)
#     is_true_positive: bool (true if genuine security vulnerability, false if verified benign/false positive)
#     notes: string (detailed justification for the true/false label)
findings: []
```
