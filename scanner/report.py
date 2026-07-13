import json
from dataclasses import asdict
from scanner.core import Finding

HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Security Scan Report</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #333; margin: 20px; line-height: 1.5; }
  h1 { border-bottom: 2px solid #eee; padding-bottom: 10px; }
  .summary { background: #f9f9f9; padding: 15px; border-radius: 5px; margin-bottom: 20px; border: 1px solid #ddd; }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin-top: 10px; }
  .stat-card { padding: 10px; border-radius: 4px; text-align: center; font-weight: bold; border: 1px solid; }
  .stat-critical { background: #ffebeb; border-color: #ffc2c2; color: #cc0000; }
  .stat-high { background: #fff3e6; border-color: #ffe0b2; color: #e65100; }
  .stat-medium { background: #fffde7; border-color: #fff9c4; color: #f57f17; }
  .stat-low { background: #f0f4c3; border-color: #e6ee9c; color: #827717; }
  .stat-total { background: #f5f5f5; border-color: #e0e0e0; color: #333; }
  .category-group { margin-top: 30px; }
  .category-header { background: #eaeaea; padding: 8px 12px; font-weight: bold; font-size: 1.1em; border-radius: 4px; }
  .finding-table { width: 100%; border-collapse: collapse; margin-top: 10px; }
  .finding-table th, .finding-table td { padding: 8px 12px; border: 1px solid #ddd; text-align: left; vertical-align: top; }
  .finding-table th { background: #f5f5f5; }
  .finding-row-suppressed { opacity: 0.6; background-color: #fafafa; }
  .suppressed-badge { display: inline-block; background-color: #e0e0e0; color: #666; font-size: 0.8em; padding: 2px 6px; border-radius: 4px; font-weight: bold; text-transform: uppercase; }
  .badge { display: inline-block; font-size: 0.85em; padding: 3px 8px; border-radius: 4px; font-weight: bold; text-transform: uppercase; }
  .badge-critical { background: #ffebeb; color: #cc0000; }
  .badge-high { background: #fff3e6; color: #e65100; }
  .badge-medium { background: #fffde7; color: #f57f17; }
  .badge-low { background: #f0f4c3; color: #827717; }
</style>
</head>
<body>
  <h1>Security Scan Report</h1>
  <div class="summary">
    <h2>Summary</h2>
    <div class="summary-grid">
      <div class="stat-card stat-total">Total: {{ total_count }}</div>
      <div class="stat-card stat-critical">Critical: {{ critical_count }}</div>
      <div class="stat-card stat-high">High: {{ high_count }}</div>
      <div class="stat-card stat-medium">Medium: {{ medium_count }}</div>
      <div class="stat-card stat-low">Low: {{ low_count }}</div>
    </div>
    {% if baseline_used %}
    <div style="margin-top: 15px; font-weight: bold;">
      Baseline Stats: {{ new_count }} new, {{ baselined_count }} baselined
    </div>
    {% endif %}
  </div>

  {% for category, cat_findings in groups.items() %}
    <div class="category-group">
      <div class="category-header">{{ category or "Uncategorized" }}</div>
      <table class="finding-table">
        <thead>
          <tr>
            <th style="width: 10%;">Severity</th>
            <th style="width: 15%;">Rule</th>
            <th style="width: 50%;">Message</th>
            <th style="width: 25%;">Location</th>
          </tr>
        </thead>
        <tbody>
          {% for f in cat_findings %}
            <tr class="{% if f.suppressed %}finding-row-suppressed{% endif %}">
              <td>
                <span class="badge badge-{{ f.severity.lower() }}">{{ f.severity }}</span>
                {% if f.suppressed %}
                  <div style="margin-top: 5px;"><span class="suppressed-badge">Suppressed</span></div>
                {% endif %}
              </td>
              <td><code>{{ f.rule }}</code></td>
              <td>{{ f.message }}</td>
              <td><code>{{ f.location }}</code></td>
            </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  {% endfor %}
</body>
</html>
"""

def write_json_report(findings: list[Finding], output_path: str) -> None:
    summary = {
        "total": len(findings),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }
    serialized_findings = []
    for f in findings:
        severity = f.severity.lower()
        summary[severity] = summary.get(severity, 0) + 1
        serialized_findings.append(asdict(f))
        
    report = {
        "summary": summary,
        "findings": serialized_findings
    }
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

def write_html_report(findings: list[Finding], output_path: str, baseline_used: bool = False, baselined_count: int = 0) -> None:
    from jinja2 import Template
    
    total_count = len(findings)
    severities = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.severity.lower()
        if sev in severities:
            severities[sev] += 1
            
    groups = {}
    for f in findings:
        ref = f.owasp_ref or "Uncategorized"
        if ref not in groups:
            groups[ref] = []
        groups[ref].append(f)
        
    new_count = total_count - baselined_count
    
    template = Template(HTML_TEMPLATE)
    rendered = template.render(
        total_count=total_count,
        critical_count=severities["critical"],
        high_count=severities["high"],
        medium_count=severities["medium"],
        low_count=severities["low"],
        baseline_used=baseline_used,
        new_count=new_count,
        baselined_count=baselined_count,
        groups=groups
    )
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(rendered)
