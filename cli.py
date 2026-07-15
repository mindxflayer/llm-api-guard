import os
import argparse
import sys
from scanner.core import load_config, PluginLoader, Runner, LiveTarget, Finding
from scanner.report import write_json_report, write_html_report, write_sarif_report
from scanner.live import confirm_authorization
from scanner.baseline import load_baseline, save_baseline, filter_new_findings

def determine_exit_code(findings: list[Finding], fail_on: str = None, fail_on_new: bool = False, baseline_provided: bool = False, baseline_set: set = None) -> tuple[int, str]:
    if fail_on_new and not baseline_provided:
        return 1, "Usage error: --fail-on-new requires --baseline to be provided."
        
    if not fail_on:
        return 0, ""
        
    severities = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    threshold = severities.get(fail_on.lower(), 1)
    
    failing_findings = []
    for f in findings:
        if f.suppressed:
            continue
        if fail_on_new and baseline_set and (f.rule, f.location) in baseline_set:
            continue
        f_val = severities.get(f.severity.lower(), 1)
        if f_val >= threshold:
            failing_findings.append(f)
            
    if failing_findings:
        highest = "low"
        for f in failing_findings:
            if severities.get(f.severity.lower(), 1) > severities.get(highest, 1):
                highest = f.severity.lower()
        summary = f"Result: {len(failing_findings)} new {highest}-severity findings at or above threshold '{fail_on}' — failing (exit 1)"
        return 1, summary
    else:
        summary = f"Result: no findings at or above threshold '{fail_on}' — passing (exit 0)"
        return 0, summary

def run_repo_scan(args):
    if getattr(args, "config", None) and not os.path.exists(args.config):
        print(f"Error: Config file '{args.config}' does not exist.")
        sys.exit(1)
        
    if getattr(args, "repo", None) and not os.path.exists(args.repo):
        print(f"Error: Repo path '{args.repo}' does not exist.")
        sys.exit(1)
        
    if getattr(args, "fail_on_new", False) and not getattr(args, "baseline", None):
        print("Usage error: --fail-on-new requires --baseline to be provided.")
        sys.exit(1)
        
    config = load_config(args.config)
    loader = PluginLoader()
    base_dir = os.path.dirname(os.path.abspath(__file__))
    plugins_dir = os.path.join(base_dir, "scanner", "static")
    
    plugins = loader.load_plugins(plugins_dir)
    
    cli_overrides = {
        "judge_provider": getattr(args, "judge_provider", None),
        "judge_model": getattr(args, "judge_model", None),
        "judge_base_url": getattr(args, "judge_base_url", None),
        "no_llm_verify": getattr(args, "no_llm_verify", False),
        "redact_before_send": getattr(args, "redact_before_send", False)
    }
    from scanner.judge import build_judge_provider
    judge_provider = build_judge_provider(config, cli_overrides)
    
    runner = Runner(
        plugins,
        config=config,
        judge_provider=judge_provider,
        target_description=getattr(args, "target_description", None),
        fast_mode=getattr(args, "fast_mode", False)
    )
    findings = runner.run(args.repo)
    
    baseline_used = bool(getattr(args, "baseline", None))
    baselined_count = 0
    if baseline_used:
        baseline_set = load_baseline(args.baseline)
        new_findings = filter_new_findings(findings, baseline_set)
        for f in findings:
            if f not in new_findings:
                f.suppressed = True
                baselined_count += 1
                
    if getattr(args, "save_baseline", None):
        save_baseline(findings, args.save_baseline)
        print(f"Baseline saved to: {args.save_baseline}")
        
    fmt_str = getattr(args, "format", "json").lower()
    if fmt_str == "both":
        formats = ["json", "html"]
    else:
        formats = [f.strip() for f in fmt_str.split(",") if f.strip()]
        
    output_base, _ = os.path.splitext(args.output)
    written_reports = []
    
    for fmt in formats:
        if fmt == "json":
            out_file = f"{output_base}.json" if len(formats) > 1 or fmt_str != "json" else args.output
            write_json_report(findings, out_file)
            written_reports.append(out_file)
        elif fmt == "html":
            html_out = f"{output_base}.html"
            write_html_report(findings, html_out, baseline_used=baseline_used, baselined_count=baselined_count)
            written_reports.append(html_out)
        elif fmt == "sarif":
            sarif_out = f"{output_base}.sarif"
            write_sarif_report(findings, sarif_out)
            written_reports.append(sarif_out)
            
    if len(written_reports) == 1:
        print(f"Report written to: {written_reports[0]}")
    elif len(written_reports) > 1:
        print(f"Reports written to: {', '.join(written_reports)}")
    
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.severity.lower()
        summary[sev] = summary.get(sev, 0) + 1
        
    print(f"Scan complete. Total findings: {len(findings)}")
    print(f"Severity breakdown: Critical={summary['critical']}, High={summary['high']}, Medium={summary['medium']}, Low={summary['low']}")
    
    code, exit_summary = determine_exit_code(
        findings=findings,
        fail_on=getattr(args, "fail_on", None),
        fail_on_new=getattr(args, "fail_on_new", False),
        baseline_provided=baseline_used,
        baseline_set=load_baseline(args.baseline) if baseline_used else None
    )
    if exit_summary:
        print(exit_summary)
    if getattr(args, "fail_on", None) is not None:
        sys.exit(code)

def run_url_scan(args):
    if getattr(args, "config", None) and not os.path.exists(args.config):
        print(f"Error: Config file '{args.config}' does not exist.")
        sys.exit(1)
        
    if getattr(args, "url", None):
        from urllib.parse import urlparse
        parsed = urlparse(args.url)
        if not parsed.scheme or not parsed.netloc:
            print(f"Error: Invalid URL '{args.url}'. URL must include a scheme (e.g. http:// or https://).")
            sys.exit(1)
            
    if getattr(args, "fail_on_new", False) and not getattr(args, "baseline", None):
        print("Usage error: --fail-on-new requires --baseline to be provided.")
        sys.exit(1)
        
    config = load_config(args.config)
    
    headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                key, val = h.split(":", 1)
                headers[key.strip()] = val.strip()
            else:
                headers[h.strip()] = ""
                
    if not confirm_authorization(args.url, interactive=True, permission_flag=args.i_have_permission):
        print("Scan refused: Live scanning requires authorization.")
        sys.exit(1)

    cli_overrides = {
        "judge_provider": getattr(args, "judge_provider", None),
        "judge_model": getattr(args, "judge_model", None),
        "judge_base_url": getattr(args, "judge_base_url", None),
        "no_llm_verify": getattr(args, "no_llm_verify", False),
        "redact_before_send": getattr(args, "redact_before_send", False)
    }
    from scanner.judge import build_judge_provider
    judge_provider = build_judge_provider(config, cli_overrides)

    target = LiveTarget(url=args.url, headers=headers)
    loader = PluginLoader()
    base_dir = os.path.dirname(os.path.abspath(__file__))
    plugins_dir = os.path.join(base_dir, "scanner", "live")
    
    plugins = loader.load_plugins(plugins_dir)
    runner = Runner(
        plugins,
        config=config,
        judge_provider=judge_provider,
        target_description=getattr(args, "target_description", None),
        fast_mode=getattr(args, "fast_mode", False),
        payload_tier=getattr(args, "payload_tier", "basic")
    )
    findings = runner.run(target)
    
    baseline_used = bool(getattr(args, "baseline", None))
    baselined_count = 0
    if baseline_used:
        baseline_set = load_baseline(args.baseline)
        new_findings = filter_new_findings(findings, baseline_set)
        for f in findings:
            if f not in new_findings:
                f.suppressed = True
                baselined_count += 1
                
    if getattr(args, "save_baseline", None):
        save_baseline(findings, args.save_baseline)
        print(f"Baseline saved to: {args.save_baseline}")
        
    fmt_str = getattr(args, "format", "json").lower()
    if fmt_str == "both":
        formats = ["json", "html"]
    else:
        formats = [f.strip() for f in fmt_str.split(",") if f.strip()]
        
    output_base, _ = os.path.splitext(args.output)
    written_reports = []
    
    for fmt in formats:
        if fmt == "json":
            out_file = f"{output_base}.json" if len(formats) > 1 or fmt_str != "json" else args.output
            write_json_report(findings, out_file)
            written_reports.append(out_file)
        elif fmt == "html":
            html_out = f"{output_base}.html"
            write_html_report(findings, html_out, baseline_used=baseline_used, baselined_count=baselined_count)
            written_reports.append(html_out)
        elif fmt == "sarif":
            sarif_out = f"{output_base}.sarif"
            write_sarif_report(findings, sarif_out)
            written_reports.append(sarif_out)
            
    if len(written_reports) == 1:
        print(f"Report written to: {written_reports[0]}")
    elif len(written_reports) > 1:
        print(f"Reports written to: {', '.join(written_reports)}")
    
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.severity.lower()
        summary[sev] = summary.get(sev, 0) + 1
        
    print(f"Scan complete. Total findings: {len(findings)}")
    print(f"Severity breakdown: Critical={summary['critical']}, High={summary['high']}, Medium={summary['medium']}, Low={summary['low']}")
    
    code, exit_summary = determine_exit_code(
        findings=findings,
        fail_on=getattr(args, "fail_on", None),
        fail_on_new=getattr(args, "fail_on_new", False),
        baseline_provided=baseline_used,
        baseline_set=load_baseline(args.baseline) if baseline_used else None
    )
    if exit_summary:
        print(exit_summary)
    if getattr(args, "fail_on", None) is not None:
        sys.exit(code)

def main():
    parser = argparse.ArgumentParser(
        description="llm-api-guard - Plugin-based security scanner for LLM-powered APIs",
        epilog="""Examples:
  llm-api-guard repo --repo .
  llm-api-guard url --url https://api.example.com/chat --i-have-permission""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--version",
        action="version",
        version="llm-api-guard 0.1.0",
        help="Show program's version number and exit"
    )
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        help="Scanner subcommands"
    )
    
    repo_parser = subparsers.add_parser("repo", help="Scan a local repository / codebase path")
    repo_parser.add_argument("--repo", required=True, help="Path to the local repository code to scan")
    repo_parser.add_argument("--config", default="scanner/config.yaml", help="Path to the configuration YAML file")
    repo_parser.add_argument("--output", default="report.json", help="Path to write the report findings")
    repo_parser.add_argument("--baseline", help="Path to baseline JSON file for filtering existing findings")
    repo_parser.add_argument("--save-baseline", help="Path to save baseline JSON file")
    repo_parser.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], help="Severity threshold to trigger a non-zero exit code")
    repo_parser.add_argument("--fail-on-new", action="store_true", help="Only fail on new findings not present in the baseline")
    repo_parser.add_argument("--format", default="json", help="Report output formats (supports comma-separated list, e.g. json,html,sarif)")
    repo_parser.add_argument("--judge-provider", choices=["anthropic", "openai", "gemini", "local", "none"], help="Override config judge provider")
    repo_parser.add_argument("--judge-model", help="Override config judge model")
    repo_parser.add_argument("--judge-base-url", help="Override config judge base URL (meaningful for local provider only)")
    repo_parser.add_argument("--no-llm-verify", action="store_true", help="Force judge provider to 'none' and make zero outbound calls")
    repo_parser.add_argument("--redact-before-send", action="store_true", help="Redact code context, comments, and secrets before judge analysis")
    repo_parser.add_argument("--target-description", help="Description of the target context/purpose for LLM judge")
    repo_parser.add_argument("--fast-mode", action="store_true", help="Enable lightweight pre-filtering to skip obviously clean responses")
    
    url_parser = subparsers.add_parser("url", help="Scan a live API url")
    url_parser.add_argument("--url", required=True, help="URL of the live LLM API endpoint to scan")
    url_parser.add_argument("--header", action="append", help="HTTP header to include in live scanning checks (e.g. 'Authorization: Bearer token')")
    url_parser.add_argument("--config", default="scanner/config.yaml", help="Path to the configuration YAML file")
    url_parser.add_argument("--output", default="report.json", help="Path to write the report findings")
    url_parser.add_argument("--i-have-permission", action="store_true", help="Authorize the live scan immediately without prompt")
    url_parser.add_argument("--payload-tier", choices=["basic", "mutated", "full"], default="basic", help="Payload tier for prompt injection checks")
    url_parser.add_argument("--checks", default="live", help="Type of checks to run")
    url_parser.add_argument("--baseline", help="Path to baseline JSON file for filtering existing findings")
    url_parser.add_argument("--save-baseline", help="Path to save baseline JSON file")
    url_parser.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], help="Severity threshold to trigger a non-zero exit code")
    url_parser.add_argument("--fail-on-new", action="store_true", help="Only fail on new findings not present in the baseline")
    url_parser.add_argument("--format", default="json", help="Report output formats (supports comma-separated list, e.g. json,html,sarif)")
    url_parser.add_argument("--judge-provider", choices=["anthropic", "openai", "gemini", "local", "none"], help="Override config judge provider")
    url_parser.add_argument("--judge-model", help="Override config judge model")
    url_parser.add_argument("--judge-base-url", help="Override config judge base URL (meaningful for local provider only)")
    url_parser.add_argument("--no-llm-verify", action="store_true", help="Force judge provider to 'none' and make zero outbound calls")
    url_parser.add_argument("--redact-before-send", action="store_true", help="Redact code context, comments, and secrets before judge analysis")
    url_parser.add_argument("--target-description", help="Description of the target context/purpose for LLM judge")
    url_parser.add_argument("--fast-mode", action="store_true", help="Enable lightweight pre-filtering to skip obviously clean responses")
    
    args = parser.parse_args()
    
    if args.command == "repo":
        run_repo_scan(args)
    elif args.command == "url":
        run_url_scan(args)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
