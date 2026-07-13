import os
import argparse
import sys
from scanner.core import load_config, PluginLoader, Runner, LiveTarget
from scanner.report import write_json_report
from scanner.live import confirm_authorization
from scanner.baseline import load_baseline, save_baseline, filter_new_findings

def run_repo_scan(args):
    config = load_config(args.config)
    loader = PluginLoader()
    base_dir = os.path.dirname(os.path.abspath(__file__))
    plugins_dir = os.path.join(base_dir, "scanner", "static")
    
    plugins = loader.load_plugins(plugins_dir)
    runner = Runner(plugins, config=config)
    findings = runner.run(args.repo)
    
    if getattr(args, "baseline", None):
        baseline_set = load_baseline(args.baseline)
        new_findings = filter_new_findings(findings, baseline_set)
        for f in findings:
            if f not in new_findings:
                f.suppressed = True
                
    if getattr(args, "save_baseline", None):
        save_baseline(findings, args.save_baseline)
        print(f"Baseline saved to: {args.save_baseline}")
        
    write_json_report(findings, args.output)
    
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.severity.lower()
        summary[sev] = summary.get(sev, 0) + 1
        
    print(f"Scan complete. Total findings: {len(findings)}")
    print(f"Severity breakdown: Critical={summary['critical']}, High={summary['high']}, Medium={summary['medium']}, Low={summary['low']}")
    print(f"Report written to: {args.output}")

def run_url_scan(args):
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

    target = LiveTarget(url=args.url, headers=headers)
    loader = PluginLoader()
    base_dir = os.path.dirname(os.path.abspath(__file__))
    plugins_dir = os.path.join(base_dir, "scanner", "live")
    
    plugins = loader.load_plugins(plugins_dir)
    runner = Runner(plugins, config=config)
    findings = runner.run(target)
    
    if getattr(args, "baseline", None):
        baseline_set = load_baseline(args.baseline)
        new_findings = filter_new_findings(findings, baseline_set)
        for f in findings:
            if f not in new_findings:
                f.suppressed = True
                
    if getattr(args, "save_baseline", None):
        save_baseline(findings, args.save_baseline)
        print(f"Baseline saved to: {args.save_baseline}")
        
    write_json_report(findings, args.output)
    
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.severity.lower()
        summary[sev] = summary.get(sev, 0) + 1
        
    print(f"Scan complete. Total findings: {len(findings)}")
    print(f"Severity breakdown: Critical={summary['critical']}, High={summary['high']}, Medium={summary['medium']}, Low={summary['low']}")
    print(f"Report written to: {args.output}")

def main():
    parser = argparse.ArgumentParser(
        description="llm-api-guard - Plugin-based security scanner for LLM-powered APIs"
    )
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        help="Scanner subcommands"
    )
    
    repo_parser = subparsers.add_parser("repo", help="Scan a local repository / codebase path")
    repo_parser.add_argument("--repo", required=True, help="Path to the repository to scan")
    repo_parser.add_argument("--config", default="scanner/config.yaml", help="Path to the config.yaml configuration file")
    repo_parser.add_argument("--output", default="report.json", help="Path to write the report findings")
    repo_parser.add_argument("--baseline", help="Path to baseline JSON file")
    repo_parser.add_argument("--save-baseline", help="Path to save baseline JSON file")
    
    url_parser = subparsers.add_parser("url", help="Scan a live API url")
    url_parser.add_argument("--url", required=True, help="URL of the LLM API endpoint to scan")
    url_parser.add_argument("--header", action="append", help="HTTP header to include (e.g. 'Authorization: Bearer token')")
    url_parser.add_argument("--config", default="scanner/config.yaml", help="Path to the config.yaml configuration file")
    url_parser.add_argument("--output", default="report.json", help="Path to write the report findings")
    url_parser.add_argument("--i-have-permission", action="store_true", help="Authorize the live scan immediately without prompt")
    url_parser.add_argument("--checks", default="live", help="Checks type (e.g., 'live')")
    url_parser.add_argument("--baseline", help="Path to baseline JSON file")
    url_parser.add_argument("--save-baseline", help="Path to save baseline JSON file")
    
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
