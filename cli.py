import os
import argparse
import sys
from scanner.core import load_config, PluginLoader, Runner
from scanner.report import write_json_report

def run_repo_scan(args):
    config = load_config(args.config)
    loader = PluginLoader()
    base_dir = os.path.dirname(os.path.abspath(__file__))
    plugins_dir = os.path.join(base_dir, "scanner", "static")
    
    plugins = loader.load_plugins(plugins_dir)
    runner = Runner(plugins, config=config)
    findings = runner.run(args.repo)
    
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
    
    url_parser = subparsers.add_parser("url", help="Scan a live API url")
    url_parser.add_argument("--url", required=True, help="URL of the LLM API endpoint to scan")
    
    args = parser.parse_args()
    
    if args.command == "repo":
        run_repo_scan(args)
    elif args.command == "url":
        print("live scanning not yet implemented")
        sys.exit(0)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
