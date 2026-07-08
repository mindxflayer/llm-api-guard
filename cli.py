import argparse
import sys

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
    repo_parser.add_argument("path", help="Path to the repository to scan")
    
    url_parser = subparsers.add_parser("url", help="Scan a live API url")
    url_parser.add_argument("url", help="URL of the LLM API endpoint to scan")
    
    args = parser.parse_args()
    
    if args.command == "repo":
        print(f"Scanning repository path: {args.path}")
    elif args.command == "url":
        print(f"Scanning API URL: {args.url}")
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
