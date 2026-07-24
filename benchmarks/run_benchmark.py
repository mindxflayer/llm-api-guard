import os
import yaml
import json
import logging
import tempfile
import subprocess
from collections import defaultdict
from scanner.core import PluginLoader, Runner, load_config

logger = logging.getLogger("llm-api-guard")

def calculate_metrics(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    return round(precision, 4), round(recall, 4), round(f1, 4)

def is_location_match(scanner_loc: str, gt_loc: str) -> bool:
    if not scanner_loc or not gt_loc:
        return False
    scanner_norm = scanner_loc.replace("\\", "/")
    gt_norm = gt_loc.replace("\\", "/")
    if gt_norm in scanner_norm or scanner_norm in gt_norm:
        return True
    scanner_path = scanner_norm.split(":")[0]
    gt_path = gt_norm.split(":")[0]
    return scanner_path == gt_path or os.path.basename(scanner_path) == os.path.basename(gt_path)

def run_benchmark(repos_config_path: str = "benchmarks/repos.yaml", ground_truth_dir: str = "benchmarks/ground_truth") -> dict:
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if not os.path.isabs(repos_config_path):
        repos_config_path = os.path.join(base_dir, repos_config_path)
    if not os.path.isabs(ground_truth_dir):
        ground_truth_dir = os.path.join(base_dir, ground_truth_dir)

    if not os.path.exists(repos_config_path):
        raise ValueError(f"Repos configuration file not found: {repos_config_path}")

    with open(repos_config_path, "r", encoding="utf-8") as f:
        repos_data = yaml.safe_load(f) or {}

    repos = repos_data.get("repos", [])
    plugins_dir = os.path.join(base_dir, "scanner", "static")
    loader = PluginLoader()
    plugins = loader.load_plugins(plugins_dir)

    config_path = os.path.join(base_dir, "scanner", "config.yaml")
    config = load_config(config_path) if os.path.exists(config_path) else {"severity_threshold": "low", "checks": {}}

    rule_stats = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "unlabeled": 0})
    unlabeled_findings = []
    scanned_count = 0

    for repo in repos:
        name = repo.get("name", "unknown")
        url = repo.get("url", "")
        commit = repo.get("commit", "")

        if not url or "PLACEHOLDER" in url or "replace with real repos" in url:
            continue

        temp_dir_obj = None
        if os.path.exists(url) or os.path.isabs(url) or url.startswith("."):
            scan_target = os.path.abspath(url)
        else:
            temp_dir_obj = tempfile.TemporaryDirectory()
            scan_target = temp_dir_obj.name
            clone_cmd = ["git", "clone", url, scan_target]
            res = subprocess.run(clone_cmd, capture_output=True, text=True)
            if res.returncode != 0:
                logger.error(f"Failed to clone repository {url}: {res.stderr}")
                temp_dir_obj.cleanup()
                continue
            if commit:
                checkout_cmd = ["git", "-C", scan_target, "checkout", commit]
                subprocess.run(checkout_cmd, capture_output=True, text=True)

        scanned_count += 1
        runner = Runner(plugins, config=config)
        findings = runner.run(scan_target)

        gt_file = os.path.join(ground_truth_dir, f"{name}.yaml")
        if not os.path.exists(gt_file):
            gt_file = os.path.join(ground_truth_dir, f"{name}.yml")

        gt_findings = []
        if os.path.exists(gt_file):
            try:
                with open(gt_file, "r", encoding="utf-8") as f:
                    gt_data = yaml.safe_load(f) or {}
                gt_findings = gt_data.get("findings", [])
            except Exception as e:
                logger.error(f"Failed to read ground truth file {gt_file}: {e}")

        matched_scanner_indices = set()

        for gt_f in gt_findings:
            gt_rule = gt_f.get("rule", "")
            gt_loc = gt_f.get("location", "")
            is_tp = gt_f.get("is_true_positive", True)

            matched_idx = None
            for idx, sf in enumerate(findings):
                if sf.rule == gt_rule and is_location_match(sf.location, gt_loc):
                    matched_idx = idx
                    matched_scanner_indices.add(idx)
                    break

            if is_tp:
                if matched_idx is not None:
                    rule_stats[gt_rule]["tp"] += 1
                else:
                    rule_stats[gt_rule]["fn"] += 1
            else:
                if matched_idx is not None:
                    rule_stats[gt_rule]["fp"] += 1

        for idx, sf in enumerate(findings):
            if idx not in matched_scanner_indices:
                rule_stats[sf.rule]["unlabeled"] += 1
                unlabeled_findings.append({
                    "repo": name,
                    "rule": sf.rule,
                    "location": sf.location,
                    "message": sf.message
                })

        if temp_dir_obj:
            temp_dir_obj.cleanup()

    rules_report = {}
    total_tp = 0
    total_fp = 0
    total_fn = 0

    for rule, stats in rule_stats.items():
        prec, rec, f1 = calculate_metrics(stats["tp"], stats["fp"], stats["fn"])
        rules_report[rule] = {
            "precision": prec,
            "recall": rec,
            "f1": f1,
            "tp": stats["tp"],
            "fp": stats["fp"],
            "fn": stats["fn"],
            "unlabeled_count": stats["unlabeled"]
        }
        total_tp += stats["tp"]
        total_fp += stats["fp"]
        total_fn += stats["fn"]

    overall_prec, overall_rec, overall_f1 = calculate_metrics(total_tp, total_fp, total_fn)

    report = {
        "summary": {
            "total_repos_scanned": scanned_count,
            "overall_precision": overall_prec,
            "overall_recall": overall_rec,
            "overall_f1": overall_f1,
            "total_tp": total_tp,
            "total_fp": total_fp,
            "total_fn": total_fn,
            "total_unlabeled_findings": len(unlabeled_findings)
        },
        "rules": rules_report,
        "unlabeled_findings_requiring_review": unlabeled_findings
    }

    report_file = os.path.join(base_dir, "benchmarks", "benchmark_report.json")
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    return report
