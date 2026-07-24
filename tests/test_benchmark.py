import os
import yaml
import tempfile
import pytest
from benchmarks.run_benchmark import run_benchmark, calculate_metrics

def test_benchmark_metrics_math():
    prec, rec, f1 = calculate_metrics(tp=4, fp=1, fn=1)
    assert prec == 0.8
    assert rec == 0.8
    assert f1 == 0.8

    prec_zero, rec_zero, f1_zero = calculate_metrics(tp=0, fp=0, fn=0)
    assert prec_zero == 0.0
    assert rec_zero == 0.0
    assert f1_zero == 0.0

def test_benchmark_true_positive_caught():
    with tempfile.TemporaryDirectory() as repo_dir, tempfile.TemporaryDirectory() as gt_dir:
        file_path = os.path.join(repo_dir, "app.py")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write('API_KEY = "sk-12345678901234567890123456789012"\n')

        repos_yaml_path = os.path.join(repo_dir, "repos.yaml")
        repos_config = {
            "repos": [
                {
                    "name": "synthetic_tp_repo",
                    "url": repo_dir,
                    "commit": "local",
                    "notes": "Synthetic TP test repo"
                }
            ]
        }
        with open(repos_yaml_path, "w", encoding="utf-8") as f:
            yaml.dump(repos_config, f)

        gt_data = {
            "findings": [
                {
                    "rule": "openai_key",
                    "location": "app.py:1",
                    "is_true_positive": True,
                    "notes": "Hardcoded OpenAI key present"
                }
            ]
        }
        gt_file_path = os.path.join(gt_dir, "synthetic_tp_repo.yaml")
        with open(gt_file_path, "w", encoding="utf-8") as f:
            yaml.dump(gt_data, f)

        report = run_benchmark(repos_config_path=repos_yaml_path, ground_truth_dir=gt_dir)

        assert report["summary"]["total_repos_scanned"] == 1
        assert "openai_key" in report["rules"]
        rule_stats = report["rules"]["openai_key"]
        assert rule_stats["precision"] == 1.0
        assert rule_stats["recall"] == 1.0
        assert rule_stats["f1"] == 1.0
        assert rule_stats["tp"] == 1
        assert rule_stats["fp"] == 0
        assert rule_stats["fn"] == 0

def test_benchmark_unlabeled_finding_requires_review():
    with tempfile.TemporaryDirectory() as repo_dir, tempfile.TemporaryDirectory() as gt_dir:
        file_path = os.path.join(repo_dir, "app.py")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write('API_KEY = "sk-12345678901234567890123456789012"\n')

        repos_yaml_path = os.path.join(repo_dir, "repos.yaml")
        repos_config = {
            "repos": [
                {
                    "name": "synthetic_unlabeled_repo",
                    "url": repo_dir,
                    "commit": "local",
                    "notes": "Synthetic unlabeled test repo"
                }
            ]
        }
        with open(repos_yaml_path, "w", encoding="utf-8") as f:
            yaml.dump(repos_config, f)

        gt_data = {"findings": []}
        gt_file_path = os.path.join(gt_dir, "synthetic_unlabeled_repo.yaml")
        with open(gt_file_path, "w", encoding="utf-8") as f:
            yaml.dump(gt_data, f)

        report = run_benchmark(repos_config_path=repos_yaml_path, ground_truth_dir=gt_dir)

        assert report["summary"]["total_unlabeled_findings"] == 1
        unlabeled = report["unlabeled_findings_requiring_review"]
        assert len(unlabeled) == 1
        assert unlabeled[0]["repo"] == "synthetic_unlabeled_repo"
        assert unlabeled[0]["rule"] == "openai_key"

def test_benchmark_missed_true_positive_lowers_recall():
    with tempfile.TemporaryDirectory() as repo_dir, tempfile.TemporaryDirectory() as gt_dir:
        file_path = os.path.join(repo_dir, "app.py")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write('clean_code = True\n')

        repos_yaml_path = os.path.join(repo_dir, "repos.yaml")
        repos_config = {
            "repos": [
                {
                    "name": "synthetic_fn_repo",
                    "url": repo_dir,
                    "commit": "local",
                    "notes": "Synthetic FN test repo"
                }
            ]
        }
        with open(repos_yaml_path, "w", encoding="utf-8") as f:
            yaml.dump(repos_config, f)

        gt_data = {
            "findings": [
                {
                    "rule": "openai_key",
                    "location": "app.py:1",
                    "is_true_positive": True,
                    "notes": "Missed secret key in clean_code"
                }
            ]
        }
        gt_file_path = os.path.join(gt_dir, "synthetic_fn_repo.yaml")
        with open(gt_file_path, "w", encoding="utf-8") as f:
            yaml.dump(gt_data, f)

        report = run_benchmark(repos_config_path=repos_yaml_path, ground_truth_dir=gt_dir)

        assert "openai_key" in report["rules"]
        rule_stats = report["rules"]["openai_key"]
        assert rule_stats["tp"] == 0
        assert rule_stats["fn"] == 1
        assert rule_stats["recall"] == 0.0
