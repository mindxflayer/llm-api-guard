import os
import sys
import json
import time
import urllib.parse
import datetime
import requests
from packaging.version import parse as parse_version

def is_version_in_ranges(version_str: str, ranges: list) -> bool:
    try:
        ver = parse_version(version_str)
    except Exception:
        return False

    for r in ranges:
        if r.get("type") != "ECOSYSTEM":
            continue
        events = r.get("events", [])
        introduced_ver = None
        for event in events:
            if "introduced" in event:
                try:
                    introduced_ver = parse_version(event["introduced"])
                except Exception:
                    introduced_ver = None
            elif "fixed" in event:
                if introduced_ver is not None:
                    try:
                        fixed_ver = parse_version(event["fixed"])
                        if introduced_ver <= ver < fixed_ver:
                            return True
                    except Exception:
                        pass
                introduced_ver = None
            elif "last_affected" in event:
                if introduced_ver is not None:
                    try:
                        last_affected_ver = parse_version(event["last_affected"])
                        if introduced_ver <= ver <= last_affected_ver:
                            return True
                    except Exception:
                        pass
                introduced_ver = None
        if introduced_ver is not None and ver >= introduced_ver:
            return True
    return False

def get_cache_path(ecosystem: str, package_name: str, version: str) -> str:
    cache_dir = os.path.expanduser("~/.cache/llm-api-guard/osv")
    os.makedirs(cache_dir, exist_ok=True)
    cache_key = f"{ecosystem.lower()}_{package_name.lower().replace('/', '_')}_{version}"
    safe_filename = urllib.parse.quote_plus(cache_key) + ".json"
    return os.path.join(cache_dir, safe_filename)

def load_offline_snapshot(ecosystem: str, package_name: str, version: str) -> list:
    caller_dir = os.path.dirname(os.path.abspath(__file__))
    snapshot_path = os.path.join(caller_dir, "data", "osv_snapshot_fallback.json")
    if not os.path.exists(snapshot_path):
        return []

    try:
        with open(snapshot_path, "r", encoding="utf-8") as f:
            snapshot_data = json.load(f)
    except Exception:
        return []

    matched = []
    for vuln in snapshot_data:
        vuln_eco = vuln.get("ecosystem", "")
        vuln_pkg = vuln.get("package", "")
        if vuln_eco.lower() == ecosystem.lower() and vuln_pkg.lower() == package_name.lower():
            if is_version_in_ranges(version, vuln.get("ranges", [])):
                matched.append({
                    "id": vuln.get("id"),
                    "summary": vuln.get("summary", ""),
                    "severity": vuln.get("severity"),
                    "ranges": vuln.get("ranges", []),
                    "source": "offline_snapshot"
                })
    return matched

def query_osv_batch(packages: list[tuple[str, str, str]], cache_ttl_hours: float = 24.0) -> dict:
    final_results = {}
    network_queries = []
    current_time = time.time()
    ttl_seconds = cache_ttl_hours * 3600.0

    for eco, pkg, ver in packages:
        cache_path = get_cache_path(eco, pkg, ver)
        cache_hit = False
        if os.path.exists(cache_path):
            try:
                with open(cache_path, "r", encoding="utf-8") as f:
                    cached_data = json.load(f)
                cached_time = cached_data.get("timestamp", 0)
                if current_time - cached_time < ttl_seconds:
                    final_results[(eco, pkg, ver)] = cached_data.get("vulns", [])
                    cache_hit = True
            except Exception:
                pass
        if not cache_hit:
            network_queries.append((eco, pkg, ver))

    if not network_queries:
        return final_results

    url = "https://api.osv.dev/v1/querybatch"
    payload = {
        "queries": [
            {
                "package": {"ecosystem": eco, "name": pkg},
                "version": ver
            }
            for eco, pkg, ver in network_queries
        ]
    }

    network_failed = False
    response_json = {}
    try:
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            response_json = response.json()
        else:
            network_failed = True
    except Exception:
        network_failed = True

    if not network_failed:
        results = response_json.get("results", [])
        for (eco, pkg, ver), result in zip(network_queries, results):
            vulns = result.get("vulns", [])
            parsed_vulns = []
            for vuln in vulns:
                severity = vuln.get("severity")
                ranges = []
                for affected in vuln.get("affected", []):
                    affected_pkg = affected.get("package", {})
                    if affected_pkg.get("name", "").lower() == pkg.lower() and affected_pkg.get("ecosystem", "").lower() == eco.lower():
                        ranges.extend(affected.get("ranges", []))
                
                parsed_vulns.append({
                    "id": vuln.get("id"),
                    "summary": vuln.get("summary", ""),
                    "severity": severity,
                    "ranges": ranges
                })
            cache_path = get_cache_path(eco, pkg, ver)
            try:
                with open(cache_path, "w", encoding="utf-8") as f:
                    json.dump({"timestamp": current_time, "vulns": parsed_vulns}, f)
            except Exception:
                pass
            final_results[(eco, pkg, ver)] = parsed_vulns
    else:
        for eco, pkg, ver in network_queries:
            cache_path = get_cache_path(eco, pkg, ver)
            fallback_done = False
            if os.path.exists(cache_path):
                try:
                    with open(cache_path, "r", encoding="utf-8") as f:
                        cached_data = json.load(f)
                    cached_time = cached_data.get("timestamp", 0)
                    dt_str = datetime.datetime.fromtimestamp(cached_time).isoformat()
                    sys.stderr.write(f"stale OSV data, last updated {dt_str}\n")
                    sys.stderr.flush()
                    final_results[(eco, pkg, ver)] = cached_data.get("vulns", [])
                    fallback_done = True
                except Exception:
                    pass
            if not fallback_done:
                offline_findings = load_offline_snapshot(eco, pkg, ver)
                final_results[(eco, pkg, ver)] = offline_findings

    return final_results
