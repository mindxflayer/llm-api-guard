import re
from scanner.core import Finding

def parse_location(loc: str):
    if not loc:
        return (True, "", 0, 0)
    if loc.startswith(("http://", "https://")):
        return (True, loc, 0, 0)
    if ":" in loc:
        parts = loc.rsplit(":", 1)
        line_part = parts[1]
        if "-" in line_part:
            r_parts = line_part.split("-")
            if len(r_parts) == 2 and r_parts[0].isdigit() and r_parts[1].isdigit():
                return (False, parts[0], int(r_parts[0]), int(r_parts[1]))
        elif line_part.isdigit():
            return (False, parts[0], int(line_part), int(line_part))
    return (True, loc, 0, 0)

def locations_overlap(loc1: str, loc2: str) -> bool:
    is_url1, key1, s1, e1 = parse_location(loc1)
    is_url2, key2, s2, e2 = parse_location(loc2)
    if is_url1 != is_url2:
        return False
    if is_url1:
        return key1 == key2
    else:
        if key1 != key2:
            return False
        return max(s1, s2) <= min(e1, e2)

def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    merged_findings = []
    by_owasp = {}
    for f in findings:
        by_owasp.setdefault(f.owasp_ref, []).append(f)
        
    for owasp_ref, group_list in by_owasp.items():
        n = len(group_list)
        adj = {i: [] for i in range(n)}
        for i in range(n):
            for j in range(i + 1, n):
                if locations_overlap(group_list[i].location, group_list[j].location):
                    adj[i].append(j)
                    adj[j].append(i)
        visited = set()
        for i in range(n):
            if i not in visited:
                component = []
                queue = [i]
                visited.add(i)
                while queue:
                    curr = queue.pop(0)
                    component.append(group_list[curr])
                    for neighbor in adj[curr]:
                        if neighbor not in visited:
                            visited.add(neighbor)
                            queue.append(neighbor)
                if len(component) == 1:
                    merged_findings.append(component[0])
                else:
                    severity_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
                    
                    best_f = component[0]
                    for f in component[1:]:
                        sev_curr = severity_order.get(f.severity.lower(), 1)
                        sev_best = severity_order.get(best_f.severity.lower(), 1)
                        if sev_curr > sev_best:
                            best_f = f
                        elif sev_curr == sev_best:
                            if f.confidence > best_f.confidence:
                                best_f = f
                                
                    contribs = []
                    for f in component:
                        contribs.append(f"{f.detection_method} ({f.message})")
                    
                    msg = "Detected via: " + "; ".join(contribs) + " — original messages: [" + ", ".join(f.message for f in component) + "]"
                    
                    max_sev = best_f.severity
                    for f in component:
                        if severity_order.get(f.severity.lower(), 1) > severity_order.get(max_sev.lower(), 1):
                            max_sev = f.severity
                            
                    max_conf = max(f.confidence for f in component)
                    
                    merged = Finding(
                        rule=best_f.rule,
                        severity=max_sev,
                        message=msg,
                        location=best_f.location,
                        suppressed=any(f.suppressed for f in component),
                        owasp_ref=owasp_ref,
                        priority=best_f.priority,
                        detection_method=best_f.detection_method,
                        confidence=max_conf
                    )
                    merged_findings.append(merged)
                    
    return merged_findings
