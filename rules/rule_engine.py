import json, os
from datetime import datetime, timezone

RULES_PATH = os.path.join(os.path.dirname(__file__), "cis_rules.json")
with open(RULES_PATH) as f:
    CIS_RULES = {r["check"]: r for r in json.load(f)}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

def _finding(check, resource):
    rule = CIS_RULES[check]
    return {
        "id": rule["id"], "check": check, "title": rule["title"],
        "severity": rule["severity"], "service": rule["service"],
        "resource": resource, "description": rule["description"],
        "fix_cli":       rule["fix_cli"].replace("{resource_name}", str(resource)),
        "fix_terraform": rule["fix_terraform"].replace("{resource_name}", str(resource)),
        "detected_at":   datetime.now(timezone.utc).isoformat()
    }

def run_rules(scan_data):
    findings = []

    for b in scan_data.get("s3_buckets", []):
        if b.get("acl") == "public-read":       findings.append(_finding("s3_public_read",  b["name"]))
        if b.get("acl") == "public-read-write":  findings.append(_finding("s3_public_write", b["name"]))
        if not b.get("encryption"):              findings.append(_finding("s3_no_encryption",b["name"]))
        if not b.get("versioning"):              findings.append(_finding("s3_no_versioning",b["name"]))

    for u in scan_data.get("iam_users", []):
        if not u.get("mfa_enabled"):             findings.append(_finding("iam_no_mfa", u["username"]))

    if scan_data.get("root_account", {}).get("has_access_keys"):
        findings.append(_finding("iam_root_access_keys", "root-account"))

    p = scan_data.get("password_policy", {})
    if p.get("minimum_length", 0) < 14 or not p.get("require_symbols"):
        findings.append(_finding("iam_password_policy_weak", "account-password-policy"))

    for sg in scan_data.get("security_groups", []):
        for r in sg.get("inbound_rules", []):
            if r.get("cidr") in ("0.0.0.0/0", "::/0"):
                if r.get("port") == 22:   findings.append(_finding("sg_open_ssh", sg["group_id"]))
                if r.get("port") == 3389: findings.append(_finding("sg_open_rdp", sg["group_id"]))

    if not scan_data.get("cloudtrail", {}).get("enabled"):
        findings.append(_finding("cloudtrail_disabled", "cloudtrail"))

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
    weights = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 4, "LOW": 1}
    score   = min(100, sum(weights.get(f["severity"], 0) for f in findings))

    return {
        "summary": {
            "total": len(findings), "risk_score": score,
            "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high":     sum(1 for f in findings if f["severity"] == "HIGH"),
            "medium":   sum(1 for f in findings if f["severity"] == "MEDIUM"),
            "low":      sum(1 for f in findings if f["severity"] == "LOW"),
            "scanned_at": datetime.now(timezone.utc).isoformat()
        },
        "findings": findings
    }
