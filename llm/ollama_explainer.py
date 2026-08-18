import requests, json

OLLAMA_URL    = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "llama3.2"

TEMPLATES = {
    "s3_public_read":          {"risk_brief": "Your S3 bucket '{resource}' is publicly readable — any file inside can be downloaded by anyone on the internet without login.", "impact": "Data exposure, GDPR fines, reputational damage.", "priority": "Set the bucket ACL to private immediately."},
    "s3_public_write":         {"risk_brief": "Your S3 bucket '{resource}' lets anyone upload or delete files — attackers can plant malware or destroy your data.", "impact": "Data tampering, malware hosting, runaway costs.", "priority": "Set ACL to private right now — actively exploitable."},
    "s3_no_encryption":        {"risk_brief": "Bucket '{resource}' stores files without encryption — if AWS storage is accessed without authorization your data is readable.", "impact": "Data confidentiality breach, compliance violations.", "priority": "Enable AES256 server-side encryption — free and instant."},
    "s3_no_versioning":        {"risk_brief": "Bucket '{resource}' has no versioning — accidentally deleted or overwritten files cannot be recovered.", "impact": "Irreversible data loss from bugs, ransomware, or human error.", "priority": "Enable versioning as part of your backup strategy."},
    "iam_no_mfa":              {"risk_brief": "IAM user '{resource}' has no MFA — stolen credentials give attackers immediate full access with no second factor to stop them.", "impact": "Full account compromise if credentials are phished or leaked.", "priority": "Enable MFA for all human IAM users today."},
    "iam_root_access_keys":    {"risk_brief": "Your root account has active API keys — root access cannot be restricted by any AWS policy and controls everything.", "impact": "Total account takeover if the key is ever exposed.", "priority": "Delete these keys right now and use IAM roles instead."},
    "iam_password_policy_weak":{"risk_brief": "The account password policy is too weak — short or simple passwords make brute-force attacks much easier.", "impact": "Easier password attacks on all IAM users.", "priority": "Enforce minimum 14 characters with symbols, numbers, and mixed case."},
    "sg_open_ssh":             {"risk_brief": "Security group '{resource}' exposes SSH (port 22) to the entire internet — bots scan for open SSH 24/7 and attempt brute-force logins.", "impact": "Server compromise via brute-force or credential stuffing.", "priority": "Restrict SSH to your VPN or office IP CIDR immediately."},
    "sg_open_rdp":             {"risk_brief": "Security group '{resource}' exposes RDP (port 3389) to the entire internet — the primary ransomware entry point, under constant attack.", "impact": "Windows server compromise and ransomware infection.", "priority": "Restrict RDP to your VPN IP only — never expose to 0.0.0.0/0."},
    "cloudtrail_disabled":     {"risk_brief": "CloudTrail is off — there is no audit log of API calls in your account, making breach investigation nearly impossible.", "impact": "No forensic capability, compliance failure (SOC2, PCI-DSS, ISO27001).", "priority": "Enable CloudTrail in all regions — costs about $2/month."},
}

def _template(finding):
    t = TEMPLATES.get(finding["check"], {"risk_brief": finding["description"], "impact": "Security risk.", "priority": "Review and remediate."})
    return {"risk_brief": t["risk_brief"].replace("{resource}", finding["resource"]), "impact": t["impact"], "priority": t["priority"], "source": "template"}

def explain_with_ollama(finding, model=DEFAULT_MODEL):
    prompt = (
        "A cloud security scan found this misconfiguration:\n"
        "Resource: " + finding["resource"] + "\n"
        "Rule: [" + finding["id"] + "] " + finding["title"] + "\n"
        "Severity: " + finding["severity"] + "\n"
        "Description: " + finding["description"] + "\n\n"
        "Reply ONLY with a JSON object with keys: risk_brief, impact, priority\n"
        "Each value is one plain-English sentence for a developer. No extra text."
    )
    try:
        r = requests.post(OLLAMA_URL, json={"model": model, "prompt": prompt, "stream": False, "options": {"temperature": 0.3, "num_predict": 250}}, timeout=30)
        if r.status_code == 200:
            raw = r.json().get("response", "").strip()
            raw = raw.replace("```json","").replace("```","").strip()
            parsed = json.loads(raw)
            parsed["source"] = "ollama"
            return parsed
    except Exception:
        pass
    return _template(finding)

def enrich_findings(findings, use_ollama=True, model=DEFAULT_MODEL):
    return [{**f, "explanation": explain_with_ollama(f, model) if use_ollama else _template(f)} for f in findings]

def check_ollama_running(model=DEFAULT_MODEL):
    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=3)
        if r.status_code == 200:
            models = [m["name"] for m in r.json().get("models", [])]
            return any(model.split(":")[0] in m for m in models)
    except Exception:
        pass
    return False
