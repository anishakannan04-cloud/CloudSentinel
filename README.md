@'
# 🛡️ CloudSentinel

**Autonomous Cloud Misconfiguration Detection & Remediation — powered by local Ollama LLM**

> Detects → Explains → Fixes AWS misconfigurations in real time. No cloud data sent to any external API.

---

## 🚨 Problem

Cloud misconfigurations cause **80% of cloud data breaches** (Gartner 2023).

- Capital One 2019 — misconfigured WAF + overpermissioned IAM → 100M records exposed
- Toyota 2023 — public S3 bucket exposed 2M customer records for 10 years
- Average breach cost: **$4.45M** (IBM 2023)

Existing tools (AWS Config, Wiz, Prisma) only **detect** — they dump a list of findings and leave your team to manually fix them. That gap costs millions.

---

## 💡 Solution

CloudSentinel closes the full loop:
Scan → Detect → Explain → Fix → Track

1. **Scan** — Connects to AWS APIs and collects resource configurations
2. **Detect** — Checks against 10+ CIS Benchmark rules
3. **Explain** — Local Ollama LLM generates plain-English risk briefs
4. **Fix** — Ready-to-run AWS CLI + Terraform commands generated instantly
5. **Track** — Risk score trends and drift detection over time

---

## 🤖 Why Ollama (Local LLM)?

- ✅ **Zero cost** — runs on your laptop, no API fees
- ✅ **Privacy-preserving** — your cloud config never leaves your machine
- ✅ **Works offline** — no internet dependency for AI explanations
- ✅ **Fast** — llama3.2 responses in under 5 seconds

---

## 🏗️ Architecture
AWS APIs → Scanner → Rule Engine → Ollama LLM → Dashboard
(boto3) (collect) (CIS rules) (explain+fix) (React UI)

---

## 📊 What It Detects

| Service | Rule | Severity |
|---|---|---|
| S3 | Public read/write access | CRITICAL |
| S3 | No encryption at rest | HIGH |
| S3 | Versioning disabled | MEDIUM |
| IAM | No MFA on user accounts | HIGH |
| IAM | Root account access keys active | CRITICAL |
| IAM | Weak password policy | MEDIUM |
| EC2 | SSH (port 22) open to world | CRITICAL |
| EC2 | RDP (port 3389) open to world | CRITICAL |
| CloudTrail | Logging disabled | HIGH |

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- [Ollama](https://ollama.com/download) installed

### Setup
```bash
# 1. Clone the repo
git clone https://github.com/anishakannan04-cloud/CloudSentinel.git
cd CloudSentinel

# 2. Install dependencies
pip install fastapi uvicorn boto3 requests pydantic

# 3. Pull the LLM model
ollama pull llama3.2

# 4. Run CloudSentinel
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

Open browser → **http://localhost:8000** → Click **Run Scan**

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Cloud Scanner | Python + boto3 (AWS SDK) |
| Rule Engine | CIS AWS Benchmark v1.5 |
| LLM | Ollama — llama3.2 (local) |
| Backend | FastAPI |
| Frontend | HTML / CSS / JavaScript |

---

## 📄 Research Angle

> *"CloudSentinel: LLM-Assisted Autonomous Cloud Posture Remediation"*

**Novel contribution:** First open-source tool to close the detect → explain → fix loop using a privacy-preserving local LLM.

Metrics:
- Mean Time to Remediation (MTTR) vs manual baseline
- LLM fix accuracy vs human engineer fixes
- False positive rate of CIS rule engine

---

## 👩‍💻 Author

**Anisha Kannan** — Cybersecurity + Cloud Computing  
GitHub: [@anishakannan04-cloud](https://github.com/anishakannan04-cloud)

---

## 📜 License

MIT License — free to use, modify, and distribute.
'@ | Out-File -Path README.md -Encoding utf8

git add README.md
git commit -m "add README"
git push origin main

Write-Host "README pushed to GitHub!"