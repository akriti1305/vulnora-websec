# AegisScan 2.0 -- AI-Agent Web Security Scanner & Cryptographic Trust Platform

> **Academic Coursework Project & Defensive Security Platform**  
> *Repository:* `akriti1305/vulnora-websec` | *Branch:* `master` | *Version:* `2.0.0 (Phase 13)`

---

## 1. Project Overview

**AegisScan 2.0** is an explainable web and AI-agent vulnerability scanner with cryptographic trust verification. In modern web architectures, web applications increasingly embed LLM-powered assistants with autonomous agency and external tool execution capabilities.

AegisScan 2.0 delivers an integrated, two-tier security audit:
1. **Layer 1 (Traditional Web Security)**: SQL Injection (SQLi), Reflected Cross-Site Scripting (XSS), Insecure Direct Object References (IDOR), Missing Security Headers, and Insecure Cookie Flags.
2. **Layer 2 (AI-Agent Security -- OWASP Top 10 for LLMs / NIST 2026)**: AI feature discovery (`.well-known/aegisscan-ai.json`), indirect prompt injection, secret canary token leakage, tool metadata rug-pulls, poisoned tool descriptions, context taint tracking, and excessive agency authorization gating.
3. **Cryptographic Provenance**: Every scan produces an **Ed25519 digital signature** over canonical finding digests and links into a tamper-evident **SHA-256 append-only hash chain** ($H_n = \text{SHA256}(R_n \parallel H_{n-1})$).

---

## 2. System Architecture

```
                                  [ Browser / Analyst ]
                                            │
                                            ▼
               ┌────────────────────────────────────────────────────────┐
               │         FastAPI Unified Dashboard (Port 8000)          │
               │  - Real-time KPI summary (Scans, Vulns, Controls)      │
               │  - Basic vs. Deep Authorized Scan modes                │
               │  - 6-Category Finding Classification                   │
               │  - Vulnerable vs. Fixed Differential Comparison        │
               │  - Ed25519 Passport Verifier & Hash Chain Auditor      │
               └───────────┬────────────────────────────────┬───────────┘
                           │                                │
            ┌──────────────▼─────────────┐     ┌────────────▼──────────────┐
            │   AegisScan Core Engine    │     │   SQLite Cryptographic    │
            │ - ScopeGuard (localhost)   │     │         Ledger            │
            │ - Crawler (BFS 20 pgs)     │     │ - scans, findings         │
            │ - Layer 1 & 2 Detectors    │     │ - scan_passports          │
            │ - Active Validation Engine │     │ - scan_chain_records      │
            └──────────────┬─────────────┘     └───────────────────────────┘
                           │ Probes
                           ▼
               ┌────────────────────────────────────────────────────────┐
               │             AegisLab Benchmark (Port 5001)             │
               │  - 9 Traditional Layer 1 Vulnerabilities               │
               │  - 6 AI-Agent Layer 2 Security Flaws                   │
               │  - 4 Benign Decoys / Controls (True Negatives)         │
               │  - Toggleable Secure Mode: /assistant/config           │
               └────────────────────────────────────────────────────────┘
```

---

## 3. Installation & Setup

### Prerequisites
- Python 3.10+ (Windows 10/11)
- Windows PowerShell

### Virtual Environments
```powershell
# Clone the repository
git clone https://github.com/akriti1305/vulnora-websec.git D:\PRJ4
cd D:\PRJ4

# Scanner environment (FastAPI, cryptography, httpx, sqlalchemy)
cd D:\PRJ4\aegisscan
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install fastapi uvicorn httpx sqlalchemy jinja2 cryptography pydantic
deactivate

# Benchmark lab environment (Flask)
cd D:\PRJ4\aegislab
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install flask markupsafe requests
deactivate
```

---

## 4. Exact Windows PowerShell Launch Commands

Open two PowerShell windows:

### Terminal 1: Launch AegisLab Benchmark (Port 5001)
```powershell
& "D:\PRJ4\aegislab\venv\Scripts\python.exe" "D:\PRJ4\aegislab\app.py"
```
*Output confirm:* `* Running on http://127.0.0.1:5001`

### Terminal 2: Launch AegisScan Dashboard (Port 8000)
```powershell
& "D:\PRJ4\aegisscan\venv\Scripts\python.exe" -m uvicorn --app-dir "D:\PRJ4\aegisscan" main:app --host 127.0.0.1 --port 8000
```
*Output confirm:* `Uvicorn running on http://127.0.0.1:8000`

---

## 5. How to Run Scans & Features

### 5.1 Performing a Deep Authorized Scan
1. Open your browser at `http://127.0.0.1:8000`.
2. In the **Target URL** field, enter: `http://127.0.0.1:5001`.
3. Under **Scan Mode**, select **Deep Authorized Scan** (tests both traditional flaws and AI-agent vectors).
4. Check the **Authorization Checkbox**: *"I am authorized to test this target and consent to deep active probes"*.
5. Click **Launch Security Scan**.
6. View the completed report with categorized cards, validation evidence, and Ed25519 digital signature badge.

### 5.2 Comparing Vulnerable vs. Fixed Modes
1. **Run Baseline Scan**: Scan `http://127.0.0.1:5001` with AegisLab in default vulnerable mode (Scan ID `A`).
2. **Switch AegisLab to Secure Mode**:
   ```powershell
   Invoke-RestMethod -Uri "http://127.0.0.1:5001/assistant/config" -Method Post -Body '{"secure_mode":true}' -ContentType "application/json"
   ```
3. **Run Rescan**: Launch a second scan against `http://127.0.0.1:5001` (Scan ID `B`).
4. **Compare**: On the dashboard home page, enter Baseline Scan `A` and Comparison Scan `B`, then click **Compare Scans**.
5. The differential engine partitions findings into 5 states:
   - `Previously Confirmed`: 15 (14 confirmed + 1 potential)
   - `Still Confirmed`: 10 (Layer 1 traditional vulnerabilities remain active)
   - `Resolved After Retest`: 5 (ALL AI vulnerabilities resolved: Prompt Injection, Canary Leakage, Excessive Agency, Context Taint Hijack, and Reflected XSS on `/assistant`)
   - `Newly Detected`: 0
   - `Not Retested`: 0

### 5.3 Verifying Signed Passports & Tampering Detection
- **Download Passport**: From any scan report, click **Download Signed Passport (.json)**.
- **Independent Verification API**:
  ```powershell
  Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/scans/1/passport/verify" -Method Get
  ```
- **Tampering Detection**: If any finding severity, title, or evidence digest is modified, verification returns `status: INVALID` due to SHA-256 payload mismatch.
- **Audit Hash-Chain Ledger**:
  ```powershell
  Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/provenance/history" -Method Get
  ```

---

## 6. Running the Automated Test Suite & Live Demo

### Full 87-Test Regression Suite
```powershell
& "D:\PRJ4\aegisscan\venv\Scripts\python.exe" -m unittest discover tests
```
*Expected Result:* `Ran 87 tests in ~13.6s ... OK (0 failures, 0 errors)`

### Automated Live Demonstration Script
```powershell
& "D:\PRJ4\aegisscan\venv\Scripts\python.exe" "D:\PRJ4\demo_phase12.py"
```
*Executes live crawling, detector pipeline, Ed25519 passport generation, tamper detection simulation, secure-mode rescan, differential comparison, 2-record hash chain verification, and key reload.*

---

## 7. Finding Classification Categories

AegisScan 2.0 strictly separates scan outputs into 6 distinct categories:

| Category | Key | Description |
| :--- | :--- | :--- |
| **Confirmed Vulnerability** | `confirmed_vulnerability` | Flaws confirmed via active dual-request validation probes |
| **Potential Vulnerability** | `potential_vulnerability` | Heuristic hits (e.g. non-sensitive IDOR, missing headers) |
| **Informational Discovery** | `informational` | Non-flaw reconnaissance (AI assistant discovered, manifest parsed) |
| **Verified Security Control**| `verified_control` | Defensive controls confirmed active (tool hashes verified, gates enforced) |
| **Not Reproducible** | `not_reproducible` | Anomalies that failed second-stage reproducibility |
| **Not Tested** | `not_tested` | Checks skipped due to scan mode selection |

---

## 8. Empirical Evaluation Metrics (AegisLab Benchmark)

Evaluation 2.0 was benchmarked against the full AegisLab answer key (15 ground-truth flaws + 4 benign controls):

| Evaluation Scope | True Positives (TP) | False Positives (FP) | False Negatives (FN) | True Negatives (TN) | Precision | Recall | F1 Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Combined (Post-Validation)**| **13** | **1** | **2** | **4** | **92.9%** | **86.7%** | **89.7%** |
| **Traditional Web Flaws** | **9** | **1** | **0** | **4** | **90.0%** | **100.0%**| **94.7%** |
| **AI-Agent Flaws** | **4** | **1** | **2** | **4** | **80.0%** | **66.7%** | **72.7%** |

---

## 9. Known Academic Limitations

1. **Local Benchmark Scope**: Ground-truth evaluation is calibrated against AegisLab. Real-world third-party web apps may exhibit unknown frameworks and dynamic client-side rendering.
2. **Deterministic Mock Agent**: AegisLab simulates LLM tool invocation deterministically to ensure reproducible academic evaluation without relying on paid external LLM APIs.
3. **SQLite Ledger Mutability**: While SQLite is ideal for single-node academic demos, an attacker with direct operating system disk access could replace the database file. In production, the Ed25519 signed chain head checkpoint ($H_n$) should be mirrored to an immutable external ledger or Transparency Log (e.g., Sigstore/Rekor).
4. **Key Management**: Ed25519 private keys are stored on local disk under `aegisscan/secrets/`. Enterprise environments require Hardware Security Modules (HSMs) or cloud KMS.
