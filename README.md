# Vulnora — Web Application Security Scanner

> **Academic Cybersecurity Project & Defensive Evaluation Platform**
> *Repository:* `akriti1305/vulnora-websec` | *Development Name:* AegisScan

---

## 1. Executive Overview

**Vulnora** is a defensive web application security scanner designed to discover, detect, validate, score, and track common web vulnerabilities on authorized targets.

Most introductory security scanners suffer from excessive false-positive rates because they rely on simple regex pattern matching against HTTP responses. Vulnora implements a **two-stage verification pipeline** that pairs automated vulnerability detectors with an active **control-request validation engine**. By comparing responses from malicious test payloads against benign baseline requests, Vulnora confirms whether an observed anomaly was directly caused by the payload before assigning risk ratings.

The project repository consists of two decoupled components:
- **`aegisscan/`**: The core scanner package, REST API, discovery engine, detection suite, and server-rendered web dashboard built with **FastAPI**, **HTTPX**, and **SQLAlchemy**.
- **`aegislab/`**: An intentionally vulnerable, isolated web application built with **Flask** used as a controlled benchmark target to test and evaluate detector accuracy.

---

## 2. System Architecture & Data Flow

Vulnora follows a deterministic pipeline from initial URL intake to report rendering:

```
[ User Input / Web UI ]
          │
          ▼
┌────────────────────────────────────────────────────────┐
│ 1. Scope Guard (scope.py)                              │
│    - Verifies target host against allowlist            │
│    - Configures HTTPX client with redirect interceptor │
└─────────────────────────┬──────────────────────────────┘
                          │
                          ▼
┌────────────────────────────────────────────────────────┐
│ 2. Discovery & Crawler (discovery/crawler.py)          │
│    - BFS crawler (max 50 pages) collecting links       │
│    - Extracts HTML forms, fields, headers, and cookies │
│    - Queues GET form actions with sample query params  │
└─────────────────────────┬──────────────────────────────┘
                          │
                          ▼
┌────────────────────────────────────────────────────────┐
│ 3. Vulnerability Detectors (detectors/)                │
│    - SQL Injection (POST forms)                        │
│    - Reflected XSS (GET & POST forms)                  │
│    - IDOR / Broken Access Control (Query parameters)   │
│    - Missing Security Headers (Passive header check)   │
│    - Insecure Cookies (Set-Cookie flag inspection)     │
└─────────────────────────┬──────────────────────────────┘
                          │
                          ▼
┌────────────────────────────────────────────────────────┐
│ 4. Validation Engine (validation/__init__.py)          │
│    - Dual-request control test (Payload vs. Control)   │
│    - Classifies findings: 'confirmed' vs 'noise'       │
└─────────────────────────┬──────────────────────────────┘
                          │
                          ▼
┌────────────────────────────────────────────────────────┐
│ 5. Risk Engine & Scorer (risk/__init__.py)             │
│    - Assigns severity (Critical / High / Med / Low)    │
│    - Attaches tailored remediation instructions        │
└─────────────────────────┬──────────────────────────────┘
                          │
                          ▼
┌────────────────────────────────────────────────────────┐
│ 6. Evaluation Harness (evaluation/__init__.py)         │
│    - Compares findings against AegisLab Ground Truth   │
│    - Calculates Precision, Recall, F1 (pre & post)     │
└─────────────────────────┬──────────────────────────────┘
                          │
                          ▼
┌────────────────────────────────────────────────────────┐
│ 7. Persistence & Reporting (models.py, report/)        │
│    - Commits Target, Scan, Findings, Eval to SQLite    │
│    - Generates Jinja2 dark-mode HTML reports           │
│    - Supports pairwise differential scan comparisons   │
└────────────────────────────────────────────────────────┘
```

---

## 3. Implemented Detector Categories

Vulnora includes five specialized detection modules located in `aegisscan/detectors/`:

### 1. SQL Injection (`sqli_detector.py`)
- **Mechanism**: Tests HTML form submissions via HTTP POST using non-destructive, read-only SQL injection probes (e.g. `' OR '1'='1' --`, `' OR 1=1 --`, and syntax error probes).
- **Signals**: Detects authentication bypass (verifying application-specific authenticated session markers) and SQL dialect error leakage (e.g. `sqlite3.OperationalError`, syntax errors, unrecognized tokens).
- **Safety**: Never injects destructive queries (`DROP`, `DELETE`, `UPDATE`).

### 2. Reflected Cross-Site Scripting (`xss_detector.py`)
- **Mechanism**: Injects probes containing unique marker tags into form fields across both GET and POST endpoints.
- **Signals**: Analyzes the raw HTTP response body using `_is_unescaped()` to verify that `<script>` or event handler tags were reflected unescaped, differentiating real vulnerabilities from safe HTML-entity encoded reflections (`&lt;script&gt;`).

### 3. Insecure Direct Object Reference (`idor_detector.py`)
- **Mechanism**: Identifies URL query parameters representing database identifiers (`id`, `user_id`, `uid`, etc.). Establishes a baseline unauthenticated response, probes sequential numeric IDs (1..5), and flags endpoints returning HTTP 200 with substantial textual body divergence (`_responses_differ`).

### 4. Missing HTTP Security Headers (`header_detector.py`)
- **Mechanism**: Passively inspects response headers collected across all discovered pages for critical defense-in-depth protections:
  - `Content-Security-Policy` (Medium)
  - `Strict-Transport-Security` (Medium)
  - `X-Frame-Options` (Low)
  - `X-Content-Type-Options` (Low)
- **Deduplication**: Deduplicates globally per application so that missing headers are reported once per scan rather than multiplied by the page count.

### 5. Insecure Cookie Flags (`cookie_detector.py`)
- **Mechanism**: Re-requests target pages and tests form authentication endpoints within the designated scope, parsing raw `Set-Cookie` headers via `multi_items()` to inspect cookie directives.
- **Flags Checked**:
  - `HttpOnly`: Missing flag flagged as High severity (risk of XSS session theft).
  - `Secure`: Missing flag flagged as Medium severity (risk of network eavesdropping).

---

## 4. Control-Request Validation Engine

A key technical feature of Vulnora is the **Control-Request Validation Engine** (`aegisscan/validation/`).

### How It Works
Traditional scanners flag a page as vulnerable if a response contains an anomaly after injecting a payload. However, a page that is already broken or noisy will always display error messages, producing persistent false positives.

Vulnora sends **two separate requests** for each potential SQLi or XSS candidate:
1. **Payload Request**: Sends the security probe (e.g. `' OR '1'='1' --`).
2. **Control Request**: Sends a harmless control value (`testvalue123`) into the same field.

### Decision Matrix
| Payload Signal | Control Signal | Validation Outcome | Status |
| :---: | :---: | :--- | :--- |
| **YES** | **NO** | Flaw is proven to be caused by the payload. | `confirmed` |
| **YES** | **YES** | Signal appears regardless of input (noisy page/decoy). | `not_reproducible` |
| **NO** | — | Probe failed to reproduce on retry. | `not_reproducible` |

### Validation Scope & Limitations
- Currently implemented for **SQL Injection** and **Reflected XSS**.
- IDOR, header checks, and cookie flags are directly observable and skip the control-request replay step.
- Transient network errors or target rate-limiting during the control request can result in unconfirmed findings being marked `not_reproducible`.

---

## 5. Persistence, Reporting & Comparison

- **Database Layer**: Built on SQLite with SQLAlchemy (`aegisscan/models.py`). Tracks `Target`, `Scan`, `Finding`, and `EvaluationRun` models.
- **Reporting**: Generates standalone, dark-mode HTML security reports displaying finding details, extracted code evidence, severity badges, and remediation recommendations.
- **Before / After Diffing**: The `/api/scans/compare` endpoint compares two scans against the same target, tracking vulnerability remediation by classifying findings into:
  - **Fixed**: Present in baseline scan A, absent in re-test scan B.
  - **Persisting**: Present in both scan A and scan B.
  - **New**: Absent in scan A, introduced in scan B.

---

## 6. Empirical Evaluation Benchmark

Vulnora includes an automated evaluation harness (`aegisscan/evaluation/`) that benchmarks scanner accuracy against AegisLab's known ground truth (9 intentional flaws) and 3 decoy routes designed to provoke false positives.

### Benchmark Results (Scan #7 with Decoys)
*Note: These metrics represent local evaluation on the controlled AegisLab testbed and are not general claims of internet-wide accuracy.*

| Metric | Pre-Validation (Raw Probes) | Post-Validation (Confirmed Only) |
| :--- | :---: | :---: |
| **True Positives (TP)** | 9 | 9 |
| **False Positives (FP)** | 1 | 1 |
| **False Negatives (FN)** | 0 | 0 |
| **Precision** | **90.0%** | **90.0%** |
| **Recall** | **100.0%** | **100.0%** |
| **F1 Score** | **94.7%** | **94.7%** |

### Analysis of Decoy Behaviors
- `/decoy/echo` (Decoy XSS): Echoes input using Jinja2 safe auto-escaping (`&lt;script&gt;`). Correctly recognized as non-exploitable by `_is_unescaped()`.
- `/decoy/login` (Decoy SQLi): Always returns `"Welcome"` regardless of credentials. Filtered out by the control-request validator because the control value also produced the signal.
- `/decoy/product?id=1` (Decoy IDOR): Public product catalog. Correctly reported as an honest **False Positive** because unauthenticated access to sequential IDs in a public catalog cannot be distinguished from private tenant IDOR without multi-user authentication context.

---

## 7. Setup & Execution Guide (Windows PowerShell)

### Prerequisites
- Python 3.10+ (tested on Python 3.14)
- Windows PowerShell

### 1. Set Up and Run AegisLab (Terminal 1)
```powershell
# Navigate to the target app directory
cd D:\PRJ4\aegislab

# Create and activate virtual environment (if not already created)
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install requirements
pip install -r requirements.txt

# Launch in Vulnerable Mode (default)
$env:AEGISLAB_SECURE = "0"
python app.py

# Optional: To test the before/after remediation diff, restart with:
# $env:AEGISLAB_SECURE = "1"
# python app.py
```
*AegisLab will start at `http://127.0.0.1:5001`.*

### 2. Set Up and Run Vulnora Scanner (Terminal 2)
```powershell
# Navigate to the scanner directory
cd D:\PRJ4\aegisscan

# Create and activate virtual environment (if not already created)
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install requirements
pip install -r requirements.txt

# Start the scanner server
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```
*The Vulnora web dashboard will be accessible at `http://127.0.0.1:8000`.*

### 3. Running a Scan
1. Open your browser and navigate to `http://127.0.0.1:8000`.
2. In the **New Security Scan** card:
   - **Target URL**: `http://127.0.0.1:5001`
   - **Target Name**: `AegisLab Local`
3. Click **Launch Scan**.
4. Once completed, the dashboard will automatically redirect to the generated HTML report at `/api/scans/{id}/report`.

---

## 8. Limitations & Future Work

Vulnora is an academic prototype and portfolio demonstration tool. It has several explicit architectural limitations:

1. **Synchronous Execution Pipeline**: Scans currently execute synchronously within the FastAPI request cycle. A scan against a larger application will hold the connection open. Future versions will incorporate an asynchronous task queue (`FastAPI BackgroundTasks` or `Celery`).
2. **No JavaScript Execution (SPAs)**: The crawler operates via static HTML parsing (`BeautifulSoup4`). Applications built with client-side JavaScript rendering (React, Angular, Vue SPAs) will not have dynamically rendered routes discovered.
3. **Form-Based Discovery Focus**: Detection engines primarily analyze discovered forms and explicit query parameters. Endpoints hidden behind unreferenced paths or modern REST/GraphQL APIs are not explored without an OpenAPI specification.
4. **Single-User IDOR Context**: The IDOR detector operates without authenticated user sessions. Distinguishing private broken access control from public record lookups requires a multi-tenant test framework (comparing User A vs. User B credentials).
5. **Scope Guard Boundaries**: The scope guard validates hostname strings and blocks off-scope redirects, but does not perform kernel-level DNS pre-resolution to defend against advanced DNS rebinding attacks on public networks.
6. **No Production Claims**: This tool is built for controlled defensive auditing and educational evaluation. It is **not** a replacement for commercial dynamic application security testing (DAST) suites.

---

## 9. Authorized Use & Ethical Warning

> [!WARNING]
> **STRICTLY FOR AUTHORIZED DEFENSIVE AUDITING ONLY**
> Running security scanning tools against systems without prior explicit written permission from the system owner is illegal and unethical. Vulnora is pre-configured with a strict `ScopeGuard` that restricts scanning to local loopback interfaces (`127.0.0.1`, `localhost`, `::1`) by default. Do not disable scope restrictions or point this scanner at unauthorized public targets.
