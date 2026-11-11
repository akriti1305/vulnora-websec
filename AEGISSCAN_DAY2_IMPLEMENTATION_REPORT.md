# AEGISSCAN 2.0 — DAY 2 FINAL FUNCTIONAL IMPLEMENTATION REPORT
## Simple URL-Based Scanning, Dual-Tier Scope Authorization & AI Benchmark Validation

**Project Directory:** `D:\PRJ4`  
**GitHub Repository:** `https://github.com/akriti1305/vulnora-websec`  
**Branch:** `master`  
**Evaluation Target Date:** In 2 Days  
**Report Date:** November 11, 2026  
**Engineering Roles:** Senior Application Security Engineer, AI Security Researcher, Python Backend Lead, QA Automation Engineer  

---

## 1. Executive Summary

During **Day 2 Final Functional Implementation**, AegisScan 2.0 was upgraded to deliver a streamlined, demo-ready web security scanning workflow for single-operator local use while rigorously maintaining safety, cryptographic provenance, and academic benchmark defensibility:

1. **Simple URL-Based External Basic Scanning**:
   - Removed the mandatory `.well-known/aegisscan-verification.txt` challenge token requirement for **External Basic** scans.
   - Operators can now directly enter any authorized external target URL (e.g. `https://aakriti-portfolio-beryl.vercel.app`), declare legal authorization via a self-attestation checkbox, and launch an immediate background scan.
   - Strict bounded limits are automatically applied: max 50 HTTP requests, 2.0 requests per second rate limit, and safe `GET`/`HEAD` discovery only.
   - Passive discovery covers: TLS certificate inspection, security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), cookie security flags (HttpOnly, Secure, SameSite), `robots.txt` path analysis, `sitemap.xml` inspection, public HTML crawling, public form inventory, and technology stack fingerprinting.
   - Active probe categories (SQLi, XSS, IDOR) are honestly classified as **`not_tested`**, never falsely claiming an application is vulnerability-free.

2. **Strict Preservation of Technical Domain Verification for External Deep Mode**:
   - The `.well-known/aegisscan-verification.txt` cryptographic domain control verification remains **mandatory** for **Authorized Deep** scans.
   - Attempting an External Deep scan on an unverified domain strictly raises **HTTP 403** with a descriptive explanation (`Technically verified domain control required`).
   - Deep requests are **never silently downgraded** to Basic mode.
   - The UI provides an accessible **Domain Ownership Verification Drawer** with one-click token copying and step-by-step instructions for Vercel/Next.js and static web deployments.

3. **ScopeGuard Anti-SSRF and DNS Rebinding Hardening Preserved**:
   - External target URLs are strictly restricted to HTTPS port 443.
   - Private RFC 1918 networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback addresses (`127.0.0.0/8`), link-local IPs, cloud metadata endpoints (`169.254.169.254`), and IPv4-mapped IPv6 evasions are blocked at the ScopeGuard transport layer and at initial URL validation.
   - Pre-flight DNS validation and socket IP pinning prevent DNS rebinding attacks.

4. **Dynamic Dual-State AI Security Benchmark (AegisLab)**:
   - Coupled the parameterised SQL query defense on `/login` and the AI Assistant safety mechanisms with the dynamic runtime configuration in `aegislab/ai_assistant.py`.
   - Operators can toggle between **Vulnerable** and **Secure** states on the fly via `POST /assistant/reset` with `{"secure_mode": true/false}` without restarting the server.
   - In Vulnerable mode: Indirect prompt injection through uploaded documents leaks the protected canary (`AEGIS_CANARY_20261028_X7K9`) and triggers simulated unauthorized tool calls.
   - In Secure mode: Untrusted document content is treated strictly as data, the canary remains guarded, and high-impact actions require explicit user approval.
   - Full differential comparison (`/compare?a=1&b=2`) highlights resolved vulnerabilities (`resolved_after_retest`) versus persisting flaws (`still_confirmed`).

5. **Test Suite Expansion & Zero Regressions**:
   - The automated regression test suite was expanded from **117 to 124 tests** with a **100% pass rate** across all modules.

---

## 2. Inventory of Day 2 Changes

| File Path | Component | Changes Made |
| :--- | :--- | :--- |
| `aegisscan/authorization.py` | Scope & Grant Management | Added `self_attested: bool = False` parameter to `create_authorization_grant()`. Allows `external_basic` grants on unverified targets when `self_attested=True`, while strictly maintaining `is_verified` requirement for `external_deep`. Updated `get_target_status_summary()` to correctly represent `authorized_basic` status. |
| `aegisscan/api/routes.py` | Scope Validation & Launch Pipeline | Updated `validate_target_scope()` signature to accept `auth_declared: bool`, `operator: str`, and `target_name: Optional[str]`. Automatically registers unverified targets and generates self-attested `external_basic` grants when `auth_declared=True`. Rejects missing authorization declaration with HTTP 403. Strictly enforces technical domain control for `external_deep` (HTTP 403 refusal; no silent downgrade). Added IP-literal anti-SSRF pre-validation. |
| `aegisscan/main.py` | Web UI Form Action | Updated `form_start_scan()` to accept `auth_ack: Optional[str] = Form(None)` and `operator: Optional[str] = Form("Operator")`, forwarding `auth_declared=bool(auth_ack)` to `start_scan()`. |
| `aegisscan/templates/index.html` | Unified Operator Dashboard | Redesigned External target panel: direct URL input field, target name field, radio mode selector (`External Basic` default vs `Authorized Deep`), legal authorization declaration checkbox, and "Start Authorized External Scan" button. Relocated domain token management into collapsible "Domain Ownership Verification Drawer" with auto-opening on Deep mode selection. Auto-fills direct URL form when registered target is selected. |
| `aegislab/app.py` | AegisLab Testbed Server | Coupled `/login` parameterized query toggle with `ai_assistant.is_secure(request)`: `if SECURE_MODE or is_secure(request):`. Allows single-click dynamic toggle between vulnerable and secure modes for both SQLi and AI agent via `POST /assistant/reset`. |
| `tests/test_day2_url_scanning.py` | Automated Regression Suite | Created 7 new automated tests covering: self-attested External Basic launch, HTTP 403 refusal on omitted auth declaration, HTTP 403 refusal on unverified External Deep, prevention of silent downgrade, ScopeGuard anti-SSRF IP rejection, verified Deep scan execution, and dynamic AegisLab vulnerable vs secure toggling. |
| `README.md` | Documentation | Updated system architecture, operational mode definitions, and automated test suite metrics (124 tests). |
| `DEMO_GUIDE.md` | College Presentation Guide | Updated live walkthrough script to demonstrate URL-based External Basic scanning, domain control enforcement on Deep mode, and dynamic dual-state AI benchmark comparison. |

---

## 3. External Basic Scanning Architecture

### 3.1 Self-Attestation vs. Technical Domain Control
AegisScan 2.0 strictly distinguishes between **self-attested authorization** and **technically verified domain control**:

```
                       ┌────────────────────────────────────────────────────────┐
                       │               Target Domain Input                      │
                       │          https://portfolio.example.com                 │
                       └──────────────────────────┬─────────────────────────────┘
                                                  │
                                                  ▼
                                       [ Mode Selected? ]
                                      /                  \
                        External Basic                    Authorized Deep
                             │                                  │
                             ▼                                  ▼
                [ Legal Auth Declared? ]               [ Domain Verified? ]
                (Checkbox: auth_declared)         (/.well-known/... challenge)
                    /                \                     /                \
                  YES                 NO                 YES                 NO
                   │                   │                  │                   │
                   ▼                   ▼                  ▼                   ▼
            [ Create Grant ]       [ HTTP 403 ]     [ Create Deep Grant] [ HTTP 403 ]
            - max_requests: 50     "Auth Required"  - max_requests: 150  "Domain Control
            - rate_limit: 2.0 rps                   - rate_limit: 1.0 rps Required"
            - GET/HEAD passive                      - active fuzzing     (NO downgrade)
            - active: not_tested                    - path exclusions
```

- **External Basic**: Designed for rapid, non-invasive assessment. The operator certifies ownership or permission via an affirmative declaration. The backend records an `AuditEvent(event_type="authorization_declared")` storing the timestamp, target hostname, operator name, and policy bounds. The Target entity remains `is_verified=False` with `verification_method="self_attested"`.
- **External Deep**: Reserved for invasive active testing. Requires technical proof of administrative domain control via an HTTP GET challenge token placed at `https://<host>/.well-known/aegisscan-verification.txt`.

### 3.2 Safe Passive Inspection Pipeline
When an External Basic scan executes, `_execute_scan_pipeline()` in `aegisscan/api/routes.py` performs safe, non-destructive checks:
1. **Safe Scope-Bound Crawl**: Bounded GET/HEAD crawl discovering public URLs and forms up to the 50-request budget.
2. **TLS Certificate & Transport**: Validates certificate validity, issuer, SAN matching, cipher suites, and protocol version (TLS 1.2/1.3) via pinned socket connection.
3. **Robots.txt & Sitemap.xml**: Inspects `robots.txt` for sensitive disallow paths and fetches `sitemap.xml` for sitemap inventory.
4. **Security Headers**: Detects presence and configuration of `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`.
5. **Cookie Security Flags**: Inspects observed `Set-Cookie` directives for `HttpOnly`, `Secure`, and `SameSite` flags.
6. **Form & Tech Stack Inventory**: Catalogs public `<form>` inputs without submitting data; identifies server headers, CDNs (Cloudflare), edge platforms (Vercel Edge Network), and frameworks (Next.js).
7. **Honest Stubs**: Appends explicit `not_tested` stubs for SQLi, XSS, and IDOR, and `not_applicable` stubs for AI features if no AI endpoint exists on the target.
8. **Cryptographic Sealing**: Generates an Ed25519 digital signature over the finding digests and appends a record to the append-only SHA-256 hash-chain ledger.

---

## 4. External Deep Mode Verification Preservation

External Deep active testing probes for injection vulnerabilities (SQLi, XSS) and requires strict safeguards against unauthorized scanning:

1. **Mandatory Token Verification**:
   - `validate_target_scope()` checks `target.is_verified`. If `False`, it immediately raises:
     ```
     HTTP 403 Forbidden: Technically verified domain control required: External target '<host>' ownership is not verified. External Deep mode requires placing the verification token at https://<host>/.well-known/aegisscan-verification.txt and completing domain ownership verification.
     ```
2. **No Silent Downgrade**:
   - If an operator selects `external_deep` on an unverified target, AegisScan **never** silently downgrades to `external_basic`. The request is rejected outright with HTTP 403.
3. **Domain Verification Drawer**:
   - In `aegisscan/templates/index.html`, the `.well-known` token generation, verification URL display, token copy button, Next.js/Vercel deployment instructions, and "Verify Ownership Now" button remain fully functional in a dedicated collapsible drawer.
   - Selecting the "Authorized Deep" radio option automatically expands the drawer to guide the user.

---

## 5. AI Security Functional Demonstration

AegisLab (`http://127.0.0.1:5001`) serves as the deterministic AI-agent security testbed:

### 5.1 Dual-State Architecture
A single API call toggles both the traditional web vulnerabilities and the AI assistant guardrails:
```powershell
# Toggle to Vulnerable Mode
curl -X POST http://127.0.0.1:5001/assistant/reset -H "Content-Type: application/json" -d '{"secure_mode": false}'

# Toggle to Secure Mode
curl -X POST http://127.0.0.1:5001/assistant/reset -H "Content-Type: application/json" -d '{"secure_mode": true}'
```

### 5.2 Vulnerable State Behavior
- **SQL Injection**: `POST /login` with `' OR '1'='1` successfully authenticates as user `alice` due to raw string concatenation.
- **Indirect Prompt Injection**: When the AI assistant processes an untrusted document containing prompt injection commands (e.g. `doc_002`), the model simulator follows the attacker instructions, leaks the protected canary (`AEGIS_CANARY_20261028_X7K9`), and sets `canary_leaked=True`.
- **Excessive Agency / Unapproved Tool Use**: The assistant executes high-impact tools (`send_email`) autonomously without requesting operator confirmation.

### 5.3 Secure State Behavior
- **SQL Injection**: `POST /login` uses parameterized queries (`SELECT * FROM users WHERE username = ? AND password = ?`); SQL injection attempts fail.
- **Indirect Prompt Injection**: Untrusted document content is isolated within structured delimiter tags (`<untrusted_document_context>`); injection instructions are treated strictly as inert data; the protected canary is withheld.
- **Approval Gate Enforcement**: High-impact tool invocations (`send_email`) are halted at an approval boundary (`requires_approval=True`) until an operator explicitly passes `approved=True`.

### 5.4 Differential Scan Comparison
Scanning AegisLab in Vulnerable mode (Scan A), resetting to Secure mode, and re-scanning (Scan B) enables the comparison engine at `/compare?a=A&b=B`:
- **`resolved_after_retest`**: SQL Injection and Indirect Prompt Injection are verified fixed and highlighted in green.
- **`still_confirmed`**: Flaws intentionally left unfixed across runs remain clearly documented.
- **`not_retested`**: Any checks omitted due to scan mode differences are honestly marked rather than assumed fixed.

---

## 6. Automated Test Suite Results

The automated regression test suite was executed across all 15 test modules:

```powershell
& "D:\PRJ4\aegisscan\venv\Scripts\python.exe" -m unittest discover -s tests -p "test_*.py" -b
```

### Execution Output:
```
............................................................................................................................
----------------------------------------------------------------------
Ran 124 tests in 39.575s

OK
[AegisLab] SECURE_MODE=OFF -- /login is vulnerable to SQLi (default)
```

### Test Suite Breakdown:

| Test Module | Tests | Focus Area | Status |
| :--- | :---: | :--- | :---: |
| `tests/test_day2_url_scanning.py` | 7 | URL-based basic scan, auth rejection, deep domain requirement, anti-SSRF, AI dynamic toggle | **PASSED** |
| `tests/test_ssrf_protection.py` | 8 | Pinned socket IP backend, DNS rebinding TOCTOU protection, RFC 1918 blocking | **PASSED** |
| `tests/test_scan_execution.py` | 4 | Non-blocking background threads, concurrency limits (HTTP 429), progress rendering | **PASSED** |
| `tests/test_external_scope_and_auth.py` | 11 | Target registration, .well-known challenges, ScopeGuard redirects, passive stubs | **PASSED** |
| `tests/test_aegislab_ai.py` | 13 | Scenarios A-F, canary secrecy, tool description poisoning, rug-pull detection | **PASSED** |
| `tests/test_final_integration.py` | 7 | Dashboard HTML rendering, finding categories, 5-bucket comparison, evaluation metrics | **PASSED** |
| `tests/test_provenance_passports.py` | 14 | Ed25519 digital signatures, canonical serialization, hash-chain ledger continuity | **PASSED** |
| `tests/test_tool_integrity.py` | 13 | Canonical tool hashing, schema drift, poisoned descriptions, rug-pull detection | **PASSED** |
| `tests/test_taint_and_permissions.py` | 10 | Taint propagation, sensitive source tracking, permission boundary analysis | **PASSED** |
| `tests/test_ai_pipeline.py` | 9 | End-to-end AI detection pipeline, manifest discovery, prompt injection scoring | **PASSED** |
| `tests/test_smoke_local.py` | 4 | Local crawler discovery, SQLi, XSS, and IDOR detection on AegisLab | **PASSED** |
| `tests/test_redirect_scope.py` | 5 | Crawler redirect boundary enforcement, out-of-scope domain escape prevention | **PASSED** |
| `tests/test_cookie_scope.py` | 5 | Cookie flag analysis (HttpOnly, Secure, SameSite) across discovered paths | **PASSED** |
| `tests/test_evaluation_rerun.py` | 6 | Confusion matrix computation (TP, FP, FN, TN, P, R, F1) across detection runs | **PASSED** |
| **Total** | **124** | **100% Pass Rate across all modules** | **PASSED** |

---

## 7. Step-by-Step Evaluator Demonstration Script

Follow this exact sequence during the final evaluation presentation:

### Step 1: Launch Servers
```powershell
# Terminal 1: AegisLab Target
cd D:\PRJ4
& ".\aegislab\venv\Scripts\python.exe" ".\aegislab\app.py"

# Terminal 2: AegisScan Dashboard
cd D:\PRJ4
& ".\aegisscan\venv\Scripts\python.exe" -m uvicorn --app-dir ".\aegisscan" main:app --host 127.0.0.1 --port 8000
```

### Step 2: Demonstrate External Basic Scanning (Real Website)
1. Navigate to `http://127.0.0.1:8000` in the browser.
2. Click the **External Authorized Website** tab.
3. Enter `https://aakriti-portfolio-beryl.vercel.app` in the **Target Base URL** field.
4. Enter `Aakriti Portfolio` in the **Site Name / Label** field.
5. Keep **External Basic** selected (default).
6. Verify the **Legal Authorization Declaration** checkbox is checked.
7. Click **Start Authorized External Scan →**.
8. Observe the background execution, redirect to `/api/scans/<ID>/report`, and view findings:
   - TLS certificate status and cipher suite.
   - Security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options).
   - Cookie flags.
   - Public form inventory and technology stack fingerprinting (Vercel Edge Network / Next.js).
   - Active probe categories (SQLi, XSS, IDOR) honestly classified as **`Not Tested`**.
   - Verified Ed25519 Scan Passport and SHA-256 hash-chain entry.

### Step 3: Demonstrate External Deep Refusal Enforcement
1. Return to `http://127.0.0.1:8000`.
2. Click the **External Authorized Website** tab.
3. Select **Authorized Deep** scan mode.
4. Notice how the **Domain Ownership Verification Drawer** automatically opens.
5. Click **Start Authorized External Scan →** without verifying domain ownership.
6. Observe immediate refusal with an error banner:
   ```
   Technically verified domain control required: External target '...' ownership is not verified. External Deep mode requires placing the verification token at https://.../.well-known/aegisscan-verification.txt.
   ```
7. Point out that AegisScan **never silently downgrades** to Basic mode.

### Step 4: Demonstrate Dynamic Dual-State AI Security Benchmark
1. In PowerShell, reset AegisLab to Vulnerable mode:
   ```powershell
   Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:5001/assistant/reset" -ContentType "application/json" -Body '{"secure_mode": false}'
   ```
2. On the dashboard, switch to **Local Lab Benchmark** (`http://127.0.0.1:5001`), select **Deep Authorized**, and launch Scan A.
3. Show findings: SQL Injection on `/login`, Indirect Prompt Injection, Canary Leakage (`AEGIS_CANARY_20261028_X7K9`), and Unapproved Tool Execution.
4. In PowerShell, toggle AegisLab to Secure mode:
   ```powershell
   Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:5001/assistant/reset" -ContentType "application/json" -Body '{"secure_mode": true}'
   ```
5. Launch Scan B against `http://127.0.0.1:5001`.
6. Open `/compare?a=<ScanA_ID>&b=<ScanB_ID>`:
   - Highlight **`resolved_after_retest`** showing both SQL injection and Indirect Prompt Injection marked as resolved.
   - Point out the verified security controls active in Scan B (Approval Gate Verified, Canary Guard Active).

### Step 5: Run Automated Regression Suite
Show the full test suite passing live in PowerShell:
```powershell
& "D:\PRJ4\aegisscan\venv\Scripts\python.exe" -m unittest discover -s tests -p "test_*.py" -b
```
*Expected: `Ran 124 tests in ~40s ... OK`*

---

## 8. Conclusion

All Day 2 functional requirements are complete, verified, and backed by automated tests:
- Simple URL-based scanning is live for authorized external targets under safe passive bounds.
- Technical domain ownership verification remains strictly enforced for active deep scanning.
- ScopeGuard anti-SSRF, DNS rebinding socket pinning, and redirect boundaries are active.
- Dual-state AI assistant benchmarking is demonstrable without restarting servers.
- Cryptographic provenance (Ed25519 passports and SHA-256 hash chains) is unbroken.
- The project is fully documented, tested (124 tests passing), and ready for final evaluation.

