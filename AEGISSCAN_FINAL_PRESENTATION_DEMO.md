# AegisScan 2.0 — Final Presentation & Video Demonstration Guide

> **College Project Final Evaluation & Live Demonstration Protocol**  
> **Repository:** https://github.com/akriti1305/vulnora-websec  
> **System:** AegisScan 2.0 + AegisShop (AegisLab) Vulnerability & AI Security Assessment Engine  
> **Evaluation Focus:** Real vulnerability detection, live source-code remediation, verifiable re-scan confirmation, and cryptographic provenance.

---

## 1. Executive Summary & Architecture Overview

AegisScan 2.0 is an enterprise-grade security scanner designed for modern web applications. Unlike traditional web vulnerability scanners (which only scan for SQLi, XSS, and broken access controls), AegisScan bridges **two critical domains**:

1. **Traditional Web Application Security:**
   - Evaluates the 5 primary web security categories:
     - **SQL Injection (SQLi)**
     - **Cross-Site Scripting (Reflected XSS)**
     - **Broken Access Control (IDOR)**
     - **Security Headers (CSP, HSTS, X-Frame-Options, etc.)**
     - **Cookie Security (HttpOnly, Secure flags)**
2. **Autonomous AI-Agent Security:**
   - Evaluates the OWASP Top 10 for LLMs in a controlled deterministic simulator:
     - **Indirect Prompt Injection**
     - **Sensitive Information Leakage (Canary Disclosure)**
     - **AI Tool Integrity (Tamper/Poisoning detection)**
     - **Unauthorized AI Actions (Taint tracking & excessive agency)**

All scan outputs are backed by an **Ed25519 digital signature passport** and an immutable, append-only **SHA-256 cryptographic hash-chain ledger**.

---

## 2. Pre-Presentation Setup (Run Once Before Recording/Presenting)

Ensure both the target application (AegisShop) and the scanner server (AegisScan) are active:

### Terminal 1: AegisShop Web Application (Target on Port 5001)
```powershell
cd D:\PRJ4
& ".\aegislab\venv\Scripts\python.exe" ".\aegislab\app.py"
```
*Verification:* Navigate to `http://127.0.0.1:5001` in your browser. You will see the AegisShop ecommerce storefront.

### Terminal 2: AegisScan Scanner Engine (API & Dashboard on Port 8000)
```powershell
cd D:\PRJ4
& ".\aegisscan\venv\Scripts\python.exe" -m uvicorn --app-dir ".\aegisscan" main:app --host 127.0.0.1 --port 8000
```
*Verification:* Navigate to `http://127.0.0.1:8000` in your browser. You will see the AegisScan 2.0 home dashboard.

---

## 3. Step-by-Step Live Video Walkthrough Script (5–6 Minutes)

### Step 1: Baseline Scan Review & Focused Web Demo (Minute 0:00 – 1:30)

1. Open your web browser to:
   ```
   http://127.0.0.1:8000/api/scans/37/report?view=focused
   ```
2. **What to Show on Screen:**
   - Point out the view toggle pills at the top:
     - `📋 Full Security Report`
     - `🎯 Focused Web Demo (2 Checks)`
   - Show the header: **"🎯 Focused Demonstration: 2 Security Checks"**.
   - Read the clear presentation disclaimer:
     > *"Presentation Filter: This focused view highlights only 2 primary web security checks (SQL Injection and Cross-Site Scripting) for a clear, beginner-friendly live demonstration. This does NOT imply that the target website has only two vulnerabilities."*
   - Display the two highlighted check categories:
     - **SQL Injection:** Status = `Issue Found` (Critical) • `3 observations (expand to view)`.
     - **Cross-Site Scripting (XSS):** Status = `Issue Found` (High) • `2 observations (expand to view)`.
3. **Expand Technical Evidence:**
   - Click **"Inspect Technical Evidence & Explanations (3 findings)"** under SQL Injection.
   - Show the exact location: `POST /login (field: username)`.
   - Point out the actual observed evidence: payload `' OR '1'='1' --` bypassed authentication and caused the server to return `"Logged in as: alice (role: admin)"`.

---

### Step 2: Live Code Remediation (Minute 1:30 – 2:30)

1. Open the source code file in your editor:
   - **File Path:** `D:\PRJ4\aegislab\app.py`
   - **Location:** Line 166–178 (`def login()` route)

2. **Show the Original Vulnerable Code:**
   ```python
   # ---- VULNERABLE: raw string concatenation (injectable) ----------
   # A real app would NEVER do this.
   query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
   # -----------------------------------------------------------------
   try:
       result = db.execute(query).fetchone()
       error  = None
   except sqlite3.OperationalError as e:
       # Show raw SQL error -- intentional information disclosure flaw
       error  = f"Database error: {e}"
       result = None
   if not result and not error:
       error = "Invalid username or password."
   ```

3. **Replace with the Secure Prepared Statement:**
   ```python
   # ---- FIXED: parameterized prepared statement (NOT injectable) ----
   query = "SELECT * FROM users WHERE username = ? AND password = ?"
   result = db.execute(query, (username, password)).fetchone()
   error = None if result else "Invalid username or password."
   # -----------------------------------------------------------------
   ```

4. **Save the File:**
   - In Flask with `debug=True`, Werkzeug automatically reloads in < 1 second.
   - If running manually in another console, restart the process:
     ```powershell
     # Press Ctrl+C in Terminal 1, then re-run:
     & ".\aegislab\venv\Scripts\python.exe" ".\aegislab\app.py"
     ```

---

### Step 3: Trigger Live Re-Scan (Minute 2:30 – 3:30)

1. Go to the AegisScan Dashboard (`http://127.0.0.1:8000`).
2. Select **Local Lab Benchmark** (`http://127.0.0.1:5001`).
3. Mode: **Deep Authorized Scan**.
4. Check the authorization checkbox and click **"Launch Security Scan"** (or use the Re-Scan button).
5. Watch the scanner execute:
   - Crawls pages and forms.
   - Re-tests SQL injection payloads (`' OR '1'='1' --`, `admin'--`, etc.).
   - Validates that authentication bypass **no longer succeeds** and no SQL errors are leaked.
   - Generates newly signed Scan (Scan #38).

---

### Step 4: Before & After Comparison Demonstration (Minute 3:30 – 5:00)

1. Navigate directly to the Comparison Report URL:
   ```
   http://127.0.0.1:8000/api/scans/compare/report?a=37&b=38
   ```

2. **Highlight the Visual Summary Cards:**
   - **Focused Demonstration Summary:**
     - `Before Fix: 2 affected categories` &rarr; `After Fix: 1 affected category`
   - **SQL Injection Comparison Card:**
     - Before: `BEFORE FIX: Issue Found` (3 observations)
     - After: `AFTER FIX: No Longer Reproduced` (0 observations)
     - Badge: **`RESOLVED AFTER RETEST`** (Green)
   - **Cross-Site Scripting (XSS) Comparison Card:**
     - Before: `BEFORE FIX: Issue Found` (2 observations)
     - After: `AFTER FIX: Issue Found` (2 observations)
     - Badge: **`UNCHANGED (STILL CONFIRMED)`** (Yellow)
   - **Other Evaluated Checks Table:**
     - Broken Access Control (IDOR): Still Confirmed
     - Security Headers: Still Confirmed
     - Cookie Security: Still Confirmed
   - **Total Web Categories Affected:** `5` &rarr; `4`

3. **Key Talking Point for Evaluators:**
   > *"Notice that AegisScan did not fake or mock this result. The detector actively re-sent all attack payloads against the running server. Because line 168 was rewritten to use parameterized query placeholders (`?`), the database treated the injection string strictly as literal characters rather than executable SQL syntax. Meanwhile, because we did not touch the XSS search endpoint, XSS remains accurately flagged as confirmed."*

---

### Step 5: Full Security Report & AI Architecture (Minute 5:00 – 6:00)

1. Click **"View Full Security Report"** or navigate to:
   ```
   http://127.0.0.1:8000/api/scans/38/report
   ```
2. **Section A — Web Application Security (5 Categories):**
   - Shows SQL Injection as `Passed` (`Low` severity).
   - Shows XSS, IDOR, Headers, and Cookies with their exact observation counts and expandable `<details>` evidence.
3. **Section B — AI Assistant Security (4 Categories):**
   - Explain the banner:
     > *"Controlled Deterministic AI Security Simulator: The target AI assistant (`/assistant`) operates in a deterministic testbed designed to measure indirect prompt injection, sensitive canary disclosure, and excessive agency under strict benchmark controls."*
   - Review the 4 checks: Prompt Injection, Sensitive Info Leakage, Tool Integrity (3 verified controls), and Unauthorized AI Actions.
4. **Section C — Cryptographic Provenance Ledger:**
   - Expand the bottom panel to show:
     - Ed25519 Digital Signature & Public Key ID.
     - SHA-256 Canonical Payload Hash.
     - Append-Only Hash-Chain Record linking Scan #37 to Scan #38.

---

## 4. How to Restore the Baseline Vulnerable State

After finishing your recording or evaluation, restore the original vulnerable line in `D:\PRJ4\aegislab\app.py`:

```python
        else:
            # ---- VULNERABLE: raw string concatenation (injectable) ----------
            # A real app would NEVER do this.
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            # -----------------------------------------------------------------
            try:
                result = db.execute(query).fetchone()
                error  = None
            except sqlite3.OperationalError as e:
                # Show raw SQL error -- intentional information disclosure flaw
                error  = f"Database error: {e}"
                result = None
            if not result and not error:
                error = "Invalid username or password."
```
Once saved, `http://127.0.0.1:5001/login` is immediately ready for another live demo.

---

## 5. Security Boundaries & ScopeGuard Summary

- **Local Lab Boundary:** Unrestricted local benchmark testing allowed for targets matching loopback addresses (`127.0.0.1`, `localhost`).
- **External Basic Boundary:** Safe passive assessment (headers, cookies, TLS certificates, robots.txt, sitemap.xml, crawl, tech fingerprinting) within strict limits (max 50 requests, 2.0 req/sec) with self-attested legal authorization. Active injection tests are blocked and classified honestly as `Not Tested`.
- **External Deep Boundary:** Strictly enforces cryptographic domain ownership verification via `.well-known/aegisscan-verification.txt`.
- **Anti-SSRF Protection:** `SSRFProtectTransport` actively enforces socket-level IP pinning, preventing DNS rebinding, loopback evasion, private RFC 1918 egress, and cloud metadata access (`169.254.169.254`).
