# AegisScan 2.0 -- 5 to 7 Minute College Demonstration Script

> **Evaluator Presentation Guide & Live Walkthrough**  
> *Project:* AegisScan 2.0: AI-Agent Web Security Scanner with Cryptographic Provenance & Hardened ScopeGuard  
> *Targets:* AegisLab Isolated Benchmark Target & Authorized External Web Targets

---

## Quick Setup (Before the Evaluators Arrive)

1. Open **PowerShell Window 1** (AegisLab Target):
   ```powershell
   cd D:\PRJ4
   & ".\aegislab\venv\Scripts\python.exe" ".\aegislab\app.py"
   ```
   *Verify:* App listening on `http://127.0.0.1:5001`.

2. Open **PowerShell Window 2** (AegisScan Scanner):
   ```powershell
   cd D:\PRJ4
   & ".\aegisscan\venv\Scripts\python.exe" -m uvicorn --app-dir ".\aegisscan" main:app --host 127.0.0.1 --port 8000
   ```
   *Verify:* Scanner dashboard accessible at `http://127.0.0.1:8000`.

3. Open your browser and navigate to: `http://127.0.0.1:8000`.

---

## 5–7 Minute Demonstration Timeline

### [Minute 0:00 – 1:15] Executive Introduction & Motivation
**Action**: Display the AegisScan 2.0 dashboard at `http://127.0.0.1:8000`.

**Talking Points**:
- *"Good morning/afternoon, evaluators. Today we are presenting **AegisScan 2.0**."*
- *"Traditional web security scanners like OWASP ZAP or Nikto only assess standard web vulnerabilities: SQL injection, XSS, and broken access controls. However, modern web applications increasingly integrate **LLM-powered autonomous AI assistants** that execute tools, access private databases, and process user documents."*
- *"This introduces a critical new attack surface: **Indirect Prompt Injection**, **AI-Agent Tool Description Poisoning**, **Sensitive Canary Leakage**, and **Excessive Agency** (OWASP Top 10 for LLMs)."*
- *"Furthermore, in Phase 14, we upgraded AegisScan from a localhost-only research tool into a hardened security scanner capable of assessing real-world external websites while maintaining **zero-trust anti-SSRF boundaries**, **domain ownership verification**, and **tamper-evident Ed25519 cryptographic scan passports** backed by an append-only **SHA-256 hash-chain ledger**."*

---

### [Minute 1:15 – 2:30] Demonstrating Phase 14 External Website Protection
**Action**:
1. Click the **External Authorized Website** tab on the dashboard.
2. In the target URL field, show an unverified domain (e.g. `https://aakriti-portfolio-beryl.vercel.app`).
3. Click **Launch Security Scan** without verifying ownership.
4. Show the immediate, clear safety refusal modal:
   *"Authorization required: External target ownership is not verified. Add the verification token to `/.well-known/aegisscan-verification.txt` before scanning."*

**Talking Points**:
- *"Notice our **Zero-Trust External Authorization Architecture**: an operator cannot scan arbitrary third-party websites without proving domain control."*
- *"We implement a cryptographically unpredictable challenge token published at `https://TARGET/.well-known/aegisscan-verification.txt` over HTTPS."*
- *"Even after ownership verification, scanning requires an **explicit legal scope declaration** recording authorized paths, excluded paths, scan rate limits, and operator acknowledgment."*
- *"Underneath, our **SSRFProtectTransport** strictly blocks loopback addresses, private RFC 1918 networks, link-local IPs, IPv4-mapped IPv6 evasions, cloud metadata services (`169.254.169.254`), and out-of-scope redirect escapes."*

---

### [Minute 2:30 – 3:45] Launching the Live Deep Local Lab Scan
**Action**:
1. Switch back to the **Local Lab Benchmark** tab.
2. Target URL: `http://127.0.0.1:5001`.
3. Scan Mode: **Deep Authorized Scan**.
4. Check the authorization checkbox and click **Launch Security Scan**.

**Talking Points while the scan runs (~10 seconds)**:
- *"For local development and regression testing, our **Local Lab mode** assesses the complete AegisLab enterprise benchmark."*
- *"The crawler discovers 28 pages and 70 HTML forms."*
- *"The engine executes a two-stage pipeline: first passive detection, then **active validation** where payloads are compared against benign control requests to confirm exploitability."*
- *"Simultaneously, the engine queries the target's `.well-known/aegisscan-ai.json` security manifest to baseline AI tools and test for indirect prompt injection in uploaded documents."*

---

### [Minute 3:45 – 4:45] Categorized Findings & Honest Reporting
**Action**: Open the completed scan report page (`http://127.0.0.1:8000/api/scans/<ID>/report`).

**Talking Points**:
- *"Notice our **Honest Classification Architecture**: findings are partitioned into 6 distinct categories:"*
  - **Confirmed Vulnerabilities** (e.g., SQLi bypass on `/login`, Reflected XSS on `/search`, IDOR on `/user/profile`).
  - **AI-Agent Flaws** (e.g., Indirect Prompt Injection on `/assistant/query`, Secret Canary Leakage `CANARY_SECRET_7702`, Excessive Agency where an untrusted document triggered an unapproved `send_email` action).
  - **Verified Security Controls** (e.g., `Tool Integrity Verified`, `AI Agent Approval Gate Verified`, `TLS 1.3 Transport Security`).
  - **Not Tested** (for external basic scans, active injection categories are honestly marked `Not Tested` rather than claiming the site is secure).
  - **Not Applicable** (for static web applications without AI features, AI tests are marked `Not Applicable` rather than reporting false alarms).
- *"Verified defensive controls are displayed in blue pills and are **NOT counted as vulnerabilities or false positives**."*

---

### [Minute 4:45 – 5:45] Cryptographic Scan Passport & Tamper Rejection
**Action**:
1. Scroll down to the **Cryptographic Provenance** card on the report page.
2. Click **Download Signed Passport (.json)** to display the JSON structure.
3. Show the **Ed25519 Digital Signature** and **Canonical SHA-256 Hash**.

**Talking Points**:
- *"How do compliance teams know an audit report has not been forged or altered? AegisScan signs every scan using asymmetric **Ed25519 cryptography**."*
- *"The passport hashes canonical finding digests, timestamp, target URL, and severity metrics."*
- *"If an attacker modifies the finding severity from `Critical` to `Low`, the independent verifier recomputes the SHA-256 hash, detects the tampering, and **instantly rejects the passport** with `status: INVALID`."*
- *"Furthermore, each scan record is cryptographically linked to the previous scan's hash in an **append-only SHA-256 hash-chain ledger** ($H_n = \text{SHA256}(R_n \parallel H_{n-1})$)."*

---

### [Minute 5:45 – 6:30] Automated Test Suite & Conclusion
**Action**:
Show the terminal running the 109 automated unit and regression tests:
```powershell
& "D:\PRJ4\aegisscan\venv\Scripts\python.exe" -m unittest discover -s tests -p "test_*.py" -b
```
*Output: `Ran 109 tests in ~24s ... OK`*

**Talking Points**:
- *"AegisScan 2.0 is validated by **109 automated unit and integration tests** covering anti-SSRF protections, subdomain isolation, challenge token validation, crawler budgets, detector accuracy, Ed25519 signatures, and hash-chain integrity."*
- *"In summary: AegisScan 2.0 provides an explainable, end-to-end security audit for both modern web apps and AI agents, backed by mathematical cryptographic trust and hardened network safety boundaries."*
- *"Thank you, and we welcome any questions!"*

---

## Anticipated Evaluator Questions & Answers

**Q1: How do you prevent attackers from using AegisScan to attack third-party websites or internal corporate networks (SSRF)?**  
*Answer:* AegisScan enforces two distinct layers:
1. **Target Authorization**: A domain cannot be scanned until the operator proves administrative control by placing a random 32-byte cryptographic challenge token at `https://TARGET/.well-known/aegisscan-verification.txt`.
2. **ScopeGuard Transport**: All outbound requests pass through `SSRFProtectTransport`. In external mode, the scanner restricts requests strictly to HTTPS port 443, resolves DNS pre-flight to validate every IP address against private, loopback, link-local, multicast, and cloud metadata (`169.254.169.254`) ranges, and intercepts every HTTP redirect destination before following it.

**Q2: What is the difference between External Basic and External Deep scan modes?**  
*Answer:*
- **External Basic**: Safe discovery mode. Performs GET/HEAD-only crawling, TLS certificate inspection, robots.txt/sitemap discovery, security header analysis, cookie flag checks, and technology inventory. It never sends injection payloads or state-changing requests, and honestly reports active categories as `Not Tested`.
- **External Deep**: Bounded active testing requiring separate affirmative legal authorization. It strictly respects path bounds, request budgets (max requests cap), rate limits, and automatically excludes sensitive paths like `/logout`, `/delete`, and payment endpoints.

**Q3: How does your Ed25519 passport prevent an attacker from modifying findings?**  
*Answer:* Before signing, the passport canonicalizes all JSON fields using deterministic serialization (`canonical_serialize`) and hashes the payload with SHA-256. The scanner signs this digest using its private Ed25519 key. If an attacker modifies even a single character in the findings or severity, the recalculated hash fails to match, or the signature verification fails.

**Q4: How does the append-only hash chain work?**  
*Answer:* Each completed scan produces a record $R_n$. Its chain hash is computed as $H_n = \text{SHA256}(\text{seq}_n \parallel \text{scan\_id}_n \parallel \text{payload\_hash}_n \parallel H_{n-1})$. The genesis block uses a 64-character zero hash. If an attacker modifies or deletes a historical scan in the database, the hash links of all subsequent records break, causing the integrity audit to report `status: TAMPERED`.
