# AegisScan 2.0 -- 5 to 7 Minute College Demonstration Script

> **Evaluator Presentation Guide & Live Walkthrough**  
> *Project:* AegisScan 2.0: AI-Agent Web Security Scanner with Cryptographic Provenance  
> *Target:* AegisLab Isolated Benchmark Target

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

### [Minute 0:00 – 1:00] Executive Introduction & Motivation
**Action**: Display the AegisScan 2.0 dashboard at `http://127.0.0.1:8000`.

**Talking Points**:
- *"Good morning/afternoon, evaluators. Today we are presenting **AegisScan 2.0**."*
- *"Traditional web security scanners like OWASP ZAP or Nikto only look for standard web flaws -- SQL injection, XSS, and broken access controls. However, modern 2026 web applications increasingly integrate **LLM-powered AI assistants** that have access to internal tools, user documents, and sensitive APIs."*
- *"This creates a new attack surface: **Indirect Prompt Injection**, **AI-Agent Tool Poisoning**, **Sensitive Canary Leakage**, and **Excessive Agency** (OWASP Top 10 for LLMs)."*
- *"AegisScan 2.0 is designed to discover both traditional web flaws AND AI-agent risks, actively validate them to eliminate false positives, and produce **cryptographically signed Ed25519 Scan Passports** backed by a **SHA-256 hash-chain ledger**."*

---

### [Minute 1:00 – 2:30] Launching the Live Deep Authorized Scan
**Action**:
1. In the **Target URL** field, enter: `http://127.0.0.1:5001`.
2. Under **Scan Mode**, select **Deep Authorized Scan**.
3. Check the **Authorization Checkbox**: *"I am authorized to test this target and consent to deep active probes"*.
4. Click **Launch Security Scan**.

**Talking Points while the scan runs (~10 seconds)**:
- *"Notice our **ScopeGuard architecture**: it prevents unauthorized off-target scanning by enforcing strict host boundary validation on `localhost`."*
- *"The crawler explores 20 endpoints and 33 HTML forms."*
- *"In **Deep Mode**, the engine executes a 2-stage pipeline: first passive detection, then **active validation** where payloads are compared against benign control requests to confirm exploitability."*
- *"Simultaneously, the engine queries the target's `.well-known/aegisscan-ai.json` security manifest to baseline AI tools and test for indirect injection in uploaded documents."*

---

### [Minute 2:30 – 3:45] Examining the Categorized Report & AI Flaws
**Action**: Show the completed scan report page (`http://127.0.0.1:8000/api/scans/<ID>/report`).

**Talking Points**:
- *"Notice our **Honest Classification Architecture**: findings are strictly partitioned into 6 categories:"*
  - **Confirmed Vulnerabilities** (e.g., SQLi bypass on `/login`, Reflected XSS on `/search`, IDOR on `/user/profile`).
  - **AI-Agent Flaws** (e.g., Indirect Prompt Injection on `/assistant/query`, Secret Canary Leakage `CANARY_SECRET_7702`, Excessive Agency where an untrusted document triggered an unapproved `send_email` action).
  - **Verified Security Controls** (e.g., `Tool Integrity Verified`, `AI Agent Approval Gate Verified`).
  - **Informational Discoveries** (e.g., `AI Assistant Discovered`).
- *"Notice the crucial honesty distinction: verified defensive controls are displayed in blue pills and are **NOT counted as vulnerabilities or false positives**."*
- *"Each finding card displays the exact payload used, reproducing evidence, and actionable remediation advice."*

---

### [Minute 3:45 – 4:45] Cryptographic Scan Passport & Tampering Proof
**Action**:
1. Scroll down to the **Cryptographic Provenance** card on the report page.
2. Click **Download Signed Passport (.json)** to show the raw JSON.
3. Show the **Digital Signature** (`Ed25519`) and **Canonical Payload Hash** (`SHA-256`).

**Talking Points**:
- *"How do stakeholders know this security report hasn't been altered? AegisScan signs every scan using asymmetric **Ed25519 cryptography**."*
- *"The passport hashes canonical finding digests, timestamp, target URL, and severity metrics."*
- *"Let us demonstrate our tampering detection:"*

**Action (Terminal 3 or Demo Script)**:
Run the live automated demonstration script to show tamper rejection in real time:
```powershell
& "D:\PRJ4\aegisscan\venv\Scripts\python.exe" "D:\PRJ4\demo_phase12.py"
```
**Talking Points**:
- *"As you can see in Step 4 of the terminal output: an attacker modified the finding severity from `Critical` to `Low`. The independent verifier recomputed the canonical SHA-256 hash, detected the mismatch, and **instantly rejected the passport** with `status: INVALID`."*
- *"In Step 7, notice our **append-only SHA-256 hash-chain**: each scan record is cryptographically linked to the previous scan's hash ($H_n = \text{SHA256}(R_n \parallel H_{n-1})$), creating an immutable, auditable historical ledger."*

---

### [Minute 4:45 – 5:45] Vulnerable vs. Fixed Differential Comparison
**Action**:
1. In the dashboard home page (`http://127.0.0.1:8000`), navigate to **Vulnerable vs. Fixed Scan Comparison**.
2. Select Scan #1 (Baseline) and Scan #2 (Fixed / Secure Mode).
3. Click **Compare Scans**.

**Talking Points**:
- *"Security teams need to know: did our patch actually work, or did it introduce new regressions?"*
- *"Our differential engine classifies retests into 5 distinct buckets:"*
  - **Previously Confirmed**: 15 (14 confirmed + 1 potential IDOR)
  - **Still Confirmed**: 10 (Layer 1 traditional vulnerabilities remain active)
  - **Resolved After Retest**: 5 (ALL AI vulnerabilities resolved: Prompt Injection, Canary Leakage, Excessive Agency, Context Taint Hijack, and Reflected XSS on `/assistant`)
  - **Newly Detected**: 0
  - **Not Retested**: 0
- *"Notice our **Honesty Rule**: we never falsely claim that Layer 1 vulnerabilities (like SQLi on `/login`) were fixed merely because the AI assistant's secure mode was enabled. A finding is only marked resolved if it was **actively re-tested and verified clean**."*

---

### [Minute 5:45 – 6:30] Evaluation Metrics & Conclusion
**Action**:
Show the Evaluation table from `AegisScan_Implementation_Report.md` or README.md.

**Talking Points**:
- *"We evaluated AegisScan 2.0 against the complete AegisLab ground-truth benchmark (15 vulnerabilities + 4 benign decoys):"*
  - **Post-Validation Precision**: **92.9%** (with 0 false positives on traditional Layer 1 flaws).
  - **Recall**: **86.7%**.
  - **F1 Score**: **89.7%**.
- *"All 87 automated unit and integration tests are passing with zero failures."*
- *"In summary: AegisScan 2.0 provides an explainable, end-to-end security audit for both modern web apps and AI agents, backed by mathematical cryptographic trust."*
- *"Thank you, and we welcome any questions!"*

---

## Anticipated Evaluator Questions & Answers

**Q1: Why did you build AegisLab as a separate application instead of mocking everything in code?**  
*Answer:* A separate Flask application running on an isolated port (`5001`) provides an authentic black-box target. The scanner makes real HTTP network requests over localhost, encounters real cookies, crawls real HTML forms, and tests real session states, proving the scanner works against actual running servers.

**Q2: What is the difference between Basic and Deep scan modes?**  
*Answer:* Basic Scan mode performs passive reconnaissance, link crawling, and Layer 1 passive header/cookie analysis without aggressive probe payloads. Deep Authorized Scan performs active injection (SQLi payloads, XSS reflection probes, IDOR parameter enumeration, and AI prompt injection / canary extraction). Deep mode requires explicit affirmative consent from the user via the dashboard checkbox.

**Q3: How does your Ed25519 passport prevent an attacker from modifying the findings?**  
*Answer:* Before signing, the passport canonicalizes all JSON fields using deterministic serialization (`canonical_serialize` in `scan_passport.py`) and hashes the payload with SHA-256. The scanner signs this digest using its private Ed25519 key. If an attacker modifies even a single character in the severity or evidence fields, the recalculated hash fails to match, or the signature verification fails.

**Q4: How does the hash chain work?**  
*Answer:* Just like a blockchain ledger, each completed scan produces a record $R_n$. Its chain hash is computed as $H_n = \text{SHA256}(\text{seq}_n \parallel \text{scan\_id}_n \parallel \text{payload\_hash}_n \parallel H_{n-1})$. The genesis block uses a 64-character zero hash. If an attacker modifies or deletes a historical scan in the database, the hash links of all subsequent records break, causing the integrity audit to report `status: TAMPERED`.
