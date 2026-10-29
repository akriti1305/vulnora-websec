# AegisScan 2.0 -- AI-Agent Web Security Scanner & Cryptographic Trust Platform

> **Defensive Security Assessment Platform with Cryptographic Provenance**  
> *Repository:* `akriti1305/vulnora-websec` | *Branch:* `master` | *Version:* `2.0.0 (Phase 14: Authorized External Scanning & Hardened ScopeGuard)`

---

## 1. Project Overview

**AegisScan 2.0** is an explainable web and AI-agent vulnerability scanner with cryptographic trust verification and hardened multi-tier scope enforcement.

Originally designed for localhost security benchmarks, Phase 14 upgrades AegisScan into a production-grade external web application assessment scanner that supports:
1. **Local Lab Benchmark**: Full-depth traditional and AI-agent vulnerability assessment on `http://127.0.0.1:5001` (AegisLab).
2. **External Website Assessments**: Scope-bound, policy-governed scanning of real external web applications under **explicit domain ownership verification** and **documented legal authorization grants**.
3. **Hardened Anti-SSRF ScopeGuard**: A single, central scope-aware transport (`SSRFProtectTransport`) enforcing zero-trust egress: HTTPS-only external targets, pre-flight DNS address validation, protection against loopback, private RFC 1918 networks, link-local, multicast, cloud metadata services (`169.254.169.254`), IPv4-mapped IPv6, and strict redirect escape verification.
4. **Three Strict Operational Modes**:
   - `Local Lab`: Localhost research benchmark. All active fuzzing, AI injection, and tool analysis enabled.
   - `External Basic`: Verified external targets. Safe GET/HEAD discovery, TLS analysis, robots.txt, security headers, cookie flags, and technology inventory. Active injection tests are honestly classified as `not_tested`.
   - `External Authorized Deep`: Verified external targets with separate explicit legal scope. Bounded, rate-limited active tests with path exclusions, strict request budgets, and instant cancellation.
5. **Cryptographic Provenance**: Every scan generates an **Ed25519 digital signature** over canonical finding digests and appends to an immutable **SHA-256 hash-chain ledger** ($H_n = \text{SHA256}(R_n \parallel H_{n-1})$).

---

## 2. System Architecture

```
                                      [ Browser / Security Operator ]
                                                     │
                                                     ▼
                  ┌────────────────────────────────────────────────────────────────────────┐
                  │              AegisScan Unified Dashboard (Port 8000)                   │
                  │  - Target Network Switcher: Local Lab vs. External Authorized Target   │
                  │  - Domain Ownership Verification Drawer (HTTP Token / DNS TXT)         │
                  │  - Explicit Legal Authorization Grant Declarations (Scope Boundaries)  │
                  │  - Real-time KPI Summary (Scans, Vulns, Controls, Passports, Ledgers)  │
                  │  - Honest 6-Category Reporting with "Not Tested" & "Not Applicable"    │
                  │  - Ed25519 Scan Passport Verifier & SHA-256 Hash-Chain Auditor         │
                  └───────────────┬────────────────────────────────────────┬───────────────┘
                                  │                                        │
           ┌──────────────────────▼─────────────────────┐   ┌──────────────▼───────────────┐
           │     ScopeGuard & Transport Engine          │   │     SQLite Cryptographic     │
           │ - Mode A (Local Lab): 127.0.0.1, localhost │   │           Ledger             │
           │ - Mode B (External Basic): HTTPS 443 Only  │   │ - targets, audit_events      │
           │ - Anti-SSRF: Blocks loopback, private IPs, │   │ - verification_challenges    │
           │   cloud metadata, IPv4-mapped IPv6         │   │ - authorization_grants       │
           │ - DNS Rebinding & Pre-Flight IP Validation │   │ - scans, findings            │
           │ - Redirect Escape Guard & Budget Caps      │   │ - scan_passports (Ed25519)   │
           │ - trust_env=False (Anti-Proxy Poisoning)   │   │ - scan_chain_records (SHA256)│
           └──────────────┬─────────────────────────────┘   └──────────────────────────────┘
                          │
          ┌───────────────┴───────────────────────────────┐
          │                                               │
          ▼                                               ▼
┌──────────────────────────────────────┐  ┌─────────────────────────────────────────────────┐
│     AegisLab Local Benchmark         │  │   Authorized External Targets (e.g., Portfolio) │
│           (Port 5001)                │  │    https://aakriti-portfolio-beryl.vercel.app   │
│ - Full-Width SaaS Portal             │  │ - HTTP Verification: /.well-known/...           │
│ - 9 Traditional Web Flaws            │  │ - Mode B: Safe Discovery, TLS, Headers, Cookies │
│ - 6 AI-Agent Vulnerabilities         │  │ - Mode C: Separately Authorized Bounded Deep    │
│ - 4 Benign True-Negative Decoys      │  │ - Zero Destructive Payloads or State Changes    │
└──────────────────────────────────────┘  └─────────────────────────────────────────────────┘
```

---

## 3. ScopeGuard & Anti-SSRF Defense Specification

Every network call in AegisScan is routed through `ScopeGuard.client()`, backed by `SSRFProtectTransport(httpx.HTTPTransport)` and an event hook:

1. **Protocol & Port Enforcement**:
   - External targets must use `https://` on standard port `443`.
   - Plain HTTP, FTP, file, or non-standard ports are rejected with `OutOfScopeError`.
   - Malformed URLs, userinfo credentials (`https://user:pass@host`), and ambiguous hosts are rejected.
2. **IP & Network Boundary Validation (`validate_ip_address_not_internal`)**:
   - **Loopback**: `127.0.0.0/8`, `::1`
   - **Private Networks**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7` (RFC 4193)
   - **Cloud Metadata Endpoints**: `169.254.169.254`, `100.100.100.200`, `fd00:ec2::254`
   - **Link-Local & Multicast**: `169.254.0.0/16`, `fe80::/10`, `224.0.0.0/4`, `ff00::/8`
   - **IPv4-Mapped IPv6**: Addresses like `::ffff:127.0.0.1` and `::ffff:169.254.169.254` are unpacked and checked against IPv4 rules.
   - **Carrier-Grade NAT & Reserved**: `100.64.0.0/10`, broadcast `255.255.255.255`, and unspecified `0.0.0.0`.
3. **DNS Resolution & Anti-Rebinding**:
   - `resolve_and_validate_hostname` resolves both IPv4 and IPv6 addresses via system DNS and validates that *every* returned IP satisfies external safety bounds before opening sockets.
4. **Redirect Escape Prevention**:
   - The transport hook inspects the `Location` header of every HTTP redirect (301, 302, 307, 308) before the client follows it. Redirects to off-scope hosts or private IP spaces are aborted immediately.
5. **No Credential/Cookie Leakage**:
   - Cross-origin authentication headers and cookies are never forwarded.
   - `trust_env=False` prevents proxy environment variable hijacking (`HTTP_PROXY`, `ALL_PROXY`).

---

## 4. External Target Authorization Workflow

Scanning an external domain requires a strict two-step verification and authorization protocol:

```
[ Step 1: Register Target ] ──► [ Step 2: Publish Challenge ] ──► [ Step 3: Verify Ownership ] ──► [ Step 4: Grant Scope ] ──► [ Scan ]
   POST /api/targets/register       https://<target>/.well-known/      POST /api/targets/{id}/verify     POST /api/targets/{id}/authorize
```

### 4.1 Ownership Verification Protocol
- AegisScan generates a cryptographically random 32-byte URL-safe token.
- The target owner publishes this token at:
  ```
  https://<TARGET>/.well-known/aegisscan-verification.txt
  ```
- AegisScan fetches this file over HTTPS, validating certificates, enforcing response-size limits (max 10 KB), and disallowing redirects.
- **Subdomain Isolation**: Verification of `sub.example.com` strictly authorizes `sub.example.com` only; it never grants permission for `example.com` or other subdomains.

### 4.2 Explicit Legal Authorization Declaration
Ownership of a domain does not automatically confer legal permission for every scan type. An explicit authorization record must be stored:
- `authorized_by`: Operator name or authorized organization
- `scan_mode`: `external_basic` or `external_deep`
- `allowed_paths`: e.g. `["/"]`
- `excluded_paths`: e.g. `["/logout", "/delete", "/billing"]`
- `acknowledgment`: Documented operator acknowledgment
- `expires_at`: Strict expiry date (default: 30 days)

---

## 5. How to Verify a Vercel-Hosted Domain (e.g. Portfolio)

To assess your deployed portfolio at `https://aakriti-portfolio-beryl.vercel.app`:

1. **Register the Target in AegisScan**:
   - In the dashboard, switch to **External Authorized Website**.
   - Target URL: `https://aakriti-portfolio-beryl.vercel.app`
   - Name: `Aakriti Portfolio`
   - Click **Register External Target**.
2. **Retrieve the Verification Token**:
   - AegisScan displays a unique challenge token (e.g. `2c3MWxOVPx-i_Rs_0BSxkOo1nQbUIAY9bs7b5079knc`).
3. **Add the Verification File to Your Vercel Project**:
   - In your portfolio's local repository, navigate to the `public/` directory (Next.js, Vite, or static HTML):
     ```bash
     mkdir -p public/.well-known
     ```
   - Create `public/.well-known/aegisscan-verification.txt` containing the exact token (single line, no quotes, no extra whitespace):
     ```
     2c3MWxOVPx-i_Rs_0BSxkOo1nQbUIAY9bs7b5079knc
     ```
   - Commit and deploy:
     ```bash
     git add public/.well-known/aegisscan-verification.txt
     git commit -m "chore: add aegisscan domain verification token"
     git push
     ```
4. **Confirm Live URL**:
   - In your browser, open `https://aakriti-portfolio-beryl.vercel.app/.well-known/aegisscan-verification.txt` and verify that the token appears.
5. **Verify and Authorize**:
   - In AegisScan, click **Verify Ownership**.
   - Once verified, review and accept the scope declaration to activate **External Basic** scanning.

---

## 6. Installation & Launch Commands

### Prerequisites
- Python 3.10+ (Windows 10/11)
- Windows PowerShell

### Setup Environments
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

### Launch Commands
Open two PowerShell windows:

**Terminal 1: Launch AegisLab Benchmark (Port 5001)**:
```powershell
& "D:\PRJ4\aegislab\venv\Scripts\python.exe" "D:\PRJ4\aegislab\app.py"
```

**Terminal 2: Launch AegisScan Dashboard (Port 8000)**:
```powershell
& "D:\PRJ4\aegisscan\venv\Scripts\python.exe" -m uvicorn --app-dir "D:\PRJ4\aegisscan" main:app --host 127.0.0.1 --port 8000
```

---

## 7. Running the Automated Test Suite

AegisScan 2.0 includes a 109-test automated regression suite covering anti-SSRF protections, external authorization workflows, crawler budgets, detector accuracy, Ed25519 passport verification, and SHA-256 hash-chain integrity:

```powershell
& "D:\PRJ4\aegisscan\venv\Scripts\python.exe" -m unittest discover -s tests -p "test_*.py" -b
```
*Expected Result:*
```
Ran 109 tests in ~24s ... OK
```

---

## 8. Finding Classification & Honest Reporting

AegisScan partitions all scan outputs into 6 distinct categories:

| Category | Key | Description |
| :--- | :--- | :--- |
| **Confirmed Vulnerability** | `confirmed_vulnerability` | Flaws confirmed via active dual-request validation probes |
| **Potential Vulnerability** | `potential_vulnerability` | Heuristic observations (e.g. non-sensitive IDOR, missing headers) |
| **Informational Discovery** | `informational` | Non-flaw reconnaissance (AI assistant discovered, technology stack) |
| **Verified Security Control**| `verified_control` | Defensive controls confirmed active (TLS 1.3, tool integrity hashes) |
| **Not Reproducible** | `not_reproducible` | Anomalies that failed second-stage reproducibility |
| **Not Tested** | `not_tested` | Checks skipped by policy (e.g. active SQLi/XSS on External Basic) |

> **Honesty Principle**: For external targets assessed under External Basic mode, active attack categories (SQLi, XSS, IDOR, Prompt Injection, Tool Rug-Pull) are explicitly reported as **`not_tested`** rather than claiming the application is "secure". Static web portfolios without AI manifestations classify AI-agent checks as **`not_applicable`** rather than inventing false vulnerabilities.

---

## 9. Known Boundaries & Limitations

1. **Bounded External Deep Testing**: Deep testing against external targets is strictly restricted to safe, non-destructive, rate-limited probes on explicitly allowed paths. State-changing actions (`POST /delete`, payments, account modifications) are automatically excluded.
2. **Ephemeral SQLite Multi-Threading**: SQLite database connections cannot be transferred across operating system threads. All synchronous scan execution pipelines run within bounded worker threads using dedicated session instances.
3. **DNS Time-of-Check to Time-of-Use**: To minimize DNS rebinding risks on external targets, resolved IP addresses are pre-validated and sockets are strictly bound to validated network destinations.
4. **Key Management**: Ed25519 signing keys are persisted under `aegisscan/secrets/`. Production enterprise deployments should integrate Hardware Security Modules (HSMs) or cloud Key Management Services (AWS KMS, Azure Key Vault, Google Cloud KMS).
