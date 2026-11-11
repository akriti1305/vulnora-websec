# AEGISSCAN 2.0 & AEGISLAB — COMPREHENSIVE EVIDENCE-BASED AUDIT REPORT
**Prepared for Final Defense & Academic Evaluation**  
**Repository:** `https://github.com/akriti1305/vulnora-websec` | **Branch:** `master`  
**Workspace:** `D:\PRJ4` | **Audit Date:** November 11, 2026  
**Auditor Roles:** Senior Cybersecurity Engineer, AI Security Researcher, Python Architect, QA Automation Specialist  

---

## 1. EXECUTIVE SUMMARY

An exhaustive, evidence-based code and execution audit was conducted across the `D:\PRJ4` workspace, evaluating **AegisScan 2.0** (FastAPI-based scanner) and **AegisLab** (deliberately vulnerable Flask benchmark).

### Headline Verdict
- **Automated Test Suite Status:** **109 Tests Run, 109 Passed, 0 Failures, 0 Errors, 0 Skipped (18.61s execution time)**. All tests pass cleanly without regressions.
- **Service Operational Status:** Both services boot and run locally without errors (**AegisLab on Port 5001**, **AegisScan on Port 8000**).
- **Local Benchmark Pipeline:** **Fully Operational**. A live end-to-end scan of AegisLab on `http://127.0.0.1:5001` completed in 9.8 seconds, discovering 28 pages and 70 forms, recording 21 findings (16 active vulnerabilities, 3 verified defensive controls, 2 informational discoveries), generating an Ed25519 signed scan passport, and appending an entry to the SHA-256 hash-chain audit ledger.
- **AI Security Capabilities:** **PARTIALLY ADDRESSES RESEARCH QUESTION**. AegisScan genuinely models and detects prompt injection, canary leakage, tool metadata tampering, and excessive agency against the built-in deterministic agent simulator (`aegislab/ai_assistant.py`). **However, there is ZERO actual LLM integration (no OpenAI, Anthropic, Gemini, or Ollama APIs)**. AegisScan **cannot** dynamically discover or autonomously interact with an arbitrary external third-party chatbot unless that target implements the custom proprietary manifest (`/.well-known/aegisscan-ai.json`).
- **External Website Scanning:** **PARTIALLY WORKING / RESTRICTED TO PASSIVE OBSERVATION**. External domain registration, `.well-known` token challenge verification, legal scope authorization grants, and passive scans (TLS certificates, robots.txt, sitemap.xml, passive headers, cookie flags, tech stack fingerprinting) function as designed. **However, active injection checks (SQLi, XSS, IDOR) and AI agent security checks DO NOT EXECUTE on external targets**, even in `external_deep` mode; they are replaced by honest `not_tested` and `not_applicable` stubs.
- **High-Severity Security Limitation Identified:** `scope.py`'s `SSRFProtectTransport` performs pre-flight DNS validation via `socket.getaddrinfo()` but delegates the actual HTTP connection to `httpcore`/`httpx`, which resolves DNS a second time at socket connect time. **This creates a classic Time-of-Check to Time-of-Use (TOCTOU) DNS Rebinding vulnerability**.

---

## 2. COMPLETE ARCHITECTURE & CODEBASE INVENTORY

### 2.1 Workspace Structure Overview
```
D:\PRJ4
├── aegislab/                     # Deliberately vulnerable Flask benchmark & AI simulator
│   ├── app.py                    # Main Flask application (port 5001)
│   ├── ai_assistant.py           # Deterministic AI-agent simulator & scenario triggers
│   ├── requirements.txt          # Flask==3.0.3
│   ├── templates/                # 9 Jinja2 templates (dashboard, search, login, profile, assistant)
│   └── venv/                     # Python 3.12 virtual environment
├── aegisscan/                    # Main Scanner Engine & Dashboard (port 8000)
│   ├── main.py                   # FastAPI application & UI routes
│   ├── database.py               # SQLite engine & session setup (aegisscan.db)
│   ├── models.py                 # 9 SQLAlchemy models (targets, scans, findings, passports, etc.)
│   ├── authorization.py          # Domain verification & legal authorization grants
│   ├── scope.py                  # ScopeGuard, SSRF protection, IP validation, Transport
│   ├── policy.py                 # ScanPolicy runtime budgets, rate-limiting, cancellation
│   ├── requirements.txt          # FastAPI, Uvicorn, SQLAlchemy, httpx, bs4, cryptography
│   ├── api/routes.py             # 25 REST endpoints & scan orchestration pipeline
│   ├── crypto/                   # Ed25519 signing, key management, SHA-256 hash-chain
│   ├── detectors/                # 12 detection modules (traditional, AI, passive)
│   ├── discovery/crawler.py      # BFS HTML web crawler (httpx + BeautifulSoup4)
│   ├── secrets/                  # ed25519_private.pem, ed25519_public.pem
│   ├── templates/                # index.html, report.html, compare_report.html
│   └── venv/                     # Python 3.12 virtual environment
└── tests/                        # 12 test suites covering 109 automated unit/integration tests
```

### 2.2 Applications & Frameworks
| Component | Directory | Framework / Core Tech | Entry Point | Default Port |
|---|---|---|---|---|
| **AegisLab** | `D:\PRJ4\aegislab` | Flask 3.0.3, Jinja2, SQLite3 | `app.py` | 5001 |
| **AegisScan** | `D:\PRJ4\aegisscan` | FastAPI 0.111.0, Uvicorn 0.30.1, SQLAlchemy 2.0.41 | `main.py` | 8000 |

### 2.3 Detailed Component Inventory

| File Path | Component Purpose | Implementation Details | Actually Used? | Tested? |
|---|---|---|---|---|
| `aegislab/app.py` | Vulnerable testbed web app | Routes: `/login` (SQLi), `/search` (XSS), `/user/profile` (IDOR), `/decoy/*`. Toggles via `AEGISLAB_SECURE`. | **YES** (Target of scans) | **YES** (`test_smoke_local.py`, `test_final_integration.py`) |
| `aegislab/ai_assistant.py` | Deterministic AI Agent Simulator | Implements rule-based agent: canary protection, tool execution (`calculate`, `search_documents`, `send_email`), document upload, manifest. | **YES** (Target of AI checks) | **YES** (`test_aegislab_ai.py` - 13 tests) |
| `aegisscan/main.py` | Web UI & API Mount | Server-rendered Jinja2 UI (`/`, `/compare`, `/scan/start`), mounts API router. | **YES** (Web dashboard entry) | **YES** (`test_final_integration.py`) |
| `aegisscan/database.py` | Database Session Manager | SQLite connection (`sqlite:///./aegisscan.db`), engine pooling, migration runner. | **YES** | **YES** (All integration tests) |
| `aegisscan/models.py` | Schema Definitions | 9 models: `Target`, `Scan`, `Finding`, `EvaluationRun`, `ScanPassport`, `ScanChainRecord`, `VerificationChallenge`, `AuthorizationGrant`, `AuditEvent`. | **YES** | **YES** (`test_provenance_passports.py`) |
| `aegisscan/authorization.py` | External Target Governance | Manages registration, cryptographically random challenge generation (32 bytes), HTTP token verification, authorization grant lifecycle. | **YES** | **YES** (`test_external_scope_and_auth.py` - 11 tests) |
| `aegisscan/scope.py` | Anti-SSRF & Scope Enforcement | `ScopeGuard` & `SSRFProtectTransport`: blocks RFC 1918, loopbacks, link-local, cloud metadata (`169.254.169.254`), verifies redirect locations. | **YES** | **YES** (`test_ssrf_protection.py` - 11 tests) |
| `aegisscan/policy.py` | Scan Budget & Rate Limiting | `ScanPolicy` tracking request budgets, per-second rate-limiting delays, cancellation flags, and path bounds. | **YES** | **YES** (`test_external_scope_and_auth.py`) |
| `aegisscan/api/routes.py` | REST API & Orchestration | 25 routes. Contains `start_scan` pipeline branching between Local Lab (Branch 1) and External Authorized (Branch 2). | **YES** | **YES** (`test_final_integration.py`, `test_ai_pipeline.py`) |
| `aegisscan/crypto/key_manager.py` | Ed25519 Keypair Lifecycle | Generates and loads unencrypted PKCS8 PEM Ed25519 keypairs from `aegisscan/secrets/`. | **YES** | **YES** (`test_provenance_passports.py`) |
| `aegisscan/crypto/scan_passport.py` | Tamper-Evident Scan Passport | Asymmetric digital signature over canonical finding digests; verification logic. | **YES** | **YES** (`test_provenance_passports.py`) |
| `aegisscan/crypto/hash_chain.py` | SHA-256 Ledger Chain | Immutable append-only hash chain ($H_n = \text{SHA256}(R_n \parallel H_{n-1})$). Sequence gap and corruption verification. | **YES** | **YES** (`test_provenance_passports.py`) |
| `aegisscan/discovery/crawler.py` | Web Crawler | BFS crawler using `httpx` + `BeautifulSoup4`. Extracts links, forms, cookies, and response headers. Max 50 pages. | **YES** | **YES** (`test_final_integration.py`) |
| `aegisscan/detectors/sqli_detector.py` | SQLi Detection | Injects 5 read-only SQLi payloads into POST forms; inspects for error strings or `"logged in as"`. | **YES** (Local scans) | **YES** (`test_final_integration.py`) |
| `aegisscan/detectors/xss_detector.py` | Reflected XSS Detection | Injects `<script>alert('AEGISSCAN_XSS')</script>` into text inputs; verifies unescaped reflection. | **YES** (Local scans) | **YES** (`test_smoke_local.py`) |
| `aegisscan/detectors/idor_detector.py` | IDOR Detection | Iterates numeric `id` query params (`1..5`); checks response differences and personal data markers. | **YES** (Local scans) | **YES** (`test_smoke_local.py`) |
| `aegisscan/detectors/header_detector.py` | Missing Header Detection | Checks CSP, HSTS, X-Frame-Options, X-Content-Type-Options. Deduplicates globally per host. | **YES** (Local & External) | **YES** (`test_final_integration.py`) |
| `aegisscan/detectors/cookie_detector.py` | Cookie Security Flags | Re-requests pages to parse raw `Set-Cookie` headers for missing `HttpOnly` and `Secure`. | **YES** (Local & External) | **YES** (`test_cookie_scope.py` - 3 tests) |
| `aegisscan/detectors/ai_discovery.py` | AI Feature Discovery | Probes `/.well-known/aegisscan-ai.json`, analyzes crawled forms for AI keywords, heuristics. | **YES** (Local Deep mode) | **YES** (`test_ai_pipeline.py`) |
| `aegisscan/detectors/prompt_injection_detector.py` | Indirect Injection Detector | Uploads audit document with override instructions; checks for canary disclosure. | **YES** (Local Deep mode) | **YES** (`test_ai_pipeline.py`) |
| `aegisscan/detectors/canary_validator.py` | Multi-Vector Canary Validator | Regex token matching (`AEGIS_CANARY_*`), headers (`X-Aegis-Canary-Found`), redacts secrets in reports. | **YES** | **YES** (`test_ai_pipeline.py`) |
| `aegisscan/detectors/tool_integrity_monitor.py` | Anti-Rug-Pull Tool Monitor | Canonical sorted JSON SHA-256 hashing; compares against `TRUSTED_TOOL_BASELINES`. | **YES** (Local Deep mode) | **YES** (`test_tool_integrity.py` - 15 tests) |
| `aegisscan/detectors/context_taint_tracker.py` | Context Taint Flow Tracker | Builds directed graph across 5 stages: Document → Context → Tool Selection → Arguments → Sink. | **YES** (Local Deep mode) | **YES** (`test_taint_and_permissions.py`) |
| `aegisscan/detectors/agent_permission_analyzer.py` | Excessive Agency Analyzer | Evaluates audit events for execution of high-impact tools without required human approval. | **YES** (Local Deep mode) | **YES** (`test_taint_and_permissions.py`) |
| `aegisscan/detectors/external_passive.py` | Passive External Detector | TLS cert inspection, robots.txt, sitemap.xml, form inventory, tech fingerprinting, not-tested stubs. | **YES** (External scans) | **YES** (`test_external_scope_and_auth.py`) |

### 2.4 Dependencies Analysis
- **AegisScan Dependencies:** `fastapi==0.111.0`, `uvicorn==0.30.1`, `sqlalchemy==2.0.41`, `jinja2==3.1.4`, `httpx==0.27.0`, `beautifulsoup4==4.12.3`, `python-multipart==0.0.32`, `cryptography>=42.0.0`.
- **AegisLab Dependencies:** `Flask==3.0.3`.
- **Absence of LLM SDKs:** Neither requirements file nor virtual environment includes `openai`, `anthropic`, `google-generativeai`, `langchain`, `litellm`, or `transformers`.

---

## 3. COMPLETE PIPELINE EXECUTION FLOW (PART 2)

```
[User Form / API]
       │
       ▼
[1. validate_target_scope()] ───> Checks Host Type: Local vs. External
       │
       ├─ LOCAL (127.0.0.1, localhost) ───> Pre-approved; bypasses challenge verification
       │                                     └──> Mode defaults to "deep" (all detectors active)
       │
       └─ EXTERNAL (e.g. example.com)  ───> Enforces:
                                             1. Must be in targets table
                                             2. Must have target.is_verified == True
                                             3. Must have active, unexpired AuthorizationGrant
                                             4. If mode is "deep", grant must permit "external_deep"
       │
       ▼
[2. Crawler (BFS)] ───────────────> ScopeGuard client checks every URL & redirect
       │                            Collects: pages, forms, cookies, headers (Cap: 50 pages)
       │
       ▼
[3. Traditional Detectors] ───────> Local Mode: SQLi (active) -> XSS (active) -> IDOR (active)
       │                                        Headers (passive) -> Cookies (passive)
       │                            External Mode: TLS -> Robots/Sitemap -> Headers -> Cookies ->
       │                                          Inventory -> Stubs (Active tests marked "not_tested")
       │
       ▼
[4. AI Security Pipeline] ────────> (Local Deep Mode ONLY)
       │                            Step 7: AI Feature & Manifest Discovery
       │                            Step 8: Indirect Prompt Injection & Canary Validation
       │                            Step 9: Tool Integrity & Anti-Rug-Pull Verification
       │                            Step 10: Context Taint Tracking & Excessive Agency Analysis
       │
       ▼
[5. Evaluation & DB Storage] ─────> Computes TP/FP/FN/Precision/Recall/F1 against known labels
       │                            Persists Findings, EvaluationRuns, Scans to SQLite
       │
       ▼
[6. Cryptographic Provenance] ────> Computes canonical SHA-256 hash of findings digest
                                    Signs payload with Ed25519 private key -> ScanPassport
                                    Appends record to SHA-256 hash chain -> ScanChainRecord
```

### Stage-by-Stage Implementation Verification
1. **Target Normalization & ScopeGuard (`validate_target_scope`, `routes.py:102`):**
   - *Status:* **FULLY IMPLEMENTED**.
   - *Behavior:* Resolves hostname, classifies as local or external. If external, strictly checks `Target.is_verified` and `AuthorizationGrant`. If missing, raises HTTP 400 or 403.
2. **Crawling (`crawler.crawl`, `crawler.py:80`):**
   - *Status:* **FULLY IMPLEMENTED**.
   - *Behavior:* Uses BFS up to `max_depth` (default 3) and `request_budget` (default 500 for local, 50-150 for external). Discovers links and forms via BeautifulSoup. Rate limits via `time.sleep()`.
   - *Limitation:* Does **not** execute JavaScript; dynamic Single Page Applications (React/Vue/Angular) will yield empty page trees.
3. **Active Traditional Detectors (`sqli_detector`, `xss_detector`, `idor_detector`):**
   - *Status:* **FULLY IMPLEMENTED FOR LOCAL; DISABLED FOR EXTERNAL**.
   - *Behavior:* In local lab scans, submits live HTTP POST/GET requests. In external scans, lines 780-815 of `routes.py` completely bypass active detectors and substitute `not_tested` stubs.
4. **AI Security Detection (`ai_discovery`, `prompt_injection_detector`, `tool_integrity_monitor`, `agent_permission_analyzer`):**
   - *Status:* **FULLY IMPLEMENTED FOR AEGISLAB BENCHMARK; NOT USABLE FOR ARBITRARY EXTERNAL AI**.
   - *Behavior:* Operates against AegisLab's simulated environment (`/.well-known/aegisscan-ai.json`, `/assistant/query`, `/assistant/upload`, `/assistant/tools`).
5. **Cryptographic Verification (`scan_passport.py`, `hash_chain.py`):**
   - *Status:* **FULLY IMPLEMENTED**.
   - *Behavior:* Canonical JSON sorting, SHA-256 hashing, Ed25519 digital signature generation and verification. Hash-chain sequence checking ($H_n = \text{SHA256}(R_n \parallel H_{n-1})$).

---

## 4. REAL WEBSITE SCANNING AUDIT (PART 3)

| # | Question | Classification | Technical Evidence & Explanation |
|---|---|---|---|
| 1 | Can AegisScan currently scan an authorized external website? | **WORKING** | `routes.py:723` implements Branch 2. Crawls external pages via HTTPS, inspects TLS, robots.txt, sitemap.xml, headers, cookies, and generates signed passports. |
| 2 | Does it require domain verification? | **WORKING** | `routes.py:153` checks `target.is_verified`. If False, raises HTTP 403 requiring token at `/.well-known/aegisscan-verification.txt`. |
| 3 | Can it scan using only URL + authorization declaration? | **NOT IMPLEMENTED** | Without prior verification of domain ownership (`is_verified=True`), entering a URL and declaration is rejected with HTTP 403 (`routes.py:155`). |
| 4 | What happens if I enter an unverified external URL? | **WORKING** | The API throws `HTTPException(403, "Authorization required: External target '{hostname}' ownership is not verified")`. The UI displays an error modal with challenge token. |
| 5 | Which checks work in External Basic mode? | **WORKING** | `inspect_tls_certificate`, `inspect_robots_and_sitemap`, `header_detector.detect`, `cookie_detector.detect`, `inventory_forms_and_technology`. |
| 6 | Which checks actually execute in External Authorized Deep mode? | **PARTIALLY WORKING** | **Code Evidence (`routes.py:780-815`):** Even when `scan_mode == "external_deep"`, Branch 2 only runs the exact same passive checks as basic mode, and appends `generate_not_tested_stubs()`. Active detectors are **not called**. |
| 7 | Can it detect SQL injection on an external website? | **NOT IMPLEMENTED** | In external mode, `sqli_detector.detect` is never invoked. Furthermore, `sqli_detector.py` only checks POST forms looking for `"logged in as"` or specific SQLite error strings. |
| 8 | Can it detect reflected XSS on an external website? | **NOT IMPLEMENTED** | In external mode, `xss_detector.detect` is never invoked. The scanner emits a `not_tested` stub (`external_passive.py:229`). |
| 9 | Can it detect IDOR on an external website? | **NOT IMPLEMENTED** | In external mode, `idor_detector.detect` is never invoked. The scanner emits a `not_tested` stub (`external_passive.py:239`). |
| 10 | Can it detect security misconfigurations? | **WORKING** | Header detector flags missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options (`header_detector.py`). Cookie detector flags missing HttpOnly and Secure flags (`cookie_detector.py`). |
| 11 | Can it crawl multiple pages? | **WORKING** | `crawler.py:115` implements BFS queue across same-netloc links up to depth 3 and page limit (cap 50). |
| 12 | Can it discover forms and endpoints? | **WORKING** | `crawler.py:192` parses all `<form>` tags, collecting input names, types, and action targets into `DiscoveryResult.all_forms`. |
| 13 | Can it handle JavaScript-heavy websites? | **NOT IMPLEMENTED** | The crawler uses `httpx.get()` + `BeautifulSoup4`. It does not use a headless browser (Playwright/Puppeteer/Selenium) and cannot render client-side SPAs. |
| 14 | Can it scan authenticated pages? | **NOT IMPLEMENTED** | Neither the crawler nor detectors support injecting user-supplied session cookies, Bearer tokens, or authentication state. Crawling is strictly unauthenticated. |
| 15 | Does it respect scan scope and rate limits? | **WORKING** | `ScanPolicy.rate_limit_delay` calls `time.sleep()`, `request_budget` caps total HTTP calls, `ScopeGuard` drops off-origin links. |
| 16 | Are there false-positive or false-negative risks? | **WORKING** | **High FN Risk on External:** Missing JS execution misses links; lack of time/boolean SQLi misses blind SQLi; hardcoded login string `"logged in as"` misses non-AegisLab logins. **Low FP Risk:** Control requests validate findings before reporting. |
| 17 | Does it work without website source code? | **WORKING** | All scanning is dynamic black-box testing over HTTP/HTTPS; no local source code access is required. |
| 18 | Does it work without GitHub repository access? | **WORKING** | Evaluates live network responses; does not inspect git commits or repository trees. |

---

## 5. AI SECURITY CAPABILITIES & RESEARCH QUESTION EVALUATION (PART 4)

### 5.1 Central Research Question
> **"Can untrusted content manipulate a website's AI assistant or cause it to perform an unsafe action?"**

### Direct Conclusion
**PARTIALLY (WITH SIGNIFICANT ARCHITECTURAL QUALIFICATIONS)**

#### Justification:
1. **Against the AegisLab Benchmark: YES.** AegisScan demonstrates that when untrusted content (an uploaded document containing `[SYSTEM OVERRIDE]`) is ingested by an AI assistant, it can hijack tool execution (dispathing simulated email) and exfiltrate confidential canary tokens (`AEGIS_CANARY_20261028_X7K9`). It also proves that when security mode is enabled, taint-tracking boundaries neutralize the attack.
2. **Against Arbitrary Real-World External Web Applications: NO.** AegisScan **cannot** test real LLM assistants (e.g., Zendesk, Intercom, Custom OpenAI wrappers) on arbitrary external websites. It requires the target to publish the custom proprietary `/.well-known/aegisscan-ai.json` manifest and expose structured endpoints (`/assistant/query`, `/assistant/upload`, `/assistant/tools`). Without this specific contract, no AI testing takes place.

### 5.2 Audit of the 12 AI Security Checks

| # | Security Check | Relevant Code | How It Operates | AegisLab? | Real LLM? | External Site? | Observed vs Simulated | Tested in CI? |
|---|---|---|---|---|---|---|---|---|
| 1 | **Indirect Prompt Injection** | `prompt_injection_detector.py:55` | Ingests probe document with override instructions via `/assistant/upload`, queries `/assistant/query`, checks output for canary. | **YES** | **NO** (Rule-based) | **NO** (Needs manifest) | **Observed** on simulator | **YES** (`test_ai_pipeline.py`) |
| 2 | **Direct Prompt Injection** | `ai_assistant.py:521` | Handled inside AegisLab simulator when query directly demands canary tokens or system prompts. | **YES** | **NO** (Rule-based) | **NO** | **Observed** on simulator | **YES** (`test_aegislab_ai.py`) |
| 3 | **Context Taint Tracking** | `context_taint_tracker.py:102` | Builds 5-stage directed graph; maps edges as `OBSERVED`, `INFERRED`, or `UNAVAILABLE`. Confirms full attack path. | **YES** | **NO** (Rule-based) | **NO** (Needs audit log) | **Observed** telemetry | **YES** (`test_taint_and_permissions.py`) |
| 4 | **Canary Leakage / Exfiltration** | `canary_validator.py:75` | Scans response body, `X-Aegis-Canary-Found` headers, and tool arguments for `AEGIS_CANARY_*`. | **YES** | **NO** (Rule-based) | **NO** | **Observed** telemetry | **YES** (`test_ai_pipeline.py`) |
| 5 | **Tool Metadata Poisoning** | `tool_integrity_monitor.py:350` | Regex scans tool description metadata for adversarial instructions (`[SYSTEM OVERRIDE]`). | **YES** | **NO** (Rule-based) | **NO** (Needs `/tools`) | **Observed** on manifest | **YES** (`test_tool_integrity.py`) |
| 6 | **Tool Rug-Pull Detection** | `tool_integrity_monitor.py:380` | Calculates canonical sorted JSON SHA-256 hash of tool schema; detects drift against pre-approved baseline. | **YES** | **NO** (Deterministic hash) | **NO** (Needs pre-approved catalog) | **Observed** hash mismatch | **YES** (`test_tool_integrity.py`) |
| 7 | **Excessive Agency** | `agent_permission_analyzer.py:64` | Evaluates audit logs to determine if high-impact actions executed autonomously without approval. | **YES** | **NO** (Rule-based) | **NO** (Needs audit log) | **Observed** telemetry | **YES** (`test_taint_and_permissions.py`) |
| 8 | **Unsafe Tool Execution** | `ai_assistant.py:229` | Evaluates whether math tool allows arbitrary execution (sanitizes input via regex; restricts `eval`). | **YES** | **NO** (Rule-based) | **NO** | **Observed** | **YES** (`test_aegislab_ai.py`) |
| 9 | **Approval Gate Bypass** | `agent_permission_analyzer.py:108` | Verifies whether high-impact tools (`send_email`) respect `requires_approval=True` or execute unapproved. | **YES** | **NO** (Rule-based) | **NO** (Needs audit log) | **Observed** telemetry | **YES** (`test_taint_and_permissions.py`) |
| 10 | **Unsafe HTML Rendering** | `ai_assistant.py:568` | Tests whether AI response containing markup is reflected directly into HTML using unescaped `Markup()`. | **YES** | **NO** (Rule-based) | **NO** | **Observed** in web UI | **YES** (`test_aegislab_ai.py`) |
| 11 | **AI Manifest Discovery** | `ai_discovery.py:103` | Probes `/.well-known/aegisscan-ai.json`; validates schema version, application name, and tool definitions. | **YES** | **NO** | **YES** (If published) | **Observed** HTTP GET | **YES** (`test_ai_pipeline.py`) |
| 12 | **AI Agent Endpoint Discovery** | `ai_discovery.py:281` | Discovers assistant endpoints via HTML forms, anchor tags with AI keywords, and heuristic probing. | **YES** | **NO** | **YES** | **Observed** crawler discovery | **YES** (`test_ai_pipeline.py`) |

### 5.3 Critical Research Questions Answered

- **A. Does AegisLab use a real LLM or a deterministic mock AI assistant?**  
  **DETERMINISTIC SIMULATOR.** `ai_assistant.py:7` explicitly states: *"This module explicitly operates as a DETERMINISTIC AI-AGENT SIMULATOR. It requires NO external LLM APIs, NO paid subscriptions, and runs 100% locally."* Query processing is handled by pattern-matching functions (`re.search`) and dictionary state transitions.
- **B. Can AegisScan discover an arbitrary website's chatbot automatically?**  
  **PARTIALLY.** `ai_discovery.py` heuristically identifies forms containing keywords like `"query"`, `"prompt"`, `"chat"`, and probes standard paths (`/assistant`, `/chat`, `/api/chat`). However, floating frontend chat widgets (e.g. Intercom, Drift, Zendesk iframes) that lack standard HTML forms or manifests will not be discovered.
- **C. Can AegisScan communicate with a real website chatbot through its UI or API?**  
  **NO.** AegisScan expects a standard REST endpoint accepting JSON `{"query": "...", "context_doc_id": "..."}` or a standard HTML form submission. It does not possess browser automation drivers to click floating chat bubbles, wait for streaming WebSockets, or parse vendor-specific message frames.
- **D. Can AegisScan safely inject controlled untrusted content into an AI assistant's retrieval context?**  
  **YES (FOR COMPLIANT APIS).** If the target implements an upload endpoint (as defined in the manifest or an HTML file form), `prompt_injection_detector.py` uploads a controlled document containing benign test markers and system override instructions without destructive payloads.
- **E. Can AegisScan detect when an AI assistant follows malicious instructions from untrusted content?**  
  **YES.** It monitors response text for the target canary secret, checks for telemetry headers (`X-Aegis-Canary-Found`), and inspects the audit log for unapproved tool dispatches.
- **F. Can AegisScan detect or prevent unauthorized tool execution?**  
  **DETECTS ONLY.** AegisScan is an external security scanner, not a runtime Web Application Firewall (WAF) or inline proxy. It detects unauthorized execution post-facto via audit logs or output responses.
- **G. Does it merely detect exposed AI-related endpoints, or actually test AI behavior?**  
  **TESTS BEHAVIOR (AGAINST SUPPORTED TARGETS).** It actively tests behavior across 6 specific attack and defense scenarios on compliant targets.
- **H. Which AI findings are real observed behavior, and which are simulated demonstrations?**  
  - *Observed Behavior:* Detection of the manifest, canary disclosure in HTTP response text, canary disclosure in headers, tool hash integrity validation, and unapproved execution recorded in audit logs.
  - *Simulated Behavior:* The "AI reasoning" inside AegisLab is deterministic Python logic mimicking LLM behavior.

---

## 6. LIVE VERIFICATION & TEST RESULTS (PART 5)

### 6.1 Automated Test Suite Execution
- **Command:** `D:\PRJ4\aegisscan\venv\Scripts\python.exe -m unittest discover -s D:\PRJ4\tests -p "test_*.py"`
- **Total Tests Run:** **109**
- **Passed:** **109**
- **Failures:** **0**
- **Errors:** **0**
- **Skipped:** **0**
- **Runtime:** **18.61 seconds**

#### Test Breakdown by Module:
| Test File | Tests | Status | Coverage Focus |
|---|---|---|---|
| `tests/test_aegislab_ai.py` | 13 | PASSED | AI simulator, document store, tools, scenarios A–F |
| `tests/test_ai_pipeline.py` | 10 | PASSED | AI discovery, manifest parsing, canary validator, prompt injection |
| `tests/test_cookie_scope.py` | 3 | PASSED | Cookie scope limits, out-of-scope form skipping |
| `tests/test_evaluation_rerun.py` | 3 | PASSED | Evaluation re-calculation, metric persistence |
| `tests/test_external_scope_and_auth.py` | 11 | PASSED | Target registration, challenge tokens, authorization grants |
| `tests/test_final_integration.py` | 7 | PASSED | End-to-end local scan, UI rendering, 5-bucket comparison |
| `tests/test_provenance_passports.py` | 14 | PASSED | Ed25519 signing, verification, tampering rejection, hash chain |
| `tests/test_redirect_scope.py` | 6 | PASSED | Relative/absolute redirect resolution, off-scope blocking |
| `tests/test_smoke_local.py` | 5 | PASSED | Local smoke tests, scope defaults, basic parsing |
| `tests/test_ssrf_protection.py` | 11 | PASSED | Loopback, RFC 1918, link-local, cloud metadata rejection |
| `tests/test_taint_and_permissions.py` | 11 | PASSED | Taint tracking graphs, excessive agency evaluation, scenario E |
| `tests/test_tool_integrity.py` | 15 | PASSED | Tool schema canonical hashing, rug-pull detection, baselines |

### 6.2 Controlled Live Localhost Scan Results
- **Target:** `http://127.0.0.1:5001` (AegisLab Local Benchmark)
- **Scan Mode:** `deep` (Authorized Full Assessment)
- **Execution Output:** Scan #28 completed in 9.8 seconds.
- **Pages Crawled:** 28 | **Forms Discovered:** 70
- **Total Findings Recorded:** **21**
  - **Active Vulnerabilities:** 16 (15 Confirmed, 1 Potential)
  - **Verified Security Controls:** 3
  - **Informational Discoveries:** 2
- **Breakdown by Category:**
  - SQL Injection: 2 Confirmed Critical (`/login` username bypass)
  - Reflected XSS: 2 Confirmed High (`/search` and `/assistant` unescaped reflection)
  - IDOR: 1 Confirmed Critical (`/user/profile?id=1`), 1 Potential Medium (`/decoy/product?id=1`)
  - Security Headers: 4 Confirmed (Missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options)
  - Insecure Cookies: 2 Confirmed (Missing HttpOnly, Missing Secure)
  - AI Manifest & Discovery: 2 Informational (`.well-known/aegisscan-ai.json`, Assistant UI)
  - Indirect Prompt Injection & Canary: 2 Confirmed Critical (Document override & Canary leak)
  - Tool Integrity: 3 Verified Controls (SHA-256 hashes matched pre-approved catalog)
  - Context Taint & Agency: 2 Confirmed Critical (Excessive Agency & End-to-End Attack Path)
- **Cryptographic Provenance Verification:**
  - `GET /api/scans/28/passport/verify` → `{"status": "VALID", "signature_valid": true}`
  - `GET /api/scans/history/verify` → `{"status": "VERIFIED", "total_records": 24}`
  - `GET /api/scans/28/report` → HTTP 200 OK (Rendered report size: 67,934 bytes)

---

## 7. UI & USER WORKFLOW AUDIT (PART 6)

### User Workflow Evaluation
| Step | User Action | Implemented? | Working? | Evidence & Audit Notes |
|---|---|---|---|---|
| 1 | Enter a URL | YES | **WORKING** | Input fields available for Local Lab (`127.0.0.1:5001`) and External Targets (`https://...`). |
| 2 | Choose scan mode | YES | **WORKING** | Radio buttons allow selecting `Deep Authorized` vs `Basic Passive`. |
| 3 | Register external target | YES | **WORKING** | Modal calls `POST /api/targets/register`, stores target in SQLite, returns target ID. |
| 4 | Verify authorization | YES | **WORKING** | Generates 32-byte token for `/.well-known/aegisscan-verification.txt`. Probes via `POST /api/targets/{id}/verify`. |
| 5 | Start scanning | YES | **WORKING** | Form submits `POST /scan/start`, which executes `start_scan` and redirects to `/api/scans/{id}/report`. |
| 6 | View scan progress | PARTIAL | **PARTIAL** | Shows a static loading overlay (`showScanProgress()`). **No real-time WebSocket or Server-Sent Events (SSE)** progress bar. |
| 7 | View vulnerabilities | YES | **WORKING** | Grouped by severity (Critical, High, Medium, Low) and category in report. |
| 8 | See evidence | YES | **WORKING** | Full HTTP request/response evidence snippets, payloads, and triggers rendered per finding. |
| 9 | View AI-security results | YES | **WORKING** | AI findings highlighted with interactive taint-graph summaries and tool-integrity badges. |
| 10 | Download / open reports | YES | **WORKING** | Full HTML report directly printable/saveable; JSON scan passport downloadable via button. |
| 11 | Verify authenticity | YES | **WORKING** | Live API verification endpoints linked directly on dashboard and report pages. |

### UI Deficiencies & UX Flaws
1. **Synchronous Scan Execution:** Launching a scan blocks the HTTP worker thread until crawling and testing finish. For larger external targets, this risks gateway timeout (HTTP 504).
2. **Scan Cancellation Limitation:** `POST /api/scans/{id}/cancel` sets `policy.is_cancelled = True`. However, because `start_scan()` runs synchronously inside the request handler, cancellation is only effective if triggered from a separate browser tab or API call.

---

## 8. SECURITY & RELIABILITY AUDIT (PART 7)

### 8.1 SSRF & DNS Rebinding Vulnerability Analysis
- **Critical Finding: Socket TOCTOU Desynchronization.**  
  In `aegisscan/scope.py:152`, `SSRFProtectTransport` intercepts HTTP requests:
  ```python
  class SSRFProtectTransport(httpx.HTTPTransport):
      def handle_request(self, request: httpx.Request) -> httpx.Response:
          url_str = str(request.url)
          self.scope_guard.check(url_str, context="Transport")
          return super().handle_request(request)
  ```
  `self.scope_guard.check()` calls `resolve_and_validate_hostname()`, which invokes `socket.getaddrinfo()`. If all resolved IPs are public, validation passes.  
  However, `super().handle_request(request)` delegates to `httpcore`, which performs **its own independent DNS resolution** when opening the socket connection.  
  **Risk:** If an attacker configures an authoritative DNS server with TTL=0 to return a valid public IP on the first resolution and `127.0.0.1` or `169.254.169.254` on the second resolution, **the pre-flight check passes, but the socket connects to the internal IP**.
- **Redirect Scope Enforcement:** **HARDENED**. An event hook (`_check_redirect_event_hook` at `scope.py:317`) inspects all `3xx` redirect `Location` headers before following them, strictly blocking redirect escapes to off-scope hosts or internal addresses.
- **Private Key Storage:** Unencrypted PKCS8 PEM file stored on disk at `aegisscan/secrets/ed25519_private.pem`. While ignored by `.gitignore` (file mode 0o600 on POSIX), on Windows default ACLs apply. Keys are not protected by a passphrase or Hardware Security Module (HSM).

---

## 9. PRIORITIZED 3-DAY COMPLETION PLAN (PART 8)

### Day 1: Pipeline Reliability & Critical Fixes
- **[P0] Bind DNS Validation to Socket Connection (Fix TOCTOU SSRF):**  
  Update `SSRFProtectTransport` to resolve DNS once, validate the IP, and connect directly to that resolved IP using a custom socket connection or HTTP adapter, preventing DNS rebinding.
- **[P0] Fix External Authorized Deep Mode Detection Gap:**  
  In `routes.py:780`, when `scan_mode == "external_deep"`, enable safe, bounded active testing (safe XSS probe, safe SQLi error probe) rather than falling back unconditionally to `generate_not_tested_stubs()`.
- **[P0] Background Task / Asynchronous Scan Execution:**  
  Wrap `start_scan` in FastAPI `BackgroundTasks` so scans return a `scan_id` immediately with status `"running"`, allowing the frontend to poll `/api/scans/{id}` without timing out.

### Day 2: External Workflow Validation & AI Demonstration Polish
- **[P0] Real-Time Scan Polling in UI:**  
  Update `index.html` overlay to poll `GET /api/scans/{id}` every 2 seconds, displaying progress stages (Crawling → Active Testing → AI Analysis → Finalizing) and handling cancellation cleanly.
- **[P1] Verified External Portfolio Live Demo:**  
  Deploy the verification token to `https://aakriti-portfolio-beryl.vercel.app/.well-known/aegisscan-verification.txt`, verify domain ownership live, and run a clean External Basic scan to prove external functionality during the evaluation.
- **[P1] Real LLM Integration Bridge (Demonstration Option):**  
  Add an optional lightweight Ollama / Gemini API bridge in `aegislab/ai_assistant.py` toggled via `AEGISLAB_REAL_LLM=1` to demonstrate that the exact same prompt injection and canary exfiltration mechanisms occur on an actual neural language model.

### Day 3: Evaluation Rehearsal, Regression Testing & Packaging
- **[P0] Full Regression Test Suite Execution:**  
  Ensure all 109 automated tests continue to pass.
- **[P1] Evaluator Demonstration Script Walkthrough:**  
  Execute dry run following `DEMO_GUIDE.md` (Local Lab scan → Before/After comparison → Passport verification → External refusal modal).
- **[P2] Clean Export & Backup Archive:**  
  Export database snapshots, verification keys, and sample signed passports for offline evaluation defense.

---

## 10. EXACT COMMANDS TO RUN & REPRODUCE

### Prerequisites
- Python 3.12+ installed.
- Repository root: `D:\PRJ4`

### Command Execution
```powershell
# 1. Start AegisLab (Target Benchmark) in Window 1
cd D:\PRJ4
.\aegislab\venv\Scripts\python.exe .\aegislab\app.py
# Verify: Listening on http://127.0.0.1:5001

# 2. Start AegisScan (Scanner & Dashboard) in Window 2
cd D:\PRJ4
.\aegisscan\venv\Scripts\python.exe -m uvicorn --app-dir .\aegisscan main:app --host 127.0.0.1 --port 8000
# Verify: Listening on http://127.0.0.1:8000

# 3. Run Complete Automated Test Suite (109 Tests)
cd D:\PRJ4
.\aegisscan\venv\Scripts\python.exe -m unittest discover -s D:\PRJ4\tests -p "test_*.py" -v

# 4. Trigger Live Controlled Local Scan via API
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/scans" -Method POST -Body '{"target_url":"http://127.0.0.1:5001","target_name":"AegisLab Local Live","scan_mode":"deep"}' -ContentType "application/json"

# 5. Verify Ed25519 Scan Passport & SHA-256 Hash-Chain
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/scans/1/passport/verify"
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/scans/history/verify"
```

---

## 11. RECOMMENDED 5-MINUTE FINAL EVALUATION DEMONSTRATION

1. **Dashboard & Architecture Overview (Minute 0:00–1:00):**  
   Open `http://127.0.0.1:8000`. Point out the dark-mode dashboard, KPI metrics, and the two operational tabs: Local Lab Benchmark vs. External Authorized Target.
2. **Zero-Trust External Authorization Refusal (Minute 1:00–2:00):**  
   Switch to the External Target tab. Enter an unverified domain (e.g. `https://aakriti-portfolio-beryl.vercel.app`). Click Scan without verifying. Show the immediate HTTP 403 refusal modal demanding `.well-known/aegisscan-verification.txt`. Explain the anti-SSRF protections and legal authorization grant requirement.
3. **Deep Local Lab Live Scan (Minute 2:00–3:15):**  
   Switch to Local Lab (`http://127.0.0.1:5001`). Launch a Deep Scan. Watch the real-time server console trace the 11-step pipeline (Crawling 28 pages → SQLi → XSS → IDOR → Headers → Cookies → AI Manifest → Indirect Prompt Injection → Tool Integrity → Context Taint Tracking).
4. **Honest 6-Category Report & AI Flaws (Minute 3:15–4:15):**  
   Open the generated HTML report. Show the clear segregation between active confirmed vulnerabilities (SQLi, XSS, Indirect Prompt Injection, Canary Leakage) and verified defensive controls (Tool Integrity Verified, Approval Gates). Highlight the context taint attack path diagram.
5. **Cryptographic Provenance & Tamper Rejection (Minute 4:15–5:00):**  
   Navigate to the Cryptographic Provenance card. Download the signed scan passport JSON. Show the Ed25519 digital signature and public key ID. Demonstrate `/api/scans/{id}/passport/verify` returning `VALID` and the immutable SHA-256 hash-chain history returning `VERIFIED`.

---

## 12. HONEST ASSESSMENT OF PROJECT READINESS

| Evaluation Dimension | Readiness Score | Realistic Engineering Assessment |
|---|---|---|
| **Academic Benchmark & Local Lab** | **95% (Ready)** | Highly complete. The 11-step pipeline, evaluation harness (Precision/Recall/F1), ground-truth comparison, and report generation are robust and fully tested by 109 unit tests. |
| **Cryptographic Trust & Provenance** | **95% (Ready)** | Ed25519 signing, canonical JSON formatting, payload hashing, signature verification, and SHA-256 hash chaining are production quality. |
| **AI Security Architecture (Simulated)** | **90% (Ready)** | Rigorously models OWASP Top 10 for LLMs (Indirect Injection, Canary Exfiltration, Tool Metadata Rug-Pulls, Excessive Agency) on a deterministic benchmark. |
| **AI Security on Real World Websites** | **25% (Not Ready)** | Cannot discover or dynamically test arbitrary external chatbots without a pre-existing manifest and structured REST endpoints. No real LLM API integration exists. |
| **External Scanning Infrastructure** | **65% (Partially Ready)** | Domain registration, challenge verification, legal authorization grants, and passive scanning (TLS, headers, cookies, robots) work well. Active injection on external sites is not implemented. |
| **Overall Defense Readiness** | **85% (Solid Academic Defense)** | Excellent demonstration of security engineering principles, explainable scanning, and cryptographic provenance. Must be presented honestly as an academic security benchmark and governance platform. |
