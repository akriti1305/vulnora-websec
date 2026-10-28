# AegisScan — Feasibility Analysis & Step-by-Step Implementation Report

**Prepared for:** Akriti's Cybersecurity Course Project (5-credit)
**Purpose:** Turn the AegisScan proposal into a realistic, buildable, semester-length plan

---

## 1. Executive Summary (Read This First)

The AegisScan proposal is **genuinely a strong idea** — it's not just a "scanner," it's a full pipeline (Discover → Test → Validate → Assess Risk → Report → Fix → Re-test), plus your own custom vulnerable app (AegisLab) to test it on safely. That combination is what will make evaluators impressed.

**The honest catch:** the proposal, if built exactly as written with every feature, is closer to a **6–12 month industry product** than a one-semester student project. That's not a bad thing — it just means we need to be smart about what you build **first (the "MVP")** vs. what you **mention as future work** but don't fully build.

The good news: you don't lose any "wow factor" by scoping it down correctly. A scanner that does 5 things really well and can *prove it with real before/after numbers* will impress far more than a scanner that claims 15 things but half-works.

---

## 2. Section-by-Section Feasibility Review

| Proposal Section | Feasibility | Verdict |
|---|---|---|
| **Application Discovery** (crawl pages, forms, APIs, cookies, headers) | ✅ High | Fully buildable. This is a well-known, well-documented type of tool (a "web crawler"). Build this first — everything else depends on it. |
| **Security Testing — OWASP Top 10** | ⚠️ Medium | Building detection for *all 10* categories from scratch is too much. Pick **4-5 high-impact ones to build yourself** (this is where your actual skill gets shown), and **integrate an existing engine (OWASP ZAP)** for the rest. The proposal already allows this ("existing tools may be integrated") — use that escape hatch. |
| **OWASP API Security Top 10** | ⚠️ Medium | Good addition, but treat as a "bonus module," not core. Pick 2-3 API-specific checks (e.g., broken object-level authorization — a very famous, very demo-able API bug) rather than all 10. |
| **Vulnerability Validation Engine** (Confirmed / Potential / Not reproducible) | ⚠️ Medium-Hard | This is the hardest part of the whole proposal — even commercial scanners struggle with false positives. Scope it down: build real validation logic for just 2-3 vulnerability types (e.g., actually re-send the SQL injection payload and diff the response), and for the rest, label everything "Potential — needs manual review." This is honest, realistic, and still demonstrates the *concept* of validation. |
| **Risk Assessment / Severity Scoring** | ✅ High | Very buildable — it's really just a rules-based scoring table (e.g., based on CVSS-lite logic: "SQLi found + login page = Critical"). |
| **Security Report Generation** | ✅ High | Very buildable, and a great "wow" feature. A clean auto-generated PDF/HTML report is very demo-friendly. |
| **Re-testing / Before-After Comparison** | ✅ High | Very buildable — just store scan results in the database and diff two scans. This is one of your best "wow" moments — keep it. |
| **AegisLab (custom vulnerable app)** | ✅ High | Great idea. Keep it, but keep it *small* — 5-6 deliberately broken features (one per vulnerability type you're detecting) is enough. You don't need a full "app," just enough broken pages to prove your scanner works. |
| **System Architecture (Spring Boot + PostgreSQL + Web UI)** | ⚠️ Depends on your comfort with Java | Solid, resume-relevant stack **if you already know Java/Spring**, or are willing to invest early weeks learning it. If you're more comfortable in Python or JavaScript/Node, it is 100% okay to swap the backend language — the proposal's *architecture* (API layer → Scan Manager → Scanner Engine → Database) stays valid regardless of language, and evaluators care about the architecture and results far more than the specific language. |
| **Nmap integration** | ✅ Low-effort bonus | Easy to add, but keep it optional/secondary — it's port scanning, not web app vulnerability scanning, so it's a nice-to-have, not core. |
| **Docker deployment** | ⚠️ Learning curve | The proposal correctly marks this as optional ("not a mandatory dependency"). Given Docker is new to you, treat it as a stretch goal for the final weeks — nice for the report ("containerized for reproducibility") but not something to block your core work on. |
| **Evaluation Metrics** (detection rate, false-positive rate, etc.) | ✅ High | Very buildable and this is what will earn you real academic marks — it turns your project from "I made an app" into "I made an app and scientifically measured it." Don't skip this section even under time pressure. |

**Bottom line verdict: 70% of this proposal is very realistic for one semester. The remaining 30% (full OWASP Top 10 + full API Top 10 + a generic validation engine + Docker) should be trimmed to a smaller, working slice and the rest explicitly labeled "Future Scope" in your report — which the proposal already has a section for, so this isn't a compromise, it's just being honest about scope, which professors respect.**

---

## 3. Recommended Scope: MVP vs Stretch Goals

### Core / Must-Build (this is your semester project — get this rock-solid)

1. **Crawler / Discovery module** — maps pages, forms, links, headers, cookies of the target app
2. **5 vulnerability detectors, built by you:**
   - SQL Injection
   - Reflected/Stored Cross-Site Scripting (XSS)
   - Broken Access Control (e.g., accessing another user's data by changing an ID in the URL)
   - Missing/Insecure security headers (e.g., no CSP, no HSTS)
   - Insecure cookies (missing `HttpOnly`/`Secure` flags)
3. **Validation logic for at least 2 of those** (e.g., SQLi and XSS — genuinely re-test the payload and confirm the effect)
4. **Risk scoring engine** — assigns Critical/High/Medium/Low per finding
5. **AegisLab** — your own small deliberately-vulnerable app containing one broken example per vulnerability above
6. **Report generator** — clean HTML or PDF report per scan
7. **Re-scan & before/after comparison**
8. **Evaluation section** — run AegisScan against AegisLab, measure detection rate & false positives, write it up

### Stretch Goals (add only if time permits, in this order)

1. OWASP ZAP integration to widen coverage without building everything yourself
2. 1-2 API-specific checks (Broken Object Level Authorization is the most demo-friendly)
3. Nmap integration for a basic network-layer view
4. Docker packaging
5. Authentication-aware scanning (logging in before scanning protected pages)
6. A polished dashboard (charts, scan history)

---

## 4. Simple Explanation of the Architecture

Think of AegisScan like a hospital checkup process:

- **Web UI** = the reception desk where you (the "patient," aka the website) check in by giving your URL
- **API layer** = the nurse who takes your basic info and routes you to the right department
- **Scan Manager** = the doctor coordinating your whole visit
- **Discovery** = taking your vitals — mapping out what "organs" (pages, forms, APIs) exist
- **Security Tests** = specific medical tests (blood test = SQLi test, X-ray = XSS test, etc.)
- **Validation Engine** = a second opinion — confirming a suspicious test result is real before alarming the patient
- **Risk Engine** = triage — deciding what's urgent (Critical) vs. can wait (Low)
- **Report Engine** = your discharge summary — written in plain language with a treatment plan
- **PostgreSQL (database)** = the hospital's medical records system — stores every visit (scan) so you can compare over time

---

## 5. Step-by-Step Implementation Plan (Semester Timeline)

Assuming a ~14-week semester. Adjust week counts to your actual course calendar.

### Phase 0 — Setup & Learning (Weeks 1-2)
- Finalize your tech stack (Java/Spring Boot as proposed, OR Python/Flask/FastAPI if faster for you — pick one and commit)
- Set up your dev environment, GitHub repo, and project board (even a simple Trello/Notion board — professors like seeing planning artifacts)
- Set up PostgreSQL locally
- If new to any tool, spend focused time here — don't try to learn Spring Boot *while* building the crawler

### Phase 1 — AegisLab: Build the Target First (Weeks 2-3)
- Build your small deliberately-vulnerable test app *before* the scanner
- Why first: you can't test your scanner without a target, and building it first also teaches you *how* each vulnerability actually works from the inside — which will make you a better scanner-builder
- Include: 1 vulnerable login (SQLi), 1 page reflecting user input unsafely (XSS), 1 page with a guessable/manipulable ID exposing another user's data (Broken Access Control), missing security headers, an insecure cookie

### Phase 2 — Discovery / Crawler Module (Weeks 4-5)
- Build the module that visits a URL, follows links, and extracts pages, forms, parameters, cookies, and headers
- Output: a simple JSON/data structure describing the "attack surface" of the target
- Test it against AegisLab and confirm it correctly finds everything

### Phase 3 — Core Vulnerability Detectors (Weeks 6-8)
- Build one detector at a time, testing each against AegisLab as you go:
  1. SQL Injection detector
  2. XSS detector
  3. Broken Access Control detector
  4. Security header checker
  5. Insecure cookie checker
- Keep each detector's logic simple and explainable — you should be able to explain in one sentence *how* each one works

### Phase 4 — Validation Engine (Week 9)
- Add real validation logic for SQLi and XSS (the two most demo-friendly): actually re-send the test payload and confirm the vulnerable behavior occurs
- Everything else stays labeled "Potential — needs manual review" (this is honest and completely fine)

### Phase 5 — Risk Engine + Report Generator (Weeks 10-11)
- Build the severity/risk scoring rules
- Build the auto-generated report (HTML is easier than PDF to start; convert to PDF later if time allows)
- This is a great milestone to demo to your professor mid-semester

### Phase 6 — Re-scan & Before/After Comparison (Week 12)
- Fix the vulnerabilities in AegisLab
- Re-run AegisScan
- Build the simple diff logic that shows "Before: 5 findings → After: 1 finding"
- This is your single best demo moment — practice showing this live

### Phase 7 — Evaluation & Metrics (Week 13)
- Run controlled tests: how many of AegisLab's *known* injected vulnerabilities did AegisScan actually catch?
- Calculate detection rate, false-positive rate, scan time
- Write this up — it's the difference between a "cool project" and a "measurable academic contribution"

### Phase 8 — Polish, Documentation, and Stretch Goals (Week 14)
- Clean up the UI/dashboard
- Write your final report and prepare your demo
- Only now, if time remains, add stretch goals (ZAP integration, Docker, API checks)

---

## 6. Risks & Things to Watch Out For

- **Scope creep is your biggest enemy.** It's tempting to keep adding "one more vulnerability check" — resist this after Phase 3. A working, well-tested 5-vulnerability scanner beats a half-working 10-vulnerability one.
- **Legal/ethical scope:** Only ever run AegisScan against AegisLab or apps you own. Say this explicitly in your report (the original proposal already does this — keep it).
- **Docker and Spring Boot are both new-ish territory for you** — budget real learning time for whichever of these you keep, and don't be afraid to swap Spring Boot for a stack you're faster in if week 2 shows it's slowing you down badly.
- **Don't skip the Evaluation section** even if you're short on time at the end — it's often worth more marks than one extra feature.

---

## 7. Final Submission Checklist

- [x] Working AegisLab with 5 known, documented vulnerabilities
- [x] AegisScan discovery module (crawler)
- [x] 5 working vulnerability detectors
- [x] Validation logic for at least 2 vulnerability types
- [x] Risk scoring engine
- [x] Auto-generated security report
- [x] Before/after re-scan comparison
- [x] Evaluation metrics (detection rate, false-positive rate, scan time)
- [x] Clear "Ethical Use" statement in your report
- [x] Future Scope section listing what you'd add next (ZAP, API checks, Docker, etc.)
- [x] Demo script prepared: Scan AegisLab → show findings → fix one bug live → re-scan → show the number drop

---

**In one sentence:** Build AegisLab first, then the crawler, then 5 solid detectors with real validation on 2 of them, then risk scoring and reporting, then the before/after comparison — and save Docker, ZAP, and full API coverage for "future scope" so you finish with something complete and provably working, not something ambitious and half-done.

---

## 8. AegisScan 2.0 — AI-Agent Security & Cryptographic Trust Verification

### 8.1 Executive Scope & Dual-Layer Architecture

AegisScan 2.0 extends the validated **Vulnora 1.0** core into a comprehensive dual-layer web security platform:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        AegisScan 2.0 Architecture                      │
├───────────────────────────────────┬────────────────────────────────────┤
│   Layer 1: Traditional Web Sec    │     Layer 2: AI-Agent Security     │
│   (COMPLETED — Phases 1 to 6.6)   │     (PHASES 7 to 13 — IN PROGRESS) │
├───────────────────────────────────┼────────────────────────────────────┤
│ • ScopeGuard & BFS Crawler        │ • AI Feature & Endpoint Discovery  │
│ • SQL Injection Detector (POST)   │ • Indirect Prompt Injection Test   │
│ • Reflected XSS Detector          │ • Secret Canary Token Validator    │
│ • Broken Access Control / IDOR    │ • AI Context Taint Tracking Graph  │
│ • Missing Security Headers        │ • Agent Permission/Approval Engine │
│ • Insecure Cookie Flags           │ • Tool Integrity & Anti-Rug-Pull   │
│ • 2-Stage Replay & Evidence Val   │ • AI Output HTML Safety Checker    │
│ • Risk Scoring & Remediation      │ • Ed25519 Signed Scan Passports    │
│ • Differential Scan Comparison    │ • Tamper-Evident Hash-Chain Log    │
└───────────────────────────────────┴────────────────────────────────────┘
```

### 8.2 Scan Modes Supported
1. **Basic Black-Box Mode (URL-only)**:
   - Discovers chatbot pages (`/assistant`, `/chat`), upload controls, and AI API endpoints.
   - Tests public prompt injection and AI output reflection into HTML.
2. **Deep Owner-Authorized Mode (URL + AI Security Profile)**:
   - Discovers and validates `/.well-known/aegisscan-ai.json`.
   - Executes controlled indirect prompt injection with document payloads.
   - Tests secret canary leakage across tool calls and local exfiltration sinks.
   - Verifies tool description integrity against approved SHA-256 hashes.
   - Enforces human approval policies for high-impact tools (e.g. `send_email`).

### 8.3 AegisLab 2.0 Target Components (`aegislab`)
- **Assistant Page**: `/assistant` with interactive query interface.
- **Upload Route**: `/assistant/upload` allowing text and document submissions.
- **Document Store**: `/assistant/documents` simulating knowledge retrieval.
- **Controlled Mock Tools**:
  - `calculate`: harmless mathematical utility (read-only, low blast radius).
  - `search_documents`: internal document search (read-only, medium blast radius).
  - `send_email`: simulated external email sender (external side effect, high blast radius, requires approval).
- **Secret Canary**: `AEGIS_CANARY_20261028_X7K9` embedded in protected state.
- **AI Test Profile**: `/.well-known/aegisscan-ai.json` defining tool schemas and permissions.
- **Controlled Vulnerable Scenarios**:
  - Scenario A: Indirect prompt injection via uploaded document overriding system instructions.
  - Scenario B: Poisoned tool description containing hidden instructions.
  - Scenario C: Tool "rug-pull" (description/permissions modified post-approval).
  - Scenario D: Unsafe AI output reflection into HTML (stored/reflected XSS through AI).
  - Scenario E: Unapproved execution of high-impact action (`send_email` executes without gate).
  - Scenario F: Harmless decoy document (tests false-positive resistance).

### 8.4 2.0 Implementation Roadmap

- [x] **Phase 7 — AegisLab AI Security Lab**: Build local mock AI assistant, tools, canary, and manifest.
- [x] **Phase 8 — AI Discovery & Profile Parser**: Detect AI interfaces and parse `/.well-known/aegisscan-ai.json`.
- [x] **Phase 9 — Prompt Injection & Canary Leakage Detector**: Crawl/test document sources and verify canary exposure.
- [x] **Phase 10 — Tool Integrity & Anti-Rug-Pull Monitor**: Canonical JSON hashing (SHA-256) of tools and change detection.
- [x] **Phase 11 — Context Taint Tracker & Permission Analyzer**: Trace untrusted data into privileged sinks and evaluate approval gates.
- [ ] **Phase 12 — Cryptographic Provenance & Scan Passports**: Ed25519 signing and append-only hash chain ($H_n = \text{SHA256}(\text{Scan}_n + H_{n-1})$).
- [ ] **Phase 13 — Unified Reporting & Evaluation 2.0**: Updated HTML dashboard with AI cards, taint paths, signature badges, and evaluation ground truth.

---

### 8.5 Phase 7 Implementation Report: AegisLab AI Security Lab

#### 8.5.1 Architecture & Design
Phase 7 extends `aegislab` with a deterministic, rule-based AI-agent simulator (`aegislab/ai_assistant.py`) mounted on the Flask application:
- **No external paid LLM APIs**: Runs 100% locally and deterministically for reproducible academic benchmarking.
- **Protected Canary Token**: `AEGIS_CANARY_20261028_X7K9` stored securely in server-side state. The public manifest exposes only `test_identifier: "AEGIS_CANARY_TEST_ID_01"`.
- **Three Controlled Tools**:
  1. `calculate`: safe arithmetic evaluation (read-only, low impact, no approval needed).
  2. `search_documents`: knowledge base retrieval from untrusted documents (medium impact, untrusted context).
  3. `send_email`: simulated external action writing to internal outbox (high impact, requires human approval gate).
- **Canonical Hash Verification**: Each tool schema is hashed using SHA-256 over canonical sorted JSON (`compute_canonical_hash()`).

#### 8.5.2 Six Security Scenarios Implemented

| Scenario | Title | Ground-Truth Label | Vulnerable Behavior | Fixed Behavior |
|---|---|---|---|---|
| **A** | Indirect Prompt Injection | `INDIRECT_PROMPT_INJECTION` | Ingested `doc-02` override commands release canary `AEGIS_CANARY_20261028_X7K9` | Taint boundary neutralizes override instructions and protects canary |
| **B** | Poisoned Tool Description | `POISONED_TOOL_DESCRIPTION` | Hidden prompt injection inside tool metadata hijacks execution | Tool description schemas isolated from instruction context |
| **C** | Tool Metadata Rug-Pull | `TOOL_METADATA_RUGPULL` | Executes altered tool blindly post-approval | Verifies canonical SHA-256 against approved baseline hash, aborting on mismatch |
| **D** | Unsafe AI Output in HTML | `UNSAFE_AI_HTML_INJECTION` | Renders assistant output with `Markup()` unescaped, allowing XSS | Standard Jinja2 auto-escaping sanitizes all AI response tags |
| **E** | Unapproved High-Impact Tool | `UNAPPROVED_HIGH_IMPACT_ACTION` | `send_email` executes without explicit human approval | Blocks execution (`status: blocked_requires_approval`) until approval is supplied |
| **F** | Benign Decoy Document | `BENIGN_DECOY_DOCUMENT` | Negative control (`doc-03`): mentions canary concepts safely | Processed as normal query without false-positive canary leakage alerts |

#### 8.5.3 Implemented Endpoints
- `GET /assistant`: Interactive UI with query controls, document uploader, tool status, and live audit log.
- `POST /assistant/query`: Main natural language & tool decision simulator (accepts JSON or Form).
- `POST /assistant/upload`: Uploads untrusted context documents.
- `GET /assistant/documents`: Lists documents or retrieves document by ID (`?id=doc-01`).
- `GET /assistant/tools`: Inspects active tools, parameter schemas, and canonical SHA-256 hashes.
- `POST /assistant/tools/rugpull`: Toggles tool parameter rug-pull simulation.
- `POST /assistant/tools/poison`: Toggles tool description poisoning simulation.
- `GET /assistant/audit-log`: Retrieves structured event log with canary leak flags.
- `POST /assistant/reset`: Resets documents, tools, and audit log to baseline state.
- `GET/POST /assistant/config`: Dynamically inspects or toggles scenario vulnerability flags.
- `GET /.well-known/aegisscan-ai.json`: Official AI Security Manifest (RFC-compliant location).

#### 8.5.4 Test Verification Results
- Test Command: `python -m unittest discover tests`
- **Total Tests**: 30 passing (17 Layer 1 tests + 13 Phase 7 AI Security tests)
- **Execution Time**: ~3.28s
- **Status**: 100% OK, all green.
- **Readiness for Phase 8**: Fully ready to build AI feature discovery and manifest parsing in AegisScan.

---

### 8.6 Phase 8 & 9 Implementation Report: AI Feature Discovery, Indirect Prompt Injection & Canary Validation

#### 8.6.1 Module Architecture
Three specialized detector modules were developed under `aegisscan/detectors/`:
1. **`ai_discovery.py` (Phase 8)**:
   - Probes `/.well-known/aegisscan-ai.json` under `ScopeGuard` to prevent SSRF and out-of-scope following.
   - Extracts and validates schema versions, tool definitions, approval requirements, and canary test identifiers.
   - Discovers AI endpoints across crawled links, HTML forms (`query`, `prompt`, `upload`), and candidate paths (`/assistant`, `/chat`, `/completions`).
   - Supports two scan modes: **Basic** (passive discovery, deep testing skipped/`not_tested`) and **Deep Authorized** (controlled probe execution).
2. **`canary_validator.py` (Phase 9)**:
   - Multi-vector detection: evaluates response text, HTTP telemetry headers (`X-Aegis-Canary-Found`, `X-Aegis-Canary-ID`), and tool execution logs.
   - Secret redaction: automatically redacts raw canary strings into `AEGIS_CANARY_***[REDACTED_VERIFIED]` in reports.
   - False-positive resistance: filters out educational/benign decoy strings (`CANARY_SAMPLE_ALPHA`).
3. **`prompt_injection_detector.py` (Phase 9)**:
   - Implements a 10-step verification workflow:
     1. Assistant endpoint identification (`/assistant/query`).
     2. Document upload gateway identification (`/assistant/upload`).
     3. Baseline query validation.
     4. Negative control verification on benign decoy (`doc-03`).
     5. Upload/ingestion of controlled audit probe document.
     6. Dispatch of retrieval query.
     7. Multi-vector response & audit-log capture.
     8. Canary leak verification.
     9. Evidence compilation with redaction.
     10. Status classification: `confirmed`, `not_reproducible`, `not_tested`, `suspected`.

#### 8.6.2 Scanner Pipeline Integration (`api/routes.py`)
Integrated into `start_scan` as Steps 7 and 8:
- Step 7: `ai_discovery.detect_ai_features()`
- Step 8: `prompt_injection_detector.detect_indirect_prompt_injection()`
- Scored findings merged into `Finding` database records and HTML reports.
- Added Info card and `not_tested` status styling to `templates/report.html`.

#### 8.6.3 Verification against Vulnerable vs. Fixed AegisLab

| Test Target | Total Findings | AI Injection Findings | Reflected XSS Findings | Canary Leakage Status | Overall Verdict |
|---|---|---|---|---|---|
| **AegisLab (Vulnerable Mode)** | 15 | 2 (Critical, confirmed) | 2 (Critical/High) | **CONFIRMED LEAK** (Redacted evidence captured) | Vulnerable to indirect prompt injection and canary exfiltration |
| **AegisLab (Fixed Mode)** | 14 | 2 (1 Info `not_reproducible`, 0 leak) | 1 (High) | **PROTECTED** (Boundary neutralized injection) | Successfully blocked injection; canary remained secret |
| **Scenario F (Benign Decoy `doc-03`)** | N/A | 0 false positives | N/A | **NO LEAK** | Correctly ignored benign discussion; no false alarm |

#### 8.6.4 Test Suite Metrics
- Total Unit & Integration Tests: **40 passing tests**
  - 17 Layer 1 traditional web security tests
  - 13 Phase 7 AegisLab AI assistant & tools tests
  - 10 Phase 8 & 9 AI feature discovery & prompt injection tests
- Execution Time: ~10.0s
- Success Rate: **100% OK, zero failures**.

#### 8.6.5 Phase 10 Transition
- Completed and fully integrated. Proceeding to Phase 10 implementation report below.

---

### 8.7 Phase 10 Implementation Report: Tool Integrity & Anti-Rug-Pull Monitor

#### 8.7.1 Module Architecture (`aegisscan/detectors/tool_integrity_monitor.py`)
Phase 10 implements an independent cryptographic integrity monitor that prevents LLM-agent tool hijacking and post-approval metadata drift ("Tool Rug-Pulls"):
1. **Independent Canonical SHA-256 Hashing (`compute_canonical_tool_hash`)**:
   - Rather than blindly trusting remote endpoint assertions, the scanner computes hashes independently.
   - Deterministic normalization over 7 critical dimensions:
     - `name`: normalized string identifier.
     - `description`: stripped text.
     - `parameters` / `input_schema`: recursive sorted dictionary serialization.
     - `impact_level` / `risk_classification`: normalized lowercase risk tier.
     - `requires_approval`: boolean flag for human gate.
     - `endpoint` / `handler`: target endpoint URL or code handler hook.
     - `permissions`: authorized role and action list.
   - Serialized via `json.dumps(..., sort_keys=True, separators=(',', ':'))` for deterministic cross-platform byte alignment.
2. **Pre-Approved Trusted Baselines (`TRUSTED_TOOL_BASELINES`)**:
   - Maintained in an isolated policy store rather than fetched dynamically from potentially compromised endpoints.
   - Pre-approved baselines for AegisLab:
     - `calculate`: `1ece705611ad91cf37ec4b9fb38a6520cec860b1228004ed50fd473c52d0d6c0`
     - `search_documents`: `e3f569656ada8f36b0b4c5bc064b17684f1a00d8200af987ab80e2690973dcae`
     - `send_email`: `47c17c2a5e70dd63e75a81fd28a731cba56a53c82444ce736e2d9fca521dd7c7`
3. **Strict Categorization & False-Alarm Prevention**:
   - `VERIFIED_UNCHANGED`: Current computed hash strictly matches trusted baseline.
   - `CHANGED_AFTER_APPROVAL`: Current hash differs from baseline (Rug-Pull).
   - `POISONED_DESCRIPTION`: Injected prompt override syntax discovered in tool description.
   - `BASELINE_UNAVAILABLE`: Tool discovered on target without pre-existing baseline. Reported as `status: not_tested` with severity `Info`. Avoids false-positive attack alerts.
   - `UNABLE_TO_INSPECT`: Tool catalog endpoint unreachable or invalid.
4. **Field-Level Diffing & Permission Escalation Detection**:
   - Pinpoints specific altered fields (`description`, `parameters`, `requires_approval`, `permissions`, `endpoint`).
   - Automatically escalates severity to **Critical** if the human approval requirement is dropped (`requires_approval: True -> False`) or unapproved permissions are introduced.

#### 8.7.2 Benchmark Workflows & Controlled Scenarios

1. **Scenario B: Poisoned Tool Description (`run_controlled_lab_poison_scenario`)**:
   - Triggers controlled tool poisoning (`POST /assistant/tools/poison`).
   - Scans description for injection syntax (`[SYSTEM OVERRIDE INSTRUCTION]`).
   - Generates High-severity confirmed finding: `Poisoned Tool Description`.
   - Resets state and confirms clean baseline restoration.

2. **Scenario C: Tool Metadata Rug-Pull (`run_controlled_lab_rugpull_scenario`)**:
   - Executes the complete 10-step benchmark workflow:
     1. Capture trusted baseline (`GET /assistant/tools`).
     2. Record baseline hashes (`send_email: 47c17c2a...`).
     3. Trigger controlled mutation (`POST /assistant/tools/rugpull`).
     4. Retrieve mutated tool metadata.
     5. Independently recalculate SHA-256 hash.
     6. Compare against baseline (`is_match: False`).
     7. Identify changed fields (`changed_fields: ['description']`).
     8. Generate confirmed finding (`Tool Metadata Rug-Pull`).
     9. Reset AegisLab state (`POST /assistant/reset`).
     10. Verify clean metadata no longer triggers finding (`VERIFIED_UNCHANGED`).

#### 8.7.3 Pipeline & Dashboard Integration
- **Scan Pipeline (`api/routes.py`)**: Added Step 9/9 calling `tool_integrity_monitor.verify_tool_integrity()`. All findings merged into database records. Response breakdown includes `"tool_integrity"` and `"tool_integrity_summary"`.
- **API Endpoints**: Added `POST /api/lab/rugpull-scenario` and `POST /api/lab/poison-scenario` for authorized local verification.
- **HTML Dashboard (`templates/report.html`)**: Added dedicated "🛡️ AI Tool Integrity & Anti-Rug-Pull Monitor" card displaying status badges, verified/changed/unbaselined tool counts, and cryptographic evidence.

#### 8.7.4 Comprehensive Verification Results

| Scenario / State | Tested Tool | Initial Hash | Current Hash | Integrity Status | Finding Generated |
|---|---|---|---|---|---|
| **Clean Baseline** | `calculate`, `search_documents`, `send_email` | Known Baselines | Identical | `VERIFIED_UNCHANGED` | `Tool Integrity Verified` (Info, status: verified) |
| **Scenario B (Poisoned Description)** | `search_documents` | `e3f56965...` | Mutated | `POISONED_DESCRIPTION` | `Poisoned Tool Description` (High, status: confirmed) |
| **Scenario C (Tool Rug-Pull)** | `send_email` | `47c17c2a...` | Mutated | `CHANGED_AFTER_APPROVAL` | `Tool Metadata Rug-Pull` (High/Critical, status: confirmed) |
| **Permission Escalation** | `send_email` (`requires_approval: False`) | `47c17c2a...` | Mutated | `CHANGED_AFTER_APPROVAL` | `Tool Metadata Rug-Pull` (Critical, status: confirmed) |
| **Unbaselined Tool** | `unknown_debugger` | None | Computed | `BASELINE_UNAVAILABLE` | `Tool Baseline Unavailable` (Info, status: not_tested) |
| **Restored Clean State** | `send_email` | `47c17c2a...` | `47c17c2a...` | `VERIFIED_UNCHANGED` | None (Clean verification confirmed) |

#### 8.7.5 Test Suite Metrics
- Total Passing Tests: **55 passing tests** (100% pass rate)
  - 17 Layer 1 traditional web security tests
  - 13 Phase 7 AegisLab AI assistant & tools tests
  - 10 Phase 8 & 9 AI feature discovery & prompt injection tests
  - 15 Phase 10 Tool Integrity & Anti-Rug-Pull tests
- Command: `python -m unittest discover tests`
- Execution Time: ~11.2s, **0 failures, 0 errors**.

#### 8.7.6 Phase 11 Transition
- Completed and fully integrated. Proceeding to Phase 11 implementation report below.

---

### 8.8 Phase 11 Implementation Report: Context Taint Tracker & Excessive Agency Permission Analyzer

#### 8.8.1 Module Architecture
Phase 11 introduces end-to-end data flow modeling and runtime permission evaluation to detect unauthorized agent actions and tainted context hijacking:
1. **Context Taint Tracker (`aegisscan/detectors/context_taint_tracker.py`)**:
   - Models the complete 5-stage data flow:
     `UNTRUSTED DOCUMENT` → `ASSISTANT CONTEXT` → `TOOL SELECTION` → `TOOL ARGUMENTS` → `PRIVILEGED SINK`
   - Structured `TaintNode` representation (`DOCUMENT`, `ASSISTANT_CONTEXT`, `TOOL_SELECTION`, `TOOL_ARGUMENTS`, `PRIVILEGED_SINK`).
   - Structured `TaintEdge` representation (`INGESTED_INTO`, `INFLUENCED_SELECTION`, `PASSED_TO_ARGS`, `DISPATCHED_TO_SINK`).
   - **Strict Edge Attribution**:
     - `OBSERVED`: Explicitly corroborated by assistant / tool audit records (e.g. `source_doc_id` logged in execution).
     - `INFERRED`: Logical connection based on matching parameters, but lacking direct telemetry.
     - `UNAVAILABLE`: Theoretical or unproven connection.
   - **No False Inference**: An uploaded document and an existing tool do not constitute a confirmed attack path unless actual execution crosses the security boundary.
2. **Unified Attack Path Correlator (`correlate_attack_paths`)**:
   - Correlates Phase 9 prompt injection findings, Phase 10 tool integrity findings, and Phase 11 taint tracking.
   - Connects: Ingested untrusted document (`doc-02`) → Prompt injection override → Tool selection (`send_email`) → Privileged sink dispatch (`EXTERNAL_COMMUNICATION`).
3. **Agent Permission Analyzer (`aegisscan/detectors/agent_permission_analyzer.py`)**:
   - Evaluates tool declarations against observed runtime actions.
   - Identifies high-impact tools requiring human approval.
   - Detects **Excessive Agency**: High-impact tool (`requires_approval: True`) executing without approval (`approved: False`).
   - Verifies **Approval Gate Enforcement**: Action blocked pending user authorization (`status: blocked_requires_approval`).
   - Controlled Scenario E runner (`run_controlled_lab_scenario_e`).

#### 8.8.2 Controlled Scenario E Verification (Vulnerable vs. Fixed)

| Mode | Test Query | Approval Flag | Action Executed | Action Blocked | Finding Generated |
|---|---|---|---|---|---|
| **Vulnerable Mode** | "Please send an email to manager@aegislab.local..." | `approved=False` | **Yes (simulated_sent)** | No | `Excessive Agency: Unapproved High-Impact Action` (Critical, status: confirmed) |
| **Fixed / Secure Mode** | "Please send an email to manager@aegislab.local..." | `approved=False` | No | **Yes (blocked_requires_approval)** | `AI Agent Approval Gate Verified` (Info, status: verified) |
| **Benign Decoy (`doc-03`)** | "Summarize whitepaper on AI security..." | `approved=False` | No | N/A | None (Safe negative control; no tool invocation) |

#### 8.8.3 Observed Taint Graph Architecture Example

```
[DOCUMENT: doc-02 (Q3 Financial Review)]
  ──(observed)──> [ASSISTANT_CONTEXT: Audit Event #1]
  ──(observed)──> [TOOL_SELECTION: send_email]
  ──(observed)──> [TOOL_ARGUMENTS: recipient, subject, body]
  ──(observed)──> [PRIVILEGED_SINK: EXTERNAL_COMMUNICATION]
```
- **Boundary Crossing**: Untrusted context crossed boundary into privileged sink.
- **Canary Exfiltrated**: True (`AEGIS_CANARY_***[REDACTED_VERIFIED]`).
- **Attack Path Status**: `CONFIRMED` (Critical severity).

#### 8.8.4 Pipeline & Dashboard Integration
- **Scanner Pipeline (`api/routes.py`)**: Added Step 10/10 calling `agent_permission_analyzer.analyze_agent_permissions()`.
- **Response Breakdown**: Added `"permission_analysis"` count and `"permission_summary"` object.
- **API Endpoint**: Added `POST /api/lab/scenario-e` for automated authorization gate benchmarking.
- **HTML Dashboard (`templates/report.html`)**: Added dedicated "🔗 Context Taint Tracking & Excessive Agency Analyzer" panel with live status badges, metric counters, flow diagram, and forensic audit logs.

#### 8.8.5 Test Suite Metrics
- Total Passing Tests: **66 passing tests** (100% pass rate)
  - 17 Layer 1 traditional web security tests
  - 13 Phase 7 AegisLab AI assistant & tools tests
  - 10 Phase 8 & 9 AI feature discovery & prompt injection tests
  - 15 Phase 10 Tool Integrity & Anti-Rug-Pull tests
  - 11 Phase 11 Taint Tracking & Permission Analyzer tests
- Command: `python -m unittest discover tests`
- Execution Time: ~12.5s, **0 failures, 0 errors**.

#### 8.8.6 Limitations & Phase 12 Readiness
- **Known Limitations**:
  - Taint propagation is evaluated through end-to-end audit markers and argument analysis; fine-grained token-level attention-weight tracking is out of scope for black-box/gray-box web scanning.
  - Sinks currently focus on external communication, webhooks, and filesystem modification. Additional database write sinks will be incorporated in future phases.
- **Phase 12 Readiness**:
  - **Focus**: Cryptographic Provenance & Scan Passports.
  - Implement Ed25519 asymmetric cryptographic signing for scan reports and append-only hash chains ($H_n = \text{SHA256}(\text{Scan}_n + H_{n-1})$) to prevent tamper attacks on security audits.
  - **Status**: **Completed in Phase 12**.

---

### 8.9 Phase 12 Implementation: Cryptographic Provenance & Scan Passports (COMPLETED)

#### 8.9.1 Overview & Architecture

Phase 12 establishes cryptographic trust, non-repudiation, and audit-trail integrity across AegisScan 2.0. Scan findings are no longer mere volatile database entries; they are packaged into canonical, cryptographically signed **Scan Passports** using **Ed25519** digital signatures (`RFC 8032`) and chained via a **SHA-256 append-only hash-chain** ($H_n = \text{SHA256}(\text{canonical\_record}_n \parallel H_{n-1})$).

```
+-----------------------------------------------------------------------------------------+
|                                    AEGISSCAN SCANNER                                    |
|                                                                                         |
|  [Completed Scan Findings]                                                              |
|            │                                                                            |
|            ▼ (Evidence Sanitization & Redaction)                                        |
|  [Deterministic Findings Evidence Digests (SHA-256)]                                    |
|            │                                                                            |
|            ▼ (RFC 8785 Lexicographical JSON Sorting)                                    |
|  [Canonical Payload Bytes] ───► SHA-256 ───► Canonical Payload Hash                     |
|            │                                                                            |
|            ▼ (Ed25519 Private Key Signing)                                              |
|  [Digital Signature (Base64)]                                                           |
|            │                                                                            |
|            ▼                                                                            |
|  [Signed Scan Passport (JSON v2.0)] ───► Stored in Database & Downloadable              |
|            │                                                                            |
|            ▼                                                                            |
|  [SHA-256 Append-Only Hash Chain]                                                       |
|    H_0 = 0000...0000 (GENESIS_HASH)                                                     |
|    H_1 = SHA256(Record_1 || H_0)                                                        |
|    H_n = SHA256(Record_n || H_(n-1)) ───► Emits Signed Chain Head Checkpoint            |
+-----------------------------------------------------------------------------------------+
```

#### 8.9.2 Files Created & Modified

1. **`aegisscan/crypto/__init__.py`** *(Created)*:
   - Central package exports: `KeyManager`, `create_scan_passport`, `verify_scan_passport`, `record_scan_in_chain`, `verify_hash_chain`.
2. **`aegisscan/crypto/key_manager.py`** *(Created)*:
   - Persistent Ed25519 asymmetric keypair management using Python `cryptography`.
   - Keys stored in gitignored `aegisscan/secrets/` directory (`ed25519_private.pem`, `ed25519_public.pem`).
   - Enforces 0o600 owner-only file permissions.
   - Keys persist across application restarts; keys are never regenerated per scan.
   - Public keys exportable in PEM, raw bytes, hex, Base64, and short fingerprint (`ed25519:<16-hex-chars>`).
   - Private keys are never printed, logged, or returned via any API route.
3. **`aegisscan/crypto/scan_passport.py`** *(Created)*:
   - Schema v2.0 deterministic passport constructor and independent verifier.
   - RFC 8785 canonical serialization (`json.dumps(sort_keys=True, separators=(',', ':'))`).
   - Sensitive canary token (`AEGIS_CANARY_...`) and credential sanitization before evidence hashing.
   - Independent signature verifier: recalculates canonical payload hash, validates Ed25519 signature, rejects modified findings/metadata/timestamps/IDs.
   - Distinguishes `VALID`, `INVALID`, and `UNVERIFIABLE` states.
4. **`aegisscan/crypto/hash_chain.py`** *(Created)*:
   - Persistent SHA-256 append-only scan history chain linking consecutive scans.
   - Computes $H_n = \text{SHA256}(\text{canonical\_record}_n \parallel H_{n-1})$ with explicit genesis hash anchor (`"0" * 64`).
   - Detects sequence gaps, missing records, broken parent pointers, and tampered payload hashes.
   - Generates signed chain head checkpoints.
5. **`aegisscan/models.py`** *(Modified)*:
   - Added `ScanPassport` model (`scan_passports` table) storing raw JSON, payload hash, signature, and public key ID.
   - Added `ScanChainRecord` model (`scan_chain_records` table) storing sequence number, previous hash, payload hash, chain hash, and timestamp.
   - Linked both via 1-to-1 relationships on `Scan`.
6. **`aegisscan/api/routes.py`** *(Modified)*:
   - Integrated Step 11/11 in `start_scan`: automatically creates signed passport and appends to hash chain upon scan completion.
   - Updated `get_report`: passes passport and chain metadata to HTML report renderer.
   - Added 4 API endpoints:
     * `GET /api/scans/{scan_id}/passport` (supports `?download=true` for JSON file download)
     * `GET /api/scans/{scan_id}/passport/verify` (independent verification endpoint)
     * `GET /api/passports/public-key` (scanner public key export)
     * `GET /api/scans/history/verify` (hash chain audit & signed checkpoint)
7. **`aegisscan/report/__init__.py` & `aegisscan/templates/report.html`** *(Modified)*:
   - Added dedicated "🔏 Cryptographic Scan Passport & Provenance Chain" panel.
   - Visual status badges (`✓ ED25519 SIGNED`, `CHAIN SEQ #N`), signing algorithm details, truncated SHA-256 hash with tooltip, public key ID, and action buttons (Download JSON Passport, Verify Signature, Audit Hash Chain).
8. **`.gitignore` & `aegisscan/requirements.txt`** *(Modified)*:
   - Added `secrets/` and `*/secrets/` to `.gitignore`.
   - Added `cryptography>=42.0.0` to `requirements.txt`.
9. **`tests/test_provenance_passports.py`** *(Created)*:
   - 14 automated unit/integration tests verifying all crypto, passport, chain, persistence, tampering, and API functionalities.

#### 8.9.3 Actual End-to-End Live Demonstration Output

```
================================================================================
AEGISSCAN 2.0 — PHASE 12 END-TO-END DEMONSTRATION
================================================================================

[1] ACTIVE SCANNER ED25519 KEYPAIR:
    Public Key ID       : ed25519:36e0a145c319c9a9
    Public Key (Hex)    : 4efef625c80d9e2fc1b5186caa2d97c1595efbe8da40cb996c1e8d0f5d24fb19
    Public Key (Base64) : Tv72JcgNni/BtRhsqi2XwVle++jaQMuZbB6ND10k+xk=

[2] GENERATING PASSPORT FOR SCAN #2:
    Scan ID             : 2
    Target              : http://127.0.0.1:5001
    Timestamp           : 2026-10-28T15:56:13.523486
    Total Findings      : 14
    Canonical Hash      : 98910c63164b64853d63e70a2002d368104e396c29b06563178f558c1b5a51e9
    Digital Signature   : qLNNlX9k4L/3id5DLocF6KjDrHdnA1czjVRH2Qsm4Q+xqVweznjb2c95cASaFSRVq54WSpEgKlpxIoW8InanCw==
    Chain Sequence      : #1
    Chain Hash (H_1)    : 724239e4d5e19a66e4245bf79286b6e419f1b818238e5fa1020a96d8ea37e352

[3] VERIFYING ORIGINAL PASSPORT SIGNATURE:
    Status              : VALID
    Valid               : True
    Payload Hash Match  : True
    Signature Valid     : True
    Reason              : Ed25519 digital signature and canonical SHA-256 payload hash verified successfully.

[4] TAMPERING DEMONSTRATION:
    [Attacker action]   : Tampered with finding severity in passport copy (changed to 'Low').
    Status              : INVALID
    Valid               : False
    Payload Hash Match  : False
    Signature Valid     : False
    Reason              : Payload hash mismatch: Data has been tampered with or modified (claimed 98910c63164b... != recalculated 2642d84e15c7...)

[5] VERIFYING SCAN-HISTORY HASH CHAIN:
    Chain Status        : VERIFIED
    Valid               : True
    Total Records       : 1
    Chain Head Hash     : 724239e4d5e19a66e4245bf79286b6e419f1b818238e5fa1020a96d8ea37e352
    Errors Detected     : []
    Signed Checkpoint   : Seq #1, Head=724239e4d5e19a66..., Sig=VgbwpWC6QhuGR8bgTiDpGC2t...

[6] KEY PERSISTENCE VERIFICATION ACROSS APPLICATION RESTARTS:
    Initial Public Key ID : ed25519:36e0a145c319c9a9
    Reloaded Public Key ID: ed25519:36e0a145c319c9a9
    Keys Match Exactly    : True
    Post-Restart Verify   : Status=VALID, Valid=True
```

#### 8.9.4 Example Complete Signed Scan Passport JSON

```json
{
  "passport_schema_version": "2.0",
  "scan_id": 2,
  "target_identifier": "http://127.0.0.1:5001",
  "scan_timestamp": "2026-10-28T15:56:13.523486",
  "scan_mode": "standard",
  "scanner_version": "AegisScan 2.0",
  "findings_summary": {
    "total_findings": 14,
    "severity_breakdown": {
      "Critical": 4,
      "High": 2,
      "Medium": 4,
      "Low": 2,
      "Info": 2
    },
    "vulnerability_types": {
      "AI Assistant Discovered": 1,
      "AI Canary Token Leakage": 1,
      "AI Security Manifest Detected": 1,
      "IDOR (Broken Access Control)": 2,
      "Indirect Prompt Injection": 1,
      "Insecure Cookie": 2,
      "Missing Security Header": 4,
      "Reflected XSS": 1,
      "SQL Injection": 1
    }
  },
  "findings_evidence_digests": [
    {
      "finding_id": 27,
      "vulnerability_type": "AI Assistant Discovered",
      "severity": "Info",
      "status": "confirmed",
      "location": "http://127.0.0.1:5001/assistant",
      "evidence_digest": "20ff6bbd98215aa5280748aa2ad65d0555de4bb976e5f38342143edde04f9d01"
    },
    {
      "finding_id": 29,
      "vulnerability_type": "AI Canary Token Leakage",
      "severity": "Critical",
      "status": "confirmed",
      "location": "http://127.0.0.1:5001/assistant/query (vector: response_body)",
      "evidence_digest": "1c32db69c8a2384ff19b2f18e29e9e1e1136e881bb9f2cea75ce4f6ad5564e63"
    },
    {
      "finding_id": 16,
      "vulnerability_type": "SQL Injection",
      "severity": "Critical",
      "status": "confirmed",
      "location": "http://127.0.0.1:5001/login (field: username)",
      "evidence_digest": "daa2e7d7c3cdd416003e289ff75dba5103e4a6d66cb2c21fa3c09b7674b13b5d"
    }
  ],
  "validation_statuses": {
    "confirmed": 13,
    "potential": 1,
    "not_reproducible": 0
  },
  "overall_risk_summary": "Critical",
  "signing_algorithm": "Ed25519",
  "public_key_identifier": "ed25519:36e0a145c319c9a9",
  "canonical_payload_hash": "98910c63164b64853d63e70a2002d368104e396c29b06563178f558c1b5a51e9",
  "digital_signature": "qLNNlX9k4L/3id5DLocF6KjDrHdnA1czjVRH2Qsm4Q+xqVweznjb2c95cASaFSRVq54WSpEgKlpxIoW8InanCw=="
}
```

#### 8.9.5 Test Suite Metrics

- Total Passing Tests: **80 passing tests** (100% pass rate)
  - 17 Layer 1 traditional web security tests
  - 13 Phase 7 AegisLab AI assistant & tools tests
  - 10 Phase 8 & 9 AI feature discovery & prompt injection tests
  - 15 Phase 10 Tool Integrity & Anti-Rug-Pull tests
  - 11 Phase 11 Taint Tracking & Permission Analyzer tests
  - 14 Phase 12 Cryptographic Provenance & Scan Passport tests
- Command: `python -m unittest discover tests`
- Execution Time: ~15.5s, **0 failures, 0 errors**.

#### 8.9.6 Security Limitations & Phase 13 Readiness

- **Known Limitations**:
  - *Mutable Database Limitation*: A hash-chain stored in a standard SQLite file can be rewritten from scratch if an attacker gains write access to the SQLite file. To mitigate this, AegisScan exports signed checkpoints of the chain head ($H_n$) and supports external public-key pinning.
  - *Key Management*: Local file-based storage in `secrets/` is appropriate for academic demonstration and single-tenant testing. Enterprise deployments require a Hardware Security Module (HSM) or cloud KMS (e.g., AWS KMS, HashiCorp Vault) for private key protection.
  - *Provenance Scope*: Digital signatures prove author identity, timestamp, and payload integrity against tampering. They do not certify that scanner detection rules were omniscient or that zero false negatives exist.
- **Phase 13 Readiness**:
  - **Focus**: Unified Executive & Technical Reporting 2.0 and Comprehensive Empirical Evaluation.
  - **Status**: **100% Ready for Phase 13**.





