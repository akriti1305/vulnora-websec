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
