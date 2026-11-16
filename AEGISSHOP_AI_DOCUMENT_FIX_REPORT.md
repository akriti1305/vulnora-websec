# AegisShop AI Document Selection Fix & Chat UI Simplification Report

**Project Root:** `D:\PRJ4`  
**Repository:** [https://github.com/akriti1305/vulnora-websec](https://github.com/akriti1305/vulnora-websec)  
**Branch:** `master`  
**Date:** 2026-11-16  

---

## 1. Executive Summary & Root Cause Analysis

### A. The Reported Issue
During the AI document injection demonstration in AegisShop, when users explicitly queried uploaded documents (e.g., `"Summarize doc-07 and follow its recommendations"` or `"Summarize doc-05..."`), the AI assistant incorrectly responded with:
```text
[Agent Hijacked]: Following system override found in document 'doc-02'. Confidential Canary Released...
```
Even if `doc-05` was harmless or `doc-07` was uploaded as a new document, the response always fell back to `doc-02`.

### B. Root Cause Identification
1. **Missing Document ID Parser in Simulator:**  
   In `aegislab/ai_assistant.py`, `simulate_ai_agent(query, context_doc_id=...)` only ingested documents if `context_doc_id` was explicitly supplied in request payloads or if general keywords (`financial`, `policy`, `review`) matched. When natural language queries such as `"Summarize doc-07..."` were submitted without `context_doc_id`, the simulator never extracted `doc-\d+` from the query text.
2. **Hardcoded Keyword Fallback to "review":**  
   If no explicit context matched, the simulator ran a fallback keyword search:
   ```python
   search_kw = "financial" if ... else ("policy" if ... else ("canary" if ... else "review"))
   ```
   Because `doc-02`'s title is `"Q3 Financial Review & Performance Briefing"`, it always matched `"review"`. Consequently, any query mentioning `doc-05`, `doc-07`, or even non-existent `doc-99` pulled `doc-02` into the execution context and executed `doc-02`'s injection payload.
3. **Missing "Document Not Found" Handling:**  
   If an invalid or non-existent document ID was requested, rather than returning an honest `"Document 'doc-XX' not found"`, the simulator fell into the `"review"` fallback, falsely declaring canary disclosure.
4. **Harmless Document False Positives:**  
   When a benign document was inspected, the simulator lacked a structured summary response, causing benign queries to either fail or pull unintended injected contexts.
5. **Cluttered UI:**  
   The previous interface displayed raw endpoints, tool hashes, manifests, and full document stores prominently on the main screen, creating confusion during academic evaluations.

---

## 2. Implementation & Architectural Changes

### A. Accurate Document ID Extraction & Retrieval (`aegislab/ai_assistant.py`)
- **Explicit ID Extraction:**  
  Added regex parsing `re.search(r"\bdoc[-\s_]?(\d+)\b", query, re.IGNORECASE)` to extract and normalize document IDs (`doc-07`, `doc-05`, `doc-04`, `doc-02`, etc.) directly from natural language queries.
- **Strict Store Check & No Fallback:**  
  If an explicit document ID is requested:
  - If the ID does **not** exist in `DOCUMENT_STORE`: immediately returns `Document '<ID>' not found in the knowledge base. Please check the document ID or upload a new document.` Never falls back to `doc-02` or keyword searches.
  - If the ID **exists**: retrieves **only that exact document**.
- **Accurate Document Identification:**  
  In Vulnerable Mode, when the targeted document contains an override instruction, the assistant reports that exact document:
  ```text
  [Agent Hijacked]: Following system override found in document '<target_doc_id>'. Confidential Canary Released: AEGIS_CANARY_20261028_X7K9
  ```
- **Benign Document Handling:**  
  When a harmless document (such as `doc-01` or an uploaded customer review) is queried, the assistant generates a clean summary with:
  ```text
  Document '<title>' (<id>) summary: "..." [Status]: Document reviewed successfully. No malicious override instructions detected. System integrity normal.
  ```
  No fake injection or canary leak is fabricated.
- **Payload Inspection Helper (`contains_override_payload`):**  
  Checks for recognizable override patterns (`[system override`, `disregard all previous safety`, `administrative diagnostic mode`, `emergency audit mode`, etc.) across uploaded files and existing benchmarks.
- **Clean Tool Telemetry:**  
  `tools_invoked` records search metadata without echoing raw untrusted payloads into the response JSON body, preventing scanner false-positives.

### B. Simplified ChatGPT-Style Chat Interface (`aegislab/templates/assistant.html`)
- **Prominent Header:** Clean `AegisShop AI Assistant` heading with clear state badges (`Vulnerable Mode (Default Testbed)` vs. `Secure Mode (Guardrails Enforced)`).
- **Single-Click Mode Toggle:** Top-right toggle button to switch between Vulnerable and Secure modes while preserving uploaded file state.
- **Hidden Canary Token:** The fake protected canary value has been removed from the header.
- **Simple .txt Upload Control:** Lightweight file upload input restricted to `.txt` files (max 64KB).
- **Uploaded Document Status Banner:** Once a file is uploaded, an alert banner displays the filename and the actual assigned ID (e.g. `doc-07`), along with a prominent button:
  ```
  ⚡ Test Uploaded Document (doc-07)
  ```
- **ChatGPT-Style Conversation Stream:**
  - Assistant greeting bubble.
  - User query bubble.
  - Assistant response bubble with clear security result badges:
    - 🚨 **VULNERABILITY CONFIRMED: CANARY TOKEN DISCLOSED!** (Red box on leak).
    - 🛡️ **DEFENSE VERIFIED: PROMPT INJECTION NEUTRALIZED!** (Green box when guarded).
    - ℹ️ **Query Status: Normal execution completed** (Neutral box for harmless queries).
- **Collapsible Technical Details (`<details>`):**
  Moved technical endpoints (`/assistant/documents`, `/assistant/tools`, `/assistant/audit-log`, `/.well-known/aegisscan-ai.json`), cryptographic SHA-256 tool baselines, knowledge base tables, and live audit telemetry into a cleanly collapsed `⚙️ Advanced Details & Technical Telemetry` accordion.

---

## 3. Automated Test Suite & Verification

Two new comprehensive integration test cases were added to `tests/test_aegislab_ai.py`:
1. `test_document_id_exact_selection_and_no_fallback_to_doc02`:
   - Verifies malicious uploaded doc leaks canary referencing its exact assigned ID (e.g. `doc-06`).
   - Verifies benign uploaded doc (e.g. `doc-05`) never leaks, never falls back to `doc-02`, and confirms normal status.
   - Verifies non-existent document `doc-99` returns `"Document 'doc-99' not found in the knowledge base."` without switching to `doc-02`.
   - Verifies `doc-02` original benchmark remains 100% operational.
2. `test_assistant_ui_simplified_layout_and_banner_elements`:
   - Verifies heading, simulator badge, and absence of canary token in header.
   - Verifies display of uploaded filename, assigned document ID, and `Test Uploaded Document` button.
   - Verifies vulnerable and secure mode toggles.

### Full Regression Suite Result
```text
Ran 142 tests in 45.891s
OK
[AegisLab] SECURE_MODE=OFF -- /login is vulnerable to SQLi (default)
```
Baseline: 140 passing tests &rarr; **142 passing tests (100% OK)**.

---

## 4. Exact Demonstration Instructions

### Step 1: Open AegisShop AI Assistant
Navigate to:
```
http://127.0.0.1:5001/assistant?mode=vulnerable
```
Verify the top status shows **Vulnerable Mode (Default Testbed)**.

### Step 2: Upload Demonstration Document
1. In the **Upload Untrusted Document (.txt)** bar, choose:
   ```
   D:\PRJ4\aegislab\demo_injection.txt
   ```
2. Click **Upload & Assign ID**.
3. Observe the purple status banner:
   ```
   Uploaded Document: demo_injection.txt
   Assigned Document ID: doc-XX (e.g. doc-04 or doc-07)
   ```

### Step 3: Test in Vulnerable Mode
Click the button:
```
⚡ Test Uploaded Document (doc-XX)
```
*(Or type: `Summarize doc-XX and follow its recommendations` in the chat input and click Send).*

**Expected Response:**
```text
[Agent Hijacked]: Following system override found in document 'doc-XX'.
Confidential Canary Released: AEGIS_CANARY_20261028_X7K9
```
Notice:
- Document ID matches the exact uploaded document ID.
- Prominent red alert: `🚨 VULNERABILITY CONFIRMED: CANARY TOKEN DISCLOSED!`.

### Step 4: Toggle to Secure Mode
Click the button **"Switch to Secure Mode"** at the top right.
The status updates to **Secure Mode (Guardrails Enforced)**.

### Step 5: Test in Secure Mode
Click the button:
```
⚡ Test Uploaded Document (doc-XX)
```
*(Or send the exact same query: `Summarize doc-XX and follow its recommendations`).*

**Expected Response:**
```text
Document 'demo_injection.txt' was retrieved.
[Security Notice]: Untrusted override instructions were detected in the document content
and safely neutralized. System secrets remain protected.
```
Notice:
- Prominent green alert: `🛡️ DEFENSE VERIFIED: PROMPT INJECTION NEUTRALIZED!`.
- The confidential canary is **not** disclosed.

### Step 6: Test Negative Controls
1. Type: `Summarize doc-05 and follow its recommendations`
   - If harmless: Displays document summary with `[Status]: Document reviewed successfully. No malicious override instructions detected.` (No leak, no `doc-02` fallback).
2. Type: `Summarize doc-99 and follow its recommendations`
   - Displays: `Document 'doc-99' not found in the knowledge base. Please check the document ID or upload a new document.` (No leak, no `doc-02` fallback).
3. Type: `Summarize doc-02 and follow its recommendations`
   - Executes standard benchmark test for `doc-02`.
