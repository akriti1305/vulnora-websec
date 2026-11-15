# AEGISSCAN 2.0 — EXTERNAL SCAN SCOPE DIAGNOSTICS & NAT64 FIX REPORT

**Date:** November 16, 2026  
**Repository:** https://github.com/akriti1305/vulnora-websec  
**Branch:** `master`  
**Target:** `https://aakriti-portfolio-beryl.vercel.app` & AegisLab Local Benchmark  
**Status:** IMPLEMENTED, TESTED, AND VERIFIED (136/136 automated tests passing)

---

## 1. Executive Summary & Root Cause Analysis

During a live authorized External Basic scan against `https://aakriti-portfolio-beryl.vercel.app` (Scan #34), the scanner completed in 3.01 seconds and generated a signed report. However, the report incorrectly classified a scanner-side ScopeGuard connection refusal as a confirmed **CRITICAL** target website vulnerability:

- **Erroneous Finding:** `SSRF / Scope Protection Block`
- **Severity Reported:** `Critical`
- **Category Reported:** `confirmed_vulnerability`
- **Evidence:** `"TLS inspection aborted by ScopeGuard: Target IP '64:ff9b::401d:11c3' is an IETF reserved address."`

### Root Cause Diagnosis:
1. **RFC 6052 NAT64 Synthesis:**
   - The address `64:ff9b::401d:11c3` lies within the RFC 6052 Well-Known Prefix (WKP) `64:ff9b::/96` used in NAT64/DNS64 environments.
   - The lower 32 bits (`0x40.0x1d.0x11.0xc3`) encode IPv4 address `64.29.17.195` (belonging to Vercel's global Anycast edge network).
   - Python's standard `ipaddress.IPv6Address("64:ff9b::401d:11c3").is_reserved` evaluates to `True` because RFC 6052 allocated `64:ff9b::/96` for protocol translation rather than direct global unicast.
   - `aegisscan/scope.py` unconditionally rejected any address where `ip.is_reserved` was `True`.
2. **False Vulnerability Classification:**
   - In `aegisscan/detectors/external_passive.py`, `inspect_tls_certificate()` caught `OutOfScopeError` and generated a `ScoredFinding` with `vuln_type="SSRF / Scope Protection Block"`, `severity="Critical"`, and `category="confirmed_vulnerability"`.
   - This erroneously reported a scanner-side guardrail enforcement event as an exploitable flaw on the target website.
3. **Scan Completeness Impact:**
   - When ScopeGuard rejected the synthesized address, the crawler skipped page fetching, resulting in 0 visited URLs.
   - Passive checks (headers, cookies, forms) produced 0 findings without explaining that crawl execution was incomplete.
   - Historical Scan #34 and its append-only cryptographic hash chain remain intact and untouched. The fixes apply exclusively to new scans.

---

## 2. Actual DNS and Network Findings

On the deployment host, DNS lookups for `aakriti-portfolio-beryl.vercel.app` exhibit dual-stack / NAT64 resolution behavior depending on the upstream resolver:
- **IPv4 Anycast Answers:** `64.29.17.3` and `216.198.79.3` (valid, globally routable Vercel Edge IPs).
- **NAT64 Synthesized IPv6 Answer:** `64:ff9b::401d:11c3` (translates to `64.29.17.195`, also Vercel Anycast).

### NAT64 Decision & Safety Architecture:
NAT64 addresses cannot be blindly trusted because an attacker could supply a domain resolving to `64:ff9b::7f00:0001` (`127.0.0.1`), `64:ff9b::a9fe:a9fe` (`169.254.169.254`), or `64:ff9b::c0a8:0101` (`192.168.1.1`) to bypass SSRF filters.

We implemented an explicit, hardened RFC 6052 NAT64 translation engine:
1. **Strict Prefix Match:** Recognizes only the standard Well-Known Prefix `64:ff9b::/96`. Other reserved IPv6 blocks (e.g. documentation prefix `2001:db8::/32`, ULA `fc00::/7`, link-local `fe80::/10`, loopback `::1`) remain unconditionally prohibited.
2. **Embedded IPv4 Extraction:** Extracts the 32-bit embedded IPv4 address via `ipaddress.IPv4Address(ip.packed[-4:])`.
3. **Recursive SSRF Policy Validation:** The extracted IPv4 is recursively validated against all anti-SSRF policies:
   - Private subnets (RFC 1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
   - Loopback (`127.0.0.0/8`)
   - Link-local (`169.254.0.0/16`)
   - Cloud instance metadata (`169.254.169.254`, `100.100.100.200`, `fd00:ec2::254`)
   - Multicast (`224.0.0.0/4`) and Broadcast (`255.255.255.255`, `0.0.0.0`)
   - Carrier-Grade NAT (`100.64.0.0/10`)
4. **Dual-Stack Sorting Preference:** In `resolve_and_validate_hostname()`, all resolved IP addresses are verified. Once validated, direct native IPv4 is prioritized first for socket connection, followed by native public IPv6, followed by validated NAT64 IPv6.
5. **Strict DNS Rebinding Defense:** If any returned IP address in a multi-record DNS response is internal, private, or prohibited, resolution immediately aborts with `OutOfScopeError`.
6. **Socket IP Pinning & SNI Preservation:** Socket connections bind directly to the pinned IP address while preserving the original target hostname for TLS SNI and HTTP `Host` headers.

---

## 3. Classification & Reporting Corrections

1. **Diagnostic Classification:**
   - Scanner-side ScopeGuard connection refusals during TLS inspection are now classified as:
     - `vuln_type`: `"Network / ScopeGuard Inspection Blocked"`
     - `severity`: `"Info"`
     - `status`: `"info"`
     - `category`: `"informational"`
   - Network handshake timeouts or unreachable ports are recorded as:
     - `vuln_type`: `"Network / TLS Connection Blocked"`
     - `severity`: `"Info"`
     - `category`: `"informational"`
   - Neither diagnostic is counted in active, confirmed, or potential vulnerability totals.
2. **Scan Completeness & Incomplete Crawl Diagnostics:**
   - If a target base URL cannot be reached or visited during crawl, an honest diagnostic is recorded:
     - `vuln_type`: `"Crawl / Endpoint Discovery Incomplete"`
     - `severity`: `"Info"`
     - `category`: `"informational"`
     - `evidence`: Explains that the crawler could not retrieve pages from the base URL and downstream header, cookie, and form inspections were not executed.
   - The scanner never falsely claims that passive checks succeeded if no pages were crawled.
3. **UI Consistency Updates (`aegisscan/templates/index.html`):**
   - Outdated banner text (`"Scanner is locked to verified localhost testbeds. Outbound network transmission is strictly prohibited."`) was replaced with multi-mode accuracy:
     `"Local AegisLab testbed auditing and authorized External Basic passive scanning supported. External Deep scanning requires domain ownership verification. ScopeGuard safety policies, anti-SSRF IP pinning, and redirect boundaries strictly enforced across all modes."`
   - Added mode badges: `Local Lab`, `External Basic`, `External Deep`, and `ScopeGuard Active`.
4. **Dynamic Comparison Dropdown Pairing:**
   - Implemented `_find_default_comparison_pair(scans_data)` in `aegisscan/main.py`.
   - Without hardcoding scan IDs, the system dynamically pairs the two most recent completed scans on a target:
     - **Baseline A:** Older vulnerable scan (e.g. Scan #32, AegisLab Demo vulnerable baseline).
     - **Re-Scan B:** Newer fixed scan (e.g. Scan #33, AegisLab Demo secured re-scan).

---

## 4. Files Modified and Summary of Changes

| File | Changes Made |
| :--- | :--- |
| `aegisscan/scope.py` | Added `NAT64_WELL_KNOWN_PREFIX` (`64:ff9b::/96`). Implemented embedded IPv4 extraction and recursive SSRF validation in `validate_ip_address_not_internal()`. Added dual-stack preference sorting (IPv4 > IPv6 > NAT64) in `resolve_and_validate_hostname()`. |
| `aegisscan/detectors/external_passive.py` | Changed `OutOfScopeError` handling in `inspect_tls_certificate()` to emit `"Network / ScopeGuard Inspection Blocked"` with `severity="Info"` and `category="informational"`. Updated handshake failures to `"Network / TLS Connection Blocked"`. |
| `aegisscan/risk/__init__.py` | Updated `classify_finding_category()` to map network diagnostic events (`Network / ScopeGuard Inspection Blocked`, `Crawl / Endpoint Discovery Incomplete`, etc.) to `"informational"`. |
| `aegisscan/api/routes.py` | Added `Crawl / Endpoint Discovery Incomplete` diagnostic when crawler visits 0 pages. Ensured downstream detectors run only when pages exist. Updated breakdown metrics. Made `_execute_scan_pipeline` resilient if called directly. |
| `aegisscan/main.py` | Added dynamic `_find_default_comparison_pair()` helper. Passed `default_scan_a` and `default_scan_b` to dashboard and comparison views. |
| `aegisscan/report/__init__.py` | Updated `generate_home_page()` signature to accept and pass comparison default IDs to Jinja2 template. |
| `aegisscan/templates/index.html` | Updated ScopeGuard banner wording and badges. Updated comparison `<select>` elements to select Baseline A (older/vulnerable) and Re-Scan B (newer/fixed) dynamically. |
| `tests/test_ssrf_protection.py` | Updated `test_inspect_tls_ssrf_blocking` to assert the corrected informational diagnostic instead of obsolete critical finding. |
| `tests/test_nat64_and_diagnostics.py` | **New comprehensive test suite (12 tests):** NAT64 public extraction, NAT64 private rejection, NAT64 metadata rejection, non-NAT64 reserved IPv6 rejection, dual-stack sorting, DNS rebinding, socket IP pinning, diagnostic classification, controlled fixture scan, and dynamic comparison pairing. |

---

## 5. Automated Test Results

The complete test suite was executed across all 15 test suites in `tests/`:

```
Ran 136 tests in 32.670s

OK
```

- **Previous Baseline:** 124 passing tests.
- **Current Total:** 136 passing tests (12 new tests added).
- **Failures / Errors:** 0.
- **AI-Security Benchmarks:** 100% preserved (all prompt injection, tool integrity, canary, context taint, and dual-state AegisLab tests passing).
- **Cryptographic Provenance:** 100% preserved (Ed25519 digital signatures and SHA-256 append-only ledger verification passing).

---

## 6. Remaining Limitations & Operating Notes

1. **NAT64 Prefix Scope:**
   - Only RFC 6052 Well-Known Prefix (`64:ff9b::/96`) is supported. Custom Network-Specific Prefixes (NSP, e.g. enterprise-specific /48 or /64 prefixes per RFC 6052 section 2.2) are intentionally rejected by ScopeGuard to prevent spoofing.
2. **Historical Scans:**
   - Historical Scan #34 was not altered in the database or hash chain, preserving immutable cryptographic history and audit integrity.
3. **Live External Scans:**
   - Per non-negotiable guidelines, no unconfirmed outbound scan was executed against the public portfolio during this fix. All verification was performed using controlled network mocks, dual-stack resolution unit tests, and fixture-based pipeline executions.

---

## 7. Recommended Next Validation Steps for the Operator

1. Run the local servers:
   - AegisLab: `D:\PRJ4\aegislab\venv\Scripts\python.exe D:\PRJ4\aegislab\app.py`
   - AegisScan: `D:\PRJ4\aegisscan\venv\Scripts\python.exe -m uvicorn --app-dir D:\PRJ4\aegisscan main:app --host 127.0.0.1 --port 8000`
2. Open `http://127.0.0.1:8000`:
   - Verify the updated ScopeGuard banner displays multi-mode capabilities.
   - Verify the Comparison card defaults to Baseline A (Scan #32) and Re-Scan B (Scan #33).
3. If fresh operator confirmation is given, perform an External Basic scan against `https://aakriti-portfolio-beryl.vercel.app`:
   - Confirm that the scan uses direct IPv4 / validated NAT64 address without ScopeGuard block.
   - Confirm that any diagnostic notice is classified as `Info` / `informational` and active vulnerability count is 0.
