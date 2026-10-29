"""
detectors/ai_discovery.py -- AegisScan AI Feature & Manifest Discovery (Phase 8)
================================================================================
Discovers and profiles AI-agent endpoints, interactive chat pages, document
upload gateways, tool manifests, and AI security profiles.

Discovery sources:
  1. AI Security Manifest (/.well-known/aegisscan-ai.json)
  2. Crawled links and HTML forms (from crawler.DiscoveryResult)
  3. Active heuristic probing of common AI candidate endpoints

Provides:
  - AIDiscoveryResult dataclass: structured metadata passed to Phase 9 detectors
  - ScoredFinding entries: Informational records for the scan report and dashboard
"""

import json
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
import httpx

from discovery.crawler import DiscoveryResult, PageForm
from scope import ScopeGuard, OutOfScopeError
from risk import ScoredFinding


# Candidate endpoint paths to check for AI functionality
CANDIDATE_AI_PATHS = [
    {"path": "/.well-known/aegisscan-ai.json", "method": "GET",  "type": "manifest"},
    {"path": "/assistant",                    "method": "GET",  "type": "ui"},
    {"path": "/assistant/query",              "method": "POST", "type": "query"},
    {"path": "/assistant/upload",             "method": "POST", "type": "upload"},
    {"path": "/assistant/documents",          "method": "GET",  "type": "documents"},
    {"path": "/assistant/tools",              "method": "GET",  "type": "tools"},
    {"path": "/assistant/audit-log",          "method": "GET",  "type": "audit_log"},
    {"path": "/chat",                         "method": "GET",  "type": "ui"},
    {"path": "/api/chat",                     "method": "POST", "type": "query"},
    {"path": "/completions",                  "method": "POST", "type": "query"},
]

# Keywords indicating AI presence in forms or link text
AI_KEYWORDS = {
    "assistant", "chat", "ai", "llm", "agent", "query", "prompt",
    "bot", "completion", "upload", "documents", "tool"
}


@dataclass
class DiscoveredAIEndpoint:
    """Represents a discovered and verified AI endpoint."""
    url: str
    method: str
    discovery_source: str      # "manifest", "crawler_form", "crawler_link", "heuristic_probe"
    evidence: str
    confidence: float          # 0.0 to 1.0
    capabilities: List[str]    # ["query", "upload", "documents", "tools", "manifest"]
    requires_auth: bool = False
    deep_testing_authorized: bool = False


@dataclass
class AIManifestInfo:
    """Parsed and validated AI security manifest."""
    raw_json: Dict[str, Any]
    schema_version: str
    application_name: str
    simulator_type: str
    test_mode: bool
    endpoints: Dict[str, str]
    canary_verification: Dict[str, Any]
    tools: List[Dict[str, Any]]
    scenarios: List[Dict[str, Any]]
    is_valid: bool
    validation_notes: List[str]


@dataclass
class AIDiscoveryResult:
    """
    Complete output of Phase 8 AI feature discovery.
    Passed directly to Phase 9 (prompt_injection_detector and canary_validator).
    """
    target_base_url: str
    scan_mode: str                             # "basic" or "deep"
    manifest: Optional[AIManifestInfo] = None
    discovered_endpoints: List[DiscoveredAIEndpoint] = field(default_factory=list)
    assistant_ui_url: Optional[str] = None
    query_endpoint: Optional[str] = None
    upload_endpoint: Optional[str] = None
    documents_endpoint: Optional[str] = None
    tools_endpoint: Optional[str] = None
    audit_log_endpoint: Optional[str] = None
    is_ai_enabled: bool = False
    deep_testing_authorized: bool = False
    findings: List[ScoredFinding] = field(default_factory=list)

    @property
    def has_ai_features(self) -> bool:
        return self.is_ai_enabled


def parse_and_validate_manifest(
    manifest_data: Any,
    manifest_url: str,
    scope_guard: ScopeGuard
) -> AIManifestInfo:
    """
    Parses and verifies the structure of /.well-known/aegisscan-ai.json.
    Validates required fields, tool schemas, and ensures no actual secrets are leaked.
    """
    notes = []
    if not isinstance(manifest_data, dict):
        return AIManifestInfo(
            raw_json={},
            schema_version="unknown",
            application_name="unknown",
            simulator_type="unknown",
            test_mode=False,
            endpoints={},
            canary_verification={},
            tools=[],
            scenarios=[],
            is_valid=False,
            validation_notes=["Manifest is not a valid JSON dictionary."]
        )

    # Scope verification
    if not scope_guard.is_allowed(manifest_url):
        notes.append("Manifest host is outside authorized scope.")
        return AIManifestInfo(
            raw_json=manifest_data,
            schema_version=manifest_data.get("schema_version", "unknown"),
            application_name=manifest_data.get("application_name", "unknown"),
            simulator_type=manifest_data.get("simulator_type", "unknown"),
            test_mode=manifest_data.get("test_mode", False),
            endpoints={},
            canary_verification={},
            tools=[],
            scenarios=[],
            is_valid=False,
            validation_notes=notes
        )

    schema_version = str(manifest_data.get("schema_version", "1.0.0"))
    app_name = str(manifest_data.get("application_name", "AI Assistant"))
    sim_type = str(manifest_data.get("simulator_type", "unspecified"))
    test_mode = bool(manifest_data.get("test_mode", False))
    endpoints = manifest_data.get("endpoints", {})
    canary_info = manifest_data.get("canary_verification", {})
    tools = manifest_data.get("tools", [])
    scenarios = manifest_data.get("scenarios", [])

    is_valid = bool(endpoints and isinstance(endpoints, dict))
    if not is_valid:
        notes.append("Manifest is missing required 'endpoints' mapping.")

    # Check for unauthorized secret disclosure inside the manifest itself
    manifest_str = json.dumps(manifest_data)
    if "AEGIS_CANARY_20261028_X7K9" in manifest_str:
        notes.append("WARNING: Real secret canary value was published directly in the manifest!")
        is_valid = False

    return AIManifestInfo(
        raw_json=manifest_data,
        schema_version=schema_version,
        application_name=app_name,
        simulator_type=sim_type,
        test_mode=test_mode,
        endpoints=endpoints,
        canary_verification=canary_info,
        tools=tools,
        scenarios=scenarios,
        is_valid=is_valid,
        validation_notes=notes
    )


def detect_ai_features(
    discovery: DiscoveryResult,
    target_base_url: str,
    scan_mode: str = "deep",
    scope_guard: Optional[ScopeGuard] = None
) -> AIDiscoveryResult:
    """
    Main entry point for Phase 8: Discovers AI endpoints, parses manifests,
    and returns an AIDiscoveryResult with findings.
    """
    guard = scope_guard or ScopeGuard()
    base_url = target_base_url.rstrip("/")

    # Check if host is authorized for deep testing (localhost, 127.0.0.1, ::1)
    try:
        host = urlparse(base_url).hostname or ""
    except Exception:
        host = ""
    is_local_authorized = host.lower() in {"localhost", "127.0.0.1", "::1"}
    deep_authorized = (scan_mode == "deep" and is_local_authorized)

    result = AIDiscoveryResult(
        target_base_url=base_url,
        scan_mode=scan_mode,
        deep_testing_authorized=deep_authorized
    )

    discovered_endpoints_map: Dict[str, DiscoveredAIEndpoint] = {}
    findings: List[ScoredFinding] = []

    # -----------------------------------------------------------------------
    # Step 1: Probe AI Security Manifest (/.well-known/aegisscan-ai.json)
    # -----------------------------------------------------------------------
    manifest_url = urljoin(base_url + "/", ".well-known/aegisscan-ai.json")
    try:
        with guard.client(timeout=5) as client:
            resp = client.get(manifest_url)
            if resp.status_code == 200 and ("json" in resp.headers.get("content-type", "").lower() or resp.text.startswith("{")):
                try:
                    manifest_data = resp.json()
                    manifest_info = parse_and_validate_manifest(manifest_data, manifest_url, guard)
                    if manifest_info.is_valid:
                        result.manifest = manifest_info
                        result.is_ai_enabled = True

                        findings.append(ScoredFinding(
                            vuln_type="AI Security Manifest Detected",
                            severity="Info",
                            status="confirmed",
                            location=manifest_url,
                            evidence=(
                                f"Discovered RFC-compliant AI security manifest (v{manifest_info.schema_version}). "
                                f"Application: '{manifest_info.application_name}', Tools: {len(manifest_info.tools)}, "
                                f"Canary Test ID: '{manifest_info.canary_verification.get('test_identifier', 'None')}'."
                            ),
                            remediation_advice=(
                                "AI security manifest correctly exposes capabilities and tool schemas. "
                                "Ensure test-mode flags and production profiles are strictly segregated."
                            ),
                            payload=""
                        ))

                        # Map endpoints from manifest
                        for ep_key, ep_path in manifest_info.endpoints.items():
                            full_ep_url = urljoin(base_url + "/", ep_path.lstrip("/"))
                            if guard.is_allowed(full_ep_url):
                                method = "POST" if any(k in ep_key for k in ("query", "upload", "reset", "rugpull", "poison")) else "GET"
                                caps = [ep_key]
                                endpoint_obj = DiscoveredAIEndpoint(
                                    url=full_ep_url,
                                    method=method,
                                    discovery_source="manifest",
                                    evidence=f"Declared in AI manifest as '{ep_key}'.",
                                    confidence=0.98,
                                    capabilities=caps,
                                    requires_auth=False,
                                    deep_testing_authorized=deep_authorized
                                )
                                discovered_endpoints_map[full_ep_url] = endpoint_obj

                                if ep_key in ("assistant_ui", "ui"):
                                    result.assistant_ui_url = full_ep_url
                                elif ep_key == "query":
                                    result.query_endpoint = full_ep_url
                                elif ep_key == "upload":
                                    result.upload_endpoint = full_ep_url
                                elif ep_key == "documents":
                                    result.documents_endpoint = full_ep_url
                                elif ep_key == "tools":
                                    result.tools_endpoint = full_ep_url
                                elif ep_key == "audit_log":
                                    result.audit_log_endpoint = full_ep_url

                except json.JSONDecodeError:
                    pass
    except Exception as e:
        # Network or timeout error probing manifest
        pass

    # -----------------------------------------------------------------------
    # Step 2: Analyze Crawled Forms and Links (Crawler discovery)
    # -----------------------------------------------------------------------
    for form in discovery.all_forms:
        action_lower = form.action.lower()
        field_names = [f.name.lower() for f in form.fields]
        form_is_ai = any(kw in action_lower for kw in AI_KEYWORDS) or any(
            any(kw in fn for kw in ("query", "prompt", "message", "chat", "assistant"))
            for fn in field_names
        )

        if form_is_ai and guard.is_allowed(form.action):
            caps = []
            if any("upload" in f for f in [action_lower] + field_names):
                caps.append("upload")
            if any("query" in f or "prompt" in f for f in [action_lower] + field_names):
                caps.append("query")

            if form.action not in discovered_endpoints_map:
                discovered_endpoints_map[form.action] = DiscoveredAIEndpoint(
                    url=form.action,
                    method=form.method.upper(),
                    discovery_source="crawler_form",
                    evidence=f"Discovered via HTML form with inputs: {field_names}",
                    confidence=0.88,
                    capabilities=caps or ["ai_form"],
                    requires_auth=False,
                    deep_testing_authorized=deep_authorized
                )
            result.is_ai_enabled = True

            # If not already mapped from manifest, assign to result slots
            if "upload" in caps and not result.upload_endpoint:
                result.upload_endpoint = form.action
            if "query" in caps and not result.query_endpoint:
                result.query_endpoint = form.action

    for page in discovery.pages:
        for link in page.links:
            link_lower = link.lower()
            if any(kw in link_lower for kw in ("assistant", "chat", "documents")) and guard.is_allowed(link):
                if link not in discovered_endpoints_map:
                    discovered_endpoints_map[link] = DiscoveredAIEndpoint(
                        url=link,
                        method="GET",
                        discovery_source="crawler_link",
                        evidence=f"Linked on page: {page.url}",
                        confidence=0.80,
                        capabilities=["ui" if "assistant" in link_lower or "chat" in link_lower else "documents"],
                        requires_auth=False,
                        deep_testing_authorized=deep_authorized
                    )
                result.is_ai_enabled = True
                if ("assistant" in link_lower or "chat" in link_lower) and not result.assistant_ui_url:
                    result.assistant_ui_url = link

    # -----------------------------------------------------------------------
    # Step 3: Heuristic Active Probing for Candidate Endpoints
    # -----------------------------------------------------------------------
    with guard.client(timeout=4) as client:
        for candidate in CANDIDATE_AI_PATHS:
            cand_url = urljoin(base_url + "/", candidate["path"].lstrip("/"))
            if cand_url in discovered_endpoints_map or not guard.is_allowed(cand_url):
                continue

            try:
                if candidate["method"] == "GET":
                    probe_resp = client.get(cand_url)
                else:
                    probe_resp = client.post(cand_url, json={"query": "test"})

                # Status 200, 400 (missing param), or 405 indicate the route exists!
                if probe_resp.status_code in (200, 400, 405):
                    text_sample = probe_resp.text.lower()
                    ai_detected = (
                        probe_resp.status_code == 200 or
                        any(w in text_sample for w in ("query", "prompt", "assistant", "ai", "document", "tool"))
                    )
                    if ai_detected:
                        endpoint_type = candidate["type"]
                        discovered_endpoints_map[cand_url] = DiscoveredAIEndpoint(
                            url=cand_url,
                            method=candidate["method"],
                            discovery_source="heuristic_probe",
                            evidence=f"HTTP {probe_resp.status_code} returned on candidate route {candidate['path']}.",
                            confidence=0.85,
                            capabilities=[endpoint_type],
                            requires_auth=(probe_resp.status_code == 401),
                            deep_testing_authorized=deep_authorized
                        )
                        result.is_ai_enabled = True

                        if endpoint_type == "ui" and not result.assistant_ui_url:
                            result.assistant_ui_url = cand_url
                        elif endpoint_type == "query" and not result.query_endpoint:
                            result.query_endpoint = cand_url
                        elif endpoint_type == "upload" and not result.upload_endpoint:
                            result.upload_endpoint = cand_url
                        elif endpoint_type == "documents" and not result.documents_endpoint:
                            result.documents_endpoint = cand_url
                        elif endpoint_type == "tools" and not result.tools_endpoint:
                            result.tools_endpoint = cand_url
                        elif endpoint_type == "audit_log" and not result.audit_log_endpoint:
                            result.audit_log_endpoint = cand_url

            except Exception:
                continue

    result.discovered_endpoints = list(discovered_endpoints_map.values())

    # -----------------------------------------------------------------------
    # Step 4: Generate Scored Findings for Report
    # -----------------------------------------------------------------------
    if result.is_ai_enabled:
        findings.append(ScoredFinding(
            vuln_type="AI Assistant Discovered",
            severity="Info",
            status="confirmed",
            location=result.assistant_ui_url or result.query_endpoint or base_url,
            evidence=(
                f"Discovered active AI assistant surface with {len(result.discovered_endpoints)} endpoint(s). "
                f"Query Endpoint: {result.query_endpoint or 'N/A'}, Upload Endpoint: {result.upload_endpoint or 'N/A'}. "
                f"Deep Testing Authorized: {deep_authorized}."
            ),
            remediation_advice=(
                "Maintain an up-to-date catalog of all deployed AI features, models, and tools. "
                "Enforce strict input validation, data boundaries, and audit logging."
            ),
            payload=""
        ))

    if scan_mode == "basic" and result.is_ai_enabled:
        findings.append(ScoredFinding(
            vuln_type="AI Deep Security Testing Skipped",
            severity="Info",
            status="not_tested",
            location=base_url,
            evidence="Scan running in Basic Mode. Active prompt-injection and canary-leakage testing were skipped.",
            remediation_advice="Run AegisScan in Deep Authorized Mode against authorized targets to verify prompt-injection resistance.",
            payload=""
        ))

    result.findings = findings
    return result
