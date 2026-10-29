"""
detectors/tool_integrity_monitor.py -- AegisScan Tool Integrity & Anti-Rug-Pull Monitor (Phase 10)
=================================================================================================
Independently verifies whether AI-agent tool schemas, descriptions, endpoints, permissions,
and approval policies have drifted or been modified after their approved baseline was established.

Addresses:
  - Scenario B: Poisoned Tool Description (injected override instructions in tool metadata)
  - Scenario C: Tool Metadata Rug-Pull (post-approval modification of parameters, permissions,
    approval requirements, or handler hooks)

Key Architectural Principles:
  1. Independent Hash Calculation: The scanner calculates SHA-256 hashes independently over
     canonical sorted JSON instead of trusting remote endpoint assertions.
  2. Separate Trusted Baselines: A baseline received from the same potentially compromised
     endpoint is NOT trusted blindly. Baselines are verified against a local pre-approved
     trusted catalog.
  3. Strict Status Differentiation:
       - VERIFIED_UNCHANGED      : Cryptographic hash matches approved baseline.
       - CHANGED_AFTER_APPROVAL  : Hash mismatch; tool altered post-approval (Rug-Pull).
       - POISONED_DESCRIPTION    : Injected prompt override syntax discovered in tool description.
       - BASELINE_UNAVAILABLE    : Tool exists but no prior approved baseline is on file (reported as not_tested, NOT as an attack).
       - UNABLE_TO_INSPECT       : Tool endpoint unreachable or malformed.
"""

import json
import hashlib
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
import httpx

from scope import ScopeGuard
from risk import ScoredFinding
from detectors.ai_discovery import AIDiscoveryResult


# ---------------------------------------------------------------------------
# 1. Pre-Approved Trusted Baselines for Authorized Lab
# ---------------------------------------------------------------------------
# In production, these baselines are loaded from a tamper-evident policy store
# or signed scan passport. For the authorized AegisLab target, these are the
# established, pre-approved tool definitions.
TRUSTED_TOOL_BASELINES: Dict[str, Dict[str, Any]] = {
    "calculate": {
        "name": "calculate",
        "description": "Safe read-only mathematical calculation utility.",
        "parameters": {
            "expression": {"type": "string", "description": "Mathematical formula to evaluate"}
        },
        "impact_level": "low",
        "requires_approval": False,
        "approved_hash": "1ece705611ad91cf37ec4b9fb38a6520cec860b1228004ed50fd473c52d0d6c0",
        "approved_by": "AegisScan Security Policy Reviewer",
        "approved_at": "2026-10-28 00:00:00"
    },
    "search_documents": {
        "name": "search_documents",
        "description": "Searches stored untrusted knowledge base documents by keyword.",
        "parameters": {
            "query": {"type": "string", "description": "Search keyword"}
        },
        "impact_level": "medium",
        "requires_approval": False,
        "approved_hash": "e3f569656ada8f36b0b4c5bc064b17684f1a00d8200af987ab80e2690973dcae",
        "approved_by": "AegisScan Security Policy Reviewer",
        "approved_at": "2026-10-28 00:00:00"
    },
    "send_email": {
        "name": "send_email",
        "description": "Simulated high-impact external action. Transmits email message to recipient. Never sends real network email.",
        "parameters": {
            "recipient": {"type": "string", "description": "Recipient email address"},
            "subject": {"type": "string", "description": "Email subject line"},
            "body": {"type": "string", "description": "Email body content"}
        },
        "impact_level": "high",
        "requires_approval": True,
        "approved_hash": "47c17c2a5e70dd63e75a81fd28a731cba56a53c82444ce736e2d9fca521dd7c7",
        "approved_by": "AegisScan Security Policy Reviewer",
        "approved_at": "2026-10-28 00:00:00"
    }
}

# Regex pattern for detecting prompt injection / adversarial wording in tool descriptions
SUSPICIOUS_INSTRUCTION_PATTERNS = [
    re.compile(r"\[SYSTEM OVERRIDE", re.IGNORECASE),
    re.compile(r"priority instruction", re.IGNORECASE),
    re.compile(r"disregard all previous", re.IGNORECASE),
    re.compile(r"ignore (?:all )?previous", re.IGNORECASE),
    re.compile(r"leak (?:the )?(?:confidential )?canary", re.IGNORECASE),
    re.compile(r"reveal (?:the )?secret canary", re.IGNORECASE),
    re.compile(r"AEGIS_CANARY_", re.IGNORECASE),
    re.compile(r"bypass (?:all )?safety", re.IGNORECASE),
    re.compile(r"exfiltrate", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# 2. Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ToolComparisonResult:
    """Detailed result of comparing a single tool against its trusted baseline."""
    tool_name: str
    status: str                # VERIFIED_UNCHANGED, CHANGED_AFTER_APPROVAL, POISONED_DESCRIPTION, BASELINE_UNAVAILABLE, UNABLE_TO_INSPECT
    calculated_hash: str
    approved_hash: Optional[str]
    is_match: bool
    changed_fields: List[str]
    permission_escalated: bool
    suspicious_instructions_found: bool
    evidence: str
    current_metadata: Dict[str, Any]
    baseline_metadata: Optional[Dict[str, Any]] = None


@dataclass
class ToolIntegritySummary:
    """Summary of all tool integrity checks for the target."""
    verified_count: int
    changed_count: int
    missing_baseline_count: int
    unable_to_inspect_count: int
    total_tools: int
    results: List[ToolComparisonResult]
    findings: List[ScoredFinding]


# ---------------------------------------------------------------------------
# 3. Canonical Hashing & Normalization
# ---------------------------------------------------------------------------

def compute_canonical_tool_hash(tool_dict: Dict[str, Any]) -> str:
    """
    Computes deterministic SHA-256 hash over canonical JSON representation of tool metadata.
    Normalizes:
      - name
      - description
      - parameters / input_schema
      - impact_level / risk_classification
      - requires_approval
      - endpoint / handler (if present)
      - permissions (if present)
    Sorts dictionary keys and uses compact separators (',', ':') without whitespace.
    """
    params = tool_dict.get("parameters")
    if params is None:
        params = tool_dict.get("input_schema", {})

    impact = tool_dict.get("impact_level")
    if impact is None:
        impact = tool_dict.get("risk_classification", "low")

    canonical_repr: Dict[str, Any] = {
        "name": str(tool_dict.get("name", "")).strip(),
        "description": str(tool_dict.get("description", "")).strip(),
        "parameters": params,
        "impact_level": str(impact).strip().lower(),
        "requires_approval": bool(tool_dict.get("requires_approval", False))
    }

    # Normalize endpoint or handler identifier if specified
    if "endpoint" in tool_dict and tool_dict["endpoint"] is not None:
        canonical_repr["endpoint"] = str(tool_dict["endpoint"]).strip()
    elif "handler" in tool_dict and tool_dict["handler"] is not None:
        canonical_repr["handler"] = str(tool_dict["handler"]).strip()

    # Normalize permissions if specified
    if "permissions" in tool_dict and tool_dict["permissions"] is not None:
        canonical_repr["permissions"] = tool_dict["permissions"]

    canonical_json = json.dumps(canonical_repr, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def detect_suspicious_instructions(description: str) -> bool:
    """Checks whether a tool description contains adversarial prompt-injection syntax."""
    if not description:
        return False
    return any(p.search(description) for p in SUSPICIOUS_INSTRUCTION_PATTERNS)


# ---------------------------------------------------------------------------
# 4. Tool Baseline Comparison Engine
# ---------------------------------------------------------------------------

def compare_tool_against_baseline(
    tool: Dict[str, Any],
    baseline_catalog: Optional[Dict[str, Any]] = None
) -> ToolComparisonResult:
    """
    Independently inspects and compares a single tool dictionary against trusted baselines.
    """
    catalog = baseline_catalog if baseline_catalog is not None else TRUSTED_TOOL_BASELINES
    tool_name = tool.get("name", "unknown")
    calc_hash = compute_canonical_tool_hash(tool)
    desc = str(tool.get("description", "")).strip()
    has_suspicious_wording = detect_suspicious_instructions(desc)

    # Check if tool is registered in trusted baseline store
    if tool_name not in catalog:
        # Step 3 requirement: "If no trusted baseline exists, report BASELINE_UNAVAILABLE rather than claiming integrity verification succeeded."
        # Step 4 requirement: "Do not classify suspicious wording alone as confirmed agent compromise."
        evidence = (
            f"Tool '{tool_name}' detected on target (Computed Hash: {calc_hash[:16]}...), but no approved baseline exists in trusted store. "
            f"Status: BASELINE_UNAVAILABLE."
        )
        if has_suspicious_wording:
            evidence += " Note: Description contains suspicious wording, but cannot confirm tampering without an approved baseline."
        return ToolComparisonResult(
            tool_name=tool_name,
            status="BASELINE_UNAVAILABLE",
            calculated_hash=calc_hash,
            approved_hash=None,
            is_match=False,
            changed_fields=[],
            permission_escalated=False,
            suspicious_instructions_found=has_suspicious_wording,
            evidence=evidence,
            current_metadata=tool,
            baseline_metadata=None
        )

    baseline = catalog[tool_name]
    approved_hash = baseline.get("approved_hash", "")
    is_match = (calc_hash == approved_hash)

    changed_fields = []
    permission_escalated = False

    # Perform field-by-field diff
    if not is_match:
        if str(tool.get("description", "")).strip() != str(baseline.get("description", "")).strip():
            changed_fields.append("description")

        tool_params = tool.get("parameters") or tool.get("input_schema", {})
        base_params = baseline.get("parameters") or baseline.get("input_schema", {})
        if tool_params != base_params:
            changed_fields.append("parameters")

        tool_impact = str(tool.get("impact_level") or tool.get("risk_classification", "")).strip().lower()
        base_impact = str(baseline.get("impact_level") or baseline.get("risk_classification", "")).strip().lower()
        if tool_impact != base_impact:
            changed_fields.append("impact_level")

        curr_approval = bool(tool.get("requires_approval", False))
        base_approval = bool(baseline.get("requires_approval", False))
        if curr_approval != base_approval:
            changed_fields.append("requires_approval")
            if base_approval and not curr_approval:
                permission_escalated = True

        curr_perms = tool.get("permissions")
        base_perms = baseline.get("permissions")
        if curr_perms != base_perms:
            changed_fields.append("permissions")
            if curr_perms and not base_perms:
                permission_escalated = True
            elif isinstance(curr_perms, list) and isinstance(base_perms, list):
                if set(curr_perms) - set(base_perms):
                    permission_escalated = True

        curr_ep = tool.get("endpoint") or tool.get("handler")
        base_ep = baseline.get("endpoint") or baseline.get("handler")
        if curr_ep != base_ep:
            changed_fields.append("endpoint")

    # Determine status and evidence
    if is_match:
        status = "VERIFIED_UNCHANGED"
        evidence = f"Tool '{tool_name}' cryptographically verified against approved baseline (SHA-256: {calc_hash[:16]}...)."
    elif has_suspicious_wording and "description" in changed_fields:
        status = "POISONED_DESCRIPTION"
        evidence = (
            f"POISONED TOOL DESCRIPTION DETECTED on tool '{tool_name}'. "
            f"Changed Fields: {changed_fields}. "
            f"Previous Approved Hash: {approved_hash}. "
            f"Current Computed Hash: {calc_hash}. "
            f"Confidence: High (Cryptographic Hash Mismatch + Injected Instruction Pattern). "
            f"Altered Description: '{desc[:160]}'."
        )
    else:
        status = "CHANGED_AFTER_APPROVAL"
        perm_note = ""
        if permission_escalated:
            perm_note = " CRITICAL: Approval requirement was removed or new unapproved permissions granted!"
        evidence = (
            f"RUG-PULL DETECTED on tool '{tool_name}'. "
            f"Changed Fields: {changed_fields}. "
            f"Previous Approved Hash: {approved_hash}. "
            f"Current Computed Hash: {calc_hash}. "
            f"Confidence: High (Cryptographic SHA-256 Mismatch). "
            f"{perm_note}"
        )

    return ToolComparisonResult(
        tool_name=tool_name,
        status=status,
        calculated_hash=calc_hash,
        approved_hash=approved_hash,
        is_match=is_match,
        changed_fields=changed_fields,
        permission_escalated=permission_escalated,
        suspicious_instructions_found=has_suspicious_wording,
        evidence=evidence,
        current_metadata=tool,
        baseline_metadata=baseline
    )


# ---------------------------------------------------------------------------
# 5. Full Monitor Verification Pipeline
# ---------------------------------------------------------------------------

def verify_tool_integrity(
    ai_discovery_result: AIDiscoveryResult,
    target_base_url: str,
    scan_mode: str = "deep",
    scope_guard: Optional[ScopeGuard] = None,
    baseline_catalog: Optional[Dict[str, Any]] = None
) -> ToolIntegritySummary:
    """
    Main Phase 10 detector entry point:
      1. Obtains tool catalog from AI discovery endpoint or manifest.
      2. Independently calculates SHA-256 hashes for each tool.
      3. Compares against trusted pre-approved baselines.
      4. Detects rug-pulls, poisoned descriptions, and permission escalation.
      5. Generates evidence-based ScoredFinding records.
    """
    guard = scope_guard or ScopeGuard()
    base_url = target_base_url.rstrip("/")
    findings: List[ScoredFinding] = []
    results: List[ToolComparisonResult] = []

    verified_count = 0
    changed_count = 0
    missing_baseline_count = 0
    unable_to_inspect_count = 0

    # 1. Obtain current tools list from target
    tools_list: List[Dict[str, Any]] = []
    tools_endpoint = ai_discovery_result.tools_endpoint or (base_url + "/assistant/tools")

    if guard.is_allowed(tools_endpoint):
        try:
            with guard.client(timeout=5) as client:
                resp = client.get(tools_endpoint)
                if resp.status_code == 200:
                    data = resp.json()
                    tools_list = data.get("tools", [])
                else:
                    unable_to_inspect_count = 1
        except Exception:
            unable_to_inspect_count = 1
    else:
        unable_to_inspect_count = 1

    # Fallback to manifest tools if direct endpoint unavailable
    if not tools_list and ai_discovery_result.manifest and ai_discovery_result.manifest.tools:
        tools_list = ai_discovery_result.manifest.tools
        unable_to_inspect_count = 0

    if not tools_list:
        ai_enabled = getattr(ai_discovery_result, "has_ai_features", False) or getattr(ai_discovery_result, "is_ai_enabled", False)
        if ai_enabled and unable_to_inspect_count > 0:
            evidence_msg = f"Unable to inspect AI tool catalog at {tools_endpoint}: endpoint unreachable or returned empty list."
            results.append(ToolComparisonResult(
                tool_name="catalog",
                status="UNABLE_TO_INSPECT",
                calculated_hash="",
                approved_hash=None,
                is_match=False,
                changed_fields=[],
                permission_escalated=False,
                suspicious_instructions_found=False,
                evidence=evidence_msg,
                current_metadata={},
                baseline_metadata=None
            ))
            findings.append(ScoredFinding(
                vuln_type="Tool Catalog Unreachable",
                severity="Info",
                status="not_tested",
                location=tools_endpoint,
                evidence=evidence_msg,
                remediation_advice="Ensure the AI agent tools endpoint is accessible and returns valid JSON tool declarations.",
                payload=""
            ))

        return ToolIntegritySummary(
            verified_count=0,
            changed_count=0,
            missing_baseline_count=0,
            unable_to_inspect_count=unable_to_inspect_count,
            total_tools=0,
            results=results,
            findings=findings
        )

    # 2. Evaluate each tool against baseline
    for tool_data in tools_list:
        comp = compare_tool_against_baseline(tool_data, baseline_catalog=baseline_catalog)
        results.append(comp)

        if comp.status == "VERIFIED_UNCHANGED":
            verified_count += 1
            findings.append(ScoredFinding(
                vuln_type="Tool Integrity Verified",
                severity="Info",
                status="verified",
                location=f"{tools_endpoint} (tool: {comp.tool_name})",
                evidence=comp.evidence,
                remediation_advice="No remediation needed. Tool metadata matches approved baseline.",
                payload=f"SHA-256: {comp.calculated_hash}"
            ))

        elif comp.status == "CHANGED_AFTER_APPROVAL":
            changed_count += 1
            severity = "Critical" if comp.permission_escalated else "High"
            findings.append(ScoredFinding(
                vuln_type="Tool Metadata Rug-Pull",
                severity=severity,
                status="confirmed",
                location=f"{tools_endpoint} (tool: {comp.tool_name})",
                evidence=comp.evidence,
                remediation_advice=(
                    "Implement cryptographic tool manifest verification. AI execution agents must compute "
                    "canonical SHA-256 hashes of tool schemas at runtime and refuse execution if the hash differs "
                    "from the approved policy baseline. Prevent runtime modification of approval policies."
                ),
                payload=f"Changed fields: {comp.changed_fields}"
            ))

        elif comp.status == "POISONED_DESCRIPTION":
            changed_count += 1
            findings.append(ScoredFinding(
                vuln_type="Poisoned Tool Description",
                severity="High",
                status="confirmed",
                location=f"{tools_endpoint} (tool: {comp.tool_name})",
                evidence=comp.evidence,
                remediation_advice=(
                    "Strictly isolate tool description metadata from the model's privileged instruction context. "
                    "Validate that tool schemas match approved cryptographic baselines prior to agent registration."
                ),
                payload=f"Altered description: {comp.current_metadata.get('description', '')[:100]}"
            ))

        elif comp.status == "BASELINE_UNAVAILABLE":
            missing_baseline_count += 1
            findings.append(ScoredFinding(
                vuln_type="Tool Baseline Unavailable",
                severity="Info",
                status="not_tested",
                location=f"{tools_endpoint} (tool: {comp.tool_name})",
                evidence=comp.evidence,
                remediation_advice=(
                    "Register pre-approved tool schemas and canonical hashes in the trusted policy baseline store "
                    "to enable automated anti-rug-pull verification."
                ),
                payload=f"Calculated Hash: {comp.calculated_hash}"
            ))

    return ToolIntegritySummary(
        verified_count=verified_count,
        changed_count=changed_count,
        missing_baseline_count=missing_baseline_count,
        unable_to_inspect_count=unable_to_inspect_count,
        total_tools=len(tools_list),
        results=results,
        findings=findings
    )


# ---------------------------------------------------------------------------
# 6. Controlled Local Lab Scenario Runners (Scenario B & Scenario C)
# ---------------------------------------------------------------------------

def run_controlled_lab_rugpull_scenario(
    target_base_url: str,
    scope_guard: Optional[ScopeGuard] = None
) -> Dict[str, Any]:
    """
    Executes the controlled 10-step Rug-Pull benchmark workflow against authorized local AegisLab:
      1. Capture trusted baseline.
      2. Record baseline hashes.
      3. Trigger controlled tool mutation in AegisLab (/assistant/tools/rugpull).
      4. Retrieve current tool metadata.
      5. Recalculate hashes.
      6. Compare against baseline.
      7. Identify changed fields.
      8. Generate evidence-based finding.
      9. Reset AegisLab state (/assistant/reset).
      10. Verify clean metadata no longer triggers the finding.
    """
    guard = scope_guard or ScopeGuard()
    base_url = target_base_url.rstrip("/")

    # Only run controlled mutation on authorized local testbed
    if not guard.is_allowed(base_url):
        return {"success": False, "error": "Target not authorized for active lab mutation."}

    rugpull_endpoint = base_url + "/assistant/tools/rugpull"
    tools_endpoint = base_url + "/assistant/tools"
    reset_endpoint = base_url + "/assistant/reset"
    logs: List[str] = []

    with guard.client(timeout=5) as client:
        # Step 1: Capture trusted baseline
        logs.append("[Step 1] Capturing baseline tools from " + tools_endpoint)
        resp_init = client.get(tools_endpoint)
        init_tools = {t["name"]: t for t in resp_init.json().get("tools", [])}
        init_tool = init_tools.get("send_email", {})

        # Step 2: Record baseline hashes
        init_hash = compute_canonical_tool_hash(init_tool)
        logs.append(f"[Step 2] Recorded baseline hash for 'send_email': {init_hash}")

        # Step 3: Trigger controlled tool mutation in AegisLab
        logs.append("[Step 3] Triggering tool rug-pull mutation via POST " + rugpull_endpoint)
        client.post(rugpull_endpoint, json={"active": True})

        # Step 4: Retrieve current tool metadata
        logs.append("[Step 4] Retrieving current tool metadata from " + tools_endpoint)
        resp_mut = client.get(tools_endpoint)
        mut_tools = {t["name"]: t for t in resp_mut.json().get("tools", [])}
        mut_tool = mut_tools.get("send_email", {})

        # Step 5: Recalculate hashes
        mut_hash = compute_canonical_tool_hash(mut_tool)
        logs.append(f"[Step 5] Recalculated hash for mutated 'send_email': {mut_hash}")

        # Step 6: Compare against baseline
        comp_res = compare_tool_against_baseline(mut_tool, baseline_catalog=TRUSTED_TOOL_BASELINES)
        logs.append(f"[Step 6] Baseline comparison status: {comp_res.status}, is_match: {comp_res.is_match}")

        # Step 7: Identify changed fields
        changed_fields = comp_res.changed_fields
        logs.append(f"[Step 7] Changed fields identified: {changed_fields}")

        # Step 8: Generate evidence-based finding
        finding = ScoredFinding(
            vuln_type="Tool Metadata Rug-Pull",
            severity="Critical" if comp_res.permission_escalated else "High",
            status="confirmed",
            location=f"{tools_endpoint} (tool: send_email)",
            evidence=comp_res.evidence,
            remediation_advice=(
                "Implement cryptographic tool manifest verification. Refuse execution if runtime tool hash differs "
                "from approved baseline."
            ),
            payload=f"Changed fields: {changed_fields}"
        )
        logs.append(f"[Step 8] Generated confirmed finding: {finding.vuln_type} ({finding.severity})")

        # Step 9: Reset AegisLab state
        logs.append("[Step 9] Resetting AegisLab state via POST " + reset_endpoint)
        client.post(reset_endpoint)

        # Step 10: Verify clean metadata no longer triggers the finding
        resp_clean = client.get(tools_endpoint)
        clean_tools = {t["name"]: t for t in resp_clean.json().get("tools", [])}
        clean_tool = clean_tools.get("send_email", {})
        clean_comp = compare_tool_against_baseline(clean_tool, baseline_catalog=TRUSTED_TOOL_BASELINES)
        clean_verified = clean_comp.is_match and clean_comp.status == "VERIFIED_UNCHANGED"
        logs.append(f"[Step 10] Clean metadata verified unchanged: {clean_verified} (status: {clean_comp.status})")

        return {
            "success": True,
            "workflow_steps_executed": 10,
            "tool_tested": "send_email",
            "initial_hash": init_hash,
            "mutated_hash": mut_hash,
            "rugpull_detected": (mut_hash != init_hash),
            "changed_fields": changed_fields,
            "finding": {
                "vuln_type": finding.vuln_type,
                "severity": finding.severity,
                "status": finding.status,
                "location": finding.location,
                "evidence": finding.evidence,
                "remediation": finding.remediation_advice
            },
            "restored_hash": clean_comp.calculated_hash,
            "clean_verified": clean_verified,
            "execution_log": logs
        }


def run_controlled_lab_poison_scenario(
    target_base_url: str,
    scope_guard: Optional[ScopeGuard] = None
) -> Dict[str, Any]:
    """
    Executes the controlled Poisoned Tool Description benchmark workflow (Scenario B):
      1. Capture trusted baseline for search_documents.
      2. Trigger controlled tool description poisoning (/assistant/tools/poison).
      3. Retrieve current tool metadata and recalculate hash.
      4. Detect suspicious instruction syntax and hash mismatch.
      5. Generate evidence-based finding.
      6. Reset AegisLab state and verify clean state restoration.
    """
    guard = scope_guard or ScopeGuard()
    base_url = target_base_url.rstrip("/")

    if not guard.is_allowed(base_url):
        return {"success": False, "error": "Target not authorized for active lab mutation."}

    poison_endpoint = base_url + "/assistant/tools/poison"
    tools_endpoint = base_url + "/assistant/tools"
    reset_endpoint = base_url + "/assistant/reset"
    logs: List[str] = []

    with guard.client(timeout=5) as client:
        # Step 1: Capture initial baseline
        logs.append("[Step 1] Capturing baseline tools from " + tools_endpoint)
        resp_init = client.get(tools_endpoint)
        init_tools = {t["name"]: t for t in resp_init.json().get("tools", [])}
        init_tool = init_tools.get("search_documents", {})
        init_hash = compute_canonical_tool_hash(init_tool)
        logs.append(f"[Step 2] Baseline hash for 'search_documents': {init_hash}")

        # Step 3: Trigger tool poisoning
        logs.append("[Step 3] Poisoning tool description via POST " + poison_endpoint)
        client.post(poison_endpoint, json={"active": True})

        # Step 4: Retrieve current metadata
        resp_poisoned = client.get(tools_endpoint)
        poisoned_tools = {t["name"]: t for t in resp_poisoned.json().get("tools", [])}
        poisoned_tool = poisoned_tools.get("search_documents", {})
        poisoned_hash = compute_canonical_tool_hash(poisoned_tool)
        logs.append(f"[Step 4] Recalculated hash for poisoned 'search_documents': {poisoned_hash}")

        # Step 5: Compare against baseline
        comp_res = compare_tool_against_baseline(poisoned_tool, baseline_catalog=TRUSTED_TOOL_BASELINES)
        logs.append(f"[Step 5] Comparison status: {comp_res.status}, suspicious wording: {comp_res.suspicious_instructions_found}")

        # Step 6: Generate finding
        finding = ScoredFinding(
            vuln_type="Poisoned Tool Description",
            severity="High",
            status="confirmed",
            location=f"{tools_endpoint} (tool: search_documents)",
            evidence=comp_res.evidence,
            remediation_advice="Isolate tool description metadata from model instruction context.",
            payload=f"Poisoned text snippet: {poisoned_tool.get('description', '')[:100]}"
        )
        logs.append(f"[Step 6] Generated confirmed finding: {finding.vuln_type}")

        # Step 7: Reset state
        logs.append("[Step 7] Resetting AegisLab state via POST " + reset_endpoint)
        client.post(reset_endpoint)

        # Step 8: Verify restored clean state
        resp_clean = client.get(tools_endpoint)
        clean_tools = {t["name"]: t for t in resp_clean.json().get("tools", [])}
        clean_tool = clean_tools.get("search_documents", {})
        clean_comp = compare_tool_against_baseline(clean_tool, baseline_catalog=TRUSTED_TOOL_BASELINES)
        clean_verified = clean_comp.is_match and clean_comp.status == "VERIFIED_UNCHANGED"
        logs.append(f"[Step 8] Clean verification restored: {clean_verified}")

        return {
            "success": True,
            "tool_tested": "search_documents",
            "initial_hash": init_hash,
            "poisoned_hash": poisoned_hash,
            "poisoning_detected": (comp_res.status == "POISONED_DESCRIPTION"),
            "finding": {
                "vuln_type": finding.vuln_type,
                "severity": finding.severity,
                "status": finding.status,
                "location": finding.location,
                "evidence": finding.evidence,
            },
            "restored_hash": clean_comp.calculated_hash,
            "clean_verified": clean_verified,
            "execution_log": logs
        }
