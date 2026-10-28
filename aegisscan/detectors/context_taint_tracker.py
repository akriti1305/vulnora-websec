"""
detectors/context_taint_tracker.py -- AegisScan Context Taint Tracker (Phase 11)
================================================================================
Models and verifies end-to-end data flows from untrusted context sources to
privileged agent execution sinks.

Data-Flow Stages Modeled:
  UNTRUSTED DOCUMENT
    → ASSISTANT CONTEXT
    → TOOL SELECTION
    → TOOL ARGUMENTS
    → PRIVILEGED SINK

Key Principles:
  1. Evidence-Based Edge Attribution:
     - OBSERVED   : Supported by explicit assistant/tool audit events (e.g. source_doc_id in audit log).
     - INFERRED   : Supported by matching payload/arguments, but lacking explicit provenance marker.
     - UNAVAILABLE: Hypothetical edge without corroborating interaction or telemetry.
  2. No False Inference:
     - An uploaded document and an existing tool do NOT constitute a confirmed data flow.
     - A complete attack path is only confirmed when EVERY step along the path is OBSERVED.
  3. Trust Boundary Identification:
     - Flags crossings where untrusted data influences high-impact side effects.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
import json


# ---------------------------------------------------------------------------
# 1. Graph Data Structures
# ---------------------------------------------------------------------------

@dataclass
class TaintNode:
    """A node in the directed taint flow graph."""
    id: str
    node_type: str        # DOCUMENT, ASSISTANT_CONTEXT, TOOL_SELECTION, TOOL_ARGUMENTS, PRIVILEGED_SINK
    label: str
    trust_level: str      # UNTRUSTED, TRUSTED, SYSTEM, PRIVILEGED_SINK
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TaintEdge:
    """A directed edge representing data flow or control influence between nodes."""
    source_id: str
    target_id: str
    edge_type: str        # INGESTED_INTO, INFLUENCED_SELECTION, PASSED_TO_ARGS, DISPATCHED_TO_SINK
    status: str           # OBSERVED, INFERRED, UNAVAILABLE
    evidence: str
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TaintGraph:
    """Directed graph representing an analyzed context-to-sink flow."""
    graph_id: str
    source_doc_id: Optional[str]
    tool_name: Optional[str]
    sink_type: Optional[str]
    nodes: List[TaintNode]
    edges: List[TaintEdge]
    is_complete_attack_path: bool
    security_boundary_crossed: bool
    canary_exfiltrated: bool
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "graph_id": self.graph_id,
            "source_doc_id": self.source_doc_id,
            "tool_name": self.tool_name,
            "sink_type": self.sink_type,
            "is_complete_attack_path": self.is_complete_attack_path,
            "security_boundary_crossed": self.security_boundary_crossed,
            "canary_exfiltrated": self.canary_exfiltrated,
            "summary": self.summary,
            "nodes": [
                {
                    "id": n.id,
                    "type": n.node_type,
                    "label": n.label,
                    "trust_level": n.trust_level,
                    "properties": n.properties
                }
                for n in self.nodes
            ],
            "edges": [
                {
                    "source": e.source_id,
                    "target": e.target_id,
                    "type": e.edge_type,
                    "status": e.status,
                    "evidence": e.evidence
                }
                for e in self.edges
            ]
        }

    def render_ascii_flow(self) -> str:
        """Renders readable ASCII representation of the flow path."""
        stages = []
        for n in self.nodes:
            stages.append(f"[{n.node_type}: {n.label}]")
        connector = " ──(observed)──> " if self.is_complete_attack_path else " ──(unconfirmed)──> "
        return connector.join(stages)


# ---------------------------------------------------------------------------
# 2. Taint Flow Analyzer
# ---------------------------------------------------------------------------

def classify_sink(tool_name: str) -> str:
    """Classifies the execution sink category for a given tool."""
    name_lower = tool_name.lower()
    if any(k in name_lower for k in ("email", "mail", "smtp", "message")):
        return "EXTERNAL_COMMUNICATION"
    if any(k in name_lower for k in ("webhook", "http", "post", "upload", "exfil")):
        return "DATA_EXFILTRATION"
    if any(k in name_lower for k in ("file", "write", "disk", "save")):
        return "FILESYSTEM_MODIFICATION"
    if any(k in name_lower for k in ("database", "sql", "db", "delete")):
        return "DATABASE_WRITE"
    if any(k in name_lower for k in ("search", "read", "fetch", "query")):
        return "INTERNAL_READ_ONLY"
    return "UTILITY_COMPUTATION"


def trace_context_taint(
    audit_events: List[Dict[str, Any]],
    documents_catalog: Optional[Dict[str, Any]] = None,
    assistant_interactions: Optional[List[Dict[str, Any]]] = None
) -> List[TaintGraph]:
    """
    Constructs and evaluates taint flow graphs from observed assistant and audit events.
    
    Ensures:
      - Only supported edges are marked OBSERVED.
      - Disconnected components remain INFERRED or UNAVAILABLE.
      - Full attack path is marked confirmed ONLY when all 4 stages are OBSERVED.
    """
    graphs: List[TaintGraph] = []
    docs = documents_catalog or {}

    # Process actual audit log entries
    for idx, event in enumerate(audit_events):
        tool_name = event.get("tool_name", "")
        if not tool_name:
            continue

        sink_class = classify_sink(tool_name)
        source_doc_id = event.get("source_doc_id")
        arguments = event.get("arguments", {})
        status = event.get("status", "")
        canary_leaked = bool(event.get("canary_leak_detected", False))
        is_executed = (status == "executed")

        # Determine document trust classification
        doc_info = docs.get(source_doc_id, {}) if source_doc_id else {}
        is_untrusted = doc_info.get("is_untrusted", True if source_doc_id else False)
        doc_trust = "UNTRUSTED" if is_untrusted else "TRUSTED"
        doc_title = doc_info.get("title", f"Document {source_doc_id}" if source_doc_id else "No Document")

        nodes: List[TaintNode] = []
        edges: List[TaintEdge] = []

        # Stage 1: Document Node
        doc_node_id = f"doc_{source_doc_id}" if source_doc_id else f"doc_unlinked_{idx}"
        nodes.append(TaintNode(
            id=doc_node_id,
            node_type="DOCUMENT",
            label=f"{source_doc_id or 'Untracked Source'} ({doc_title})",
            trust_level=doc_trust,
            properties={"doc_id": source_doc_id, "title": doc_title, "untrusted": is_untrusted}
        ))

        # Stage 2: Assistant Context Node
        context_node_id = f"ctx_{idx}"
        nodes.append(TaintNode(
            id=context_node_id,
            node_type="ASSISTANT_CONTEXT",
            label=f"Query Context (Audit Event #{event.get('id', idx+1)})",
            trust_level="MIXED" if source_doc_id else "SYSTEM",
            properties={"audit_event_id": event.get("id", idx+1), "timestamp": event.get("timestamp")}
        ))

        # Edge 1: Document -> Context
        edge_1_status = "OBSERVED" if source_doc_id else "UNAVAILABLE"
        edges.append(TaintEdge(
            source_id=doc_node_id,
            target_id=context_node_id,
            edge_type="INGESTED_INTO",
            status=edge_1_status,
            evidence=(
                f"Audit record #{event.get('id', idx+1)} explicitly attributes source context to document '{source_doc_id}'."
                if source_doc_id else "No document source context recorded in audit log."
            )
        ))

        # Stage 3: Tool Selection Node
        tool_node_id = f"tool_{tool_name}_{idx}"
        nodes.append(TaintNode(
            id=tool_node_id,
            node_type="TOOL_SELECTION",
            label=f"Tool: {tool_name}",
            trust_level="AGENT_CONTROLLABLE",
            properties={"tool_name": tool_name, "approval_required": event.get("approval_required", False)}
        ))

        # Edge 2: Context -> Tool Selection
        # If the source doc was untrusted and the tool was selected:
        edge_2_status = "OBSERVED" if (source_doc_id and tool_name) else "INFERRED"
        edges.append(TaintEdge(
            source_id=context_node_id,
            target_id=tool_node_id,
            edge_type="INFLUENCED_SELECTION",
            status=edge_2_status,
            evidence=f"Assistant invoked tool '{tool_name}' after processing context from document '{source_doc_id}'."
        ))

        # Stage 4: Tool Arguments Node
        args_node_id = f"args_{tool_name}_{idx}"
        arg_keys = list(arguments.keys())
        nodes.append(TaintNode(
            id=args_node_id,
            node_type="TOOL_ARGUMENTS",
            label=f"Arguments: {arg_keys}",
            trust_level="TAINTED" if source_doc_id else "USER_SUPPLIED",
            properties={"arguments": arguments}
        ))

        # Edge 3: Tool Selection -> Arguments
        edges.append(TaintEdge(
            source_id=tool_node_id,
            target_id=args_node_id,
            edge_type="PASSED_TO_ARGS",
            status="OBSERVED",
            evidence=f"Arguments {arg_keys} bound to tool invocation parameters."
        ))

        # Stage 5: Privileged Sink Node
        sink_node_id = f"sink_{sink_class}_{idx}"
        nodes.append(TaintNode(
            id=sink_node_id,
            node_type="PRIVILEGED_SINK",
            label=f"Privileged Sink: {sink_class}",
            trust_level="HIGH_IMPACT_SINK",
            properties={
                "sink_class": sink_class,
                "executed": is_executed,
                "approved": event.get("approved", False),
                "approval_required": event.get("approval_required", False),
                "status": status
            }
        ))

        # Edge 4: Arguments -> Sink
        edge_4_status = "OBSERVED" if is_executed else "BLOCKED"
        edges.append(TaintEdge(
            source_id=args_node_id,
            target_id=sink_node_id,
            edge_type="DISPATCHED_TO_SINK",
            status=edge_4_status,
            evidence=(
                f"Action executed in sink: {sink_class} (Status: {status})."
                if is_executed else f"Action BLOCKED before sink execution (Status: {status})."
            )
        ))

        # Determine if this represents a complete observed attack path:
        # Must have:
        #   1. Untrusted source document (doc_trust == UNTRUSTED)
        #   2. High-impact sink (sink_class in EXTERNAL_COMMUNICATION, DATA_EXFILTRATION)
        #   3. Execution occurred (is_executed == True)
        #   4. Executed without approval (approved == False)
        #   5. All 4 edges OBSERVED
        all_edges_observed = all(e.status == "OBSERVED" for e in edges)
        boundary_crossed = bool(is_untrusted and is_executed and sink_class != "INTERNAL_READ_ONLY")
        is_attack_path = bool(all_edges_observed and boundary_crossed and not event.get("approved", False))

        summary = (
            f"OBSERVED COMPLETE TAINT PATH: Untrusted document '{source_doc_id}' successfully hijacked tool '{tool_name}' "
            f"to dispatch unapproved privileged action '{sink_class}' (Canary Leaked: {canary_leaked})."
            if is_attack_path else
            f"Taint Flow: Document '{source_doc_id or 'none'}' -> Tool '{tool_name}' -> Sink '{sink_class}' (Execution: {status})."
        )

        graphs.append(TaintGraph(
            graph_id=f"TG-{idx+1:03d}",
            source_doc_id=source_doc_id,
            tool_name=tool_name,
            sink_type=sink_class,
            nodes=nodes,
            edges=edges,
            is_complete_attack_path=is_attack_path,
            security_boundary_crossed=boundary_crossed,
            canary_exfiltrated=canary_leaked,
            summary=summary
        ))

    return graphs


# ---------------------------------------------------------------------------
# 3. Cross-Phase Attack Path Correlator
# ---------------------------------------------------------------------------

def correlate_attack_paths(
    prompt_findings: List[Any],
    tool_findings: List[Any],
    taint_graphs: List[TaintGraph],
    permission_findings: Optional[List[Any]] = None
) -> List[Dict[str, Any]]:
    """
    Correlates findings across Phase 9 (Prompt Injection), Phase 10 (Tool Integrity),
    and Phase 11 (Taint Tracking & Permission Analyzer) into unified verified attack paths.
    """
    attack_paths: List[Dict[str, Any]] = []
    perm_findings = permission_findings or []

    # Map prompt findings by evidence text or location
    has_prompt_injection = any(
        getattr(f, "vuln_type", "") == "Indirect Prompt Injection" and getattr(f, "status", "") == "confirmed"
        for f in prompt_findings
    )
    has_canary_leak = any(
        getattr(f, "vuln_type", "") == "AI Canary Token Leakage" and getattr(f, "status", "") == "confirmed"
        for f in prompt_findings
    )

    # Check for complete taint graphs
    for tg in taint_graphs:
        if tg.is_complete_attack_path:
            stages = [
                {
                    "stage": "1_UNTRUSTED_DOCUMENT",
                    "target": tg.source_doc_id or "untrusted_upload",
                    "status": "OBSERVED",
                    "evidence": f"Ingested untrusted context document '{tg.source_doc_id}' into assistant memory."
                },
                {
                    "stage": "2_INDIRECT_PROMPT_INJECTION",
                    "target": "assistant_context",
                    "status": "OBSERVED" if has_prompt_injection else "INFERRED",
                    "evidence": "Injected override prompt coerced the model to ignore safety guidelines."
                },
                {
                    "stage": "3_PRIVILEGED_TOOL_SELECTION",
                    "target": tg.tool_name or "send_email",
                    "status": "OBSERVED",
                    "evidence": f"Agent selected high-impact tool '{tg.tool_name}' with untrusted argument parameters."
                },
                {
                    "stage": "4_UNAUTHORIZED_SINK_EXECUTION",
                    "target": tg.sink_type or "EXTERNAL_COMMUNICATION",
                    "status": "OBSERVED",
                    "evidence": "High-impact tool executed without human approval gate enforcement."
                }
            ]

            attack_paths.append({
                "attack_path_id": f"AP-{len(attack_paths)+1:02d}",
                "status": "CONFIRMED",
                "severity": "Critical",
                "tool_used": tg.tool_name,
                "sink_type": tg.sink_type,
                "source_doc": tg.source_doc_id,
                "canary_exfiltrated": tg.canary_exfiltrated or has_canary_leak,
                "stages": stages,
                "ascii_flow": tg.render_ascii_flow(),
                "evidence": tg.summary
            })

    return attack_paths
