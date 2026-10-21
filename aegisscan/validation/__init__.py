"""
validation/__init__.py -- AegisScan Validation Engine (Phase 5)
===============================================================
Validates findings from detectors using a CONTROL REQUEST approach.

The problem with naive replay validation:
  Replaying the same payload only proves the result is reproducible.
  It does NOT prove the payload caused it. A page that always shows a
  SQL error (even for normal inputs) would be wrongly marked "confirmed".

The fix -- two requests per finding:
  1. PAYLOAD request : send the malicious payload (same as detector used)
  2. CONTROL request : send a harmless value ("testvalue123") in the same field

  Mark "confirmed" only if:
    - The signal (SQL error, XSS reflection, login success) IS present
      in the payload response, AND
    - The signal is NOT present in the control response.

  If the signal appears in BOTH, the page shows that behaviour regardless
  of input -- mark "not_reproducible" and explain why.

Detectors that do NOT need validation (finding is self-evident):
  - IDOR: data either comes back or it does not.
  - Missing headers: header is either there or not.
  - Insecure cookies: flag is either there or not.
"""

import httpx
from dataclasses import dataclass
from typing import List

from scope import ScopeGuard, OutOfScopeError
from detectors.sqli_detector import (
    RawFinding as SqliRawFinding,
    LOGIN_SUCCESS_MARKERS,
    SQL_ERROR_MARKERS,
)
from detectors.xss_detector import (
    XssRawFinding,
    XSS_MARKER,
    _is_unescaped,
)

# ---------------------------------------------------------------------------
# Shared validated finding type
# ---------------------------------------------------------------------------

@dataclass
class ValidatedFinding:
    """
    A finding after the control-request validation step.

    raw               : original raw finding object (SQLi or XSS)
    status            : "confirmed" or "not_reproducible"
    confirmation_note : human-readable explanation of the decision
    """
    raw: object
    status: str
    confirmation_note: str


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_form_data(raw_finding, payload_value: str, control_value: str = "testvalue123") -> tuple:
    """
    Build two form data dicts from a raw finding:
      - payload_data  : injects payload_value into the target field
      - control_data  : injects control_value into the target field

    Returns (payload_data, control_data).
    """
    payload_data  = {}
    control_data  = {}
    for field in raw_finding.form.fields:
        if field.field_type == "submit":
            continue
        if field.name == raw_finding.field_name:
            payload_data[field.name] = payload_value
            control_data[field.name] = control_value
        else:
            payload_data[field.name] = control_value
            control_data[field.name] = control_value
    return payload_data, control_data


def _signal_in(text: str, trigger: str) -> bool:
    """
    Return True if the response text contains the expected SQLi signal.
    trigger is "bypass" or "error".
    """
    lower = text.lower()
    if trigger == "bypass":
        return any(m in lower for m in LOGIN_SUCCESS_MARKERS)
    elif trigger == "error":
        return any(m in lower for m in SQL_ERROR_MARKERS)
    return False


# ---------------------------------------------------------------------------
# SQLi Validator
# ---------------------------------------------------------------------------

def validate_sqli_findings(raw_findings: List[SqliRawFinding]) -> List[ValidatedFinding]:
    """
    Validate each SQLi raw finding using a control request.

    Logic:
      1. Send the malicious payload  → check for SQLi signal
      2. Send a harmless control     → check for the SAME signal
      Confirmed only if payload triggers signal AND control does NOT.
    """
    validated: List[ValidatedFinding] = []

    guard = ScopeGuard()
    with guard.client() as client:

        for raw in raw_findings:
            print(f"  [Validation/SQLi] Testing: {raw.form.action} field={raw.field_name}")

            payload_data, control_data = _build_form_data(raw, raw.payload)

            # -- Payload request --
            try:
                payload_resp = client.post(raw.form.action, data=payload_data)
            except OutOfScopeError as e:
                validated.append(ValidatedFinding(
                    raw=raw,
                    status="not_reproducible",
                    confirmation_note=f"Scope violation: {e}"
                ))
                continue
            except Exception as e:
                validated.append(ValidatedFinding(
                    raw=raw,
                    status="not_reproducible",
                    confirmation_note=f"Payload request failed: {e}"
                ))
                continue

            # -- Control request --
            try:
                control_resp = client.post(raw.form.action, data=control_data)
            except OutOfScopeError as e:
                validated.append(ValidatedFinding(
                    raw=raw,
                    status="not_reproducible",
                    confirmation_note=f"Scope violation on control: {e}"
                ))
                continue
            except Exception as e:
                # If the control request fails, we can't validate fairly
                validated.append(ValidatedFinding(
                    raw=raw,
                    status="not_reproducible",
                    confirmation_note=f"Control request failed: {e}"
                ))
                continue

            payload_signal = _signal_in(payload_resp.text, raw.trigger)
            control_signal = _signal_in(control_resp.text, raw.trigger)

            if payload_signal and not control_signal:
                # Classic confirmation: payload triggers signal, control does not
                status = "confirmed"
                note = (
                    f"CONFIRMED via control test. "
                    f"Payload '{raw.payload}' into '{raw.field_name}' "
                    f"produced a {raw.trigger} signal. "
                    f"Control value 'testvalue123' produced NO {raw.trigger} signal. "
                    f"The payload is the cause."
                )
                print("  [Validation/SQLi]   CONFIRMED (payload triggers, control does not).")

            elif payload_signal and control_signal:
                # Both trigger the same signal -- the page is noisy, not necessarily vulnerable
                status = "not_reproducible"
                note = (
                    f"NOT CONFIRMED. Both the payload AND the control value triggered "
                    f"a {raw.trigger} signal. This suggests the signal appears regardless "
                    f"of input (possible false positive from page content, not injection)."
                )
                print("  [Validation/SQLi]   NOT confirmed (control also triggered signal -- likely noise).")

            else:
                # Payload didn't even trigger the signal on retry
                status = "not_reproducible"
                note = (
                    f"NOT CONFIRMED. Payload '{raw.payload}' did not reproduce "
                    f"the {raw.trigger} signal on validation retry."
                )
                print("  [Validation/SQLi]   NOT confirmed (signal not reproduced).")

            validated.append(ValidatedFinding(
                raw=raw,
                status=status,
                confirmation_note=note,
            ))

    return validated


# ---------------------------------------------------------------------------
# XSS Validator
# ---------------------------------------------------------------------------

def validate_xss_findings(raw_findings: List[XssRawFinding]) -> List[ValidatedFinding]:
    """
    Validate each XSS raw finding using a control request.

    Logic:
      1. Send the XSS payload  → check for unescaped XSS_MARKER in response
      2. Send a harmless control ("testvalue123") → check for same marker
      Confirmed only if payload reflects marker AND control does NOT.
    """
    validated: List[ValidatedFinding] = []

    guard = ScopeGuard()
    with guard.client() as client:

        for raw in raw_findings:
            print(f"  [Validation/XSS] Testing: {raw.location}")

            # Build payload and control field data
            payload_field_data  = {}
            control_field_data  = {}
            for f in raw.form.fields:
                if f.field_type == "submit":
                    continue
                if f.name == raw.field_name:
                    payload_field_data[f.name]  = raw.payload
                    control_field_data[f.name]  = "testvalue123"
                else:
                    payload_field_data[f.name]  = "test"
                    control_field_data[f.name]  = "test"

            try:
                if raw.method == "POST":
                    payload_resp  = client.post(raw.form.action, data=payload_field_data)
                    control_resp  = client.get(raw.form.action, params=control_field_data) \
                                    if raw.form.method == "GET" \
                                    else client.post(raw.form.action, data=control_field_data)
                else:
                    payload_resp  = client.get(raw.form.action, params=payload_field_data)
                    control_resp  = client.get(raw.form.action, params=control_field_data)
            except OutOfScopeError as e:
                validated.append(ValidatedFinding(
                    raw=raw,
                    status="not_reproducible",
                    confirmation_note=f"Scope violation: {e}"
                ))
                continue
            except Exception as e:
                validated.append(ValidatedFinding(
                    raw=raw,
                    status="not_reproducible",
                    confirmation_note=f"Request failed: {e}"
                ))
                continue

            # Check payload response: marker present AND unescaped
            payload_reflects = _is_unescaped(payload_resp.text, raw.payload)

            # Check control response: our marker should NOT be in it
            # (control value "testvalue123" never contains the XSS marker)
            control_lower = control_resp.text.lower()
            control_reflects = XSS_MARKER in control_lower

            if payload_reflects and not control_reflects:
                status = "confirmed"
                note = (
                    f"CONFIRMED via control test. "
                    f"XSS payload reflected unescaped in payload response. "
                    f"Control ('testvalue123') did NOT trigger reflection. "
                    f"Payload: {raw.payload[:60]}"
                )
                print("  [Validation/XSS]   CONFIRMED (payload reflects, control does not).")

            elif payload_reflects and control_reflects:
                status = "not_reproducible"
                note = (
                    "NOT CONFIRMED. Both payload and control responses contained "
                    "the XSS marker -- likely a false positive from pre-existing "
                    "page content."
                )
                print("  [Validation/XSS]   NOT confirmed (control also reflected marker).")

            else:
                status = "not_reproducible"
                note = "NOT CONFIRMED. XSS payload was not reflected on validation retry."
                print("  [Validation/XSS]   NOT confirmed (not reflected).")

            validated.append(ValidatedFinding(
                raw=raw,
                status=status,
                confirmation_note=note,
            ))

    return validated