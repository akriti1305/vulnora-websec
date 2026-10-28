"""
detectors/idor_detector.py -- AegisScan IDOR Detector
======================================================
Insecure Direct Object Reference (IDOR): an attacker changes an ID value
in a URL to access another user's data, with no access-control check.

How it works:
  1. Scan all visited page URLs for ID-like query parameters (e.g. ?id=1)
  2. Try adjacent IDs (id=2, id=3) without any auth cookie
  3. If a different user's data comes back (HTTP 200, different content)
     flag it as a confirmed IDOR finding

Design decision -- no validation step:
  IDOR findings are inherently self-confirming: either the data
  of a different user comes back or it doesn't. We mark all hits
  "confirmed" directly, skipping the replay validation step.

IMPORTANT -- read-only probes only:
  We only send GET requests with different ID values.
  We never attempt to modify or delete any records.
"""

import re
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from dataclasses import dataclass, field
from typing import List, Optional
from discovery.crawler import DiscoveryResult
from scope import ScopeGuard, OutOfScopeError


# Query parameter names that typically hold object IDs
ID_PARAM_NAMES = {"id", "user_id", "uid", "profile_id", "account_id", "pid"}

# How many adjacent IDs to try
PROBE_IDS = [1, 2, 3, 4, 5]

# Personal data indicators
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
PERSONAL_DATA_LABELS = ["email", "phone", "address", "ssn", "dob", "birth", "mobile", "contact"]


def _has_personal_data(html: str) -> bool:
    """
    Check if the response body contains personal-data indicators:
      - Email address pattern
      - Common labels like email, phone, address
    """
    if EMAIL_REGEX.search(html):
        return True
    lower = html.lower()
    for label in PERSONAL_DATA_LABELS:
        if re.search(r"\b" + re.escape(label) + r"\b", lower):
            return True
    return False


@dataclass
class IdorFinding:
    """
    An IDOR finding (confirmed or potential).

    baseline_url    : the original URL that worked (e.g. /user/profile?id=1)
    probed_url      : the URL with a different ID that ALSO worked
    baseline_content: a snippet of the baseline response body
    probed_content  : a snippet of the probed response body
    param_name      : the query parameter that was changed (e.g. "id")
    original_id     : the ID value in the crawled URL
    probed_id       : the ID value that returned different data
    evidence        : short human-readable proof for the report
    status          : "confirmed" (personal data exposed) or "potential" (manual review needed)
    severity        : "Critical" or "Medium"
    note            : explanation for potential findings
    """
    baseline_url: str
    probed_url: str
    baseline_content: str
    probed_content: str
    param_name: str
    original_id: str
    probed_id: str
    evidence: str
    status: str = "confirmed"
    severity: str = "Critical"
    note: str = ""


def detect(discovery: DiscoveryResult) -> List[IdorFinding]:
    """
    Test all ID-bearing URLs for IDOR.

    Args:
        discovery: DiscoveryResult from crawler.crawl()

    Returns:
        List of IdorFinding -- one per exploitable URL/parameter.
    """
    findings: List[IdorFinding] = []
    tested_pairs: set = set()   # avoid testing the same (url, param) twice

    guard = ScopeGuard()
    with guard.client() as client:

        for page in discovery.pages:
            url = page.url
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)

            # Check each query param to see if it looks like an ID
            for param_name, values in params.items():
                if param_name.lower() not in ID_PARAM_NAMES:
                    continue

                original_id = values[0]  # e.g. "1"
                dedup_key = (parsed.path, param_name)
                if dedup_key in tested_pairs:
                    continue
                tested_pairs.add(dedup_key)

                print(f"  [IDOR] Testing: {parsed.path}?{param_name}={original_id}")

                # Get the baseline response for the original ID
                try:
                    baseline_resp = client.get(url)
                except OutOfScopeError:
                    print(f"  [IDOR]   Baseline blocked (out-of-scope), skipping.")
                    continue
                except Exception as e:
                    print(f"  [IDOR]   Baseline request failed: {e}")
                    continue

                if baseline_resp.status_code != 200:
                    print(f"  [IDOR]   Baseline returned {baseline_resp.status_code}, skipping.")
                    continue

                baseline_text = baseline_resp.text

                # Try each probe ID
                for probe_id in PROBE_IDS:
                    probe_id_str = str(probe_id)

                    # Don't probe the same ID we already have
                    if probe_id_str == original_id:
                        continue

                    # Build the probed URL with the new ID
                    new_params = dict(params)
                    new_params[param_name] = [probe_id_str]
                    new_query = urlencode(new_params, doseq=True)
                    probed_url = urlunparse(parsed._replace(query=new_query))

                    try:
                        probed_resp = client.get(probed_url)
                    except OutOfScopeError:
                        continue
                    except Exception as e:
                        continue

                    # IDOR signal:
                    #   1. Response is HTTP 200 (not 403/401/404)
                    #   2. The response body is DIFFERENT from the baseline
                    #      (meaning it returned a different user's data, not
                    #       just the same page with different formatting)
                    if probed_resp.status_code == 200:
                        if _responses_differ(baseline_text, probed_resp.text):
                            baseline_snippet = _text_snippet(baseline_text, 200)
                            probed_snippet   = _text_snippet(probed_resp.text, 200)

                            if _has_personal_data(probed_resp.text):
                                finding_status = "confirmed"
                                finding_severity = "Critical"
                                finding_note = ""
                                evidence = (
                                    f"URL parameter '{param_name}' changed from "
                                    f"'{original_id}' to '{probe_id_str}'. "
                                    f"Both returned HTTP 200 with different content, "
                                    f"indicating a different user's data was exposed "
                                    f"without any authorisation check."
                                )
                            else:
                                finding_status = "potential"
                                finding_severity = "Medium"
                                finding_note = (
                                    "Different content returned for different IDs; "
                                    "manual review needed to decide whether the data is private."
                                )
                                evidence = (
                                    f"URL parameter '{param_name}' changed from "
                                    f"'{original_id}' to '{probe_id_str}'. "
                                    f"Both returned HTTP 200 with different content."
                                )

                            findings.append(IdorFinding(
                                baseline_url     = url,
                                probed_url       = probed_url,
                                baseline_content = baseline_snippet,
                                probed_content   = probed_snippet,
                                param_name       = param_name,
                                original_id      = original_id,
                                probed_id        = probe_id_str,
                                evidence         = evidence,
                                status           = finding_status,
                                severity         = finding_severity,
                                note             = finding_note,
                            ))
                            print(
                                f"  [IDOR]   FOUND ({finding_status})! {param_name}={original_id} -> "
                                f"{param_name}={probe_id_str} both returned 200."
                            )
                            # One finding per URL/param is enough
                            break
                    else:
                        print(
                            f"  [IDOR]   {param_name}={probe_id_str} -> "
                            f"HTTP {probed_resp.status_code} (access denied, good)"
                        )

    if not findings:
        print("  [IDOR] No IDOR vulnerabilities detected.")

    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _responses_differ(text_a: str, text_b: str) -> bool:
    """
    Return True if two response bodies have meaningfully different content.

    We compare stripped plain-text (via BS4) because HTML structure
    may be identical but the user data inside will differ.
    """
    from bs4 import BeautifulSoup
    plain_a = BeautifulSoup(text_a, "html.parser").get_text(separator=" ").strip()
    plain_b = BeautifulSoup(text_b, "html.parser").get_text(separator=" ").strip()
    # Must differ by at least 5 chars to avoid noise from timestamps etc.
    return plain_a != plain_b and abs(len(plain_a) - len(plain_b)) > 5


def _text_snippet(html: str, length: int = 200) -> str:
    """Extract plain text from HTML and return a short snippet."""
    from bs4 import BeautifulSoup
    text = BeautifulSoup(html, "html.parser").get_text(separator=" ").strip()
    return text[:length]