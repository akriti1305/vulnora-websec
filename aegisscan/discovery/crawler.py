"""
discovery/crawler.py -- AegisScan Web Crawler
==============================================
BFS (Breadth-First Search) crawler using httpx and BeautifulSoup4.

What it collects per page:
  - URL visited
  - All same-domain links found
  - All HTML forms (action, method, input field names/types)
  - HTTP response headers
  - Cookies set by the server

Returns a DiscoveryResult dataclass consumed by all detectors.
"""

import time
from typing import List, Dict, Optional, Tuple
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field
from scope import ScopeGuard, OutOfScopeError
from policy import ScanPolicy


# ---------------------------------------------------------------------------
# Shared Data Structures -- used by all detectors
# ---------------------------------------------------------------------------

@dataclass
class FormField:
    """One input field inside a form."""
    name: str        # 'name' attribute -- the POST key
    field_type: str  # 'type' attribute (text, password, hidden, submit ...)


@dataclass
class PageForm:
    """One <form> element found on a page."""
    page_url: str           # page where the form lives
    action: str             # fully-resolved submit URL
    method: str             # GET or POST
    fields: List[FormField] # all input fields in the form


@dataclass
class PageInfo:
    """Everything collected from one crawled page."""
    url: str
    links: List[str]
    forms: List[PageForm]
    response_headers: Dict[str, str]
    cookies: Dict[str, str]
    status_code: int


@dataclass
class DiscoveryResult:
    """
    Complete output of one crawl run.
    Passed directly to every detector.

    Detectors use:
      result.all_forms   -- every form across all pages
      result.pages       -- per-page info (headers, cookies)
      result.base_url    -- starting URL
    """
    base_url: str
    pages: List[PageInfo]
    all_forms: List[PageForm]
    visited_urls: List[str]


# ---------------------------------------------------------------------------
# Crawler
# ---------------------------------------------------------------------------

MAX_PAGES = 50  # safety cap to prevent crawling too many pages


def crawl(
    base_url: str,
    scan_policy: Optional[ScanPolicy] = None,
    scope_guard: Optional[ScopeGuard] = None,
) -> DiscoveryResult:
    """
    Crawl base_url using BFS. Stay strictly within authorized scope and policy bounds.

    Args:
        base_url: e.g. "http://127.0.0.1:5001" or "https://example.com"
        scan_policy: Optional ScanPolicy specifying budget, paths, rate limits, cancellation
        scope_guard: Optional hardened ScopeGuard instance

    Returns:
        DiscoveryResult with all pages, forms, headers, cookies.
    """

    # Resolve ScopeGuard
    if scope_guard:
        guard = scope_guard
    elif scan_policy:
        guard = ScopeGuard(
            is_external=(scan_policy.target_type == "external"),
            allowed_hostname=scan_policy.allowed_hostname,
        )
    else:
        guard = ScopeGuard()

    # The domain we must stay within
    base_netloc = urlparse(base_url).netloc
    max_pages = min(MAX_PAGES, scan_policy.request_budget) if scan_policy else MAX_PAGES
    max_depth = scan_policy.max_depth if scan_policy else 3
    is_external_basic = bool(scan_policy and scan_policy.scan_mode == "external_basic")

    # BFS queue -- tuples of (url, current_depth)
    queue: List[Tuple[str, int]] = [(base_url, 0)]
    visited: set = set()

    pages: List[PageInfo] = []
    all_forms: List[PageForm] = []

    # Use guard.client() so redirects to off-scope hosts or private IPs are blocked automatically
    with guard.client() as client:

        while queue and len(visited) < max_pages:

            # Check policy cancellation or budget
            if scan_policy and not scan_policy.can_make_request():
                print(f"  [Crawler] Halting crawl (cancelled={scan_policy.is_cancelled}, budget reached).")
                break

            url, depth = queue.pop(0)
            if url in visited:
                continue

            # Scope check before sending the request
            try:
                guard.check(url, context="Crawler")
            except OutOfScopeError as e:
                print(f"  [ScopeGuard] [Crawler] Blocked out-of-scope URL: {url} -> {e}")
                continue

            # Policy path check
            parsed_path = urlparse(url).path or "/"
            if scan_policy and not scan_policy.is_path_allowed(parsed_path):
                print(f"  [Policy] [Crawler] Path excluded by policy: {url}")
                continue

            # Apply rate limiting if requested
            if scan_policy and scan_policy.rate_limit_delay > 0 and len(visited) > 0:
                time.sleep(scan_policy.rate_limit_delay)

            # Record request in policy budget
            if scan_policy and not scan_policy.record_request():
                print(f"  [Crawler] Request budget exhausted at {url}")
                break

            visited.add(url)
            print(f"  [Crawler] Visiting (depth {depth}): {url}")

            # ------ HTTP GET ------------------------------------------------
            try:
                response = client.get(url)
            except OutOfScopeError:
                continue
            except Exception as e:
                print(f"  [Crawler] Error: {url} -> {e}")
                continue

            soup = BeautifulSoup(response.text, "html.parser")

            # ------ Collect links -------------------------------------------
            page_links: List[str] = []
            for tag in soup.find_all("a", href=True):
                abs_url = urljoin(url, tag["href"])
                
                # Check scope guard
                if not guard.is_allowed(abs_url):
                    print(f"  [ScopeGuard] [Crawler] skipped out-of-scope link: {abs_url}")
                    continue

                # Check policy path
                link_path = urlparse(abs_url).path or "/"
                if scan_policy and not scan_policy.is_path_allowed(link_path):
                    continue

                if urlparse(abs_url).netloc == base_netloc:
                    page_links.append(abs_url)
                    if abs_url not in visited and depth < max_depth:
                        queue.append((abs_url, depth + 1))

            # ------ Collect forms -------------------------------------------
            page_forms: List[PageForm] = []
            for form_tag in soup.find_all("form"):
                raw_action = form_tag.get("action", url)
                action_url = urljoin(url, raw_action)
                method = form_tag.get("method", "get").upper()

                # Skip forms whose action points off-scope
                if not guard.is_allowed(action_url):
                    print(f"  [ScopeGuard] [Crawler] skipped out-of-scope form action: {action_url}")
                    continue

                # Check policy path
                action_path = urlparse(action_url).path or "/"
                if scan_policy and not scan_policy.is_path_allowed(action_path):
                    continue

                fields: List[FormField] = []
                for inp in form_tag.find_all(["input", "textarea", "select"]):
                    n = inp.get("name")
                    t = inp.get("type", "text")
                    if n:
                        fields.append(FormField(name=n, field_type=t))

                pf = PageForm(
                    page_url=url,
                    action=action_url,
                    method=method,
                    fields=fields
                )
                page_forms.append(pf)
                all_forms.append(pf)

                # In local lab mode: also queue the form's GET action URL so that pages
                # reachable only via a form get crawled.
                # In external_basic mode: DO NOT synthesize form submissions to prevent accidental state change.
                if not is_external_basic and method == "GET" and urlparse(action_url).netloc == base_netloc:
                    sample_qs_parts = []
                    for inp in form_tag.find_all(["input", "textarea", "select"]):
                        n = inp.get("name")
                        v = inp.get("value", "1")
                        if n and inp.get("type", "text") != "submit":
                            sample_qs_parts.append(f"{n}={v}")
                    if sample_qs_parts:
                        action_with_qs = action_url + "?" + "&".join(sample_qs_parts)
                    else:
                        action_with_qs = action_url
                    if action_with_qs not in visited and depth < max_depth:
                        queue.append((action_with_qs, depth + 1))

            # ------ Collect cookies / headers --------------------------------
            cookies: Dict[str, str] = dict(response.cookies)
            headers: Dict[str, str] = dict(response.headers)

            pages.append(PageInfo(
                url=url,
                links=page_links,
                forms=page_forms,
                response_headers=headers,
                cookies=cookies,
                status_code=response.status_code
            ))

    print(f"  [Crawler] Done. Pages={len(visited)} Forms={len(all_forms)}")

    return DiscoveryResult(
        base_url=base_url,
        pages=pages,
        all_forms=all_forms,
        visited_urls=list(visited)
    )

