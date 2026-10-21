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

import httpx
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field
from typing import List, Dict
from scope import ScopeGuard, OutOfScopeError


# ---------------------------------------------------------------------------
# Shared Data Structures -- used by all 5 detectors
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


def crawl(base_url: str) -> DiscoveryResult:
    """
    Crawl base_url using BFS. Stay within the same domain.

    Args:
        base_url: e.g. "http://127.0.0.1:5001"

    Returns:
        DiscoveryResult with all pages, forms, headers, cookies.
    """

    # Scope guard -- restricts crawling to the same allowed hosts
    guard = ScopeGuard()

    # The domain we must stay within (e.g. "127.0.0.1:5001")
    base_netloc = urlparse(base_url).netloc

    # BFS queue -- start at homepage
    queue: List[str] = [base_url]
    visited: set = set()

    pages: List[PageInfo] = []
    all_forms: List[PageForm] = []

    # Use guard.client() so redirects to off-scope hosts are blocked automatically
    with guard.client() as client:

        while queue and len(visited) < MAX_PAGES:

            url = queue.pop(0)          # BFS: always take from the front
            if url in visited:
                continue

            # Scope check before sending the request
            try:
                guard.check(url, context="Crawler")
            except OutOfScopeError:
                continue

            visited.add(url)
            print(f"  [Crawler] Visiting: {url}")

            # ------ HTTP GET ------------------------------------------------
            try:
                response = client.get(url)
            except OutOfScopeError:
                # Redirect was blocked by the event hook
                continue
            except Exception as e:
                print(f"  [Crawler] Error: {url} -> {e}")
                continue

            soup = BeautifulSoup(response.text, "html.parser")

            # ------ Collect links -------------------------------------------
            page_links: List[str] = []
            for tag in soup.find_all("a", href=True):
                abs_url = urljoin(url, tag["href"])
                if not guard.is_allowed(abs_url):
                    print(f"  [ScopeGuard] [Crawler] skipped out-of-scope: {abs_url}")
                    continue
                if urlparse(abs_url).netloc == base_netloc:
                    page_links.append(abs_url)
                    if abs_url not in visited:
                        queue.append(abs_url)

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

                # KEY FIX: also queue the form's action URL so that pages
                # reachable only via a form (not a plain <a href>) still get
                # crawled. This is what lets us discover /user/profile, which
                # has no <a href> link but IS a GET form action on the homepage.
                # Only queue same-domain GET form actions (POST would need data).
                if method == "GET" and urlparse(action_url).netloc == base_netloc:
                    # Build a minimal query-string so the page returns real content
                    # (e.g. /user/profile?id=1 so it doesn't 404 or redirect)
                    sample_qs_parts = []
                    for inp in form_tag.find_all(["input", "textarea", "select"]):
                        n = inp.get("name")
                        v = inp.get("value", "1")  # use the default value or "1"
                        if n and inp.get("type", "text") != "submit":
                            sample_qs_parts.append(f"{n}={v}")
                    if sample_qs_parts:
                        action_with_qs = action_url + "?" + "&".join(sample_qs_parts)
                    else:
                        action_with_qs = action_url
                    if action_with_qs not in visited:
                        queue.append(action_with_qs)

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
