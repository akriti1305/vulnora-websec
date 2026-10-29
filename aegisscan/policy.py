"""
policy.py -- AegisScan Central Scan Execution Policy (Phase 14)
==============================================================
Defines the unified ScanPolicy object passed through all scanner modules
(crawler, transport, detectors, and reporting).

Encapsulates:
  - Target identity and network classification (local_lab vs external)
  - Authorization grant binding
  - Scan mode (local_lab, external_basic, external_deep)
  - Allowed and excluded path boundaries
  - Request budgets and rate limiting
  - Active cancellation tracking
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Set
from urllib.parse import urlparse
import json


# Standard state-changing / sensitive paths excluded by default on external targets
DEFAULT_EXTERNAL_EXCLUDED_PATTERNS = [
    "/logout", "/signout", "/sign-out", "/log-out",
    "/delete", "/destroy", "/cancel",
    "/payment", "/checkout", "/billing", "/subscribe",
    "/change-password", "/reset-password", "/update-password",
    "/admin/delete", "/api/delete",
]


@dataclass
class ScanPolicy:
    """
    Unified execution contract for an individual scan run.
    """
    target_url: str
    target_type: str = "local_lab"        # "local_lab" or "external"
    scan_mode: str = "local_lab"          # "local_lab", "external_basic", "external_deep"
    target_id: Optional[int] = None
    authorization_grant_id: Optional[int] = None
    allowed_hostname: str = ""
    allowed_paths: List[str] = field(default_factory=lambda: ["/"])
    excluded_paths: List[str] = field(default_factory=list)
    request_budget: int = 100
    max_depth: int = 3
    timeout_seconds: float = 10.0
    concurrency_limit: int = 2
    rate_limit_delay: float = 0.1
    max_response_size: int = 2 * 1024 * 1024  # 2MB
    requests_made: int = 0
    is_cancelled: bool = False
    cancellation_reason: str = ""
    started_at: Optional[str] = None
    finished_at: Optional[str] = None

    def __post_init__(self):
        if not self.allowed_hostname and self.target_url:
            parsed = urlparse(self.target_url)
            self.allowed_hostname = parsed.hostname or ""
        
        # Ensure default exclusion patterns for external basic mode
        if self.target_type == "external" or self.scan_mode == "external_basic":
            for pat in DEFAULT_EXTERNAL_EXCLUDED_PATTERNS:
                if pat not in self.excluded_paths:
                    self.excluded_paths.append(pat)

    def can_make_request(self) -> bool:
        """Returns True if the scan has budget remaining and is not cancelled."""
        if self.is_cancelled:
            return False
        if self.request_budget > 0 and self.requests_made >= self.request_budget:
            return False
        return True

    def record_request(self) -> bool:
        """
        Record that one HTTP request was initiated.
        Returns True if allowed, or False if budget exhausted or cancelled.
        """
        if not self.can_make_request():
            return False
        self.requests_made += 1
        return True

    def cancel(self, reason: str = "User cancelled scan"):
        """Signal immediate scan cancellation."""
        self.is_cancelled = True
        self.cancellation_reason = reason

    def is_path_allowed(self, path: str) -> bool:
        """
        Check if a given URL path is within approved scope.
        Validates both allowed_paths prefixes and excluded_paths restrictions.
        """
        clean_path = path if path.startswith("/") else f"/{path}"
        lower_path = clean_path.lower()

        # Check explicit and default exclusions
        for excl in self.excluded_paths:
            excl_lower = excl.lower()
            if excl_lower in lower_path:
                return False

        # In local_lab mode, all paths not explicitly excluded are allowed
        if self.target_type == "local_lab" and (not self.allowed_paths or self.allowed_paths == ["/"]):
            return True

        # Check if path falls within any allowed prefix
        for allowed in self.allowed_paths:
            allowed_clean = allowed.lower()
            if allowed_clean == "/" or lower_path.startswith(allowed_clean):
                return True

        return False

    def to_dict(self) -> dict:
        """Serializes policy for database and passport provenance recording."""
        return {
            "target_url": self.target_url,
            "target_type": self.target_type,
            "scan_mode": self.scan_mode,
            "target_id": self.target_id,
            "authorization_grant_id": self.authorization_grant_id,
            "allowed_hostname": self.allowed_hostname,
            "allowed_paths": self.allowed_paths,
            "excluded_paths": self.excluded_paths,
            "request_budget": self.request_budget,
            "max_depth": self.max_depth,
            "timeout_seconds": self.timeout_seconds,
            "concurrency_limit": self.concurrency_limit,
            "rate_limit_delay": self.rate_limit_delay,
            "max_response_size": self.max_response_size,
            "requests_made": self.requests_made,
            "is_cancelled": self.is_cancelled,
            "cancellation_reason": self.cancellation_reason,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict) -> "ScanPolicy":
        return cls(
            target_url=data.get("target_url", ""),
            target_type=data.get("target_type", "local_lab"),
            scan_mode=data.get("scan_mode", "local_lab"),
            target_id=data.get("target_id"),
            authorization_grant_id=data.get("authorization_grant_id"),
            allowed_hostname=data.get("allowed_hostname", ""),
            allowed_paths=data.get("allowed_paths", ["/"]),
            excluded_paths=data.get("excluded_paths", []),
            request_budget=data.get("request_budget", 100),
            max_depth=data.get("max_depth", 3),
            timeout_seconds=data.get("timeout_seconds", 10.0),
            concurrency_limit=data.get("concurrency_limit", 2),
            rate_limit_delay=data.get("rate_limit_delay", 0.1),
            max_response_size=data.get("max_response_size", 2 * 1024 * 1024),
            requests_made=data.get("requests_made", 0),
            is_cancelled=data.get("is_cancelled", False),
            cancellation_reason=data.get("cancellation_reason", ""),
            started_at=data.get("started_at"),
            finished_at=data.get("finished_at"),
        )
