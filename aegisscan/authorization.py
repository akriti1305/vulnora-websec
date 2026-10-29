"""
authorization.py -- AegisScan Target Registration & Authorization Engine
========================================================================
Manages external target registration, cryptographic domain verification
challenges, explicit authorization declarations, and audit event tracking.

Key Security Rules:
  1. Domain control verification is strictly bound to the canonical hostname.
     Verifying sub.domain.com does NOT authorize domain.com or other.domain.com.
  2. HTTP verification checks https://<target>/.well-known/aegisscan-verification.txt
     with strict SSL certificate validation and redirects disabled.
  3. External scans require an active, unexpired AuthorizationGrant with an
     approved scope (allowed paths, excluded paths, and scan mode).
  4. Full verification secrets are never written to plaintext log messages.
"""

import secrets
import json
from datetime import datetime, timedelta
from urllib.parse import urlparse
from typing import Optional, Dict, Any, List
import httpx
from sqlalchemy.orm import Session

from models import Target, VerificationChallenge, AuthorizationGrant, AuditEvent
from scope import ScopeGuard, OutOfScopeError, DEFAULT_ALLOWED_HOSTS


CHALLENGE_EXPIRY_DAYS = 7
AUTHORIZATION_EXPIRY_DAYS = 30
MAX_VERIFICATION_BYTES = 10240  # 10 KB safety limit


def normalize_target_url(raw_url: str) -> Dict[str, Any]:
    """
    Canonicalize target URL and classify target type (local vs external).
    Enforces HTTPS for external destinations.
    """
    cleaned = (raw_url or "").strip()
    if not cleaned:
        raise ValueError("Target URL cannot be empty.")

    if "://" not in cleaned:
        # Default to https for external domains, http for localhost
        if cleaned.lower().startswith("localhost") or cleaned.startswith("127.0.0.1"):
            cleaned = f"http://{cleaned}"
        else:
            cleaned = f"https://{cleaned}"

    parsed = urlparse(cleaned)
    scheme = (parsed.scheme or "").lower()
    hostname = (parsed.hostname or "").lower()
    port = parsed.port

    if not hostname:
        raise ValueError(f"Invalid URL: missing hostname in '{raw_url}'.")

    # Determine target type
    if hostname in DEFAULT_ALLOWED_HOSTS:
        target_type = "local"
        if scheme not in ("http", "https"):
            raise ValueError(f"Local testbed target must use HTTP or HTTPS scheme.")
        port_part = f":{port}" if port and port not in (80, 443) else ""
        canonical_base = f"{scheme}://{hostname}{port_part}"
    else:
        target_type = "external"
        if scheme != "https":
            raise ValueError(f"External target '{hostname}' must use HTTPS scheme.")
        if port is not None and port != 443:
            raise ValueError(f"External target '{hostname}' must use standard HTTPS port 443.")
        canonical_base = f"https://{hostname}"

    return {
        "raw_url": raw_url,
        "canonical_base": canonical_base,
        "hostname": hostname,
        "scheme": scheme,
        "port": port,
        "target_type": target_type,
    }


def register_target(
    db: Session,
    url: str,
    name: Optional[str] = None,
    authorized_by: str = "operator"
) -> Target:
    """
    Register a local or external target in the database.
    If external, generates an initial pending VerificationChallenge.
    """
    info = normalize_target_url(url)
    canonical_base = info["canonical_base"]
    target_type = info["target_type"]
    hostname = info["hostname"]
    display_name = (name or "").strip() or hostname

    # Check if target already exists
    target = db.query(Target).filter(Target.base_url == canonical_base).first()
    if not target:
        is_verified = (target_type == "local")  # local testbeds are pre-verified
        target = Target(
            name=display_name,
            base_url=canonical_base,
            target_type=target_type,
            is_verified=is_verified,
            verified_at=datetime.utcnow() if is_verified else None,
            verification_method="pre_authorized" if is_verified else None,
        )
        db.add(target)
        db.commit()
        db.refresh(target)

        # Audit log
        db.add(AuditEvent(
            event_type="target_registered",
            target_id=target.id,
            operator=authorized_by,
            details=f"Target '{display_name}' registered as {target_type} ({canonical_base})."
        ))
        db.commit()
    else:
        # If target already exists and is local, ensure is_verified is True
        if target.target_type == "local" or hostname in DEFAULT_ALLOWED_HOSTS:
            if not target.is_verified:
                target.is_verified = True
                target.target_type = "local"
                target.verified_at = datetime.utcnow()
                target.verification_method = "pre_authorized"
                db.commit()

    # If external, ensure an active verification challenge exists
    if target.target_type == "external" and not target.is_verified:
        get_or_create_challenge(db, target.id)

    return target


def get_or_create_challenge(db: Session, target_id: int) -> VerificationChallenge:
    """Retrieve existing active challenge or generate a new cryptographically random token."""
    now = datetime.utcnow()
    challenge = (
        db.query(VerificationChallenge)
        .filter(
            VerificationChallenge.target_id == target_id,
            VerificationChallenge.status == "pending",
            VerificationChallenge.expires_at > now,
        )
        .order_by(VerificationChallenge.id.desc())
        .first()
    )
    if challenge:
        return challenge

    # Generate 32-byte URL-safe unpredictable secret
    token = secrets.token_urlsafe(32)
    expires_at = now + timedelta(days=CHALLENGE_EXPIRY_DAYS)

    new_challenge = VerificationChallenge(
        target_id=target_id,
        challenge_token=token,
        challenge_type="http",
        status="pending",
        created_at=now,
        expires_at=expires_at,
    )
    db.add(new_challenge)
    db.commit()
    db.refresh(new_challenge)

    db.add(AuditEvent(
        event_type="challenge_generated",
        target_id=target_id,
        details=f"HTTP verification challenge created. Token prefix: {token[:8]}... Expires: {expires_at.isoformat()}"
    ))
    db.commit()

    return new_challenge


def get_challenge_instructions(target: Target, challenge: VerificationChallenge) -> Dict[str, Any]:
    """Generate user-facing deployment instructions for domain verification."""
    hostname = urlparse(target.base_url).hostname or target.base_url
    verification_url = f"{target.base_url.rstrip('/')}/.well-known/aegisscan-verification.txt"
    token = challenge.challenge_token

    instructions_markdown = f"""### AegisScan Domain Verification Instructions

To prove administrative control of **{hostname}**, publish the verification token at the following URL:

- **Target URL**: `{verification_url}`
- **Exact File Content**: `{token}`

#### Instructions for Vercel / Next.js / Static Portfolios:
1. In your project repository root, create or open the `public/` directory.
2. Inside `public/`, create a folder named `.well-known`.
3. Inside `public/.well-known/`, create a file named `aegisscan-verification.txt`.
4. Paste the exact token above into `aegisscan-verification.txt` (single line, no quotes, no extra spaces).
5. Deploy your changes (e.g. `git push` or `vercel --prod`).
6. Verify in your browser that `{verification_url}` loads and displays your token.
7. Return to AegisScan and click **Verify Ownership**.
"""

    return {
        "target_id": target.id,
        "hostname": hostname,
        "base_url": target.base_url,
        "challenge_token": token,
        "verification_url": verification_url,
        "expected_path": "public/.well-known/aegisscan-verification.txt",
        "expires_at": challenge.expires_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "status": challenge.status,
        "instructions_markdown": instructions_markdown,
    }


def verify_domain_ownership(
    db: Session,
    target_id: int,
    custom_client: Optional[httpx.Client] = None
) -> Dict[str, Any]:
    """
    Perform active HTTP domain ownership verification against:
    https://<hostname>/.well-known/aegisscan-verification.txt

    Security Constraints:
      - HTTPS only
      - Strict TLS certificate verification
      - No redirects allowed
      - Max response size 10 KB
      - Strict timeout
    """
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        return {"success": False, "error": f"Target ID {target_id} not found."}

    if target.target_type == "local":
        return {
            "success": True,
            "verified": True,
            "message": "Local lab target does not require domain verification."
        }

    now = datetime.utcnow()
    challenge = (
        db.query(VerificationChallenge)
        .filter(
            VerificationChallenge.target_id == target_id,
            VerificationChallenge.status == "pending",
            VerificationChallenge.expires_at > now,
        )
        .order_by(VerificationChallenge.id.desc())
        .first()
    )

    if not challenge:
        return {
            "success": False,
            "error": "No active pending challenge found. Please generate a new verification token."
        }

    hostname = urlparse(target.base_url).hostname or ""
    verification_url = f"{target.base_url.rstrip('/')}/.well-known/aegisscan-verification.txt"
    expected_token = challenge.challenge_token.strip()

    # Mark check timestamp
    challenge.last_checked_at = now

    try:
        # If no mock/custom client passed, construct strict verification client
        if custom_client is not None:
            resp = custom_client.get(verification_url)
        else:
            # Build dedicated ScopeGuard ensuring SSRF protection
            guard = ScopeGuard(allowed_hosts={hostname}, mode="external")
            # We enforce follow_redirects=False for domain verification (redirects not allowed)
            with guard.client(follow_redirects=False, timeout=8.0, verify=True) as client:
                resp = client.get(
                    verification_url,
                    headers={"User-Agent": "AegisScan-Verification/2.0 (+https://github.com/akriti1305/vulnora-websec)"}
                )

        if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
            err_msg = f"Verification rejected redirect to '{resp.headers.get('location', '')}'. Domain verification must serve the challenge directly without redirects."
            challenge.failure_reason = err_msg
            db.commit()
            return {"success": False, "verified": False, "error": err_msg}

        if resp.status_code != 200:
            err_msg = f"HTTP {resp.status_code} returned when fetching verification file. Expected HTTP 200 OK."
            challenge.failure_reason = err_msg
            db.commit()
            return {"success": False, "verified": False, "error": err_msg}

        # Check size and content
        body_text = resp.text[:MAX_VERIFICATION_BYTES].strip()
        if body_text == expected_token or expected_token in body_text:
            # Successfully verified
            target.is_verified = True
            target.verified_at = now
            target.verification_method = "http"

            challenge.status = "verified"
            challenge.verified_at = now
            challenge.failure_reason = None

            db.add(AuditEvent(
                event_type="verification_succeeded",
                target_id=target.id,
                details=f"Domain ownership verified successfully for host '{hostname}' via HTTP token."
            ))
            db.commit()

            return {
                "success": True,
                "verified": True,
                "message": f"Domain ownership of '{hostname}' verified successfully via HTTP challenge.",
                "verified_at": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
            }
        else:
            err_msg = "Verification file content did not match the expected challenge token."
            challenge.failure_reason = err_msg
            db.commit()
            return {"success": False, "verified": False, "error": err_msg}

    except OutOfScopeError as e:
        err_msg = f"Scope violation during verification: {e}"
        challenge.failure_reason = err_msg
        db.commit()
        return {"success": False, "verified": False, "error": err_msg}
    except Exception as e:
        err_msg = f"Connection or TLS error during verification: {e}"
        challenge.failure_reason = err_msg
        db.commit()
        return {"success": False, "verified": False, "error": err_msg}


def create_authorization_grant(
    db: Session,
    target_id: int,
    authorized_by: str,
    scan_mode: str = "external_basic",
    allowed_paths: Optional[List[str]] = None,
    excluded_paths: Optional[List[str]] = None,
    acknowledgment: str = "I confirm ownership/authorization to assess this target.",
    duration_days: int = AUTHORIZATION_EXPIRY_DAYS,
) -> AuthorizationGrant:
    """
    Establish an explicit legal authorization grant with scope boundaries.
    Target MUST be verified prior to granting authorization.
    """
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise ValueError(f"Target ID {target_id} not found.")

    if not target.is_verified and target.target_type == "external":
        raise ValueError(f"Target '{target.base_url}' must be verified before authorization can be granted.")

    hostname = urlparse(target.base_url).hostname or target.base_url
    mode_clean = scan_mode.strip().lower()
    if mode_clean not in ("external_basic", "external_deep", "local_lab"):
        mode_clean = "external_basic"

    paths_allowed = allowed_paths or ["/"]
    paths_excluded = excluded_paths or ["/logout", "/signout", "/delete", "/admin"]

    now = datetime.utcnow()
    expires_at = now + timedelta(days=duration_days)

    grant = AuthorizationGrant(
        target_id=target.id,
        approved_hostname=hostname,
        authorized_by=authorized_by.strip() or "Operator",
        scan_mode=mode_clean,
        allowed_paths=json.dumps(paths_allowed),
        excluded_paths=json.dumps(paths_excluded),
        max_requests=50 if mode_clean == "external_basic" else 150,
        rate_limit_per_second=2.0 if mode_clean == "external_basic" else 1.0,
        valid_from=now,
        expires_at=expires_at,
        operator_acknowledgment=acknowledgment.strip(),
        status="active",
        created_at=now,
    )
    db.add(grant)
    db.commit()
    db.refresh(grant)

    db.add(AuditEvent(
        event_type="authorization_granted",
        target_id=target.id,
        operator=authorized_by,
        details=f"Grant #{grant.id} created for '{hostname}'. Mode: {mode_clean}. Valid until: {expires_at.isoformat()}"
    ))
    db.commit()

    return grant


def revoke_authorization(
    db: Session,
    target_id: int,
    reason: str = "Operator requested revocation",
    operator: str = "operator"
) -> Dict[str, Any]:
    """Revoke verification and all active authorization grants for a target."""
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        return {"success": False, "error": f"Target ID {target_id} not found."}

    target.is_verified = False

    # Revoke all grants
    grants = db.query(AuthorizationGrant).filter(
        AuthorizationGrant.target_id == target_id,
        AuthorizationGrant.status == "active"
    ).all()
    for g in grants:
        g.status = "revoked"

    # Revoke active challenges
    challenges = db.query(VerificationChallenge).filter(
        VerificationChallenge.target_id == target_id,
        VerificationChallenge.status.in_(["pending", "verified"])
    ).all()
    for c in challenges:
        c.status = "revoked"

    db.add(AuditEvent(
        event_type="authorization_revoked",
        target_id=target.id,
        operator=operator,
        details=f"Authorization revoked. Reason: {reason}"
    ))
    db.commit()

    return {
        "success": True,
        "message": f"Authorization and verification revoked for target '{target.base_url}'."
    }


def get_target_status_summary(db: Session, target_id: int) -> Dict[str, Any]:
    """Return consolidated target authorization and verification status."""
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        return {"status": "unregistered"}

    if target.target_type == "local":
        return {
            "target_id": target.id,
            "target_type": "local",
            "name": target.name,
            "base_url": target.base_url,
            "is_verified": True,
            "status": "local_lab",
            "status_label": "Local Lab (Authorized)",
            "can_scan": True,
            "allowed_modes": ["local_lab", "deep", "basic"],
        }

    now = datetime.utcnow()
    active_grant = (
        db.query(AuthorizationGrant)
        .filter(
            AuthorizationGrant.target_id == target_id,
            AuthorizationGrant.status == "active",
            AuthorizationGrant.expires_at > now,
        )
        .order_by(AuthorizationGrant.id.desc())
        .first()
    )

    if not target.is_verified:
        challenge = (
            db.query(VerificationChallenge)
            .filter(
                VerificationChallenge.target_id == target_id,
                VerificationChallenge.status == "pending",
                VerificationChallenge.expires_at > now,
            )
            .first()
        )
        status = "pending_verification" if challenge else "unverified"
        label = "Pending Domain Verification" if challenge else "Unverified External Target"
        can_scan = False
    elif not active_grant:
        status = "verified_unauthorized"
        label = "Domain Verified (Needs Scope Authorization)"
        can_scan = False
    else:
        status = "authorized"
        label = f"Authorized ({active_grant.scan_mode.upper()})"
        can_scan = True

    return {
        "target_id": target.id,
        "target_type": "external",
        "name": target.name,
        "base_url": target.base_url,
        "is_verified": target.is_verified,
        "verified_at": target.verified_at.strftime("%Y-%m-%d %H:%M:%S UTC") if target.verified_at else None,
        "status": status,
        "status_label": label,
        "can_scan": can_scan,
        "authorization_status": "active_grant" if active_grant else "no_active_grant",
        "active_grant": {
            "id": active_grant.id,
            "scan_mode": active_grant.scan_mode,
            "authorized_by": active_grant.authorized_by,
            "expires_at": active_grant.expires_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
        } if active_grant else None,
        "allowed_modes": ["external_basic"] if (active_grant and active_grant.scan_mode == "external_basic") else (["external_basic", "external_deep"] if active_grant else []),
    }
