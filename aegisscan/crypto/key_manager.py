"""
key_manager.py -- Ed25519 Asymmetric Key Management for AegisScan 2.0
======================================================================
Provides persistent Ed25519 key generation, storage, export, signing, and verification.

Security & Architectural Notes:
- Private keys are stored in a gitignored local directory (default: aegisscan/secrets/).
- Permissions are set to restrictive 0o600 where supported by the OS.
- Keys persist across scanner runs and application restarts; keys are not regenerated per scan.
- Public keys are exportable in PEM, raw hex, and Base64 format for independent verification.
- Key rotation limitation: Rotating the private key establishes a new scanner identity;
  historical passports require retaining/archiving earlier public keys for continuous verification.
- Private key material is never printed, logged, or returned via API routes.
"""

import os
import stat
import base64
import hashlib
from typing import Optional, Tuple, Union
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

DEFAULT_SECRETS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "secrets"
)


class KeyManager:
    """
    Manages persistent Ed25519 asymmetric cryptographic keypairs for scan passports.
    """

    def __init__(self, secrets_dir: Optional[str] = None):
        self.secrets_dir = secrets_dir or os.environ.get("AEGISSCAN_SECRETS_DIR", DEFAULT_SECRETS_DIR)
        os.makedirs(self.secrets_dir, exist_ok=True)
        self.private_key_path = os.path.join(self.secrets_dir, "ed25519_private.pem")
        self.public_key_path = os.path.join(self.secrets_dir, "ed25519_public.pem")
        self._private_key: Optional[ed25519.Ed25519PrivateKey] = None
        self._public_key: Optional[ed25519.Ed25519PublicKey] = None
        self._ensure_keys_loaded()

    def _ensure_keys_loaded(self) -> None:
        """
        Loads existing Ed25519 keypair from storage or generates and persists a new one.
        """
        if os.path.exists(self.private_key_path):
            with open(self.private_key_path, "rb") as f:
                priv_data = f.read()
            self._private_key = serialization.load_pem_private_key(priv_data, password=None)
            self._public_key = self._private_key.public_key()
            # Ensure public key file is also present
            if not os.path.exists(self.public_key_path):
                self._save_public_key()
        else:
            self._generate_and_save_new_keypair()

    def _generate_and_save_new_keypair(self) -> None:
        """
        Generates a fresh Ed25519 keypair and securely persists it.
        """
        self._private_key = ed25519.Ed25519PrivateKey.generate()
        self._public_key = self._private_key.public_key()

        # Serialize private key to PKCS8 PEM (unencrypted for automated local scanning)
        priv_pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        with open(self.private_key_path, "wb") as f:
            f.write(priv_pem)

        # Restrictive file permissions (owner read/write only)
        try:
            os.chmod(self.private_key_path, stat.S_IRUSR | stat.S_IWUSR)
        except Exception:
            pass

        self._save_public_key()

    def _save_public_key(self) -> None:
        """Saves public key to PEM file."""
        if self._public_key is None:
            return
        pub_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(self.public_key_path, "wb") as f:
            f.write(pub_pem)

    def get_public_key(self) -> ed25519.Ed25519PublicKey:
        """Returns the active Ed25519 public key instance."""
        if self._public_key is None:
            self._ensure_keys_loaded()
        return self._public_key

    def get_public_key_raw(self) -> bytes:
        """Returns the 32 raw bytes of the public key."""
        return self.get_public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    def get_public_key_hex(self) -> str:
        """Returns the public key as a 64-character lowercase hex string."""
        return self.get_public_key_raw().hex()

    def get_public_key_b64(self) -> str:
        """Returns the public key as standard Base64 string."""
        return base64.b64encode(self.get_public_key_raw()).decode("ascii")

    def get_public_key_pem(self) -> str:
        """Returns the public key in standard SubjectPublicKeyInfo PEM format."""
        pem_bytes = self.get_public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem_bytes.decode("ascii")

    def get_public_key_id(self) -> str:
        """
        Returns a short SHA-256 fingerprint identifier for the public key.
        Format: 'ed25519:<16-hex-chars>'
        """
        raw = self.get_public_key_raw()
        return f"ed25519:{hashlib.sha256(raw).hexdigest()[:16]}"

    def sign(self, data: bytes) -> bytes:
        """
        Cryptographically signs binary data with the Ed25519 private key.
        Returns the raw 64-byte signature.
        """
        if self._private_key is None:
            self._ensure_keys_loaded()
        return self._private_key.sign(data)

    def verify(
        self,
        signature: bytes,
        data: bytes,
        public_key: Optional[Union[ed25519.Ed25519PublicKey, bytes, str]] = None
    ) -> bool:
        """
        Verifies an Ed25519 digital signature over binary data.
        Returns True if valid, False otherwise.
        """
        pub = self.resolve_public_key(public_key) if public_key is not None else self.get_public_key()
        try:
            pub.verify(signature, data)
            return True
        except (InvalidSignature, Exception):
            return False

    @staticmethod
    def resolve_public_key(
        key_input: Union[ed25519.Ed25519PublicKey, bytes, str]
    ) -> ed25519.Ed25519PublicKey:
        """
        Helper to convert various public key representations (instance, PEM string,
        hex string, base64 string, or raw 32 bytes) into an Ed25519PublicKey.
        """
        if isinstance(key_input, ed25519.Ed25519PublicKey):
            return key_input
        if isinstance(key_input, str):
            clean = key_input.strip()
            if "-----BEGIN PUBLIC KEY-----" in clean:
                return serialization.load_pem_public_key(clean.encode("ascii"))
            # Check if 64 hex characters (32 bytes)
            if len(clean) == 64:
                try:
                    raw = bytes.fromhex(clean)
                    return ed25519.Ed25519PublicKey.from_public_bytes(raw)
                except ValueError:
                    pass
            # Try Base64 (44 characters for 32 bytes with padding)
            try:
                raw = base64.b64decode(clean)
                if len(raw) == 32:
                    return ed25519.Ed25519PublicKey.from_public_bytes(raw)
            except Exception:
                pass
            raise ValueError(f"Unable to parse Ed25519 public key string: {clean[:20]}...")
        if isinstance(key_input, (bytes, bytearray)):
            if b"-----BEGIN PUBLIC KEY-----" in key_input:
                return serialization.load_pem_public_key(key_input)
            if len(key_input) == 32:
                return ed25519.Ed25519PublicKey.from_public_bytes(bytes(key_input))
            raise ValueError(f"Invalid byte length for raw Ed25519 public key: {len(key_input)}")
        raise TypeError(f"Unsupported public key type: {type(key_input)}")

    def rotate_keys(self) -> Tuple[str, str]:
        """
        Rotates the scanner's keypair. Archives the old keys with a timestamp suffix
        and generates a fresh active keypair.
        Returns: (old_public_key_id, new_public_key_id)
        """
        old_pub_id = self.get_public_key_id()
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        if os.path.exists(self.private_key_path):
            os.rename(self.private_key_path, f"{self.private_key_path}.archive_{ts}")
        if os.path.exists(self.public_key_path):
            os.rename(self.public_key_path, f"{self.public_key_path}.archive_{ts}")
        self._generate_and_save_new_keypair()
        new_pub_id = self.get_public_key_id()
        return old_pub_id, new_pub_id

    def __repr__(self) -> str:
        # Never leak private key or secrets path in representation
        return f"<KeyManager pub_id='{self.get_public_key_id()}'>"


# Global singleton helper
_global_key_manager: Optional[KeyManager] = None


def get_key_manager() -> KeyManager:
    """Returns the process-wide KeyManager singleton."""
    global _global_key_manager
    if _global_key_manager is None:
        _global_key_manager = KeyManager()
    return _global_key_manager


def reset_key_manager() -> None:
    """Resets the singleton (primarily for testing key rotation and persistence)."""
    global _global_key_manager
    _global_key_manager = None
