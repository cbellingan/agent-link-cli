"""Modern, vetted cryptographic routines for AgentLink.

Uses standard Ed25519 for mutual authentication and digital signatures,
X25519 for Diffie-Hellman key exchange, and AES-256-GCM for message encryption.
"""

from __future__ import annotations
import base64
import hashlib
import json
import os
import stat
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from agent_link.security import AgentLinkSecurityError


def _default_key_dir() -> Path:
    if os.environ.get("AGENT_LINK_KEY_DIR"):
        return Path(os.environ["AGENT_LINK_KEY_DIR"])
    if os.environ.get("AGENT_LINK_STATE_DIR"):
        return Path(os.environ["AGENT_LINK_STATE_DIR"])
    return Path.home() / ".agent-link"


class AgentKeypair:
    """Manages an agent's asymmetric keys and E2EE cryptographic routines."""

    def __init__(
        self,
        ed25519_priv: Optional[ed25519.Ed25519PrivateKey] = None,
        x25519_priv: Optional[x25519.X25519PrivateKey] = None,
        agent_id: str = "agent",
        directory: Optional[Path] = None,
    ):
        self.agent_id = agent_id
        self._ed25519_priv = ed25519_priv or ed25519.Ed25519PrivateKey.generate()
        self._x25519_priv = x25519_priv or x25519.X25519PrivateKey.generate()
        self.directory = Path(directory) if directory else _default_key_dir()

    @property
    def ed25519_public(self) -> ed25519.Ed25519PublicKey:
        return self._ed25519_priv.public_key()

    @property
    def x25519_public(self) -> x25519.X25519PublicKey:
        return self._x25519_priv.public_key()

    @property
    def sign_pub_raw(self) -> bytes:
        return self.ed25519_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def enc_pub_raw(self) -> bytes:
        return self.x25519_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def sign_pub_b64(self) -> str:
        return base64.b64encode(self.sign_pub_raw).decode("ascii")

    @property
    def enc_pub_b64(self) -> str:
        return base64.b64encode(self.enc_pub_raw).decode("ascii")

    @property
    def kid(self) -> str:
        """Key ID: SHA-256 fingerprint of the public signing key."""
        h = hashlib.sha256(self.sign_pub_raw).hexdigest()[:16]
        return f"kid-{self.agent_id}-{h}"

    def sign(self, message: bytes) -> str:
        """Sign arbitrary data with Ed25519, returning base64 signature."""
        sig = self._ed25519_priv.sign(message)
        return base64.b64encode(sig).decode("ascii")

    @staticmethod
    def verify_signature(peer_sign_pub_b64: str, message: bytes, signature_b64: str) -> bool:
        """Verify peer signature against their public Ed25519 key."""
        try:
            peer_pub_bytes = base64.b64decode(peer_sign_pub_b64)
            peer_pub = ed25519.Ed25519PublicKey.from_public_bytes(peer_pub_bytes)
            sig_bytes = base64.b64decode(signature_b64)
            peer_pub.verify(sig_bytes, message)
            return True
        except Exception:
            return False

    def derive_shared_secret(self, peer_enc_pub_b64: str, link_id: Optional[str] = None) -> bytes:
        """Derive 256-bit AES symmetric key using X25519 ECDH and HKDF-SHA256.
        When link_id is provided, keys are salted and bound to that specific link.
        """
        peer_pub_bytes = base64.b64decode(peer_enc_pub_b64)
        peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
        shared_key = self._x25519_priv.exchange(peer_pub)

        if link_id:
            salt = hashlib.sha256(link_id.encode("utf-8")).digest()
            info = f"AgentLink-v2-E2EE:{link_id}".encode("utf-8")
        else:
            salt = hashlib.sha256(b"AgentLink-v2-default").digest()
            info = b"AgentLink-v2-E2EE:default"

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=info,
        ).derive(shared_key)
        return derived_key

    def encrypt(
        self,
        peer_enc_pub_b64: str,
        plaintext: bytes,
        aad: Optional[bytes] = None,
        link_id: Optional[str] = None,
    ) -> Dict[str, str]:
        """Encrypt message to peer using AES-256-GCM with optional AAD and link context."""
        aes_key = self.derive_shared_secret(peer_enc_pub_b64, link_id=link_id)
        aesgcm = AESGCM(aes_key)
        iv = os.urandom(12)
        ciphertext = aesgcm.encrypt(iv, plaintext, aad)
        return {
            "iv": base64.b64encode(iv).decode("ascii"),
            "data": base64.b64encode(ciphertext).decode("ascii"),
        }

    def decrypt(
        self,
        peer_enc_pub_b64: str,
        iv_b64: str,
        data_b64: str,
        aad: Optional[bytes] = None,
        link_id: Optional[str] = None,
    ) -> bytes:
        """Decrypt AES-256-GCM message from peer with optional AAD and link context."""
        aes_key = self.derive_shared_secret(peer_enc_pub_b64, link_id=link_id)
        aesgcm = AESGCM(aes_key)
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(data_b64)
        return aesgcm.decrypt(iv, ciphertext, aad)

    def create_envelope(
        self,
        link_id: str,
        recipient_id: str,
        peer_enc_pub_b64: str,
        plaintext: str,
        seq: int,
    ) -> Dict[str, Any]:
        """Create signed and encrypted v2 envelope bound to link_id, seq, and recipient."""
        nonce = os.urandom(16).hex()
        timestamp = int(time.time())
        aad = f"v2:{link_id}:{self.agent_id}:{recipient_id}:{seq}:{nonce}".encode("utf-8")
        enc_result = self.encrypt(
            peer_enc_pub_b64=peer_enc_pub_b64,
            plaintext=plaintext.encode("utf-8"),
            aad=aad,
            link_id=link_id,
        )
        iv_b64 = enc_result["iv"]
        data_b64 = enc_result["data"]
        canonical_str = f"v2:{link_id}:{self.agent_id}:{recipient_id}:{seq}:{timestamp}:{nonce}:{iv_b64}:{data_b64}"
        sig = self.sign(canonical_str.encode("utf-8"))

        return {
            "v": 2,
            "linkId": link_id,
            "senderId": self.agent_id,
            "recipientId": recipient_id,
            "seq": seq,
            "timestamp": timestamp,
            "nonce": nonce,
            "iv": iv_b64,
            "data": data_b64,
            "sig": sig,
        }

    def open_envelope(
        self,
        link_id: str,
        peer_sign_pub_b64: str,
        peer_enc_pub_b64: str,
        envelope: Dict[str, Any],
    ) -> str:
        """Verify Ed25519 signature, context binding, and decrypt AES-256-GCM envelope.
        
        Strictly enforces protocol v2: rejects unauthenticated legacy envelopes,
        missing signatures, or tampered context bindings (fail-closed).
        """
        v = envelope.get("v")
        if v != 2:
            raise AgentLinkSecurityError(
                f"Rejecting unauthenticated envelope (v={v}): v2 with mandatory Ed25519 signature and context binding is strictly required"
            )

        sender_id = envelope.get("senderId", "")
        recipient_id = envelope.get("recipientId", "")
        seq = envelope.get("seq", 0)
        timestamp = envelope.get("timestamp", 0)
        nonce = envelope.get("nonce", "")
        iv_b64 = envelope.get("iv", "")
        data_b64 = envelope.get("data", "")
        sig = envelope.get("sig", "")

        if not sig:
            raise AgentLinkSecurityError("Envelope missing mandatory digital signature ('sig')")

        # 1. Verify Ed25519 signature
        canonical_str = f"v2:{link_id}:{sender_id}:{recipient_id}:{seq}:{timestamp}:{nonce}:{iv_b64}:{data_b64}"
        if not self.verify_signature(peer_sign_pub_b64, canonical_str.encode("utf-8"), sig):
            raise AgentLinkSecurityError(
                f"Signature verification failed for message from '{sender_id}' on link '{link_id}'"
            )

        # 2. Decrypt with bound AAD and per-link key
        aad = f"v2:{link_id}:{sender_id}:{recipient_id}:{seq}:{nonce}".encode("utf-8")
        try:
            decrypted_bytes = self.decrypt(
                peer_enc_pub_b64=peer_enc_pub_b64,
                iv_b64=iv_b64,
                data_b64=data_b64,
                aad=aad,
                link_id=link_id,
            )
            return decrypted_bytes.decode("utf-8")
        except Exception as e:
            raise AgentLinkSecurityError(f"Decryption / context authentication failed: {e}") from e

    def save(self, directory: Optional[Path] = None) -> Path:
        """Save keypair to disk with 0600 file permissions."""
        dir_path = Path(directory) if directory else self.directory
        dir_path.mkdir(parents=True, exist_ok=True)
        self.directory = dir_path
        key_file = dir_path / f"{self.agent_id}.json"

        ed_raw = self._ed25519_priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        x_raw = self._x25519_priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

        data = {
            "agent_id": self.agent_id,
            "ed25519_priv_b64": base64.b64encode(ed_raw).decode("ascii"),
            "x25519_priv_b64": base64.b64encode(x_raw).decode("ascii"),
            "signPub": self.sign_pub_b64,
            "encPub": self.enc_pub_b64,
            "kid": self.kid,
        }

        # Write with strict permissions
        key_file.write_text(json.dumps(data, indent=2))
        key_file.chmod(stat.S_IRUSR | stat.S_IWUSR)
        return key_file

    @classmethod
    def load(cls, agent_id: str, directory: Optional[Path] = None) -> AgentKeypair:
        """Load existing keypair from disk. Raises FileNotFoundError if missing (typo protection)."""
        dir_path = Path(directory) if directory else _default_key_dir()
        key_file = dir_path / f"{agent_id}.json"

        if not key_file.exists():
            raise FileNotFoundError(
                f"Agent identity '{agent_id}' does not exist in {dir_path}. "
                f"Run 'python3 -m agent_link.cli keygen --agent-id {agent_id}' to create it."
            )

        data = json.loads(key_file.read_text())
        ed_bytes = base64.b64decode(data["ed25519_priv_b64"])
        x_bytes = base64.b64decode(data["x25519_priv_b64"])
        ed_priv = ed25519.Ed25519PrivateKey.from_private_bytes(ed_bytes)
        x_priv = x25519.X25519PrivateKey.from_private_bytes(x_bytes)
        return cls(ed25519_priv=ed_priv, x25519_priv=x_priv, agent_id=agent_id, directory=dir_path)

    @classmethod
    def keygen(cls, agent_id: str, directory: Optional[Path] = None, overwrite: bool = False) -> AgentKeypair:
        """Explicitly generate and persist a new agent identity."""
        dir_path = Path(directory) if directory else _default_key_dir()
        key_file = dir_path / f"{agent_id}.json"
        if key_file.exists() and not overwrite:
            return cls.load(agent_id, directory=dir_path)
        kp = cls(agent_id=agent_id, directory=dir_path)
        kp.save(dir_path)
        return kp
