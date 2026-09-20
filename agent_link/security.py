"""Security invariants, replay protection, and error hierarchy for AgentLink."""

from __future__ import annotations
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, Optional


# ==========================================
# 1. Custom Exception Hierarchy
# ==========================================

class AgentLinkError(Exception):
    """Base exception for all AgentLink errors."""
    pass


class AgentLinkSecurityError(AgentLinkError):
    """Raised when cryptographic verification, signature, replay, or auth tag fails."""
    pass


class AgentLinkAuthError(AgentLinkError):
    """Raised on HTTP 401 Unauthorized or 403 Forbidden."""
    pass


class AgentLinkNotFoundError(AgentLinkError):
    """Raised on HTTP 404 Not Found."""
    pass


class AgentLinkNetworkError(AgentLinkError):
    """Raised on transport-level network errors."""
    pass


class AgentLinkTimeoutError(AgentLinkNetworkError):
    """Raised on connection or read timeouts."""
    pass


class AgentLinkTruncatedResponseError(AgentLinkNetworkError):
    """Raised when a stream is terminated mid-chunk or incomplete read occurs."""
    pass


# ==========================================
# 2. Replay Protection & Sequence Tracking
# ==========================================

class ReplayProtector:
    """Tracks monotonic sequence numbers and timestamps with atomic, concurrency-safe locking."""

    def __init__(
        self,
        state_dir: Optional[Path] = None,
        agent_id: str = "agent",
        server_url: Optional[str] = None,
    ):
        if state_dir is not None:
            self.state_dir = Path(state_dir)
        elif os.environ.get("AGENT_LINK_STATE_DIR"):
            self.state_dir = Path(os.environ["AGENT_LINK_STATE_DIR"])
        else:
            self.state_dir = Path.home() / ".agent-link"
        self.agent_id = agent_id
        self.server_url = (server_url or os.environ.get("AGENTLINK_SERVER") or "default").rstrip("/")
        self.store_file = self.state_dir / f"seq_store_{agent_id}.json"
        self.lock_file = self.state_dir / f"seq_store_{agent_id}.lock"
        self._data: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _get_lock(self):
        """Context manager to acquire an exclusive lock for atomic state updates."""
        class FileLock:
            def __init__(self, lock_path: Path):
                self.lock_path = lock_path
                self.fd = None

            def __enter__(self):
                self.lock_path.parent.mkdir(parents=True, exist_ok=True)
                self.fd = open(self.lock_path, "w")
                try:
                    import fcntl
                    fcntl.flock(self.fd, fcntl.LOCK_EX)
                except (ImportError, OSError):
                    pass
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                try:
                    import fcntl
                    fcntl.flock(self.fd, fcntl.LOCK_UN)
                except (ImportError, OSError):
                    pass
                if self.fd:
                    try:
                        self.fd.close()
                    except Exception:
                        pass

        return FileLock(self.lock_file)

    def _load(self) -> None:
        if self.store_file.exists():
            try:
                self._data = json.loads(self.store_file.read_text(encoding="utf-8"))
            except Exception:
                self._data = {}
        else:
            self._data = {}

    def _save_atomic(self) -> None:
        """Atomically persist state; fails visibly if persistence cannot be committed."""
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            tmp_file = self.state_dir / f".seq_store_{self.agent_id}.tmp.{os.getpid()}_{time.time()}"
            tmp_file.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
            os.replace(tmp_file, self.store_file)
        except Exception as e:
            raise AgentLinkSecurityError(f"Replay state persistence failed: {e}") from e

    def _resolve_link_state(self, link_id: str) -> Dict[str, Any]:
        """Find or create link state supporting both namespaced and legacy keys."""
        ns_key = f"{self.server_url}::{link_id}"
        if ns_key in self._data:
            return self._data[ns_key]
        if link_id in self._data:
            # Migrate legacy key to namespaced key
            self._data[ns_key] = self._data.pop(link_id)
            return self._data[ns_key]
        return self._data.setdefault(ns_key, {"outbound_seq": 0, "inbound_last_seq": 0})

    def next_outbound_seq(self, link_id: str) -> int:
        """Increment and return next outbound sequence number for a link using exclusive locking."""
        with self._get_lock():
            self._load()
            link_state = self._resolve_link_state(link_id)
            link_state["outbound_seq"] = int(link_state.get("outbound_seq", 0)) + 1
            self._save_atomic()
            return link_state["outbound_seq"]

    def check_inbound(
        self,
        link_id: str,
        sender_id: str,
        seq: int,
        timestamp: float,
        max_skew_seconds: float = 300.0,
    ) -> None:
        """Phase 1: Validate sequence monotonicity and timestamp freshness WITHOUT mutating state.
        
        A forged or corrupted envelope failing signature verification will not advance sequence state.
        Raises AgentLinkSecurityError if replay or clock skew is detected.
        """
        now = time.time()
        # 1. Timestamp Freshness Check
        skew = abs(now - timestamp)
        if skew > max_skew_seconds:
            raise AgentLinkSecurityError(
                f"Expired timestamp: message timestamp {timestamp} is {skew:.1f}s off from current time {now} (max allowed skew: {max_skew_seconds}s)"
            )

        # 2. Sequence Number Monotonicity Check (non-mutating)
        self._load()
        link_state = self._resolve_link_state(link_id)
        last_seq = int(link_state.get("inbound_last_seq", 0))

        if seq <= last_seq:
            raise AgentLinkSecurityError(
                f"Replay attack detected: inbound sequence number {seq} <= last seen sequence {last_seq} for link '{link_id}' from '{sender_id}'"
            )

    def commit_inbound(self, link_id: str, seq: int) -> None:
        """Phase 2: Atomically commit the inbound sequence number after cryptographic verification succeeds."""
        with self._get_lock():
            self._load()
            link_state = self._resolve_link_state(link_id)
            last_seq = int(link_state.get("inbound_last_seq", 0))
            if seq > last_seq:
                link_state["inbound_last_seq"] = seq
                self._save_atomic()

    def validate_inbound(
        self,
        link_id: str,
        sender_id: str,
        seq: int,
        timestamp: float,
        max_skew_seconds: float = 300.0,
    ) -> None:
        """Combined check and commit for backwards compatibility."""
        self.check_inbound(link_id=link_id, sender_id=sender_id, seq=seq, timestamp=timestamp, max_skew_seconds=max_skew_seconds)
        self.commit_inbound(link_id=link_id, seq=seq)


# ==========================================
# 3. Peer Key Pinning Store
# ==========================================

class PeerKeyStore:
    """Manages locally pinned peer cryptographic identities to prevent relay key substitution."""

    def __init__(self, state_dir: Optional[Path] = None, agent_id: str = "agent"):
        if state_dir is not None:
            self.state_dir = Path(state_dir)
        elif os.environ.get("AGENT_LINK_STATE_DIR"):
            self.state_dir = Path(os.environ["AGENT_LINK_STATE_DIR"])
        else:
            self.state_dir = Path.home() / ".agent-link"
        self.agent_id = agent_id
        self.store_file = self.state_dir / f"pinned_peers_{agent_id}.json"
        self._data: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _load(self) -> None:
        if self.store_file.exists():
            try:
                self._data = json.loads(self.store_file.read_text(encoding="utf-8"))
            except Exception:
                self._data = {}
        else:
            self._data = {}

    def _save(self) -> None:
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            tmp_file = self.state_dir / f".pinned_peers_{self.agent_id}.tmp.{os.getpid()}_{time.time()}"
            tmp_file.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
            os.replace(tmp_file, self.store_file)
        except Exception as e:
            raise AgentLinkSecurityError(f"Peer key pinning persistence failed: {e}") from e

    def _key(self, link_id: str, peer_id: str) -> str:
        return f"{link_id}::{peer_id}"

    def pin_peer(
        self,
        link_id: str,
        peer_id: str,
        sign_pub: str,
        enc_pub: str,
        kid: Optional[str] = None,
        safety_number: Optional[str] = None,
    ) -> None:
        """Pin the trusted keys for a peer on a link."""
        self._load()
        k = self._key(link_id, peer_id)
        self._data[k] = {
            "link_id": link_id,
            "peer_id": peer_id,
            "sign_pub": sign_pub,
            "enc_pub": enc_pub,
            "kid": kid,
            "safety_number": safety_number,
            "pinned_at": time.time(),
        }
        self._save()

    def get_pinned_peer(self, link_id: str, peer_id: str) -> Optional[Dict[str, Any]]:
        self._load()
        return self._data.get(self._key(link_id, peer_id))

    def verify_or_pin_peer(
        self,
        link_id: str,
        peer_id: str,
        sign_pub: str,
        enc_pub: str,
        kid: Optional[str] = None,
        safety_number: Optional[str] = None,
    ) -> bool:
        """Validate that the supplied keys match pinned keys, or pin them if first seen."""
        pinned = self.get_pinned_peer(link_id, peer_id)
        if pinned:
            # Check for key substitution
            if pinned.get("sign_pub") != sign_pub or pinned.get("enc_pub") != enc_pub:
                raise AgentLinkSecurityError(
                    f"Peer key substitution detected for peer '{peer_id}' on link '{link_id}'. "
                    f"Relay supplied public keys do not match locally pinned cryptographic identity."
                )
            return True
        else:
            # Pin initial keys
            self.pin_peer(link_id, peer_id, sign_pub, enc_pub, kid, safety_number)
            return True


# ==========================================
# 4. Untrusted Peer Content Framing
# ==========================================

def format_untrusted_box(sender_id: str, link_id: str, text: str, is_e2ee: bool = True, is_signed: bool = True) -> str:
    """Visually frame untrusted external peer text to protect against prompt/terminal injection."""
    status_parts = []
    if is_e2ee:
        status_parts.append("E2EE AES-256-GCM")
    if is_signed:
        status_parts.append("Ed25519 Verified")
    status_str = " | ".join(status_parts) if status_parts else "UNENCRYPTED PLAINTEXT"

    header = f"┌─── UNTRUSTED PEER CONTENT [From: {sender_id} | Link: {link_id} | {status_str}] ───"
    footer = "└" + "─" * (len(header) - 1)
    
    lines = text.split("\n")
    framed_body = "\n".join(f"│ {line}" for line in lines)
    return f"{header}\n{framed_body}\n{footer}"


# ==========================================
# 5. End-to-End Cryptographic Envelope Pipeline
# ==========================================

def process_inbound_envelope(
    m: Dict[str, Any],
    kp: Any,
    replay_protector: Optional[ReplayProtector] = None,
    peer_key_store: Optional[PeerKeyStore] = None,
    allow_plaintext: bool = False,
    active_link: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Cryptographically verify, validate replay state, decrypt, and frame an inbound message envelope.

    Enforces:
    1. Pinned peer key verification to prevent relay key substitution (E2E-015).
    2. Two-phase replay protection: freshness & sequence check occurs before decryption,
       while sequence state mutation is committed strictly after successful decryption (E2E-014).
    3. Fail-closed against plaintext: unencrypted strings are rejected unless allow_plaintext=True (E2E-016).
    4. Distinguishable verification statuses: verified=True only when cryptographic verification passes.
    """
    sender_id = m.get("senderId", "peer")
    link_id = m.get("linkId", "unknown")
    payload = m.get("payload")
    sender_enc_pub = m.get("senderEncPub") or (active_link.get("peerEncPub") if active_link else None)
    sender_sign_pub = m.get("senderSignPub") or (active_link.get("peerSignPub") if active_link else None)

    decrypted_text = ""
    is_e2ee = False
    is_signed = False
    is_verified = False
    error_note = None
    seq = None
    if isinstance(payload, dict):
        if payload.get("v") == 2:
            seq = payload.get("seq", 0)
            ts = payload.get("timestamp", 0)
            kid = payload.get("kid")

            try:
                # 1. Peer Key Pinning Check (E2E-015)
                if peer_key_store:
                    peer_key_store.verify_or_pin_peer(
                        link_id=link_id,
                        peer_id=sender_id,
                        sign_pub=sender_sign_pub or "",
                        enc_pub=sender_enc_pub or "",
                        kid=kid,
                    )

                # 2. Phase 1 Replay Pre-check (non-mutating) (E2E-014)
                if replay_protector:
                    replay_protector.check_inbound(
                        link_id=link_id,
                        sender_id=sender_id,
                        seq=seq,
                        timestamp=ts,
                    )

                # 3. Cryptographic Verification & Decryption
                if kp:
                    decrypted_text = kp.open_envelope(
                        link_id=link_id,
                        peer_sign_pub_b64=sender_sign_pub or "",
                        peer_enc_pub_b64=sender_enc_pub or "",
                        envelope=payload,
                    )
                else:
                    raise AgentLinkSecurityError("No local keypair available for decryption")

                # 4. Phase 2 Replay Commit (ONLY after signature verification succeeds) (E2E-014)
                if replay_protector:
                    replay_protector.commit_inbound(link_id=link_id, seq=seq)

                is_e2ee = True
                is_signed = True
                is_verified = True
            except Exception as sec_err:
                error_note = str(sec_err)
                decrypted_text = f"[SECURITY REJECTION: {sec_err}]"

        elif "iv" in payload and "data" in payload:
            error_note = "Legacy unauthenticated v1 envelope rejected (protocol v2 with Ed25519 signature required)"
            decrypted_text = f"[SECURITY REJECTION: {error_note}]"
        else:
            error_note = "Unrecognized envelope format"
            decrypted_text = f"[SECURITY REJECTION: {error_note}]"

    elif isinstance(payload, str):
        if allow_plaintext:
            decrypted_text = payload
            is_verified = False
        else:
            error_note = "Plaintext payload rejected by policy (use --allow-plaintext to accept)"
            decrypted_text = f"[SECURITY REJECTION: {error_note}]"
    else:
        error_note = "Empty or missing payload"
        decrypted_text = f"[SECURITY REJECTION: {error_note}]"

    status = "verified" if is_verified else ("plaintext" if (isinstance(payload, str) and allow_plaintext) else "rejected")

    return {
        "linkId": link_id,
        "senderId": sender_id,
        "text": decrypted_text,
        "encrypted": is_e2ee,
        "signed": is_signed,
        "verified": is_verified,
        "status": status,
        "error": error_note,
        "seq": seq,
    }

