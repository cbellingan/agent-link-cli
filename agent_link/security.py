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
    """Tracks monotonic sequence numbers and timestamps to prevent replay and re-ordering."""

    def __init__(self, state_dir: Optional[Path] = None, agent_id: str = "agent"):
        if state_dir is not None:
            self.state_dir = Path(state_dir)
        elif os.environ.get("AGENT_LINK_STATE_DIR"):
            self.state_dir = Path(os.environ["AGENT_LINK_STATE_DIR"])
        else:
            self.state_dir = Path.home() / ".agent-link"
        self.agent_id = agent_id
        self.store_file = self.state_dir / f"seq_store_{agent_id}.json"
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
            self.store_file.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
        except Exception:
            pass

    def next_outbound_seq(self, link_id: str) -> int:
        """Increment and return next outbound sequence number for a link."""
        link_state = self._data.setdefault(link_id, {"outbound_seq": 0, "inbound_last_seq": 0})
        link_state["outbound_seq"] = int(link_state.get("outbound_seq", 0)) + 1
        self._save()
        return link_state["outbound_seq"]

    def validate_inbound(
        self,
        link_id: str,
        sender_id: str,
        seq: int,
        timestamp: float,
        max_skew_seconds: float = 300.0,
    ) -> None:
        """Validate sequence monotonicity and timestamp freshness.
        
        Raises AgentLinkSecurityError if replay or clock skew is detected.
        """
        now = time.time()
        # 1. Timestamp Freshness Check
        skew = abs(now - timestamp)
        if skew > max_skew_seconds:
            raise AgentLinkSecurityError(
                f"Expired timestamp: message timestamp {timestamp} is {skew:.1f}s off from current time {now} (max allowed skew: {max_skew_seconds}s)"
            )

        # 2. Sequence Number Monotonicity Check
        link_state = self._data.setdefault(link_id, {"outbound_seq": 0, "inbound_last_seq": 0})
        last_seq = int(link_state.get("inbound_last_seq", 0))

        if seq <= last_seq:
            raise AgentLinkSecurityError(
                f"Replay attack detected: inbound sequence number {seq} <= last seen sequence {last_seq} for link '{link_id}' from '{sender_id}'"
            )

        # Update last seen sequence
        link_state["inbound_last_seq"] = seq
        self._save()


# ==========================================
# 3. Untrusted Peer Content Framing
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
