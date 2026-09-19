"""Lightweight HTTP client for AgentLink server communication using standard library urllib."""

from __future__ import annotations
import json
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from agent_link.crypto import AgentKeypair
from agent_link.qr import create_qr_payload
from agent_link.security import (
    AgentLinkError,
    AgentLinkSecurityError,
    AgentLinkAuthError,
    AgentLinkNotFoundError,
    AgentLinkNetworkError,
    AgentLinkTimeoutError,
    AgentLinkTruncatedResponseError,
    ReplayProtector,
)


class AgentLinkClient:
    """Client for registering and communicating with an AgentLink relay server."""

    def __init__(
        self,
        server_url: str,
        api_key: str,
        keypair: Optional[AgentKeypair] = None,
        agent_id: Optional[str] = None,
        state_dir: Optional[Path] = None,
    ):
        self.server_url = server_url.rstrip("/")
        self.api_key = (api_key or "").strip()
        self.keypair = keypair
        resolved_id = agent_id or (keypair.agent_id if keypair else None) or "client"
        self.agent_id = resolved_id
        self.registered = False
        resolved_state_dir = state_dir or (getattr(keypair, "directory", None) if keypair else None)
        # Replay state only exists when we hold the private keys (outbound signing).
        self.replay_protector = ReplayProtector(state_dir=resolved_state_dir, agent_id=self.agent_id) if keypair else None

    def _make_request(
        self,
        path: str,
        method: str = "GET",
        data: Optional[Dict[str, Any]] = None,
        timeout: int = 20,
    ) -> Dict[str, Any]:
        """Execute HTTP request with Bearer authorization, retries, and distinct error translation."""
        url = f"{self.server_url}{path}"
        agent_str = self.keypair.agent_id if self.keypair else "client"
        headers = {
            "Accept": "application/json",
            "User-Agent": f"AgentLink-CLI/{self.agent_id}",
        }
        # Attach Bearer token when configured. The relay requires authenticated
        # callers on read and poll endpoints to protect message queues from unauthorized draining.
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        body_bytes = None
        if data is not None:
            body_bytes = json.dumps(data).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=body_bytes, headers=headers, method=method)

        max_attempts = 3 if method.upper() == "GET" else 1
        for attempt in range(max_attempts):
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    resp_data = resp.read().decode("utf-8")
                    return json.loads(resp_data) if resp_data else {}
            except urllib.error.HTTPError as e:
                err_body = e.read().decode("utf-8")
                try:
                    err_json = json.loads(err_body)
                    msg = err_json.get("message") or err_json.get("error") or str(e)
                except Exception:
                    msg = err_body or str(e)

                if e.code in (401, 403):
                    raise AgentLinkAuthError(f"HTTP {e.code}: {msg}") from e
                elif e.code == 404:
                    raise AgentLinkNotFoundError(f"HTTP 404: {msg}") from e
                raise AgentLinkError(f"HTTP {e.code}: {msg}") from e
            except Exception as e:
                err_str = str(e).lower()
                is_timeout = "timeout" in err_str or "timed out" in err_str
                is_incomplete = (
                    "incompleteread" in err_str
                    or "truncat" in err_str
                    or "connection reset" in err_str
                    or "remotedisconnected" in err_str
                    or "remote end closed" in err_str
                )

                if attempt < max_attempts - 1 and (is_timeout or is_incomplete):
                    time.sleep(0.5 * (attempt + 1))
                    continue

                if is_timeout:
                    raise AgentLinkTimeoutError(f"Connection/read timed out reaching {path}: {e}") from e
                elif is_incomplete:
                    raise AgentLinkTruncatedResponseError(f"Premature stream termination or truncated read: {e}") from e
                raise AgentLinkNetworkError(f"AgentLink network error: {e}") from e

    def register(self) -> Dict[str, Any]:
        """Register agent with the server using the human-provisioned API key."""
        if not self.keypair:
            raise AgentLinkError("register() requires the local keypair; this client is identity-less.")
        qr_dict = create_qr_payload(self.keypair)
        payload = {
            "id": self.agent_id,
            "signPub": self.keypair.sign_pub_b64,
            "encPub": self.keypair.enc_pub_b64,
            "kid": self.keypair.kid,
            "qrPayload": json.dumps(qr_dict),
        }
        res = self._make_request("/api/agents/register", method="POST", data=payload)
        self.registered = True
        return res

    def poll_messages(self, timeout_seconds: int = 15) -> List[Dict[str, Any]]:
        """Long-poll the server for incoming messages, challenges, or assigned links."""
        ms = timeout_seconds * 1000
        path = f"/api/agents/{self.agent_id}/poll?timeout={ms}"
        try:
            res = self._make_request(path, method="GET", timeout=timeout_seconds + 5)
            return res.get("messages", [])
        except AgentLinkTimeoutError:
            return []
        except Exception as e:
            if "timed out" in str(e).lower() or "504" in str(e):
                return []
            raise

    def send_encrypted(
        self,
        link_id: str,
        peer_enc_pub_b64: str,
        plaintext: str,
        recipient_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Encrypt and dispatch signed v2 envelope over an active link."""
        if not self.keypair or not self.replay_protector:
            raise AgentLinkError("send_encrypted() requires the local keypair; this client is identity-less.")
        target_recipient = recipient_id or "peer"
        seq = self.replay_protector.next_outbound_seq(link_id)
        envelope = self.keypair.create_envelope(
            link_id=link_id,
            recipient_id=target_recipient,
            peer_enc_pub_b64=peer_enc_pub_b64,
            plaintext=plaintext,
            seq=seq,
        )
        data = {
            "senderId": self.agent_id,
            "payload": envelope,
        }
        return self._make_request(f"/api/links/{link_id}/send", method="POST", data=data)

    def send_message(self, link_id: str, text: str, allow_plaintext: bool = False) -> Dict[str, Any]:
        """Send message via the link message endpoint. Fail-closed unless explicitly allowed."""
        if not allow_plaintext:
            raise AgentLinkSecurityError(
                "Refusing to send unencrypted plaintext over link. "
                "Pass 'allow_plaintext=True' or '--plaintext' if you explicitly wish to transmit in the clear."
            )
        data = {
            "senderId": self.agent_id,
            "payload": text,
        }
        return self._make_request(f"/api/links/{link_id}/message", method="POST", data=data)

    def revoke_link(self, link_id: str) -> Dict[str, Any]:
        """Sever/revoke an active or pending link."""
        return self._make_request(f"/api/links/{link_id}", method="DELETE")

    def get_links(self) -> List[Dict[str, Any]]:
        """Fetch all links involving this agent."""
        path = f"/api/links?agentId={self.agent_id}"
        res = self._make_request(path, method="GET")
        all_links = res.get("links", [])
        my_id = self.agent_id
        return [l for l in all_links if l.get("agentAId") == my_id or l.get("agentBId") == my_id]

    def get_agents(self, agent_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Fetch registered agents fleet from the server (or single agent)."""
        if agent_id:
            try:
                res = self._make_request(f"/api/agents/{agent_id}", method="GET")
                agent = res.get("agent")
                return [agent] if agent else []
            except Exception:
                pass
        res = self._make_request("/api/agents", method="GET")
        return res.get("agents", [])

    def create_invite(
        self,
        to_email: str,
        note: Optional[str] = None,
        target_agent_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a secure email invitation on the AgentLink server for a collaborator."""
        payload = {
            "toEmail": to_email,
            "fromAgentId": self.agent_id,
            "note": note,
        }
        if target_agent_id:
            payload["targetAgentId"] = target_agent_id
        return self._make_request("/api/invites", method="POST", data=payload)

    def request_link(self, peer_agent_id: str, note: Optional[str] = None) -> Dict[str, Any]:
        """Request an end-to-end encrypted peer link with another agent.
        
        The link is established in 'pending_approval' state awaiting human operator authorization.
        """
        payload = {
            "agentAId": self.agent_id,
            "agentBId": peer_agent_id,
            "note": note,
        }
        return self._make_request("/api/links/request", method="POST", data=payload)

    def submit_bug_report(
        self,
        title: str,
        details: str,
        severity: str = "medium",
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Submit an autonomous operational bug report in cleartext to the AgentLink server.
        
        Strictly enforces the maximum payload size of 10 KB (10,240 bytes).
        """
        payload: Dict[str, Any] = {
            "agentId": self.agent_id,
            "title": title,
            "details": details,
            "severity": severity,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        if context:
            payload["context"] = context

        payload_bytes = json.dumps(payload).encode("utf-8")
        if len(payload_bytes) > 10240:
            raise AgentLinkError(
                f"Bug report payload is {len(payload_bytes)} bytes, exceeding the strict 10 KB (10,240 bytes) limit."
            )

        return self._make_request("/api/bugs", method="POST", data=payload)

    def get_bug_reports(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Fetch bug reports from the AgentLink server."""
        res = self._make_request(f"/api/bugs?limit={limit}", method="GET")
        return res.get("bugs", [])

    def resolve_bug_report(
        self,
        bug_id: str,
        resolved: bool = True,
        note: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Mark a bug report as resolved (or reopened) on the AgentLink server."""
        payload: Dict[str, Any] = {
            "resolved": resolved,
            "resolvedBy": self.keypair.agent_id if self.keypair else "CLI",
        }
        if note:
            payload["note"] = note
        return self._make_request(f"/api/bugs/{bug_id}/resolve", method="POST", data=payload)

