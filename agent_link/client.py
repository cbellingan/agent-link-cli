"""Lightweight HTTP client for AgentLink server communication using standard library urllib."""

from __future__ import annotations
import json
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from agent_link.crypto import AgentKeypair
from agent_link.qr import create_qr_payload


class AgentLinkClient:
    """Client for registering and communicating with an AgentLink relay server."""

    def __init__(self, server_url: str, api_key: str, keypair: AgentKeypair):
        self.server_url = server_url.rstrip("/")
        self.api_key = api_key.strip()
        self.keypair = keypair
        self.registered = False

    def _make_request(
        self,
        path: str,
        method: str = "GET",
        data: Optional[Dict[str, Any]] = None,
        timeout: int = 20,
    ) -> Dict[str, Any]:
        """Execute HTTP request with Bearer authorization and error translation."""
        url = f"{self.server_url}{path}"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
            "User-Agent": f"AgentLink-CLI/{self.keypair.agent_id}",
        }

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
                raise RuntimeError(f"HTTP {e.code}: {msg}") from e
            except Exception as e:
                if attempt < max_attempts - 1:
                    time.sleep(0.5 * (attempt + 1))
                    continue
                raise RuntimeError(f"AgentLink network error: {e}") from e

    def register(self) -> Dict[str, Any]:
        """Register agent with the server using the human-provisioned API key."""
        qr_dict = create_qr_payload(self.keypair)
        payload = {
            "id": self.keypair.agent_id,
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
        path = f"/api/agents/{self.keypair.agent_id}/poll?timeout={ms}"
        try:
            res = self._make_request(path, method="GET", timeout=timeout_seconds + 5)
            return res.get("messages", [])
        except RuntimeError as e:
            if "timed out" in str(e).lower() or "504" in str(e):
                return []
            raise

    def send_encrypted(self, link_id: str, peer_enc_pub_b64: str, plaintext: str) -> Dict[str, Any]:
        """Encrypt and dispatch payload over an active link."""
        ciphertext_dict = self.keypair.encrypt(peer_enc_pub_b64, plaintext.encode("utf-8"))
        data = {
            "senderId": self.keypair.agent_id,
            "payload": ciphertext_dict,
        }
        return self._make_request(f"/api/links/{link_id}/send", method="POST", data=data)

    def send_message(self, link_id: str, text: str) -> Dict[str, Any]:
        """Send message via the link message endpoint."""
        data = {
            "senderId": self.keypair.agent_id,
            "payload": text,
        }
        return self._make_request(f"/api/links/{link_id}/message", method="POST", data=data)

    def get_links(self) -> List[Dict[str, Any]]:
        """Fetch all links involving this agent."""
        path = f"/api/links?agentId={self.keypair.agent_id}"
        res = self._make_request(path, method="GET")
        all_links = res.get("links", [])
        my_id = self.keypair.agent_id
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
