"""Unit tests for Feature 9: Durable delivery, client retries, and receipt-before-ack."""

import io
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch

from agent_link.cli import (
    _watch_batch,
    cmd_send,
)
from agent_link.client import AgentLinkClient
from agent_link.crypto import AgentKeypair


class MockRelayHandler(BaseHTTPRequestHandler):
    """Mock relay HTTP handler recording requests and returning durable delivery responses."""

    last_request_method = None
    last_request_path = None
    last_request_body = None

    def do_POST(self):
        MockRelayHandler.last_request_method = "POST"
        MockRelayHandler.last_request_path = self.path
        length = int(self.headers.get("Content-Length", 0))
        MockRelayHandler.last_request_body = json.loads(self.rfile.read(length).decode("utf-8"))

        if "/send" in self.path:
            body = json.dumps({
                "status": "ok",
                "state": "accepted",
                "accepted": True,
                "delivered": False,
                "msgId": MockRelayHandler.last_request_body.get("msgId", "msg_test"),
                "seq": 1,
            }).encode("utf-8")
        elif "/ack" in self.path:
            body = json.dumps({
                "status": "ok",
                "acknowledged": MockRelayHandler.last_request_body.get("messageIds", []),
                "count": len(MockRelayHandler.last_request_body.get("messageIds", [])),
            }).encode("utf-8")
        elif "/nack" in self.path:
            body = json.dumps({
                "status": "ok",
                "nacked": MockRelayHandler.last_request_body.get("messageIds", []),
                "action": MockRelayHandler.last_request_body.get("action", "requeue"),
            }).encode("utf-8")
        else:
            body = b'{"status": "ok"}'

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        MockRelayHandler.last_request_method = "GET"
        MockRelayHandler.last_request_path = self.path
        MockRelayHandler.last_request_body = None

        if "/poll" in self.path:
            body = json.dumps({
                "status": "ok",
                "leaseId": "lease_abc123",
                "leaseExpiresAt": 1789999999000,
                "messages": [
                    {
                        "msgId": "msg_001",
                        "senderId": "bob",
                        "linkId": "link_123",
                        "payload": "Hello durable world",
                    }
                ],
            }).encode("utf-8")
        else:
            body = b'{"status": "ok"}'

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def run_server():
    server = HTTPServer(("127.0.0.1", 0), MockRelayHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


class TestDurableDeliveryClient(unittest.TestCase):
    def setUp(self):
        self.server = run_server()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.temp_dir.name)
        self.keypair = AgentKeypair(agent_id="alice")
        self.keypair.save(directory=self.state_dir)
        self.client = AgentLinkClient(
            server_url=self.base_url,
            api_key="test-key",
            keypair=self.keypair,
            agent_id="alice",
            state_dir=self.state_dir,
        )

    def tearDown(self):
        self.server.shutdown()
        self.temp_dir.cleanup()

    def test_envelope_includes_client_msg_id(self):
        peer_kp = AgentKeypair(agent_id="bob")
        envelope = self.keypair.create_envelope(
            link_id="link_123",
            recipient_id="bob",
            peer_enc_pub_b64=peer_kp.enc_pub_b64,
            plaintext="secure-payload",
            seq=1,
            msg_id="msg_custom_456",
        )
        self.assertEqual(envelope["msgId"], "msg_custom_456")
        self.assertEqual(envelope["v"], 2)

    def test_send_encrypted_attaches_msg_id(self):
        peer_kp = AgentKeypair(agent_id="bob")
        res = self.client.send_encrypted(
            link_id="link_123",
            peer_enc_pub_b64=peer_kp.enc_pub_b64,
            plaintext="secret content",
            recipient_id="bob",
            msg_id="msg_fixed_id_100",
        )
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["state"], "accepted")
        self.assertTrue(res["accepted"])
        self.assertFalse(res["delivered"])
        self.assertEqual(res["msgId"], "msg_fixed_id_100")

        # Verify request body sent over wire
        self.assertEqual(MockRelayHandler.last_request_body["msgId"], "msg_fixed_id_100")
        self.assertEqual(MockRelayHandler.last_request_body["senderId"], "alice")
        self.assertEqual(MockRelayHandler.last_request_body["payload"]["msgId"], "msg_fixed_id_100")

    def test_poll_and_lease_tracking(self):
        messages = self.client.poll_messages(timeout_seconds=2)
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["msgId"], "msg_001")
        self.assertEqual(self.client.last_lease_id, "lease_abc123")

        # poll_batch preserves lease metadata
        batch = self.client.poll_batch(timeout_seconds=2)
        self.assertEqual(batch["leaseId"], "lease_abc123")
        self.assertEqual(len(batch["messages"]), 1)

    def test_explicit_ack_messages(self):
        self.client.last_lease_id = "lease_test_789"
        res = self.client.ack_messages(["msg_001", "msg_002"])
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["count"], 2)
        self.assertEqual(MockRelayHandler.last_request_path, "/api/agents/alice/ack")
        self.assertEqual(MockRelayHandler.last_request_body["leaseId"], "lease_test_789")
        self.assertEqual(MockRelayHandler.last_request_body["messageIds"], ["msg_001", "msg_002"])

    def test_explicit_nack_messages(self):
        res = self.client.nack_messages(["msg_corrupt_001"], action="quarantine")
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["action"], "quarantine")
        self.assertEqual(MockRelayHandler.last_request_path, "/api/agents/alice/nack")
        self.assertEqual(MockRelayHandler.last_request_body["action"], "quarantine")
        self.assertEqual(MockRelayHandler.last_request_body["messageIds"], ["msg_corrupt_001"])

    def test_watch_batch_durably_writes_to_disk_before_ack(self):
        inbox_file = self.state_dir / "inbox.jsonl"
        seen = set()

        ack_calls = []
        original_ack = self.client.ack_messages

        def wrapped_ack(msg_ids, lease_id=None):
            # Assert file exists and has content before ack is called!
            self.assertTrue(inbox_file.exists())
            content = inbox_file.read_text(encoding="utf-8")
            self.assertIn("msg_001", content)
            ack_calls.append((msg_ids, lease_id))
            return original_ack(msg_ids, lease_id)

        self.client.ack_messages = wrapped_ack

        count = _watch_batch(
            self.client,
            inbox_path=inbox_file,
            seen=seen,
            timeout=1,
            decrypt=False,
            as_json=True,
            allow_plaintext=True,
        )

        self.assertEqual(count, 1)
        self.assertEqual(len(ack_calls), 1)
        self.assertEqual(ack_calls[0][0], ["msg_001"])
        self.assertEqual(ack_calls[0][1], "lease_abc123")

    def test_cmd_send_prints_acceptance_output(self):
        peer_kp = AgentKeypair(agent_id="bob")
        peer_kp.save(directory=self.state_dir)

        # Mock links lookup to return active link
        with patch.object(AgentLinkClient, "get_links", return_value=[{
            "id": "link_123",
            "agentAId": "alice",
            "agentBId": "bob",
            "status": "active",
        }]), patch.object(AgentLinkClient, "get_agents", return_value=[{
            "id": "bob",
            "agentId": "bob",
            "encPub": peer_kp.enc_pub_b64,
            "signPub": peer_kp.sign_pub_b64,
            "kid": peer_kp.kid,
        }]):
            stdout_buf = io.StringIO()
            with redirect_stdout(stdout_buf):
                rc = cmd_send(
                    agent_id="alice",
                    server=self.base_url,
                    api_key="test-key",
                    message="Hello durable relay",
                    key_dir=str(self.state_dir),
                    to="bob",
                )
            self.assertEqual(rc, 0)
            output = stdout_buf.getvalue()
            self.assertIn("Message accepted by relay", output)
            self.assertIn("state: accepted", output)
            self.assertIn("awaiting recipient receipt/ack", output)


if __name__ == "__main__":
    unittest.main()
