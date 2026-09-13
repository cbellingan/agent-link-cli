"""Tests for AgentLink CLI commands and Client with mock server."""

import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
from pathlib import Path
from agent_link.cli import main, parse_args
from agent_link.client import AgentLinkClient, AgentLinkError
from agent_link.crypto import AgentKeypair


class MockServerHandler(BaseHTTPRequestHandler):
    registered_agents = []
    flakey_counter = 0

    def do_POST(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer sec_apk_valid"):
            body = b'{"error": "invalid_api_key"}'
            self.send_response(401)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length))
        MockServerHandler.registered_agents.append(body)

        path = self.path
        if path == "/api/links/request":
            link_id = f"link_{body.get('agentAId')}_{body.get('agentBId')}"
            resp = json.dumps({
                "status": "ok",
                "link": {
                    "id": link_id,
                    "agentAId": body.get("agentAId"),
                    "agentBId": body.get("agentBId"),
                    "status": "pending_approval",
                    "note": body.get("note"),
                    "approvals": {
                        "human_1": True,
                        "human_2": False,
                    }
                }
            }).encode("utf-8")
        elif path == "/api/invites":
            resp = json.dumps({
                "status": "ok",
                "invite": {
                    "id": "inv_mock_123",
                    "recipientEmail": body.get("toEmail"),
                    "token": "tok_mock_456",
                    "safetyNumber": "482-915",
                },
                "safetyNumber": "482-915",
                "agentPrompt": "You are invited to establish an end-to-end encrypted (E2EE v2) peer link with agent...",
                "inviteUrl": "http://127.0.0.1:mock/?invite=tok_mock_456",
            }).encode("utf-8")
        elif path == "/api/bugs":
            resp = json.dumps({
                "status": "ok",
                "bugId": "bug_mock_12345",
                "report": body,
            }).encode("utf-8")
        elif path.startswith("/api/bugs/") and path.endswith("/resolve"):
            bug_id = path.split("/")[3]
            resp = json.dumps({
                "status": "ok",
                "bug": {
                    "id": bug_id,
                    "resolved": body.get("resolved", True),
                    "resolvedBy": body.get("resolvedBy", "test-agent"),
                    "resolutionNote": body.get("note"),
                }
            }).encode("utf-8")
        elif path.startswith("/api/links/") and (path.endswith("/send") or path.endswith("/message")):
            resp = json.dumps({"status": "ok", "delivered": True}).encode("utf-8")
        else:
            resp = json.dumps({
                "status": "ok",
                "agentId": body.get("id"),
                "pollUrl": f"/api/agents/{body.get('id')}/poll"
            }).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def do_GET(self):
        path = self.path
        if path == "/api/flakey-test":
            MockServerHandler.flakey_counter += 1
            if MockServerHandler.flakey_counter == 1:
                # Abruptly close connection without responding to simulate transient drop
                self.close_connection = True
                return
            resp = b'{"status": "recovered"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
            return

        if path.startswith("/api/links"):
            resp = json.dumps({
                "status": "ok",
                "links": [
                    {
                        "id": "link_mock_001",
                        "agentAId": "agent-cli-test",
                        "agentBId": "agent-peer",
                        "status": "active",
                        "recentMessages": [
                            {"id": "msg_1", "text": "preview"}
                        ]
                    }
                ]
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
            return

        if path.startswith("/api/agents/") and path.endswith("/poll"):
            resp = json.dumps({"status": "ok", "messages": []}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
            return

        if path.startswith("/api/agents/agent-peer"):
            resp = json.dumps({
                "status": "ok",
                "agent": {
                    "id": "agent-peer",
                    "kid": "kid-agent-peer-1",
                    "signPub": TestCli.peer_kp.sign_pub_b64,
                    "encPub": TestCli.peer_kp.enc_pub_b64,
                }
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
            return

        if path.startswith("/api/agents"):
            resp = json.dumps({
                "status": "ok",
                "agents": [
                    {"id": "agent-cli-test", "encPub": TestCli.keypair.enc_pub_b64},
                    {"id": "agent-peer", "encPub": TestCli.peer_kp.enc_pub_b64}
                ]
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
            return

        if path.startswith("/api/bugs"):
            resp = json.dumps({
                "status": "ok",
                "count": 1,
                "bugs": [
                    {
                        "id": "bug_mock_12345",
                        "agentId": "agent-cli-test",
                        "title": "ECDH curve ratchet negotiation failure",
                        "details": "Details here",
                        "severity": "high",
                        "timestamp": "2026-09-13T10:00:00Z",
                        "resolved": False,
                    }
                ]
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        pass


class TestCli(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(prefix="agent-link-test-")
        cls.server = HTTPServer(("127.0.0.1", 0), MockServerHandler)
        cls.port = cls.server.server_port
        cls.server_url = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.keypair = AgentKeypair(agent_id="agent-cli-test")
        cls.keypair.save(directory=Path(cls.temp_dir))
        cls.peer_kp = AgentKeypair(agent_id="agent-peer")
        cls.peer_kp.save(directory=Path(cls.temp_dir))

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        if os.path.exists(cls.temp_dir):
            shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_parse_args(self):
        args = parse_args(["keygen", "--agent-id", "my-test-agent", "--key-dir", self.temp_dir])
        self.assertEqual(args.command, "keygen")
        self.assertEqual(args.agent_id, "my-test-agent")

    def test_cmd_keygen(self):
        ret = main(["keygen", "--agent-id", "agent-cli-test", "--key-dir", self.temp_dir])
        self.assertEqual(ret, 0)

    def test_cmd_status(self):
        ret = main(["status", "--agent-id", "agent-cli-test", "--key-dir", self.temp_dir])
        self.assertEqual(ret, 0)

    def test_cmd_register_unauthorized_key(self):
        ret = main([
            "register",
            "--agent-id", "agent-cli-test",
            "--server", self.server_url,
            "--api-key", "invalid_key",
            "--key-dir", self.temp_dir,
        ])
        self.assertEqual(ret, 1)

    def test_cmd_register_authorized_key(self):
        MockServerHandler.registered_agents.clear()
        ret = main([
            "register",
            "--agent-id", "agent-cli-test-registered",
            "--server", self.server_url,
            "--api-key", "sec_apk_valid_12345",
            "--key-dir", self.temp_dir,
        ])
        self.assertEqual(ret, 0)
        self.assertEqual(len(MockServerHandler.registered_agents), 1)
        self.assertEqual(MockServerHandler.registered_agents[0]["id"], "agent-cli-test-registered")

    def test_client_get_links(self):
        client = AgentLinkClient(
            server_url=self.server_url,
            api_key="sec_apk_valid_12345",
            keypair=self.keypair,
        )
        links = client.get_links()
        self.assertIsInstance(links, list)
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0]["id"], "link_mock_001")

    def test_client_get_agents(self):
        client = AgentLinkClient(
            server_url=self.server_url,
            api_key="sec_apk_valid_12345",
            keypair=self.keypair,
        )
        peers = client.get_agents("agent-peer")
        self.assertEqual(len(peers), 1)
        self.assertEqual(peers[0]["id"], "agent-peer")
        self.assertEqual(peers[0]["encPub"], self.peer_kp.enc_pub_b64)

    def test_cmd_connect_once(self):
        ret = main([
            "connect",
            "--agent-id", "agent-cli-test",
            "--server", self.server_url,
            "--api-key", "sec_apk_valid_12345",
            "--key-dir", self.temp_dir,
            "--once",
        ])
        self.assertEqual(ret, 0)

    def test_cmd_send_to_peer(self):
        ret = main([
            "send",
            "--agent-id", "agent-cli-test",
            "--to", "agent-peer",
            "--message", "Automated test message",
            "--server", self.server_url,
            "--api-key", "sec_apk_valid_12345",
            "--key-dir", self.temp_dir,
        ])
        self.assertEqual(ret, 0)

    def test_client_retry_on_transient_failure(self):
        client = AgentLinkClient(
            server_url=self.server_url,
            api_key="sec_apk_valid_12345",
            keypair=self.keypair,
        )
        res = client._make_request("/api/flakey-test", method="GET")
        self.assertEqual(res.get("status"), "recovered")
        self.assertEqual(MockServerHandler.flakey_counter, 2)

    def test_cmd_invite_json(self):
        saved_stdout = sys.stdout
        try:
            sys.stdout = io.StringIO()
            ret = main([
                "invite",
                "--to", "collaborator@example.com",
                "--agent-id", "agent-cli-test",
                "--server", self.server_url,
                "--api-key", "sec_apk_valid_12345",
                "--key-dir", self.temp_dir,
                "--json",
            ])
            self.assertEqual(ret, 0)
            output = sys.stdout.getvalue()
            data = json.loads(output)
            self.assertEqual(data.get("status"), "ok")
            self.assertEqual(data.get("to"), "collaborator@example.com")
            self.assertEqual(data.get("safetyNumber"), "482-915")
            self.assertIn("You are invited", data.get("agentPrompt", ""))
            self.assertTrue(data.get("serverRegistered"))
            self.assertIn("collaborator@example.com", data.get("body", ""))
            self.assertIn("Safety & Verification", data.get("body", ""))
        finally:
            sys.stdout = saved_stdout

    def test_cmd_invite_with_target_agent_json(self):
        saved_stdout = sys.stdout
        try:
            sys.stdout = io.StringIO()
            ret = main([
                "invite",
                "--to", "collaborator@example.com",
                "--target-agent", "agent-peer",
                "--agent-id", "agent-cli-test",
                "--server", self.server_url,
                "--api-key", "sec_apk_valid_12345",
                "--key-dir", self.temp_dir,
                "--json",
            ])
            self.assertEqual(ret, 0)
            output = sys.stdout.getvalue()
            data = json.loads(output)
            self.assertEqual(data.get("status"), "ok")
            self.assertEqual(data.get("to"), "collaborator@example.com")
            self.assertTrue(data.get("serverRegistered"))
            # Confirm MockServerHandler received targetAgentId
            last_req = MockServerHandler.registered_agents[-1]
            self.assertEqual(last_req.get("targetAgentId"), "agent-peer")
        finally:
            sys.stdout = saved_stdout

    def test_cmd_link_request_json(self):
        saved_stdout = sys.stdout
        try:
            sys.stdout = io.StringIO()
            ret = main([
                "link-request",
                "--peer", "agent-peer",
                "--note", "Let's connect our agents securely",
                "--agent-id", "agent-cli-test",
                "--server", self.server_url,
                "--api-key", "sec_apk_valid_12345",
                "--key-dir", self.temp_dir,
                "--json",
            ])
            self.assertEqual(ret, 0)
            output = sys.stdout.getvalue()
            data = json.loads(output)
            self.assertEqual(data.get("status"), "ok")
            self.assertEqual(data["link"]["status"], "pending_approval")
            self.assertEqual(data["link"]["agentAId"], "agent-cli-test")
            self.assertEqual(data["link"]["agentBId"], "agent-peer")
            self.assertEqual(data["link"]["note"], "Let's connect our agents securely")
        finally:
            sys.stdout = saved_stdout

    def test_cmd_bug_report_json(self):
        saved_stdout = sys.stdout
        try:
            sys.stdout = io.StringIO()
            ret = main([
                "bug-report",
                "--title", "ECDH curve ratchet negotiation failure",
                "--details", "Encountered unexpected ephemeral key sequence from peer",
                "--severity", "high",
                "--agent-id", "agent-cli-test",
                "--server", self.server_url,
                "--api-key", "sec_apk_valid_12345",
                "--key-dir", self.temp_dir,
                "--json",
            ])
            self.assertEqual(ret, 0)
            output = sys.stdout.getvalue()
            data = json.loads(output)
            self.assertEqual(data.get("status"), "ok")
            self.assertEqual(data.get("bugId"), "bug_mock_12345")
            self.assertEqual(data["report"]["title"], "ECDH curve ratchet negotiation failure")
            self.assertEqual(data["report"]["severity"], "high")
        finally:
            sys.stdout = saved_stdout

    def test_client_bug_report_size_limit(self):
        client = AgentLinkClient(
            server_url=self.server_url,
            api_key="sec_apk_valid_12345",
            keypair=self.keypair,
        )
        oversized_details = "A" * 10240
        with self.assertRaises(AgentLinkError) as ctx:
            client.submit_bug_report(title="Too large", details=oversized_details)
        self.assertIn("10,240 bytes", str(ctx.exception))

    def test_cmd_bug_list_json(self):
        saved_stdout = sys.stdout
        try:
            sys.stdout = io.StringIO()
            ret = main([
                "bug-list",
                "--server", self.server_url,
                "--api-key", "sec_apk_valid_12345",
                "--json",
            ])
            self.assertEqual(ret, 0)
            output = sys.stdout.getvalue()
            data = json.loads(output)
            self.assertEqual(data.get("status"), "ok")
            self.assertGreaterEqual(data.get("count"), 1)
            self.assertEqual(data["bugs"][0]["id"], "bug_mock_12345")
        finally:
            sys.stdout = saved_stdout

    def test_cmd_bug_resolve_json(self):
        saved_stdout = sys.stdout
        try:
            sys.stdout = io.StringIO()
            ret = main([
                "bug-resolve",
                "--bug-id", "bug_mock_12345",
                "--note", "Fixed socket lifecycle and invite authentication",
                "--agent-id", "agent-cli-test",
                "--server", self.server_url,
                "--api-key", "sec_apk_valid_12345",
                "--key-dir", self.temp_dir,
                "--json",
            ])
            self.assertEqual(ret, 0)
            output = sys.stdout.getvalue()
            data = json.loads(output)
            self.assertEqual(data.get("status"), "ok")
            self.assertEqual(data["bug"]["id"], "bug_mock_12345")
            self.assertTrue(data["bug"]["resolved"])
            self.assertEqual(data["bug"]["resolutionNote"], "Fixed socket lifecycle and invite authentication")
        finally:
            sys.stdout = saved_stdout


if __name__ == "__main__":
    unittest.main()
