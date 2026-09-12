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
from agent_link.client import AgentLinkClient
from agent_link.crypto import AgentKeypair


class MockServerHandler(BaseHTTPRequestHandler):
    registered_agents = []

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
        if path.startswith("/api/links/") and (path.endswith("/send") or path.endswith("/message")):
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


if __name__ == "__main__":
    unittest.main()
