"""Tests for AgentLink CLI commands with mock server."""

import io
import json
import sys
import unittest
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
from agent_link.cli import main, parse_args
from agent_link.crypto import AgentKeypair


class MockServerHandler(BaseHTTPRequestHandler):
    registered_agents = []

    def do_POST(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer sec_apk_valid"):
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "invalid_api_key"}')
            return

        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length))
        MockServerHandler.registered_agents.append(body)

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({
            "status": "ok",
            "agentId": body.get("id"),
            "pollUrl": f"/api/agents/{body.get('id')}/poll"
        }).encode("utf-8"))

    def log_message(self, format, *args):
        pass


class TestCli(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), MockServerHandler)
        cls.port = cls.server.server_port
        cls.server_url = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_parse_args(self):
        args = parse_args(["keygen", "--agent-id", "my-test-agent"])
        self.assertEqual(args.command, "keygen")
        self.assertEqual(args.agent_id, "my-test-agent")

    def test_cmd_keygen(self):
        ret = main(["keygen", "--agent-id", "agent-cli-test"])
        self.assertEqual(ret, 0)

    def test_cmd_status(self):
        ret = main(["status", "--agent-id", "agent-cli-test"])
        self.assertEqual(ret, 0)

    def test_cmd_register_unauthorized_key(self):
        ret = main([
            "register",
            "--agent-id", "agent-cli-test",
            "--server", self.server_url,
            "--api-key", "invalid_key",
        ])
        self.assertEqual(ret, 1)

    def test_cmd_register_authorized_key(self):
        MockServerHandler.registered_agents.clear()
        ret = main([
            "register",
            "--agent-id", "agent-cli-test-registered",
            "--server", self.server_url,
            "--api-key", "sec_apk_valid_12345",
        ])
        self.assertEqual(ret, 0)
        self.assertEqual(len(MockServerHandler.registered_agents), 1)
        self.assertEqual(MockServerHandler.registered_agents[0]["id"], "agent-cli-test-registered")


if __name__ == "__main__":
    unittest.main()
