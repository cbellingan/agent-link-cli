"""Unit tests for Feature 10: Graceful upgrades, 503 Retry-After backoff, and persistence error handling."""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

from agent_link.client import AgentLinkClient
from agent_link.security import (
    AgentLinkPersistenceError,
    AgentLinkServiceUnavailableError,
)


class MockUpgradeHandler(BaseHTTPRequestHandler):
    fail_count = 0
    mode = "transient_503"

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"

        if MockUpgradeHandler.mode == "transient_503":
            if MockUpgradeHandler.fail_count > 0:
                MockUpgradeHandler.fail_count -= 1
                self.send_response(503)
                self.send_header("Content-Type", "application/json")
                self.send_header("Retry-After", "0.01")
                resp = json.dumps({"error": "server_shutting_down", "message": "Upgrading"}).encode("utf-8")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)
                return
            else:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                resp = json.dumps({"status": "ok", "delivered": True}).encode("utf-8")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)
                return

        elif MockUpgradeHandler.mode == "permanent_503":
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Retry-After", "0.01")
            resp = json.dumps({"error": "server_shutting_down", "message": "Shutting down"}).encode("utf-8")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
            return

        elif MockUpgradeHandler.mode == "persistence_500":
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            resp = json.dumps({"error": "persistence_error", "message": "Failed to persist state: disk full"}).encode("utf-8")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
            return

    def log_message(self, *args):
        pass


class TestPredictableUpgrades(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), MockUpgradeHandler)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_transient_503_retries_with_backoff_and_succeeds(self):
        MockUpgradeHandler.mode = "transient_503"
        MockUpgradeHandler.fail_count = 1  # Fails once with 503, succeeds on retry 2
        client = AgentLinkClient(
            server_url=f"http://127.0.0.1:{self.port}",
            api_key="test_key",
        )
        res = client._make_request("/api/test", method="POST", data={"hello": "world"})
        self.assertEqual(res.get("status"), "ok")

    def test_permanent_503_raises_service_unavailable_with_retry_after(self):
        MockUpgradeHandler.mode = "permanent_503"
        client = AgentLinkClient(
            server_url=f"http://127.0.0.1:{self.port}",
            api_key="test_key",
        )
        with self.assertRaises(AgentLinkServiceUnavailableError) as ctx:
            client._make_request("/api/test", method="POST", data={"hello": "world"})
        self.assertIn("503", str(ctx.exception))
        self.assertAlmostEqual(ctx.exception.retry_after, 0.01)

    def test_persistence_500_raises_persistence_error(self):
        MockUpgradeHandler.mode = "persistence_500"
        client = AgentLinkClient(
            server_url=f"http://127.0.0.1:{self.port}",
            api_key="test_key",
        )
        with self.assertRaises(AgentLinkPersistenceError) as ctx:
            client._make_request("/api/test", method="POST", data={"hello": "world"})
        self.assertIn("persistence_error", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
