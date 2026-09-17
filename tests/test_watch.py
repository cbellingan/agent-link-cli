"""Tests for `receive --watch` inbox daemon and anonymous polling."""

import io
import json
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from agent_link.cli import (
    _envelope_hash,
    _load_seen_hashes,
    _watch_batch,
    cmd_receive,
)
from agent_link.client import AgentLinkClient


class StubClient:
    """Minimal stand-in exposing poll_messages() for _watch_batch tests."""

    def __init__(self, batches):
        self.batches = list(batches)

    def poll_messages(self, timeout_seconds=15):
        return self.batches.pop(0) if self.batches else []


def make_msg(i):
    return {"senderId": "ted", "linkId": "link-1", "payload": {"v": 2, "seq": i}}


class CaptureHandler(BaseHTTPRequestHandler):
    """Records request headers; answers poll with an empty queue."""

    last_headers = None

    def do_GET(self):
        CaptureHandler.last_headers = dict(self.headers)
        body = b'{"messages": []}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def run_server(handler_cls):
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


class TestEnvelopeHash(unittest.TestCase):
    def test_stable_and_key_order_insensitive(self):
        a = {"b": 1, "a": {"y": 2, "x": 1}}
        b = {"a": {"x": 1, "y": 2}, "b": 1}
        self.assertEqual(_envelope_hash(a), _envelope_hash(b))

    def test_distinguishes_messages(self):
        self.assertNotEqual(_envelope_hash(make_msg(1)), _envelope_hash(make_msg(2)))


class TestWatchBatch(unittest.TestCase):
    def test_appends_and_emits_new(self):
        with tempfile.TemporaryDirectory() as td:
            inbox = Path(td) / "inbox.jsonl"
            seen = set()
            client = StubClient([[make_msg(1), make_msg(2)]])
            buf = io.StringIO()
            with redirect_stdout(buf):
                new_count = _watch_batch(client, inbox, seen, timeout=1)
            self.assertEqual(new_count, 2)

            lines = inbox.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 2)
            for line, i in zip(lines, (1, 2)):
                record = json.loads(line)
                self.assertIn("received_at", record)
                self.assertEqual(record["sha256"], _envelope_hash(make_msg(i)))
                self.assertEqual(record["message"], make_msg(i))

            emitted = [json.loads(l) for l in buf.getvalue().splitlines()]
            self.assertEqual(emitted, [make_msg(1), make_msg(2)])

    def test_dedupes_within_and_across_batches(self):
        with tempfile.TemporaryDirectory() as td:
            inbox = Path(td) / "inbox.jsonl"
            seen = set()
            client = StubClient([[make_msg(1), make_msg(1)], [make_msg(1), make_msg(2)]])
            with redirect_stdout(io.StringIO()):
                self.assertEqual(_watch_batch(client, inbox, seen, timeout=1), 1)
                self.assertEqual(_watch_batch(client, inbox, seen, timeout=1), 1)
            self.assertEqual(len(inbox.read_text(encoding="utf-8").splitlines()), 2)

    def test_skips_non_dict_messages(self):
        with tempfile.TemporaryDirectory() as td:
            inbox = Path(td) / "inbox.jsonl"
            client = StubClient([["not-a-dict", None, make_msg(3)]])
            with redirect_stdout(io.StringIO()):
                self.assertEqual(_watch_batch(client, inbox, set(), timeout=1), 1)

    def test_restart_does_not_reemit(self):
        with tempfile.TemporaryDirectory() as td:
            inbox = Path(td) / "inbox.jsonl"
            client = StubClient([[make_msg(1)]])
            with redirect_stdout(io.StringIO()):
                _watch_batch(client, inbox, set(), timeout=1)

            # Simulate a daemon restart: rebuild dedupe state from the inbox file.
            seen = _load_seen_hashes(inbox)
            self.assertEqual(len(seen), 1)
            buf = io.StringIO()
            with redirect_stdout(buf):
                new_count = _watch_batch(StubClient([[make_msg(1)]]), inbox, seen, timeout=1)
            self.assertEqual(new_count, 0)
            self.assertEqual(buf.getvalue(), "")
            self.assertEqual(len(inbox.read_text(encoding="utf-8").splitlines()), 1)

    def test_load_seen_hashes_tolerates_garbage(self):
        with tempfile.TemporaryDirectory() as td:
            inbox = Path(td) / "inbox.jsonl"
            inbox.write_text("not json\n{\"message\": \"nope\"}\n", encoding="utf-8")
            self.assertEqual(_load_seen_hashes(inbox), set())


class TestAnonymousPoll(unittest.TestCase):
    def test_no_authorization_header_without_api_key(self):
        server = run_server(CaptureHandler)
        try:
            url = f"http://127.0.0.1:{server.server_port}"
            client = AgentLinkClient(server_url=url, api_key="", keypair=None, agent_id="anon")
            self.assertEqual(client.poll_messages(timeout_seconds=1), [])
            self.assertNotIn("Authorization", CaptureHandler.last_headers)
            self.assertIn("anon", CaptureHandler.last_headers.get("User-Agent", ""))
        finally:
            server.shutdown()

    def test_identity_less_client_rejects_signing_ops(self):
        client = AgentLinkClient(server_url="http://127.0.0.1:1", api_key="", agent_id="anon")
        with self.assertRaises(Exception):
            client.register()
        with self.assertRaises(Exception):
            client.send_encrypted("link-1", "peer-pub", "hi")

    def test_receive_requires_key_or_no_auth(self):
        # No key and no --no-auth: fail fast before any network use.
        rc = cmd_receive("x", "http://127.0.0.1:1", api_key="", no_auth=False)
        self.assertEqual(rc, 1)

    def test_receive_no_auth_single_shot_empty_queue(self):
        from agent_link.crypto import AgentKeypair

        server = run_server(CaptureHandler)
        try:
            url = f"http://127.0.0.1:{server.server_port}"
            with tempfile.TemporaryDirectory() as td:
                AgentKeypair(agent_id="anon").save(directory=Path(td))
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = cmd_receive("anon", url, api_key="", key_dir=td, no_auth=True, timeout=1)
            self.assertEqual(rc, 0)
            self.assertNotIn("Authorization", CaptureHandler.last_headers)
        finally:
            server.shutdown()


if __name__ == "__main__":
    unittest.main()
