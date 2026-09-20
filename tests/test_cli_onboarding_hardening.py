import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import patch

from agent_link.cli import main, cmd_keygen, cmd_connect, cmd_receive
from agent_link.crypto import AgentKeypair


import os


class TestCliOnboardingHardening(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.key_dir = Path(self.temp_dir.name)
        self.orig_state_dir = os.environ.get("AGENT_LINK_STATE_DIR")
        self.orig_key_dir = os.environ.get("AGENT_LINK_KEY_DIR")
        os.environ["AGENT_LINK_STATE_DIR"] = str(self.key_dir)
        os.environ["AGENT_LINK_KEY_DIR"] = str(self.key_dir)

    def tearDown(self):
        if self.orig_state_dir is not None:
            os.environ["AGENT_LINK_STATE_DIR"] = self.orig_state_dir
        else:
            os.environ.pop("AGENT_LINK_STATE_DIR", None)
        if self.orig_key_dir is not None:
            os.environ["AGENT_LINK_KEY_DIR"] = self.orig_key_dir
        else:
            os.environ.pop("AGENT_LINK_KEY_DIR", None)
        self.temp_dir.cleanup()

    def test_keygen_json_flag(self):
        """keygen --json emits compact JSON and suppresses ASCII QR code."""
        out = io.StringIO()
        with redirect_stdout(out):
            ret = main(["keygen", "--agent-id", "test-agent", "--key-dir", str(self.key_dir), "--json"])
        self.assertEqual(ret, 0)
        output = out.getvalue()
        self.assertNotIn("██", output)  # QR code suppressed
        data = json.loads(output)
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["agentId"], "test-agent")
        self.assertTrue(data["kid"].startswith("kid-test-agent-"))
        self.assertTrue(len(data["signPub"]) > 0)
        self.assertTrue(len(data["encPub"]) > 0)

    def test_keygen_quiet_flag(self):
        """keygen --quiet suppresses ASCII QR code and prints single-line confirmation."""
        out = io.StringIO()
        with redirect_stdout(out):
            ret = main(["keygen", "--agent-id", "quiet-agent", "--key-dir", str(self.key_dir), "--quiet"])
        self.assertEqual(ret, 0)
        output = out.getvalue()
        self.assertNotIn("██", output)
        self.assertIn("Generated keypair for 'quiet-agent'", output)

    def test_connect_non_interactive_guard(self):
        """connect without --once in non-interactive environment does not hang on stdin."""
        with patch("agent_link.cli.cmd_register", return_value=0), \
             patch("sys.stdin.isatty", return_value=False):
            out = io.StringIO()
            with redirect_stdout(out):
                ret = cmd_connect(
                    agent_id="auto-agent",
                    server="http://mock.local",
                    api_key="mock_key",
                    key_dir=str(self.key_dir),
                    once=False,
                    interactive=False,
                )
            self.assertEqual(ret, 0)
            self.assertIn("[AUTONOMOUS AGENT DETECTED]", out.getvalue())

    def test_receive_inbox_decrypt(self):
        """receive --inbox <FILE> --decrypt decrypts JSONL envelopes offline using local keypair."""
        # 1. Generate keypairs for Alice and Bob
        alice_kp = AgentKeypair.keygen(agent_id="alice", directory=self.key_dir)
        alice_kp.save(directory=self.key_dir)
        bob_kp = AgentKeypair.keygen(agent_id="bob", directory=self.key_dir)
        bob_kp.save(directory=self.key_dir)

        # 2. Alice seals a signed v2 envelope for Bob
        link_id = "link_alice_bob_test"
        msg_text = "Secret operational message from Alice to Bob"
        envelope = alice_kp.create_envelope(
            link_id=link_id,
            peer_enc_pub_b64=bob_kp.enc_pub_b64,
            recipient_id="bob",
            plaintext=msg_text,
            seq=1,
        )

        raw_relay_message = {
            "linkId": link_id,
            "senderId": "alice",
            "senderEncPub": alice_kp.enc_pub_b64,
            "senderSignPub": alice_kp.sign_pub_b64,
            "payload": envelope,
        }

        # 3. Write raw envelope into an inbox file
        inbox_file = self.key_dir / "inbox.jsonl"
        with inbox_file.open("w", encoding="utf-8") as f:
            record = {
                "received_at": "2026-09-18T20:00:00Z",
                "sha256": "fake_sha256_hash",
                "message": raw_relay_message,
            }
            f.write(json.dumps(record) + "\n")

        # 4. Bob runs receive --inbox <FILE> --decrypt --json
        out = io.StringIO()
        with redirect_stdout(out):
            ret = cmd_receive(
                agent_id="bob",
                server="http://mock.local",
                api_key="",
                key_dir=str(self.key_dir),
                inbox=str(inbox_file),
                decrypt=True,
                as_json=True,
            )
        self.assertEqual(ret, 0)
        output = json.loads(out.getvalue())
        self.assertEqual(output["status"], "ok")
        self.assertEqual(len(output["messages"]), 1)
        decrypted = output["messages"][0]
        self.assertEqual(decrypted["text"], msg_text)
        self.assertEqual(decrypted["senderId"], "alice")
        self.assertTrue(decrypted["encrypted"])
        self.assertTrue(decrypted["signed"])
        self.assertIsNone(decrypted["error"])

    def test_keygen_overwrite_flag(self):
        """keygen without --overwrite preserves existing keys; keygen with --overwrite generates fresh keys."""
        out1 = io.StringIO()
        with redirect_stdout(out1):
            ret1 = main(["keygen", "--agent-id", "rot-agent", "--key-dir", str(self.key_dir), "--json"])
        self.assertEqual(ret1, 0)
        data1 = json.loads(out1.getvalue())

        # Second run without --overwrite returns same keys
        out2 = io.StringIO()
        with redirect_stdout(out2):
            ret2 = main(["keygen", "--agent-id", "rot-agent", "--key-dir", str(self.key_dir), "--json"])
        self.assertEqual(ret2, 0)
        data2 = json.loads(out2.getvalue())
        self.assertEqual(data1["signPub"], data2["signPub"])
        self.assertEqual(data1["kid"], data2["kid"])

        # Third run with --overwrite generates fresh keypair
        out3 = io.StringIO()
        with redirect_stdout(out3):
            ret3 = main(["keygen", "--agent-id", "rot-agent", "--key-dir", str(self.key_dir), "--json", "--overwrite"])
        self.assertEqual(ret3, 0)
        data3 = json.loads(out3.getvalue())
        self.assertNotEqual(data1["signPub"], data3["signPub"])
        self.assertNotEqual(data1["kid"], data3["kid"])


if __name__ == "__main__":
    unittest.main()

