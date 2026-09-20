"""Tests for client identity verification, two-phase replay protection, and peer key pinning."""

import base64
import os
import shutil
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from agent_link.crypto import AgentKeypair
from agent_link.security import (
    AgentLinkSecurityError,
    PeerKeyStore,
    ReplayProtector,
    process_inbound_envelope,
)


class TestReplayAndIdentityHardening(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp(prefix="agentlink-replay-test-"))
        self.alice_kp = AgentKeypair.keygen(agent_id="alice", directory=self.temp_dir)
        self.bob_kp = AgentKeypair.keygen(agent_id="bob", directory=self.temp_dir)
        self.link_id = "link_test_alice_bob_101"

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_two_phase_replay_prevents_high_sequence_poisoning(self):
        """E2E-014: Forged high-sequence envelope cannot poison sequence state."""
        bob_replay = ReplayProtector(state_dir=self.temp_dir, agent_id="bob")
        bob_peer_store = PeerKeyStore(state_dir=self.temp_dir, agent_id="bob")

        # 1. Craft a forged envelope with invalid signature and seq=99999
        forged_envelope = {
            "v": 2,
            "seq": 99999,
            "timestamp": time.time(),
            "ephemPub": self.alice_kp.enc_pub_b64,
            "ciphertext": base64.b64encode(b"forged_ciphertext").decode("utf-8"),
            "iv": base64.b64encode(os.urandom(12)).decode("utf-8"),
            "sig": base64.b64encode(b"\x00" * 64).decode("utf-8"),  # Bad Ed25519 signature
        }
        forged_msg = {
            "linkId": self.link_id,
            "senderId": "alice",
            "senderSignPub": self.alice_kp.sign_pub_b64,
            "senderEncPub": self.alice_kp.enc_pub_b64,
            "payload": forged_envelope,
        }

        # Process the forged message
        result1 = process_inbound_envelope(
            m=forged_msg,
            kp=self.bob_kp,
            replay_protector=bob_replay,
            peer_key_store=bob_peer_store,
        )

        self.assertFalse(result1["verified"])
        self.assertEqual(result1["status"], "rejected")
        self.assertIn("SECURITY REJECTION", result1["text"])

        # Invariant: Sequence state was NOT advanced to 99999
        self.assertEqual(bob_replay._resolve_link_state(self.link_id)["inbound_last_seq"], 0)

        # 2. Subsequent legitimate message with lower seq=1 must be accepted
        valid_envelope = self.alice_kp.create_envelope(
            link_id=self.link_id,
            recipient_id="bob",
            peer_enc_pub_b64=self.bob_kp.enc_pub_b64,
            plaintext="Legitimate message from Alice",
            seq=1,
        )
        valid_msg = {
            "linkId": self.link_id,
            "senderId": "alice",
            "senderSignPub": self.alice_kp.sign_pub_b64,
            "senderEncPub": self.alice_kp.enc_pub_b64,
            "payload": valid_envelope,
        }

        result2 = process_inbound_envelope(
            m=valid_msg,
            kp=self.bob_kp,
            replay_protector=bob_replay,
            peer_key_store=bob_peer_store,
        )

        self.assertTrue(result2["verified"])
        self.assertEqual(result2["status"], "verified")
        self.assertEqual(result2["text"], "Legitimate message from Alice")

        # Now sequence state has been atomically advanced to 1
        self.assertEqual(bob_replay._resolve_link_state(self.link_id)["inbound_last_seq"], 1)

    def test_peer_key_substitution_rejected(self):
        """E2E-015: Relay key substitution is detected and rejected against pinned identity."""
        bob_replay = ReplayProtector(state_dir=self.temp_dir, agent_id="bob")
        bob_peer_store = PeerKeyStore(state_dir=self.temp_dir, agent_id="bob")

        # 1. Alice sends initial legitimate message; Bob pins Alice's keys
        env1 = self.alice_kp.create_envelope(
            link_id=self.link_id,
            recipient_id="bob",
            peer_enc_pub_b64=self.bob_kp.enc_pub_b64,
            plaintext="Hello from real Alice",
            seq=1,
        )
        msg1 = {
            "linkId": self.link_id,
            "senderId": "alice",
            "senderSignPub": self.alice_kp.sign_pub_b64,
            "senderEncPub": self.alice_kp.enc_pub_b64,
            "payload": env1,
        }

        res1 = process_inbound_envelope(
            m=msg1,
            kp=self.bob_kp,
            replay_protector=bob_replay,
            peer_key_store=bob_peer_store,
        )
        self.assertTrue(res1["verified"])

        # 2. Mallory attempts to impersonate Alice with different public keys
        mallory_kp = AgentKeypair.keygen(agent_id="mallory", directory=self.temp_dir)
        env_mallory = mallory_kp.create_envelope(
            link_id=self.link_id,
            recipient_id="bob",
            peer_enc_pub_b64=self.bob_kp.enc_pub_b64,
            plaintext="Impersonated content from Mallory",
            seq=2,
        )
        substituted_msg = {
            "linkId": self.link_id,
            "senderId": "alice",  # Claiming to be Alice
            "senderSignPub": mallory_kp.sign_pub_b64,  # Substituted key
            "senderEncPub": mallory_kp.enc_pub_b64,
            "payload": env_mallory,
        }

        res2 = process_inbound_envelope(
            m=substituted_msg,
            kp=self.bob_kp,
            replay_protector=bob_replay,
            peer_key_store=bob_peer_store,
        )

        self.assertFalse(res2["verified"])
        self.assertEqual(res2["status"], "rejected")
        self.assertIn("Peer key substitution detected", res2["text"])

    def test_plaintext_rejected_by_default(self):
        """E2E-016: Plaintext is rejected by default; requires explicit allow_plaintext policy."""
        bob_replay = ReplayProtector(state_dir=self.temp_dir, agent_id="bob")
        bob_peer_store = PeerKeyStore(state_dir=self.temp_dir, agent_id="bob")

        plaintext_msg = {
            "linkId": self.link_id,
            "senderId": "alice",
            "payload": "Plain unencrypted string",
        }

        # 1. Default policy: Rejected
        res1 = process_inbound_envelope(
            m=plaintext_msg,
            kp=self.bob_kp,
            replay_protector=bob_replay,
            peer_key_store=bob_peer_store,
            allow_plaintext=False,
        )
        self.assertFalse(res1["verified"])
        self.assertEqual(res1["status"], "rejected")
        self.assertIn("Plaintext payload rejected by policy", res1["text"])

        # 2. Explicit policy: Accepted as plaintext
        res2 = process_inbound_envelope(
            m=plaintext_msg,
            kp=self.bob_kp,
            replay_protector=bob_replay,
            peer_key_store=bob_peer_store,
            allow_plaintext=True,
        )
        self.assertFalse(res2["verified"])
        self.assertEqual(res2["status"], "plaintext")
        self.assertEqual(res2["text"], "Plain unencrypted string")

    def test_legacy_v1_envelope_rejected(self):
        """E2E-015: Legacy unauthenticated v1 envelopes are rejected fail-closed."""
        v1_msg = {
            "linkId": self.link_id,
            "senderId": "alice",
            "payload": {
                "iv": "fake_iv",
                "data": "fake_data",
            },
        }
        res = process_inbound_envelope(
            m=v1_msg,
            kp=self.bob_kp,
        )
        self.assertFalse(res["verified"])
        self.assertEqual(res["status"], "rejected")
        self.assertIn("Legacy unauthenticated v1 envelope rejected", res["text"])

    def test_replay_state_write_failure_raises_visibly(self):
        """E2E-026: Persistence failures fail visibly instead of silently succeeding."""
        replay = ReplayProtector(state_dir=self.temp_dir, agent_id="alice")

        with patch.object(Path, "write_text", side_effect=OSError("Disk write I/O error")):
            with self.assertRaises(AgentLinkSecurityError) as ctx:
                replay.next_outbound_seq(self.link_id)
            self.assertIn("Replay state persistence failed", str(ctx.exception))

    def test_concurrent_outbound_sequence_allocations(self):
        """E2E-026: Concurrent processes allocating outbound sequence numbers do not collide."""
        replay = ReplayProtector(state_dir=self.temp_dir, agent_id="alice")
        allocated_seqs = []

        def allocate():
            return replay.next_outbound_seq(self.link_id)

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(allocate) for _ in range(50)]
            for f in futures:
                allocated_seqs.append(f.result())

        self.assertEqual(len(allocated_seqs), 50)
        self.assertEqual(len(set(allocated_seqs)), 50, "Collisions detected in concurrent sequence numbers!")
        self.assertEqual(sorted(allocated_seqs), list(range(1, 51)))


if __name__ == "__main__":
    unittest.main()
