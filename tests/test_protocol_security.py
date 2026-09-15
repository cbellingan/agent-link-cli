"""Test suite reproducing security vulnerabilities and protocol composition gaps.
Adheres to Rule 1: Always write the reproduction tests first before implementing fixes.
"""

import io
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

from agent_link.crypto import AgentKeypair


class TestProtocolSecurityVulnerabilities(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="agentlink-security-test-")
        self.key_dir = Path(self.temp_dir)
        self.alice_kp = AgentKeypair(agent_id="alice")
        self.alice_kp.save(self.key_dir)
        self.bob_kp = AgentKeypair(agent_id="bob")
        self.bob_kp.save(self.key_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_typo_agent_id_must_raise_file_not_found(self):
        """Typo'd agent ID in load() must NOT silently mint a new identity."""
        with self.assertRaises(FileNotFoundError):
            AgentKeypair.load("non_existent_typo_agent", directory=self.key_dir)

    def test_envelope_v2_signing_and_verification(self):
        """Messages must be signed with Ed25519 and verified against peer's signPub."""
        link_id = "link_alice_bob_1"
        seq = 1
        plaintext = "Critical instruction: transfer 100 credits"

        # Alice creates encrypted & signed envelope for Bob
        envelope = self.alice_kp.create_envelope(
            link_id=link_id,
            recipient_id="bob",
            peer_enc_pub_b64=self.bob_kp.enc_pub_b64,
            plaintext=plaintext,
            seq=seq,
        )

        self.assertEqual(envelope.get("v"), 2)
        self.assertEqual(envelope.get("senderId"), "alice")
        self.assertEqual(envelope.get("recipientId"), "bob")
        self.assertEqual(envelope.get("seq"), 1)
        self.assertIn("sig", envelope)
        self.assertIn("nonce", envelope)

        # Bob verifies and decrypts envelope from Alice
        decrypted_text = self.bob_kp.open_envelope(
            link_id=link_id,
            peer_sign_pub_b64=self.alice_kp.sign_pub_b64,
            peer_enc_pub_b64=self.alice_kp.enc_pub_b64,
            envelope=envelope,
        )
        self.assertEqual(decrypted_text, plaintext)

    def test_envelope_tampering_fails_signature(self):
        """Tampering with ciphertext, seq, sender, or linkId must fail verification."""
        link_id = "link_alice_bob_1"
        envelope = self.alice_kp.create_envelope(
            link_id=link_id,
            recipient_id="bob",
            peer_enc_pub_b64=self.bob_kp.enc_pub_b64,
            plaintext="Legitimate payload",
            seq=1,
        )

        # Attacker tampers with seq
        tampered = dict(envelope)
        tampered["seq"] = 2
        with self.assertRaises(Exception) as ctx:
            self.bob_kp.open_envelope(
                link_id=link_id,
                peer_sign_pub_b64=self.alice_kp.sign_pub_b64,
                peer_enc_pub_b64=self.alice_kp.enc_pub_b64,
                envelope=tampered,
            )
        self.assertIn("signature", str(ctx.exception).lower())

    def test_context_transposition_fails_decryption(self):
        """Ciphertext encrypted for link_1 must NOT decrypt on link_2 (AAD & salt binding)."""
        link_1 = "link_legitimate_1"
        link_2 = "link_transposed_2"

        envelope = self.alice_kp.create_envelope(
            link_id=link_1,
            recipient_id="bob",
            peer_enc_pub_b64=self.bob_kp.enc_pub_b64,
            plaintext="Secret for link 1 only",
            seq=1,
        )

        # Attempt to open envelope across link_2 with Alice's keys
        with self.assertRaises(Exception):
            self.bob_kp.open_envelope(
                link_id=link_2,
                peer_sign_pub_b64=self.alice_kp.sign_pub_b64,
                peer_enc_pub_b64=self.alice_kp.enc_pub_b64,
                envelope=envelope,
            )

    def test_replay_attack_rejected_by_sequence_and_timestamp(self):
        """Re-injecting the same envelope or an older sequence number must be rejected."""
        from agent_link.security import ReplayProtector

        protector = ReplayProtector(state_dir=self.key_dir, agent_id="bob")
        link_id = "link_alice_bob_replay"

        # First message at seq 1
        protector.validate_inbound(link_id=link_id, sender_id="alice", seq=1, timestamp=time.time())

        # Replay same seq 1
        with self.assertRaises(Exception) as ctx:
            protector.validate_inbound(link_id=link_id, sender_id="alice", seq=1, timestamp=time.time())
        self.assertIn("replay", str(ctx.exception).lower())

        # Old seq 0
        with self.assertRaises(Exception) as ctx:
            protector.validate_inbound(link_id=link_id, sender_id="alice", seq=0, timestamp=time.time())
        self.assertIn("replay", str(ctx.exception).lower())

        # Old timestamp (e.g. 10 minutes ago)
        with self.assertRaises(Exception) as ctx:
            protector.validate_inbound(link_id=link_id, sender_id="alice", seq=2, timestamp=time.time() - 600)
        self.assertIn("expired", str(ctx.exception).lower())

        # Legitimate next message at seq 2
        protector.validate_inbound(link_id=link_id, sender_id="alice", seq=2, timestamp=time.time())

    def test_fail_closed_plaintext_refuses_without_explicit_flag(self):
        """Sending without peer encryption keys must fail closed unless explicitly permitted."""
        from agent_link.client import AgentLinkClient, AgentLinkSecurityError
        client = AgentLinkClient(
            server_url="http://127.0.0.1:9999",
            api_key="mock",
            keypair=self.alice_kp,
        )
        # Attempting to send unencrypted message without allow_plaintext=True must raise AgentLinkSecurityError
        with self.assertRaises(AgentLinkSecurityError) as ctx:
            client.send_message(link_id="link_123", text="Hello", allow_plaintext=False)
        self.assertIn("plaintext", str(ctx.exception).lower())

    def test_legacy_v1_envelope_is_rejected(self):
        """Legacy unauthenticated v1 envelopes (missing v2, sig, sequence, AAD) must be strictly rejected."""
        import base64
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from agent_link.crypto import AgentLinkSecurityError

        # Craft a legacy v1 envelope (only iv and data, no v: 2, no sig, no AAD context)
        aes_key = self.alice_kp.derive_shared_secret(self.bob_kp.enc_pub_b64)
        iv = os.urandom(12)
        ciphertext = AESGCM(aes_key).encrypt(iv, b"Legacy v1 plain text", None)
        legacy_envelope = {
            "iv": base64.b64encode(iv).decode("ascii"),
            "data": base64.b64encode(ciphertext).decode("ascii"),
        }

        # Bob opening legacy v1 envelope must fail with AgentLinkSecurityError (fail-closed)
        with self.assertRaises(AgentLinkSecurityError) as ctx:
            self.bob_kp.open_envelope(
                link_id="link_alice_bob_1",
                peer_sign_pub_b64=self.alice_kp.sign_pub_b64,
                peer_enc_pub_b64=self.alice_kp.enc_pub_b64,
                envelope=legacy_envelope,
            )
        self.assertIn("v2", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()

