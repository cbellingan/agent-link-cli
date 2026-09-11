"""Tests for AgentLink cryptographic routines."""

import tempfile
import unittest
from pathlib import Path
from agent_link.crypto import AgentKeypair


class TestCrypto(unittest.TestCase):

    def test_key_generation_and_properties(self):
        kp = AgentKeypair(agent_id="test-agent")
        self.assertEqual(kp.agent_id, "test-agent")
        self.assertTrue(kp.sign_pub_b64)
        self.assertTrue(kp.enc_pub_b64)
        self.assertTrue(kp.kid.startswith("kid-test-agent-"))
        self.assertEqual(len(kp.sign_pub_raw), 32)
        self.assertEqual(len(kp.enc_pub_raw), 32)

    def test_ed25519_sign_and_verify(self):
        kp = AgentKeypair(agent_id="signer")
        msg = b"Antigravity AgentLink Challenge 2026"
        sig = kp.sign(msg)

        # Valid signature
        self.assertTrue(AgentKeypair.verify_signature(kp.sign_pub_b64, msg, sig))

        # Tampered message fails
        self.assertFalse(AgentKeypair.verify_signature(kp.sign_pub_b64, b"tampered", sig))

        # Wrong public key fails
        other_kp = AgentKeypair(agent_id="other")
        self.assertFalse(AgentKeypair.verify_signature(other_kp.sign_pub_b64, msg, sig))

    def test_x25519_aes_gcm_e2ee(self):
        alice = AgentKeypair(agent_id="alice")
        bob = AgentKeypair(agent_id="bob")

        plaintext = b"Super confidential payload across zero-knowledge relay pipe"

        # Alice encrypts for Bob
        cipher_dict = alice.encrypt(bob.enc_pub_b64, plaintext)
        self.assertIn("iv", cipher_dict)
        self.assertIn("data", cipher_dict)

        # Bob decrypts from Alice
        decrypted = bob.decrypt(alice.enc_pub_b64, cipher_dict["iv"], cipher_dict["data"])
        self.assertEqual(decrypted, plaintext)

    def test_keypair_persistence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            kp = AgentKeypair(agent_id="persistent-agent")
            kp.save(tmp_path)

            loaded = AgentKeypair.load(agent_id="persistent-agent", directory=tmp_path)
            self.assertEqual(loaded.sign_pub_b64, kp.sign_pub_b64)
            self.assertEqual(loaded.enc_pub_b64, kp.enc_pub_b64)
            self.assertEqual(loaded.kid, kp.kid)


if __name__ == "__main__":
    unittest.main()
