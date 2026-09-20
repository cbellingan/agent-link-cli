import unittest
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from agent_link.crypto import AgentKeypair
from agent_link.security import AgentLinkSecurityError


class TestProtocolSpecificationVectors(unittest.TestCase):
    """Verifies that agent-link-cli conforms to the normative test vectors in SPECIFICATION.md."""

    def setUp(self):
        # Normative seeds from SPECIFICATION.md
        self.alice_seed = b"alice-seed-32-bytes-deterministic!"[:32]
        self.bob_seed = b"bob-seed-32-bytes-deterministic-!!"[:32]

        self.alice_ed = ed25519.Ed25519PrivateKey.from_private_bytes(self.alice_seed)
        self.alice_x = x25519.X25519PrivateKey.from_private_bytes(self.alice_seed)
        self.bob_ed = ed25519.Ed25519PrivateKey.from_private_bytes(self.bob_seed)
        self.bob_x = x25519.X25519PrivateKey.from_private_bytes(self.bob_seed)

        self.alice = AgentKeypair(ed25519_priv=self.alice_ed, x25519_priv=self.alice_x, agent_id="alice")
        self.bob = AgentKeypair(ed25519_priv=self.bob_ed, x25519_priv=self.bob_x, agent_id="bob")

        self.link_id = "link_vector_test_001"
        self.seq = 1
        self.timestamp = 1789254000
        self.nonce = "0123456789abcdef0123456789abcdef"
        self.expected_plaintext = "Canonical AgentLink Protocol v2.1 Test Payload"

        self.expected_derived_key_hex = "a316366148711a3dfb790a2ad8b47660068829aa1ad909a7c6ae858942578784"
        self.expected_iv_b64 = "ABEiM0RVZneImaq7"
        self.expected_data_b64 = "SQGoMyHE3tvmAZe7IxU0GaIuFQ+Q5AF4uiGmPk0Wd0M9h3WG7JyrrsYUq5xQkbS1ci3RexVUCaNx1zkx1+4="
        self.expected_sig_b64 = "zvNq4RJ93ifplEvtPUCxk9JUJxd0n1OQnQ4dTxn6yIpeI6+eUfzmEvRTLIP4Q0udwTS34vTQnuy7gqTcTGXfCA=="

    def test_normative_public_keys_and_fingerprints(self):
        self.assertEqual(self.alice.sign_pub_b64, "o3IC+U9VTT3zJldqYSHfvlX7YBoDselksrLU0riPUBg=")
        self.assertEqual(self.alice.enc_pub_b64, "QNrquoPck7z3btQktbLrdeW2nfbiQmkycmv2Qy5JKVM=")
        self.assertEqual(self.alice.kid, "kid-alice-32022ca472e9065e")

        self.assertEqual(self.bob.sign_pub_b64, "QgxX4xv5GP+cdyX0Sg2r/fvvWeYvRW70bOHm7Jqu1Zo=")
        self.assertEqual(self.bob.enc_pub_b64, "jC9UEX1kooqk5A0h+aIidsAVxXBUDo2caxujhac4cjU=")
        self.assertEqual(self.bob.kid, "kid-bob-b2e58518b5e42de9")

    def test_normative_hkdf_key_derivation(self):
        derived_alice = self.alice.derive_shared_secret(self.bob.enc_pub_b64, link_id=self.link_id)
        derived_bob = self.bob.derive_shared_secret(self.alice.enc_pub_b64, link_id=self.link_id)
        self.assertEqual(derived_alice, derived_bob)
        self.assertEqual(derived_alice.hex(), self.expected_derived_key_hex)

    def test_open_normative_envelope(self):
        envelope = {
            "v": 2,
            "linkId": self.link_id,
            "senderId": "alice",
            "recipientId": "bob",
            "seq": self.seq,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "iv": self.expected_iv_b64,
            "data": self.expected_data_b64,
            "sig": self.expected_sig_b64,
        }
        decrypted = self.bob.open_envelope(
            link_id=self.link_id,
            peer_sign_pub_b64=self.alice.sign_pub_b64,
            peer_enc_pub_b64=self.alice.enc_pub_b64,
            envelope=envelope,
        )
        self.assertEqual(decrypted, self.expected_plaintext)

    def test_tamper_detection_fail_closed(self):
        envelope = {
            "v": 2,
            "linkId": self.link_id,
            "senderId": "alice",
            "recipientId": "bob",
            "seq": self.seq,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "iv": self.expected_iv_b64,
            "data": self.expected_data_b64,
            "sig": self.expected_sig_b64,
        }

        # 1. Tampered signature
        tampered_sig_env = dict(envelope, sig="AAAA" + self.expected_sig_b64[4:])
        with self.assertRaises(AgentLinkSecurityError):
            self.bob.open_envelope(
                link_id=self.link_id,
                peer_sign_pub_b64=self.alice.sign_pub_b64,
                peer_enc_pub_b64=self.alice.enc_pub_b64,
                envelope=tampered_sig_env,
            )

        # 2. Tampered sequence in envelope
        tampered_seq_env = dict(envelope, seq=999)
        with self.assertRaises(AgentLinkSecurityError):
            self.bob.open_envelope(
                link_id=self.link_id,
                peer_sign_pub_b64=self.alice.sign_pub_b64,
                peer_enc_pub_b64=self.alice.enc_pub_b64,
                envelope=tampered_seq_env,
            )

        # 3. Tampered ciphertext data
        tampered_data_env = dict(envelope, data="AAAA" + self.expected_data_b64[4:])
        with self.assertRaises(AgentLinkSecurityError):
            self.bob.open_envelope(
                link_id=self.link_id,
                peer_sign_pub_b64=self.alice.sign_pub_b64,
                peer_enc_pub_b64=self.alice.enc_pub_b64,
                envelope=tampered_data_env,
            )


if __name__ == "__main__":
    unittest.main()
