"""Tests for Optical QR code payload generation and ASCII rendering."""

import json
import unittest
from agent_link.crypto import AgentKeypair
from agent_link.qr import create_qr_payload, render_ascii_qr, display_qr


class TestQr(unittest.TestCase):

    def test_create_qr_payload(self):
        kp = AgentKeypair(agent_id="test-ted")
        payload = create_qr_payload(kp)

        self.assertEqual(payload["v"], 1)
        self.assertEqual(payload["agent"], "test-ted")
        self.assertEqual(payload["signPub"], kp.sign_pub_b64)
        self.assertEqual(payload["encPub"], kp.enc_pub_b64)
        self.assertEqual(payload["kid"], kp.kid)
        self.assertIn("iat", payload)

    def test_render_ascii_qr(self):
        kp = AgentKeypair(agent_id="test-ted")
        payload = create_qr_payload(kp)
        payload_str = json.dumps(payload)

        rendered = render_ascii_qr(payload_str)
        self.assertTrue(len(rendered) > 50)

    def test_display_qr_output(self):
        kp = AgentKeypair(agent_id="test-puck")
        output = display_qr(kp)
        self.assertIn("test-puck", output)
        self.assertIn(kp.kid, output)
        self.assertIn(kp.sign_pub_b64, output)


if __name__ == "__main__":
    unittest.main()
