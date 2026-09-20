"""Unit and integration tests for named connection profiles, peer disambiguation,
lifecycle status distinctions, and operator message handling (Feature 6).
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from agent_link.cli import main, cmd_send, cmd_whoami
from agent_link.crypto import AgentKeypair
from agent_link.profile import ProfileManager
from agent_link.security import process_inbound_envelope, AgentLinkSecurityError


class TestProfileAndUXHardening(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="agentlink-ux-test-")
        os.environ["AGENT_LINK_STATE_DIR"] = self.temp_dir
        os.environ["AGENT_LINK_KEY_DIR"] = self.temp_dir

        self.alice_kp = AgentKeypair.keygen(agent_id="alice", directory=self.temp_dir)
        self.bob_kp = AgentKeypair.keygen(agent_id="bob", directory=self.temp_dir)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        os.environ.pop("AGENT_LINK_STATE_DIR", None)
        os.environ.pop("AGENT_LINK_KEY_DIR", None)

    # ========================================================
    # 1. ProfileManager Direct & CLI Subcommands (6.3)
    # ========================================================

    def test_profile_manager_crud(self):
        """ProfileManager creates, lists, activates, and removes named connection profiles."""
        mgr = ProfileManager(state_dir=Path(self.temp_dir))

        # 1. Set first profile -> becomes active automatically
        p1 = mgr.set_profile(name="staging", server_url="https://staging.relay.internal", agent_id="alice")
        self.assertEqual(p1["name"], "staging")
        self.assertEqual(p1["server_url"], "https://staging.relay.internal")
        self.assertEqual(p1["agent_id"], "alice")

        active = mgr.get_profile()
        self.assertIsNotNone(active)
        self.assertEqual(active["name"], "staging")

        # 2. Set second profile without is_default
        mgr.set_profile(name="prod", server_url="https://mesh.signetmesh.internal", agent_id="alice-prod")
        self.assertEqual(mgr.get_profile()["name"], "staging")  # Still staging

        # 3. List profiles
        all_profiles = mgr.list_profiles()
        self.assertEqual(len(all_profiles), 2)
        names = [p["name"] for p in all_profiles]
        self.assertIn("staging", names)
        self.assertIn("prod", names)

        # 4. Use profile
        mgr.use_profile("prod")
        self.assertEqual(mgr.get_profile()["name"], "prod")

        # 5. Remove profile
        self.assertTrue(mgr.remove_profile("prod"))
        # Active profile should fall back to staging
        self.assertEqual(mgr.get_profile()["name"], "staging")

    def test_cli_profile_commands(self):
        """CLI profile set, list, show, use, and remove execute cleanly."""
        # 1. CLI profile set
        ret = main(["profile", "set", "localdev", "--server", "http://127.0.0.1:4000", "--agent-id", "alice", "--json"])
        self.assertEqual(ret, 0)

        # 2. CLI profile list
        ret = main(["profile", "list", "--json"])
        self.assertEqual(ret, 0)

        # 3. CLI profile show
        ret = main(["profile", "show", "localdev", "--json"])
        self.assertEqual(ret, 0)

        # 4. Profile inheritance: whoami uses profile's server and agent_id when omitted
        with patch("agent_link.cli.AgentLinkClient") as mock_client_cls:
            mock_instance = MagicMock()
            mock_client_cls.return_value = mock_instance
            mock_instance.get_agents.return_value = []
            mock_instance.get_links.return_value = []

            ret = main(["whoami", "--api-key", "test_key", "--json"])
            self.assertEqual(ret, 0)

            # Verified that AgentLinkClient was initialized with the profile's server_url
            mock_client_cls.assert_called_with(
                server_url="http://127.0.0.1:4000",
                api_key="test_key",
                keypair=unittest.mock.ANY,
            )

    # ========================================================
    # 2. Strict Peer Disambiguation with Multiple Active Links (6.4)
    # ========================================================

    def test_send_rejects_silent_selection_when_multiple_active_links(self):
        """When multiple active links exist, cmd_send requires --to or --link-id and refuses to guess."""
        mock_links = [
            {"id": "link_001", "agentAId": "alice", "agentBId": "bob", "status": "active"},
            {"id": "link_002", "agentAId": "alice", "agentBId": "carol", "status": "active"},
        ]

        with patch("agent_link.cli.AgentLinkClient") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client
            mock_client.get_links.return_value = mock_links

            # Attempt send without --to and without --link-id
            ret = cmd_send(
                agent_id="alice",
                server="http://127.0.0.1:3000",
                api_key="sec_test",
                message="Ambiguous message",
                to=None,
                link_id=None,
                key_dir=self.temp_dir,
            )
            # Must fail visibly with non-zero exit code
            self.assertEqual(ret, 1)

    def test_send_resolves_peer_automatically_from_link_id(self):
        """When --link-id is specified without --to, peer ID is resolved from link record."""
        mock_links = [
            {"id": "link_001", "agentAId": "alice", "agentBId": "bob", "status": "active"},
            {"id": "link_002", "agentAId": "alice", "agentBId": "carol", "status": "active"},
        ]
        mock_bob_agent = [{"id": "bob", "encPub": self.bob_kp.enc_pub_b64}]

        with patch("agent_link.cli.AgentLinkClient") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client
            mock_client.get_links.return_value = mock_links
            mock_client.get_agents.return_value = mock_bob_agent

            ret = cmd_send(
                agent_id="alice",
                server="http://127.0.0.1:3000",
                api_key="sec_test",
                message="Message via link_id",
                to=None,
                link_id="link_001",
                key_dir=self.temp_dir,
            )
            self.assertEqual(ret, 0)
            mock_client.send_encrypted.assert_called_once_with(
                link_id="link_001",
                peer_enc_pub_b64=self.bob_kp.enc_pub_b64,
                plaintext="Message via link_id",
                recipient_id="bob",
            )

    def test_send_succeeds_unambiguously_when_single_active_link(self):
        """When exactly one active link exists, cmd_send resolves peer and link without error."""
        mock_links = [
            {"id": "link_001", "agentAId": "alice", "agentBId": "bob", "status": "active"},
        ]
        mock_bob_agent = [{"id": "bob", "encPub": self.bob_kp.enc_pub_b64}]

        with patch("agent_link.cli.AgentLinkClient") as mock_client_cls:
            mock_client = MagicMock()
            mock_client_cls.return_value = mock_client
            mock_client.get_links.return_value = mock_links
            mock_client.get_agents.return_value = mock_bob_agent

            ret = cmd_send(
                agent_id="alice",
                server="http://127.0.0.1:3000",
                api_key="sec_test",
                message="Single link message",
                key_dir=self.temp_dir,
            )
            self.assertEqual(ret, 0)
            mock_client.send_encrypted.assert_called_once_with(
                link_id="link_001",
                peer_enc_pub_b64=self.bob_kp.enc_pub_b64,
                plaintext="Single link message",
                recipient_id="bob",
            )

    # ========================================================
    # 3. Operator Notice vs Agent Message Distinction (6.5)
    # ========================================================

    def test_operator_message_distinct_from_agent_envelope(self):
        """Operator messages sent from dashboard are marked operator_notice and verified=False."""
        msg = {
            "linkId": "link_001",
            "senderId": "alice",
            "senderType": "operator",
            "operatorEmail": "admin@signetmesh.internal",
            "payload": "Please drain your queue and restart for migration.",
        }

        result = process_inbound_envelope(
            m=msg,
            kp=self.bob_kp,
        )

        self.assertFalse(result["verified"])
        self.assertEqual(result["status"], "operator_notice")
        self.assertEqual(result["senderType"], "operator")
        self.assertEqual(result["operatorEmail"], "admin@signetmesh.internal")
        self.assertIn("[OPERATOR NOTICE from admin@signetmesh.internal]", result["text"])
        self.assertIn("Please drain your queue", result["text"])


if __name__ == "__main__":
    unittest.main()
