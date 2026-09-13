"""Command Line Interface for AgentLink CLI with Protocol Hardening and Agent-Safe Interfaces."""

from __future__ import annotations
import argparse
import json
import os
import queue
import sys
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from agent_link.client import (
    AgentLinkClient,
    AgentLinkError,
    AgentLinkSecurityError,
    AgentLinkAuthError,
    AgentLinkNotFoundError,
    AgentLinkTimeoutError,
)
from agent_link.crypto import AgentKeypair
from agent_link.qr import display_qr
from agent_link.security import format_untrusted_box


def check_cli_secrets_warning(argv: Optional[List[str]] = None) -> None:
    """Warn when secrets are passed directly via argv to prevent process list (ps) leakage."""
    args_list = argv if argv is not None else sys.argv
    for arg in args_list:
        if arg.startswith("--api-key"):
            print(
                "⚠️  [SECURITY WARNING] Passing '--api-key' via command-line arguments can expose secrets "
                "in process lists ('ps') and shell history. Prefer setting the 'AGENTLINK_API_KEY' environment variable.",
                file=sys.stderr,
            )
            break


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="agent-link",
        description="AgentLink: Lightweight Zero-Knowledge Agent Mesh CLI & Optical Anchor",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. keygen
    p_keygen = subparsers.add_parser("keygen", help="Generate or display local Ed25519/X25519 identity keys and QR")
    p_keygen.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Identifier for this agent")
    p_keygen.add_argument("--key-dir", default=os.getenv("AGENTLINK_KEY_DIR"), help="Directory to store keys (defaults to ~/.agent-link)")

    # 2. register
    p_reg = subparsers.add_parser("register", help="Register agent with AgentLink server using API key")
    p_reg.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Identifier for this agent")
    p_reg.add_argument("--server", default=os.getenv("AGENTLINK_SERVER_URL", "https://agent.signetmesh.com"), help="AgentLink server URL")
    p_reg.add_argument("--api-key", default=os.getenv("AGENTLINK_API_KEY", ""), help="Human-provisioned API key")
    p_reg.add_argument("--key-dir", default=os.getenv("AGENTLINK_KEY_DIR"), help="Directory to store keys")

    # 3. status
    p_status = subparsers.add_parser("status", help="Show local identity status and fingerprints")
    p_status.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Identifier for this agent")
    p_status.add_argument("--key-dir", default=os.getenv("AGENTLINK_KEY_DIR"), help="Directory to store keys")

    # 4. whoami
    p_whoami = subparsers.add_parser("whoami", help="Show full agent identity, registration, and active links")
    p_whoami.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Identifier for this agent")
    p_whoami.add_argument("--server", default=os.getenv("AGENTLINK_SERVER_URL", "https://agent.signetmesh.com"), help="AgentLink server URL")
    p_whoami.add_argument("--api-key", default=os.getenv("AGENTLINK_API_KEY", ""), help="Human-provisioned API key")
    p_whoami.add_argument("--key-dir", default=os.getenv("AGENTLINK_KEY_DIR"), help="Directory to store keys")
    p_whoami.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # 5. links
    p_links = subparsers.add_parser("links", help="List all active and pending links")
    p_links.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Identifier for this agent")
    p_links.add_argument("--server", default=os.getenv("AGENTLINK_SERVER_URL", "https://agent.signetmesh.com"), help="AgentLink server URL")
    p_links.add_argument("--api-key", default=os.getenv("AGENTLINK_API_KEY", ""), help="Human-provisioned API key")
    p_links.add_argument("--key-dir", default=os.getenv("AGENTLINK_KEY_DIR"), help="Directory to store keys")
    p_links.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # 5b. link-request / request-link
    p_link_req = subparsers.add_parser("link-request", aliases=["request-link"], help="Request an end-to-end encrypted peer link with another agent")
    p_link_req.add_argument("--peer", "--to", required=True, dest="peer", help="Target peer agent ID to connect with")
    p_link_req.add_argument("--note", help="Optional note or purpose for the requested link")
    p_link_req.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Identifier for your agent")
    p_link_req.add_argument("--server", default=os.getenv("AGENTLINK_SERVER_URL", "https://agent.signetmesh.com"), help="AgentLink server URL")
    p_link_req.add_argument("--api-key", default=os.getenv("AGENTLINK_API_KEY", ""), help="Human-provisioned API key")
    p_link_req.add_argument("--key-dir", default=os.getenv("AGENTLINK_KEY_DIR"), help="Directory to store keys")
    p_link_req.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # 6. revoke
    p_revoke = subparsers.add_parser("revoke", help="Sever / revoke a link")
    p_revoke.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Identifier for this agent")
    p_revoke.add_argument("--link-id", required=True, help="Link ID to revoke")
    p_revoke.add_argument("--server", default=os.getenv("AGENTLINK_SERVER_URL", "https://agent.signetmesh.com"), help="AgentLink server URL")
    p_revoke.add_argument("--api-key", default=os.getenv("AGENTLINK_API_KEY", ""), help="Human-provisioned API key")
    p_revoke.add_argument("--key-dir", default=os.getenv("AGENTLINK_KEY_DIR"), help="Directory to store keys")
    p_revoke.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # 7. connect
    p_connect = subparsers.add_parser("connect", help="Keygen, display optical QR, register, and listen/chat on peer mesh")
    p_connect.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Identifier for this agent")
    p_connect.add_argument("--server", default=os.getenv("AGENTLINK_SERVER_URL", "https://agent.signetmesh.com"), help="AgentLink server URL")
    p_connect.add_argument("--api-key", default=os.getenv("AGENTLINK_API_KEY", ""), help="Human-provisioned API key")
    p_connect.add_argument("--key-dir", default=os.getenv("AGENTLINK_KEY_DIR"), help="Directory to store keys")
    p_connect.add_argument("--once", action="store_true", help="Register and exit without long-polling")
    p_connect.add_argument("--plaintext", action="store_true", help="Allow unencrypted fallback transmissions (insecure)")

    # 8. send
    p_send = subparsers.add_parser("send", help="Send a message to a peer agent or link")
    p_send.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Sender agent identifier")
    p_send.add_argument("--to", help="Target recipient agent ID")
    p_send.add_argument("--link-id", help="Link ID to dispatch message over")
    p_send.add_argument("--message", "-m", help="Message body to send")
    p_send.add_argument("--server", default=os.getenv("AGENTLINK_SERVER_URL", "https://agent.signetmesh.com"), help="AgentLink server URL")
    p_send.add_argument("--api-key", default=os.getenv("AGENTLINK_API_KEY", ""), help="Human-provisioned API key")
    p_send.add_argument("--key-dir", default=os.getenv("AGENTLINK_KEY_DIR"), help="Directory to store keys")
    p_send.add_argument("--plaintext", action="store_true", help="Allow unencrypted fallback transmission (insecure)")
    p_send.add_argument("--json", action="store_true", help="Output machine-readable JSON result")

    # 9. receive (agent-safe scriptable command)
    p_receive = subparsers.add_parser("receive", help="Poll and decrypt incoming messages (agent-safe single-shot or daemon)")
    p_receive.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Identifier for this agent")
    p_receive.add_argument("--server", default=os.getenv("AGENTLINK_SERVER_URL", "https://agent.signetmesh.com"), help="AgentLink server URL")
    p_receive.add_argument("--api-key", default=os.getenv("AGENTLINK_API_KEY", ""), help="Human-provisioned API key")
    p_receive.add_argument("--key-dir", default=os.getenv("AGENTLINK_KEY_DIR"), help="Directory to store keys")
    p_receive.add_argument("--once", action="store_true", default=True, help="Poll once and exit immediately (default for receive)")
    p_receive.add_argument("--timeout", type=int, default=5, help="Poll timeout in seconds")
    p_receive.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # 10. invite (generate secure email invite knowledge / token)
    # 11. invite
    p_invite = subparsers.add_parser("invite", help="Generate secure email invitation knowledge and link for a collaborator")
    p_invite.add_argument("--to", required=True, help="Recipient email address to invite (e.g. collaborator@example.com)")
    p_invite.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Identifier for your agent")
    p_invite.add_argument("--target-agent", "--peer", dest="target_agent", help="Optional peer agent ID to connect with upon invite acceptance")
    p_invite.add_argument("--note", help="Optional invitation note/context")
    p_invite.add_argument("--server", default=os.getenv("AGENTLINK_SERVER_URL", "https://agent.signetmesh.com"), help="AgentLink server URL")
    p_invite.add_argument("--api-key", default=os.getenv("AGENTLINK_API_KEY", ""), help="Human-provisioned API key")
    p_invite.add_argument("--key-dir", default=os.getenv("AGENTLINK_KEY_DIR"), help="Directory to store keys")
    p_invite.add_argument("--json", action="store_true", help="Output machine-readable JSON invite knowledge")

    # 12. bug-report
    p_bug = subparsers.add_parser("bug-report", help="Submit an autonomous operational bug report to AgentLink")
    p_bug.add_argument("--title", required=True, help="Short summary of the bug or error")
    p_bug.add_argument("--details", "-d", help="Detailed description, stack trace, or error payload (reads from stdin if omitted)")
    p_bug.add_argument("--severity", choices=["low", "medium", "high", "critical"], default="medium", help="Bug severity level (default: medium)")
    p_bug.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Identifier for your agent")
    p_bug.add_argument("--server", default=os.getenv("AGENTLINK_SERVER_URL", "https://agent.signetmesh.com"), help="AgentLink server URL")
    p_bug.add_argument("--api-key", default=os.getenv("AGENTLINK_API_KEY", ""), help="AgentLink API key (optional for bug reporting)")
    p_bug.add_argument("--key-dir", default=os.getenv("AGENTLINK_KEY_DIR"), help="Directory to store keys")
    p_bug.add_argument("--json", action="store_true", help="Output machine-readable JSON response")

    # 13. bug-list
    p_bug_list = subparsers.add_parser("bug-list", help="List operational bug reports on AgentLink")
    p_bug_list.add_argument("--limit", type=int, default=50, help="Max reports to retrieve (default: 50)")
    p_bug_list.add_argument("--agent-id", default=None, help="Filter reports by agent ID")
    p_bug_list.add_argument("--open-only", action="store_true", help="Show only unresolved open bugs")
    p_bug_list.add_argument("--server", default=os.getenv("AGENTLINK_SERVER_URL", "https://agent.signetmesh.com"), help="AgentLink server URL")
    p_bug_list.add_argument("--api-key", default=os.getenv("AGENTLINK_API_KEY", ""), help="AgentLink API key")
    p_bug_list.add_argument("--key-dir", default=os.getenv("AGENTLINK_KEY_DIR"), help="Directory to store keys")
    p_bug_list.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # 14. bug-resolve
    p_bug_res = subparsers.add_parser("bug-resolve", help="Mark an operational bug report as resolved (or reopened)")
    p_bug_res.add_argument("--bug-id", required=True, help="Bug report ID (e.g. bug_1789318804571_49531da3)")
    p_bug_res.add_argument("--note", help="Optional resolution note or fix commit reference")
    p_bug_res.add_argument("--reopen", action="store_true", help="Reopen the bug report instead of resolving")
    p_bug_res.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Identifier for your agent")
    p_bug_res.add_argument("--server", default=os.getenv("AGENTLINK_SERVER_URL", "https://agent.signetmesh.com"), help="AgentLink server URL")
    p_bug_res.add_argument("--api-key", default=os.getenv("AGENTLINK_API_KEY", ""), help="AgentLink API key")
    p_bug_res.add_argument("--key-dir", default=os.getenv("AGENTLINK_KEY_DIR"), help="Directory to store keys")
    p_bug_res.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    return parser.parse_args(argv)


def cmd_keygen(agent_id: str, key_dir: Optional[str] = None) -> int:
    directory = Path(key_dir) if key_dir else None
    kp = AgentKeypair.keygen(agent_id=agent_id, directory=directory)
    print(display_qr(kp))
    return 0


def cmd_register(agent_id: str, server: str, api_key: str, key_dir: Optional[str] = None) -> int:
    if not api_key:
        print("❌ Error: API key required. Provide via --api-key or set AGENTLINK_API_KEY environment variable.", file=sys.stderr)
        return 1

    directory = Path(key_dir) if key_dir else None
    try:
        kp = AgentKeypair.load(agent_id=agent_id, directory=directory)
    except FileNotFoundError:
        kp = AgentKeypair.keygen(agent_id=agent_id, directory=directory)
    kp.save(directory=directory)

    print(f"📡 Registering agent '{agent_id}' with AgentLink server: {server}")
    client = AgentLinkClient(server_url=server, api_key=api_key, keypair=kp)
    try:
        res = client.register()
        print(f"✅ Successfully registered! Status: {res.get('status')} | Agent ID: {res.get('agentId')}")
        print(f"🔑 Identity Key ID: {kp.kid}")
        print("\nDisplaying Optical Public Identity QR Code for Human Verification:")
        print(display_qr(kp))
        return 0
    except Exception as e:
        print(f"❌ Registration failed: {e}", file=sys.stderr)
        return 1


def cmd_status(agent_id: str, key_dir: Optional[str] = None) -> int:
    directory = Path(key_dir) if key_dir else None
    try:
        kp = AgentKeypair.load(agent_id=agent_id, directory=directory)
    except FileNotFoundError as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        return 1

    print(f"Agent ID:       {kp.agent_id}")
    print(f"Signing Pub:    {kp.sign_pub_b64}")
    print(f"Encryption Pub: {kp.enc_pub_b64}")
    print(f"Key ID (kid):   {kp.kid}")
    return 0


def cmd_whoami(agent_id: str, server: str, api_key: str, key_dir: Optional[str] = None, as_json: bool = False) -> int:
    directory = Path(key_dir) if key_dir else None
    try:
        kp = AgentKeypair.load(agent_id=agent_id, directory=directory)
    except FileNotFoundError as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        return 1

    info: Dict[str, Any] = {
        "agentId": kp.agent_id,
        "kid": kp.kid,
        "signPub": kp.sign_pub_b64,
        "encPub": kp.enc_pub_b64,
        "registered": False,
        "activeLinksCount": 0,
    }

    if api_key:
        client = AgentLinkClient(server_url=server, api_key=api_key, keypair=kp)
        try:
            agents = client.get_agents(agent_id)
            if any(a.get("id") == agent_id for a in agents):
                info["registered"] = True
            links = client.get_links()
            info["activeLinksCount"] = len([l for l in links if l.get("status") == "active"])
        except Exception:
            pass

    if as_json:
        print(json.dumps(info, indent=2))
        return 0

    print("==================================================")
    print(f"  AgentLink Identity: {kp.agent_id}")
    print("==================================================")
    print(f"Fingerprint (kid):   {kp.kid}")
    print(f"Signing Public:      {kp.sign_pub_b64}")
    print(f"Encryption Public:   {kp.enc_pub_b64}")
    print(f"Server Registration: {'✅ Registered' if info['registered'] else '⚠️ Unregistered'}")
    print(f"Active Links:        {info['activeLinksCount']}")
    return 0


def cmd_links(agent_id: str, server: str, api_key: str, key_dir: Optional[str] = None, as_json: bool = False) -> int:
    if not api_key:
        print("❌ Error: API key required to query links.", file=sys.stderr)
        return 1

    directory = Path(key_dir) if key_dir else None
    try:
        kp = AgentKeypair.load(agent_id=agent_id, directory=directory)
    except FileNotFoundError as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        return 1

    client = AgentLinkClient(server_url=server, api_key=api_key, keypair=kp)
    try:
        links = client.get_links()
    except Exception as e:
        print(f"❌ Failed to query links: {e}", file=sys.stderr)
        return 1

    if as_json:
        print(json.dumps({"status": "ok", "links": links}, indent=2))
        return 0

    print(f"🔗 Links involving agent '{agent_id}': ({len(links)} total)")
    for l in links:
        link_id = l.get("id")
        status = l.get("status")
        peer_id = l.get("agentBId") if l.get("agentAId") == agent_id else l.get("agentAId")
        verification = l.get("peerVerification", "none")
        print(f"  - Link ID: {link_id} | Peer: {peer_id} | Status: {status} | Verification: {verification}")
    return 0


def cmd_revoke(agent_id: str, server: str, api_key: str, link_id: str, key_dir: Optional[str] = None, as_json: bool = False) -> int:
    if not api_key:
        print("❌ Error: API key required to revoke links.", file=sys.stderr)
        return 1

    directory = Path(key_dir) if key_dir else None
    try:
        kp = AgentKeypair.load(agent_id=agent_id, directory=directory)
    except FileNotFoundError as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        return 1

    client = AgentLinkClient(server_url=server, api_key=api_key, keypair=kp)
    try:
        res = client.revoke_link(link_id)
        if as_json:
            print(json.dumps(res))
        else:
            print(f"✅ Successfully severed link '{link_id}'.")
        return 0
    except Exception as e:
        print(f"❌ Failed to revoke link: {e}", file=sys.stderr)
        return 1


def cmd_link_request(
    agent_id: str,
    peer: str,
    server: str,
    api_key: str,
    note: Optional[str] = None,
    key_dir: Optional[str] = None,
    as_json: bool = False,
) -> int:
    """Request an end-to-end encrypted peer link with another agent."""
    if not api_key:
        print("❌ Error: API key required. Provide via --api-key or set AGENTLINK_API_KEY environment variable.", file=sys.stderr)
        return 1

    directory = Path(key_dir) if key_dir else None
    try:
        kp = AgentKeypair.load(agent_id=agent_id, directory=directory)
    except Exception:
        kp = None

    client = AgentLinkClient(server_url=server, api_key=api_key, keypair=kp)
    try:
        res = client.request_link(peer_agent_id=peer, note=note)
        if as_json:
            print(json.dumps(res, indent=2))
        else:
            link_id = res.get("linkId", res.get("link", {}).get("id", "unknown"))
            status = res.get("link", {}).get("status", "pending_approval")
            print(f"✅ Link request submitted successfully!")
            print(f"Link ID:   {link_id}")
            print(f"Agents:    {agent_id} ⟷ {peer}")
            print(f"Status:    {status.upper()}")
            print(f"Note:      Dual human approval is required before encrypted messages can route.")
        return 0
    except Exception as e:
        if as_json:
            print(json.dumps({"status": "error", "message": str(e)}))
        else:
            print(f"❌ Failed to request link: {e}", file=sys.stderr)
        return 1


def cmd_send(
    agent_id: str,
    server: str,
    api_key: str,
    message: Optional[str] = None,
    to: Optional[str] = None,
    link_id: Optional[str] = None,
    key_dir: Optional[str] = None,
    allow_plaintext: bool = False,
    as_json: bool = False,
) -> int:
    if not api_key:
        print("❌ Error: API key required. Provide via --api-key or set AGENTLINK_API_KEY environment variable.", file=sys.stderr)
        return 1

    msg_text = message
    if not msg_text:
        try:
            msg_text = input("Enter message to send: ").strip()
        except EOFError:
            pass
    if not msg_text:
        print("❌ Error: Message text required.", file=sys.stderr)
        return 1

    directory = Path(key_dir) if key_dir else None
    try:
        kp = AgentKeypair.load(agent_id=agent_id, directory=directory)
    except FileNotFoundError as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        return 1

    client = AgentLinkClient(server_url=server, api_key=api_key, keypair=kp)

    target_link_id = link_id
    peer_enc_pub = None
    target_peer_id = to

    if not target_link_id:
        my_links = client.get_links()
        if target_peer_id:
            matching = [l for l in my_links if (l.get("agentAId") == target_peer_id or l.get("agentBId") == target_peer_id) and l.get("status") == "active"]
            if matching:
                target_link_id = matching[0].get("id")
            else:
                print(f"❌ Error: No active link found with peer '{target_peer_id}'.", file=sys.stderr)
                return 1
        else:
            active = [l for l in my_links if l.get("status") == "active"]
            if active:
                target_link_id = active[0].get("id")
                target_peer_id = active[0].get("agentBId") if active[0].get("agentAId") == agent_id else active[0].get("agentAId")
            else:
                print("❌ Error: No active links found for this agent. Establish a link in dashboard first.", file=sys.stderr)
                return 1

    # Look up peer public encryption key if peer ID is known
    if target_peer_id:
        agents = client.get_agents(target_peer_id)
        peer_agent = next((a for a in agents if a.get("id") == target_peer_id), None)
        if peer_agent and peer_agent.get("encPub"):
            peer_enc_pub = peer_agent.get("encPub")

    # Fail-closed check
    if not peer_enc_pub and not allow_plaintext:
        print(
            "❌ [FAIL-CLOSED SECURITY REJECTION] Cannot establish end-to-end encryption to peer: "
            "Peer public encryption key not found. Refusing to transmit plaintext. "
            "Pass '--plaintext' if you explicitly intend to send unencrypted messages.",
            file=sys.stderr,
        )
        return 1

    try:
        if peer_enc_pub:
            client.send_encrypted(
                link_id=target_link_id,
                peer_enc_pub_b64=peer_enc_pub,
                plaintext=msg_text,
                recipient_id=target_peer_id,
            )
            if as_json:
                print(json.dumps({"status": "ok", "delivered": True, "linkId": target_link_id, "encrypted": True, "to": target_peer_id}))
            else:
                print(f"🚀 [FAIL-CLOSED E2EE] Successfully sent signed & encrypted message to '{target_peer_id}' across {target_link_id}!")
        else:
            client.send_message(link_id=target_link_id, text=msg_text, allow_plaintext=True)
            if as_json:
                print(json.dumps({"status": "ok", "delivered": True, "linkId": target_link_id, "encrypted": False, "to": target_peer_id}))
            else:
                print(f"⚠️ [PLAINTEXT] Sent unencrypted message across {target_link_id}!")
        return 0
    except Exception as e:
        print(f"❌ Send failed: {e}", file=sys.stderr)
        return 1


def cmd_receive(
    agent_id: str,
    server: str,
    api_key: str,
    key_dir: Optional[str] = None,
    once: bool = True,
    timeout: int = 5,
    as_json: bool = False,
) -> int:
    if not api_key:
        print("❌ Error: API key required.", file=sys.stderr)
        return 1

    directory = Path(key_dir) if key_dir else None
    try:
        kp = AgentKeypair.load(agent_id=agent_id, directory=directory)
    except FileNotFoundError as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        return 1

    client = AgentLinkClient(server_url=server, api_key=api_key, keypair=kp)
    processed_messages: List[Dict[str, Any]] = []

    try:
        raw_messages = client.poll_messages(timeout_seconds=timeout)
        for m in raw_messages:
            sender_id = m.get("senderId", "peer")
            link_id = m.get("linkId", "unknown")
            payload = m.get("payload")
            is_encrypted = False
            is_signed = False
            decrypted_text = ""
            err_note = None

            if isinstance(payload, dict):
                sender_enc_pub = m.get("senderEncPub")
                sender_sign_pub = m.get("senderSignPub")

                if payload.get("v") == 2:
                    is_encrypted = True
                    is_signed = True
                    seq = payload.get("seq", 0)
                    ts = payload.get("timestamp", 0)

                    try:
                        # 1. Validate replay protection & sequence monotonicity
                        client.replay_protector.validate_inbound(
                            link_id=link_id,
                            sender_id=sender_id,
                            seq=seq,
                            timestamp=ts,
                        )

                        # 2. Open signed & context-bound envelope
                        decrypted_text = kp.open_envelope(
                            link_id=link_id,
                            peer_sign_pub_b64=sender_sign_pub or "",
                            peer_enc_pub_b64=sender_enc_pub or "",
                            envelope=payload,
                        )
                    except Exception as sec_err:
                        err_note = f"Security verification rejected: {sec_err}"
                        decrypted_text = f"[REJECTED: {sec_err}]"

                elif "iv" in payload and "data" in payload and sender_enc_pub:
                    # Legacy v1 fallback
                    is_encrypted = True
                    try:
                        decrypted_text = kp.open_envelope(
                            link_id=link_id,
                            peer_sign_pub_b64="",
                            peer_enc_pub_b64=sender_enc_pub,
                            envelope=payload,
                        )
                    except Exception as dec_err:
                        err_note = f"Decryption failed: {dec_err}"
                        decrypted_text = f"[DECRYPTION FAILED: {dec_err}]"
            elif isinstance(payload, str):
                decrypted_text = payload

            msg_record = {
                "linkId": link_id,
                "senderId": sender_id,
                "text": decrypted_text,
                "encrypted": is_encrypted,
                "signed": is_signed,
                "error": err_note,
            }
            processed_messages.append(msg_record)

            if not as_json:
                print(format_untrusted_box(
                    sender_id=sender_id,
                    link_id=link_id,
                    text=decrypted_text,
                    is_e2ee=is_encrypted,
                    is_signed=is_signed,
                ))

        if as_json:
            print(json.dumps({"status": "ok", "messages": processed_messages}, indent=2))
        return 0
    except Exception as e:
        print(f"❌ Error receiving messages: {e}", file=sys.stderr)
        return 1


def cmd_connect(
    agent_id: str,
    server: str,
    api_key: str,
    key_dir: Optional[str] = None,
    once: bool = False,
    allow_plaintext: bool = False,
) -> int:
    if agent_id == "agent":
        print("💡 Tip: Connecting as default agent ID 'agent'. To use a custom ID (e.g. 'ted'), use: --agent-id ted\n")

    ret = cmd_register(agent_id, server, api_key, key_dir=key_dir)
    if ret != 0 or once:
        return ret

    directory = Path(key_dir) if key_dir else None
    kp = AgentKeypair.load(agent_id=agent_id, directory=directory)
    client = AgentLinkClient(server_url=server, api_key=api_key, keypair=kp)

    mode_banner = (
        "🔒 [SECURITY MODE: STRICT E2EE FAIL-CLOSED (Ed25519-Signed + AES-256-GCM)]"
        if not allow_plaintext
        else "⚠️  [SECURITY MODE: PLAINTEXT PERMITTED (INSECURE)]"
    )

    print(f"\n{mode_banner}")
    print(f"👂 Listening for peer connection requests and messages on {server}")
    print("💬 [Interactive Chat] Type a reply and press Enter to send across the mesh! (Ctrl+C to stop)\n")

    last_active_link: Dict[str, Any] = {"linkId": None, "peerId": None, "peerEncPub": None, "peerSignPub": None}

    # Pre-populate known links
    try:
        my_links = client.get_links()
        active = [l for l in my_links if l.get("status") == "active"]
        if active:
            l = active[0]
            peer_id = l.get("agentBId") if l.get("agentAId") == agent_id else l.get("agentAId")
            last_active_link["linkId"] = l.get("id")
            last_active_link["peerId"] = peer_id
    except Exception:
        pass

    input_queue: queue.Queue[str] = queue.Queue()
    stop_event = threading.Event()

    def stdin_reader():
        while not stop_event.is_set():
            try:
                line = sys.stdin.readline()
                if not line:
                    break
                text = line.strip()
                if text:
                    input_queue.put(text)
            except Exception:
                break

    reader_thread = threading.Thread(target=stdin_reader, daemon=True)
    reader_thread.start()

    try:
        while True:
            # 1. Process terminal user input
            while not input_queue.empty():
                text_to_send = input_queue.get_nowait()
                target_link = last_active_link.get("linkId")
                target_peer = last_active_link.get("peerId") or "peer"

                if not target_link:
                    try:
                        my_links = client.get_links()
                        active = [l for l in my_links if l.get("status") == "active"]
                        if active:
                            target_link = active[0].get("id")
                            target_peer = active[0].get("agentBId") if active[0].get("agentAId") == agent_id else active[0].get("agentAId")
                            last_active_link["linkId"] = target_link
                            last_active_link["peerId"] = target_peer
                    except Exception:
                        pass

                if target_link:
                    peer_enc_pub = last_active_link.get("peerEncPub")
                    if not peer_enc_pub and target_peer:
                        try:
                            agents = client.get_agents(target_peer)
                            p_agent = next((a for a in agents if a.get("id") == target_peer), None)
                            if p_agent and p_agent.get("encPub"):
                                peer_enc_pub = p_agent.get("encPub")
                                last_active_link["peerEncPub"] = peer_enc_pub
                                if p_agent.get("signPub"):
                                    last_active_link["peerSignPub"] = p_agent.get("signPub")
                        except Exception:
                            pass

                    if not peer_enc_pub and not allow_plaintext:
                        print(f"❌ [FAIL-CLOSED] Cannot encrypt to '{target_peer}': missing peer encryption key. Message not sent.")
                        continue

                    try:
                        if peer_enc_pub:
                            client.send_encrypted(
                                link_id=target_link,
                                peer_enc_pub_b64=peer_enc_pub,
                                plaintext=text_to_send,
                                recipient_id=target_peer,
                            )
                            print(f"🚀 [SENT STRICT E2EE to {target_peer}]: {text_to_send}")
                        else:
                            client.send_message(link_id=target_link, text=text_to_send, allow_plaintext=True)
                            print(f"⚠️  [SENT PLAINTEXT to {target_peer}]: {text_to_send}")
                    except Exception as send_err:
                        print(f"❌ Failed to send message: {send_err}")
                else:
                    print(f"⚠️ Cannot send '{text_to_send}': No active peer link found yet.")

            # 2. Long-poll for incoming messages
            messages = client.poll_messages(timeout_seconds=2)
            for m in messages:
                sender_id = m.get("senderId", "peer")
                link_id = m.get("linkId", "unknown")
                last_active_link["linkId"] = link_id
                last_active_link["peerId"] = sender_id
                if m.get("senderEncPub"):
                    last_active_link["peerEncPub"] = m.get("senderEncPub")
                if m.get("senderSignPub"):
                    last_active_link["peerSignPub"] = m.get("senderSignPub")

                payload = m.get("payload")
                is_e2ee = False
                is_signed = False
                decrypted_text = ""

                if isinstance(payload, dict):
                    sender_enc = m.get("senderEncPub") or last_active_link.get("peerEncPub")
                    sender_sign = m.get("senderSignPub") or last_active_link.get("peerSignPub")

                    if payload.get("v") == 2:
                        is_e2ee = True
                        is_signed = True
                        seq = payload.get("seq", 0)
                        ts = payload.get("timestamp", 0)
                        try:
                            client.replay_protector.validate_inbound(
                                link_id=link_id,
                                sender_id=sender_id,
                                seq=seq,
                                timestamp=ts,
                            )
                            decrypted_text = kp.open_envelope(
                                link_id=link_id,
                                peer_sign_pub_b64=sender_sign or "",
                                peer_enc_pub_b64=sender_enc or "",
                                envelope=payload,
                            )
                        except Exception as sec_err:
                            decrypted_text = f"[SECURITY REJECTION: {sec_err}]"
                    elif "iv" in payload and "data" in payload and sender_enc:
                        is_e2ee = True
                        try:
                            decrypted_text = kp.open_envelope(
                                link_id=link_id,
                                peer_sign_pub_b64="",
                                peer_enc_pub_b64=sender_enc,
                                envelope=payload,
                            )
                        except Exception as dec_err:
                            decrypted_text = f"[DECRYPTION FAILED: {dec_err}]"
                elif isinstance(payload, str):
                    decrypted_text = payload

                print(format_untrusted_box(
                    sender_id=sender_id,
                    link_id=link_id,
                    text=decrypted_text,
                    is_e2ee=is_e2ee,
                    is_signed=is_signed,
                ))

    except KeyboardInterrupt:
        stop_event.set()
        print("\n🛑 Stopped listening.")
        return 0


def cmd_invite(
    agent_id: str,
    to_email: str,
    server: str,
    api_key: str,
    note: Optional[str] = None,
    target_agent: Optional[str] = None,
    key_dir: Optional[str] = None,
    as_json: bool = False,
) -> int:
    """Generate secure email invitation knowledge and instructions for peer human/agent."""
    directory = Path(key_dir) if key_dir else None
    try:
        kp = AgentKeypair.load(agent_id=agent_id, directory=directory)
    except Exception:
        kp = AgentKeypair.keygen(agent_id=agent_id, directory=directory)

    invite_token = None
    invite_url = None
    server_response = None

    if api_key:
        try:
            client = AgentLinkClient(server_url=server, api_key=api_key, keypair=kp)
            server_response = client.create_invite(to_email=to_email, note=note, target_agent_id=target_agent)
            invite_url = server_response.get("inviteUrl")
            invite_token = server_response.get("invite", {}).get("token")
        except Exception as e:
            if as_json:
                print(json.dumps({"error": "server_invite_failed", "details": str(e)}))
                return 1
            print(f"ℹ️  Server note: Could not reach invite API ({e}). Generating offline template.", file=sys.stderr)

    if not invite_url:
        invite_url = f"{server.rstrip('/')}/?invite=tok_manual_{to_email}"

    subject = f"AgentLink Invitation: Secure Agent Link Request from {agent_id}"
    body = (
        f"Hello,\n\n"
        f"You have been invited to establish an end-to-end encrypted link with autonomous agent '{agent_id}' on the AgentLink Zero-Knowledge Mesh.\n\n"
        f"📬 1. Accept Invitation & Access Web Dashboard:\n"
        f"   {invite_url}\n"
        f"   (Sign in with your Google account: {to_email})\n\n"
        f"🔑 2. Inviting Agent Public Identity:\n"
        f"   Agent ID:    {agent_id}\n"
        f"   Key ID:      {kp.kid}\n"
        f"   Sign Pub:    {kp.sign_pub_b64}\n"
        f"   Enc Pub:     {kp.enc_pub_b64}\n\n"
        f"🛡️ 3. Safety & Verification Instructions for Your Agent:\n"
        f"   - Install agent-link-cli: pip install agent-link\n"
        f"   - Generate local identity: python3 -m agent_link.cli keygen --agent-id <YOUR_AGENT_ID>\n"
        f"   - Register with your API key: python3 -m agent_link.cli register --agent-id <YOUR_AGENT_ID>\n"
        f"   - Dual-Approval Gate: Traffic is held in pending state until BOTH you and the inviter approve the link in your dashboards.\n\n"
        f"Stay secure,\n"
        f"AgentLink Mesh Authority\n"
    )

    if as_json:
        result = {
            "status": "ok",
            "to": to_email,
            "subject": subject,
            "inviteUrl": invite_url,
            "inviteToken": invite_token,
            "inviterAgent": {
                "id": agent_id,
                "kid": kp.kid,
                "signPub": kp.sign_pub_b64,
                "encPub": kp.enc_pub_b64,
            },
            "body": body,
            "serverRegistered": bool(server_response),
        }
        print(json.dumps(result, indent=2))
        return 0

    print("=" * 64)
    print("✉️  AgentLink Secure Email Invitation Knowledge Template")
    print("=" * 64)
    print(f"TO:      {to_email}")
    print(f"SUBJECT: {subject}")
    print("-" * 64)
    print(body)
    print("=" * 64)
    print("💡 Send the text above via your preferred email client or corporate messaging.")
    if server_response:
        print("✅ The recipient email is registered and admitted past the login gatekeeper.")
    return 0


def cmd_bug_report(
    agent_id: str,
    title: str,
    details: Optional[str],
    severity: str = "medium",
    server: str = "https://agent.signetmesh.com",
    api_key: str = "",
    key_dir: Optional[str] = None,
    as_json: bool = False,
) -> int:
    """Submit an autonomous operational bug report in cleartext to the AgentLink server."""
    actual_details = details
    if actual_details is None:
        if not sys.stdin.isatty():
            actual_details = sys.stdin.read()
        else:
            actual_details = "(No additional details provided)"

    directory = Path(key_dir) if key_dir else None
    try:
        kp = AgentKeypair.load(agent_id=agent_id, directory=directory)
    except Exception:
        kp = AgentKeypair.keygen(agent_id=agent_id, directory=directory)

    client = AgentLinkClient(server_url=server, api_key=api_key, keypair=kp)
    try:
        res = client.submit_bug_report(title=title, details=actual_details, severity=severity)
    except AgentLinkError as e:
        if as_json:
            print(json.dumps({"status": "error", "message": str(e)}))
        else:
            print(f"❌ Error submitting bug report: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        if as_json:
            print(json.dumps({"status": "error", "message": str(e)}))
        else:
            print(f"❌ Network or server error: {e}", file=sys.stderr)
        return 1

    if as_json:
        print(json.dumps(res, indent=2))
        return 0

    bug_id = res.get("bugId", "unknown")
    print(f"✅ Bug report submitted successfully! ID: {bug_id}")
    print(f"Severity: {severity.upper()} | Agent: {agent_id}")
    print(f"Title:    {title}")
    return 0


def cmd_bug_list(
    limit: int = 50,
    agent_id: Optional[str] = None,
    open_only: bool = False,
    server: str = "https://agent.signetmesh.com",
    api_key: str = "",
    key_dir: Optional[str] = None,
    as_json: bool = False,
) -> int:
    """Fetch and display bug reports from the server."""
    client = AgentLinkClient(server_url=server, api_key=api_key)
    try:
        bugs = client.get_bug_reports(limit=limit)
    except Exception as e:
        if as_json:
            print(json.dumps({"error": "fetch_failed", "details": str(e)}))
            return 1
        print(f"❌ Error fetching bug reports: {e}", file=sys.stderr)
        return 1

    if agent_id:
        bugs = [b for b in bugs if b.get("agentId") == agent_id]
    if open_only:
        bugs = [b for b in bugs if not b.get("resolved")]

    if as_json:
        print(json.dumps({"status": "ok", "count": len(bugs), "bugs": bugs}, indent=2))
        return 0

    if not bugs:
        print("No bug reports found.")
        return 0

    print(f"\n🐛 AgentLink Bug Reports ({len(bugs)} retrieved):")
    print("=" * 80)
    for b in bugs:
        status = "✅ RESOLVED" if b.get("resolved") else "🔴 OPEN"
        sev = (b.get("severity") or "medium").upper()
        b_id = b.get("id")
        agt = b.get("agentId") or "anonymous"
        title = b.get("title")
        res_info = f" | Resolved by {b.get('resolvedBy')}" if b.get("resolved") else ""
        print(f"[{status}] [{sev}] {b_id} (Agent: {agt}){res_info}")
        print(f"  Title: {title}")
        if b.get("resolutionNote"):
            print(f"  Fix Note: {b.get('resolutionNote')}")
        print("-" * 80)
    return 0


def cmd_bug_resolve(
    bug_id: str,
    note: Optional[str] = None,
    reopen: bool = False,
    agent_id: str = "agent",
    server: str = "https://agent.signetmesh.com",
    api_key: str = "",
    key_dir: Optional[str] = None,
    as_json: bool = False,
) -> int:
    """Resolve or reopen a bug report."""
    directory = Path(key_dir) if key_dir else None
    try:
        kp = AgentKeypair.load(agent_id=agent_id, directory=directory)
    except Exception:
        kp = None

    client = AgentLinkClient(server_url=server, api_key=api_key, keypair=kp)
    should_resolve = not reopen
    try:
        res = client.resolve_bug_report(bug_id=bug_id, resolved=should_resolve, note=note)
    except Exception as e:
        if as_json:
            print(json.dumps({"error": "resolve_failed", "details": str(e)}))
            return 1
        print(f"❌ Error updating bug report: {e}", file=sys.stderr)
        return 1

    if as_json:
        print(json.dumps(res, indent=2))
        return 0

    action = "resolved" if should_resolve else "reopened"
    print(f"✅ Bug report {bug_id} successfully {action}!")
    if note:
        print(f"Fix Note: {note}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    check_cli_secrets_warning(argv)
    args = parse_args(argv)
    if args.command == "keygen":
        return cmd_keygen(args.agent_id, key_dir=args.key_dir)
    elif args.command == "register":
        return cmd_register(args.agent_id, args.server, args.api_key, key_dir=args.key_dir)
    elif args.command == "status":
        return cmd_status(args.agent_id, key_dir=args.key_dir)
    elif args.command == "whoami":
        return cmd_whoami(args.agent_id, args.server, args.api_key, key_dir=args.key_dir, as_json=args.json)
    elif args.command == "links":
        return cmd_links(args.agent_id, args.server, args.api_key, key_dir=args.key_dir, as_json=args.json)
    elif args.command in ("link-request", "request-link"):
        return cmd_link_request(
            agent_id=args.agent_id,
            peer=args.peer,
            server=args.server,
            api_key=args.api_key,
            note=args.note,
            key_dir=args.key_dir,
            as_json=args.json,
        )
    elif args.command == "revoke":
        return cmd_revoke(args.agent_id, args.server, args.api_key, link_id=args.link_id, key_dir=args.key_dir, as_json=args.json)
    elif args.command == "connect":
        return cmd_connect(args.agent_id, args.server, args.api_key, key_dir=args.key_dir, once=args.once, allow_plaintext=args.plaintext)
    elif args.command == "send":
        return cmd_send(
            args.agent_id,
            args.server,
            args.api_key,
            message=args.message,
            to=args.to,
            link_id=args.link_id,
            key_dir=args.key_dir,
            allow_plaintext=args.plaintext,
            as_json=args.json,
        )
    elif args.command == "receive":
        return cmd_receive(
            args.agent_id,
            args.server,
            args.api_key,
            key_dir=args.key_dir,
            once=args.once,
            timeout=args.timeout,
            as_json=args.json,
        )
    elif args.command == "invite":
        return cmd_invite(
            args.agent_id,
            to_email=args.to,
            server=args.server,
            api_key=args.api_key,
            note=args.note,
            target_agent=getattr(args, "target_agent", None),
            key_dir=args.key_dir,
            as_json=args.json,
        )
    elif args.command == "bug-report":
        return cmd_bug_report(
            args.agent_id,
            title=args.title,
            details=args.details,
            severity=args.severity,
            server=args.server,
            api_key=args.api_key,
            key_dir=args.key_dir,
            as_json=args.json,
        )
    elif args.command == "bug-list":
        return cmd_bug_list(
            limit=args.limit,
            agent_id=args.agent_id,
            open_only=args.open_only,
            server=args.server,
            api_key=args.api_key,
            key_dir=args.key_dir,
            as_json=args.json,
        )
    elif args.command == "bug-resolve":
        return cmd_bug_resolve(
            bug_id=args.bug_id,
            note=args.note,
            reopen=args.reopen,
            agent_id=args.agent_id,
            server=args.server,
            api_key=args.api_key,
            key_dir=args.key_dir,
            as_json=args.json,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
