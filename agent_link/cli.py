"""Command Line Interface for AgentLink CLI with Protocol Hardening and Agent-Safe Interfaces."""

from __future__ import annotations
import argparse
import hashlib
import json
import os
import queue
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from agent_link.client import (
    AgentLinkClient,
    AgentLinkError,
    AgentLinkSecurityError,
    AgentLinkAuthError,
    AgentLinkNotFoundError,
    AgentLinkNetworkError,
    AgentLinkTimeoutError,
    AgentLinkTruncatedResponseError,
)
from agent_link.crypto import AgentKeypair
from agent_link.qr import display_qr
from agent_link.profile import ProfileManager
from agent_link.security import (
    format_untrusted_box,
    process_inbound_envelope,
    PeerKeyStore,
    ReplayProtector,
)

DEFAULT_SERVER = os.getenv("AGENTLINK_SERVER_URL", "http://localhost:3000")


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
    p_keygen.add_argument("--json", action="store_true", help="Output machine-readable JSON (suppresses ASCII QR code)")
    p_keygen.add_argument("--quiet", "-q", action="store_true", help="Suppress ASCII QR code output")
    p_keygen.add_argument("--force", "--overwrite", dest="overwrite", action="store_true", help="Force overwrite of existing keypair (key rotation)")

    # 2. register
    p_reg = subparsers.add_parser("register", help="Register agent with AgentLink server using API key")
    p_reg.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Identifier for this agent")
    p_reg.add_argument("--server", default=DEFAULT_SERVER, help="AgentLink server URL")
    p_reg.add_argument("--api-key", default=os.getenv("AGENTLINK_API_KEY", ""), help="Human-provisioned API key")
    p_reg.add_argument("--key-dir", default=os.getenv("AGENTLINK_KEY_DIR"), help="Directory to store keys")
    p_reg.add_argument("--json", action="store_true", help="Output machine-readable JSON (suppresses ASCII QR code)")
    p_reg.add_argument("--quiet", "-q", action="store_true", help="Suppress ASCII QR code output")

    # 3. status
    p_status = subparsers.add_parser("status", help="Show local identity status and fingerprints")
    p_status.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Identifier for this agent")
    p_status.add_argument("--key-dir", default=os.getenv("AGENTLINK_KEY_DIR"), help="Directory to store keys")

    # 4. whoami
    p_whoami = subparsers.add_parser("whoami", help="Show full agent identity, registration, and active links")
    p_whoami.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Identifier for this agent")
    p_whoami.add_argument("--server", default=DEFAULT_SERVER, help="AgentLink server URL")
    p_whoami.add_argument("--api-key", default=os.getenv("AGENTLINK_API_KEY", ""), help="Human-provisioned API key")
    p_whoami.add_argument("--key-dir", default=os.getenv("AGENTLINK_KEY_DIR"), help="Directory to store keys")
    p_whoami.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # 5. links
    p_links = subparsers.add_parser("links", help="List all active and pending links")
    p_links.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Identifier for this agent")
    p_links.add_argument("--server", default=DEFAULT_SERVER, help="AgentLink server URL")
    p_links.add_argument("--api-key", default=os.getenv("AGENTLINK_API_KEY", ""), help="Human-provisioned API key")
    p_links.add_argument("--key-dir", default=os.getenv("AGENTLINK_KEY_DIR"), help="Directory to store keys")
    p_links.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # 5b. link-request / request-link
    p_link_req = subparsers.add_parser("link-request", aliases=["request-link"], help="Request an end-to-end encrypted peer link with another agent")
    p_link_req.add_argument("--peer", "--to", required=True, dest="peer", help="Target peer agent ID to connect with")
    p_link_req.add_argument("--note", help="Optional note or purpose for the requested link")
    p_link_req.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Identifier for your agent")
    p_link_req.add_argument("--server", default=DEFAULT_SERVER, help="AgentLink server URL")
    p_link_req.add_argument("--api-key", default=os.getenv("AGENTLINK_API_KEY", ""), help="Human-provisioned API key")
    p_link_req.add_argument("--key-dir", default=os.getenv("AGENTLINK_KEY_DIR"), help="Directory to store keys")
    p_link_req.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # 6. revoke
    p_revoke = subparsers.add_parser("revoke", help="Sever / revoke a link")
    p_revoke.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Identifier for this agent")
    p_revoke.add_argument("--link-id", required=True, help="Link ID to revoke")
    p_revoke.add_argument("--server", default=DEFAULT_SERVER, help="AgentLink server URL")
    p_revoke.add_argument("--api-key", default=os.getenv("AGENTLINK_API_KEY", ""), help="Human-provisioned API key")
    p_revoke.add_argument("--key-dir", default=os.getenv("AGENTLINK_KEY_DIR"), help="Directory to store keys")
    p_revoke.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # 7. connect
    p_connect = subparsers.add_parser("connect", help="Keygen, display optical QR, register, and listen/chat on peer mesh")
    p_connect.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Identifier for this agent")
    p_connect.add_argument("--server", default=DEFAULT_SERVER, help="AgentLink server URL")
    p_connect.add_argument("--api-key", default=os.getenv("AGENTLINK_API_KEY", ""), help="Human-provisioned API key")
    p_connect.add_argument("--key-dir", default=os.getenv("AGENTLINK_KEY_DIR"), help="Directory to store keys")
    p_connect.add_argument("--once", action="store_true", help="Register and exit without long-polling")
    p_connect.add_argument("--interactive", "-i", action="store_true", help="Run interactive stdin chat loop (for human operators in terminal)")
    p_connect.add_argument("--plaintext", action="store_true", help="Allow unencrypted fallback transmissions (insecure)")

    # 8. send
    p_send = subparsers.add_parser("send", help="Send a message to a peer agent or link")
    p_send.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Sender agent identifier")
    p_send.add_argument("--to", help="Target recipient agent ID")
    p_send.add_argument("--link-id", help="Link ID to dispatch message over")
    p_send.add_argument("--message", "-m", help="Message body to send")
    p_send.add_argument("--server", default=DEFAULT_SERVER, help="AgentLink server URL")
    p_send.add_argument("--api-key", default=os.getenv("AGENTLINK_API_KEY", ""), help="Human-provisioned API key")
    p_send.add_argument("--key-dir", default=os.getenv("AGENTLINK_KEY_DIR"), help="Directory to store keys")
    p_send.add_argument("--plaintext", action="store_true", help="Allow unencrypted fallback transmission (insecure)")
    p_send.add_argument("--json", action="store_true", help="Output machine-readable JSON result")

    # 9. receive (agent-safe scriptable command)
    p_receive = subparsers.add_parser("receive", help="Poll and decrypt incoming messages (single-shot), or run an inbox watcher daemon (--watch)")
    p_receive.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Identifier for this agent")
    p_receive.add_argument("--server", default=DEFAULT_SERVER, help="AgentLink server URL")
    p_receive.add_argument("--api-key", default=os.getenv("AGENTLINK_API_KEY", ""), help="Human-provisioned API key")
    p_receive.add_argument("--key-dir", default=os.getenv("AGENTLINK_KEY_DIR"), help="Directory to store keys")
    p_receive.add_argument("--once", action="store_true", default=True, help="Poll once and exit immediately (default for receive)")
    p_receive.add_argument("--timeout", type=int, default=5, help="Poll timeout in seconds")
    p_receive.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    p_receive.add_argument("--watch", action="store_true", help="Daemon mode: long-poll in a loop, append raw envelopes to --inbox, print new ones as JSON lines")
    p_receive.add_argument("--inbox", help="Path to the JSONL inbox file")
    p_receive.add_argument("--decrypt", action="store_true", help="Decrypt envelopes from --inbox file, or decrypt in real-time in --watch mode")
    p_receive.add_argument("--interval", type=float, default=2.0, help="Seconds between long-poll rounds in --watch mode")
    p_receive.add_argument("--no-auth", action="store_true", help="Poll without an API key; the relay serves read endpoints anonymously")
    p_receive.add_argument("--allow-plaintext", "--plaintext", dest="allow_plaintext", action="store_true", help="Explicitly allow receiving unencrypted plaintext messages")

    # 10. invite (generate secure email invite knowledge / token)
    # 11. invite
    p_invite = subparsers.add_parser("invite", help="Generate secure email invitation knowledge and link for a collaborator")
    p_invite.add_argument("--to", required=True, help="Recipient email address to invite (e.g. collaborator@example.com)")
    p_invite.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Identifier for your agent")
    p_invite.add_argument("--target-agent", "--peer", dest="target_agent", help="Optional peer agent ID to connect with upon invite acceptance")
    p_invite.add_argument("--note", help="Optional invitation note/context")
    p_invite.add_argument("--server", default=DEFAULT_SERVER, help="AgentLink server URL")
    p_invite.add_argument("--api-key", default=os.getenv("AGENTLINK_API_KEY", ""), help="Human-provisioned API key")
    p_invite.add_argument("--key-dir", default=os.getenv("AGENTLINK_KEY_DIR"), help="Directory to store keys")
    p_invite.add_argument("--json", action="store_true", help="Output machine-readable JSON invite knowledge")

    # 12. bug-report
    p_bug = subparsers.add_parser("bug-report", help="Submit an autonomous operational bug report to AgentLink")
    p_bug.add_argument("--title", required=True, help="Short summary of the bug or error")
    p_bug.add_argument("--details", "-d", help="Detailed description, stack trace, or error payload (reads from stdin if omitted)")
    p_bug.add_argument("--severity", choices=["low", "medium", "high", "critical"], default="medium", help="Bug severity level (default: medium)")
    p_bug.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Identifier for your agent")
    p_bug.add_argument("--server", default=DEFAULT_SERVER, help="AgentLink server URL")
    p_bug.add_argument("--api-key", default=os.getenv("AGENTLINK_API_KEY", ""), help="AgentLink API key (optional for bug reporting)")
    p_bug.add_argument("--key-dir", default=os.getenv("AGENTLINK_KEY_DIR"), help="Directory to store keys")
    p_bug.add_argument("--json", action="store_true", help="Output machine-readable JSON response")

    # 13. bug-list
    p_bug_list = subparsers.add_parser("bug-list", help="List operational bug reports on AgentLink")
    p_bug_list.add_argument("--limit", type=int, default=50, help="Max reports to retrieve (default: 50)")
    p_bug_list.add_argument("--agent-id", default=None, help="Filter reports by agent ID")
    p_bug_list.add_argument("--open-only", action="store_true", help="Show only unresolved open bugs")
    p_bug_list.add_argument("--server", default=DEFAULT_SERVER, help="AgentLink server URL")
    p_bug_list.add_argument("--api-key", default=os.getenv("AGENTLINK_API_KEY", ""), help="AgentLink API key")
    p_bug_list.add_argument("--key-dir", default=os.getenv("AGENTLINK_KEY_DIR"), help="Directory to store keys")
    p_bug_list.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # 14. bug-resolve
    p_bug_res = subparsers.add_parser("bug-resolve", help="Mark an operational bug report as resolved (or reopened)")
    p_bug_res.add_argument("--bug-id", required=True, help="Bug report ID (e.g. bug_1789318804571_49531da3)")
    p_bug_res.add_argument("--note", help="Optional resolution note or fix commit reference")
    p_bug_res.add_argument("--reopen", action="store_true", help="Reopen the bug report instead of resolving")
    p_bug_res.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Identifier for your agent")
    p_bug_res.add_argument("--server", default=DEFAULT_SERVER, help="AgentLink server URL")
    p_bug_res.add_argument("--api-key", default=os.getenv("AGENTLINK_API_KEY", ""), help="AgentLink API key")
    p_bug_res.add_argument("--key-dir", default=os.getenv("AGENTLINK_KEY_DIR"), help="Directory to store keys")
    p_bug_res.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # Global connection profile flag
    parser.add_argument("--profile", help="Named connection profile to use (configured via 'agent-link profile')")

    # 15. profile
    p_profile = subparsers.add_parser("profile", help="Manage named connection profiles (server URL & default identity)")
    sub_profile = p_profile.add_subparsers(dest="profile_action", required=True)

    p_p_set = sub_profile.add_parser("set", help="Create or update a named connection profile")
    p_p_set.add_argument("name", help="Profile name (e.g. 'staging', 'production', 'default')")
    p_p_set.add_argument("--server", required=True, help="AgentLink relay server URL")
    p_p_set.add_argument("--agent-id", default=None, help="Default agent ID for this profile")
    p_p_set.add_argument("--default", action="store_true", help="Set as active/default profile")
    p_p_set.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    p_p_list = sub_profile.add_parser("list", help="List all configured connection profiles")
    p_p_list.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    p_p_show = sub_profile.add_parser("show", help="Show details of a profile")
    p_p_show.add_argument("name", nargs="?", default=None, help="Profile name (defaults to active profile)")
    p_p_show.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    p_p_use = sub_profile.add_parser("use", help="Set the active connection profile")
    p_p_use.add_argument("name", help="Profile name to activate")

    p_p_rm = sub_profile.add_parser("remove", aliases=["rm", "delete"], help="Delete a connection profile")
    p_p_rm.add_argument("name", help="Profile name to remove")

    return parser.parse_args(argv)


def cmd_keygen(
    agent_id: str,
    key_dir: Optional[str] = None,
    as_json: bool = False,
    quiet: bool = False,
    overwrite: bool = False,
) -> int:
    directory = Path(key_dir) if key_dir else None
    kp = AgentKeypair.keygen(agent_id=agent_id, directory=directory, overwrite=overwrite)
    if as_json:
        data = {
            "status": "ok",
            "agentId": kp.agent_id,
            "kid": kp.kid,
            "signPub": kp.sign_pub_b64,
            "encPub": kp.enc_pub_b64,
        }
        print(json.dumps(data, indent=2))
        return 0
    if not quiet:
        print(display_qr(kp))
    else:
        print(f"🔑 Generated keypair for '{kp.agent_id}' (kid: {kp.kid})")
    return 0


def cmd_register(
    agent_id: str,
    server: str,
    api_key: str,
    key_dir: Optional[str] = None,
    as_json: bool = False,
    quiet: bool = False,
) -> int:
    if not api_key:
        print("❌ Error: API key required. Provide via --api-key or set AGENTLINK_API_KEY environment variable.", file=sys.stderr)
        return 1

    directory = Path(key_dir) if key_dir else None
    try:
        kp = AgentKeypair.load(agent_id=agent_id, directory=directory)
    except FileNotFoundError:
        kp = AgentKeypair.keygen(agent_id=agent_id, directory=directory)
    kp.save(directory=directory)

    if not as_json and not quiet:
        print(f"📡 Registering agent '{agent_id}' with AgentLink server: {server}")
    client = AgentLinkClient(server_url=server, api_key=api_key, keypair=kp)
    try:
        res = client.register()
        if as_json:
            out = {
                "status": res.get("status", "ok"),
                "agentId": res.get("agentId", agent_id),
                "kid": kp.kid,
                "pollUrl": res.get("pollUrl"),
                "registeredAt": res.get("registeredAt"),
                "nextStep": f"Ask your human operator to approve any pending peer links in the dashboard, then check links with: python3 -m agent_link.cli links --agent-id {agent_id} --json",
            }
            print(json.dumps(out, indent=2))
            return 0

        print(f"✅ Successfully registered! Status: {res.get('status')} | Agent ID: {res.get('agentId')}")
        print(f"🔑 Identity Key ID: {kp.kid}")
        if not quiet:
            print("\nDisplaying Optical Public Identity QR Code for Human Verification:")
            print(display_qr(kp))

        print("\n👉 Next Steps:")
        print("1. Have your human operator approve any peer links in the AgentLink dashboard.")
        print(f"2. Check link status: python3 -m agent_link.cli links --agent-id \"{agent_id}\"")
        print(f"3. Start listening for messages: python3 -m agent_link.cli receive --agent-id \"{agent_id}\" --watch --inbox ~/.agent-link/inbox.jsonl")
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
        "serverUrl": server,
        "registered": False,
        "pollingStatus": "never",
        "reachable": False,
        "activeLinksCount": 0,
        "pendingLinksCount": 0,
    }

    if api_key:
        client = AgentLinkClient(server_url=server, api_key=api_key, keypair=kp)
        try:
            agents = client.get_agents(agent_id)
            matching = next((a for a in agents if a.get("id") == agent_id), None)
            if matching:
                info["registered"] = True
                last_seen_str = matching.get("lastSeen")
                if last_seen_str:
                    try:
                        last_seen_dt = datetime.fromisoformat(last_seen_str.replace("Z", "+00:00"))
                        now_dt = datetime.now(timezone.utc)
                        age_sec = (now_dt - last_seen_dt).total_seconds()
                        if age_sec <= 120:
                            info["pollingStatus"] = "active"
                            info["reachable"] = True
                        else:
                            info["pollingStatus"] = "idle"
                            info["reachable"] = False
                    except Exception:
                        info["pollingStatus"] = "unknown"
            links = client.get_links()
            info["activeLinksCount"] = len([l for l in links if l.get("status") == "active"])
            info["pendingLinksCount"] = len([l for l in links if l.get("status") == "pending_approval"])
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
    print(f"Server URL:          {server}")
    print(f"Server Registration: {'✅ Registered' if info['registered'] else '⚠️ Unregistered'}")
    polling_label = "🟢 Active (recently polled)" if info["pollingStatus"] == "active" else ("🟡 Idle" if info["pollingStatus"] == "idle" else "⚪ Never")
    print(f"Polling Status:      {polling_label}")
    print(f"Reachable:           {'✅ Reachable (polling relay)' if info['reachable'] else '⚠️ Unreachable (idle/not polling)'}")
    print(f"Active Links:        {info['activeLinksCount']}")
    print(f"Pending Links:       {info['pendingLinksCount']}")
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

    has_pending = any(l.get("status") == "pending_approval" for l in links)
    if has_pending:
        print("\n⏳ Notice: Some links are 'pending_approval'.")
        print("   Both human operators must approve the link in their dashboards before messages can flow.")
        print(f"   👉 Re-check status: python3 -m agent_link.cli links --agent-id \"{agent_id}\"")

    has_active = any(l.get("status") == "active" for l in links)
    if has_active:
        print("\n🚀 Active link(s) ready for communication:")
        print(f"   👉 Send message: python3 -m agent_link.cli send --agent-id \"{agent_id}\" --to <PEER_ID> --message \"...\" --json")
        print(f"   👉 Listen for replies: python3 -m agent_link.cli receive --agent-id \"{agent_id}\" --watch --inbox ~/.agent-link/inbox.jsonl")
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

    my_links = client.get_links()

    if target_link_id:
        if not target_peer_id:
            link_obj = next((l for l in my_links if l.get("id") == target_link_id), None)
            if link_obj:
                target_peer_id = link_obj.get("agentBId") if link_obj.get("agentAId") == agent_id else link_obj.get("agentAId")
    else:
        if target_peer_id:
            matching = [l for l in my_links if (l.get("agentAId") == target_peer_id or l.get("agentBId") == target_peer_id) and l.get("status") == "active"]
            if matching:
                target_link_id = matching[0].get("id")
            else:
                print(f"❌ Error: No active link found with peer '{target_peer_id}'.", file=sys.stderr)
                return 1
        else:
            active = [l for l in my_links if l.get("status") == "active"]
            if len(active) == 0:
                print(f"❌ Error: No active links found for agent '{agent_id}'. Establish a link in dashboard first.", file=sys.stderr)
                return 1
            elif len(active) == 1:
                target_link_id = active[0].get("id")
                target_peer_id = active[0].get("agentBId") if active[0].get("agentAId") == agent_id else active[0].get("agentAId")
            else:
                peers = [active_l.get("agentBId") if active_l.get("agentAId") == agent_id else active_l.get("agentAId") for active_l in active]
                print(
                    f"❌ Error: Multiple active links exist ({len(active)}). "
                    f"You must explicitly specify the peer (--to <PEER_ID>) or link (--link-id <LINK_ID>).\n"
                    f"   Available active peers: {', '.join(peers)}",
                    file=sys.stderr,
                )
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
            send_res = client.send_encrypted(
                link_id=target_link_id,
                peer_enc_pub_b64=peer_enc_pub,
                plaintext=msg_text,
                recipient_id=target_peer_id,
            )
            msg_id = send_res.get("msgId") or "unknown"
            if as_json:
                print(json.dumps({
                    "status": "ok",
                    "state": "accepted",
                    "accepted": True,
                    "delivered": False,
                    "msgId": msg_id,
                    "linkId": target_link_id,
                    "encrypted": True,
                    "to": target_peer_id,
                    "targetPeer": target_peer_id,
                }))
            else:
                print(f"🚀 [FAIL-CLOSED E2EE] Message accepted by relay (id: {msg_id}, state: accepted, awaiting recipient receipt/ack) across {target_link_id}!")
        else:
            send_res = client.send_message(link_id=target_link_id, text=msg_text, allow_plaintext=True)
            msg_id = send_res.get("msgId") or "unknown"
            if as_json:
                print(json.dumps({
                    "status": "ok",
                    "state": "accepted",
                    "accepted": True,
                    "delivered": False,
                    "msgId": msg_id,
                    "linkId": target_link_id,
                    "encrypted": False,
                    "to": target_peer_id,
                    "targetPeer": target_peer_id,
                }))
            else:
                print(f"⚠️ [PLAINTEXT] Message accepted by relay (id: {msg_id}, state: accepted, unencrypted) across {target_link_id}!")
        return 0
    except Exception as e:
        print(f"❌ Send failed: {e}", file=sys.stderr)
        return 1


def _envelope_hash(message: Dict[str, Any]) -> str:
    """Stable sha256 over the canonical JSON of a raw relay message (dedupe key)."""
    canonical = json.dumps(message, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _load_seen_hashes(inbox_path: Path) -> Set[str]:
    """Rebuild the dedupe set from an existing inbox file so restarts don't re-emit."""
    seen: Set[str] = set()
    if inbox_path.exists():
        for line in inbox_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            msg = record.get("message")
            if isinstance(msg, dict):
                seen.add(_envelope_hash(msg))
    return seen


def _watch_batch(
    client: AgentLinkClient,
    inbox_path: Path,
    seen: Set[str],
    timeout: int,
    decrypt: bool = False,
    as_json: bool = False,
    allow_plaintext: bool = False,
) -> int:
    """Poll once; append newly seen raw envelopes to the inbox file.

    Each new message is appended as one JSON line
    ({"received_at", "sha256", "message"}) and also printed to stdout.
    If decrypt is True and a local keypair is available, decrypted content is output.
    Returns the number of newly seen messages.
    """
    new_messages = []
    raw_messages = client.poll_messages(timeout_seconds=timeout)
    for m in raw_messages:
        if not isinstance(m, dict):
            continue
        digest = _envelope_hash(m)
        if digest in seen:
            continue
        seen.add(digest)
        new_messages.append((digest, m))

    if new_messages:
        with inbox_path.open("a", encoding="utf-8") as fh:
            for digest, m in new_messages:
                record = {
                    "received_at": datetime.now(timezone.utc).isoformat(),
                    "sha256": digest,
                    "message": m,
                }
                fh.write(json.dumps(record, separators=(",", ":")) + "\n")
                if decrypt and client.keypair:
                    result = process_inbound_envelope(
                        m=m,
                        kp=client.keypair,
                        replay_protector=client.replay_protector,
                        peer_key_store=client.peer_key_store,
                        allow_plaintext=allow_plaintext,
                    )

                    if as_json:
                        print(json.dumps({
                            "received_at": record["received_at"],
                            "sha256": digest,
                            "linkId": result["linkId"],
                            "senderId": result["senderId"],
                            "text": result["text"],
                            "encrypted": result["encrypted"],
                            "signed": result["signed"],
                            "verified": result["verified"],
                            "status": result["status"],
                            "error": result["error"],
                        }, separators=(",", ":")))
                    else:
                        print(format_untrusted_box(
                            sender_id=result["senderId"],
                            link_id=result["linkId"],
                            text=result["text"],
                            is_e2ee=result["encrypted"],
                            is_signed=result["signed"],
                        ))
                else:
                    print(json.dumps(m, separators=(",", ":")))
        sys.stdout.flush()

        # Feature 9.5: Durably recorded to inbox on disk BEFORE acknowledging to relay!
        msg_ids_to_ack = [m.get("msgId") for _, m in new_messages if isinstance(m, dict) and m.get("msgId")]
        if msg_ids_to_ack and client.api_key:
            try:
                client.ack_messages(msg_ids_to_ack, lease_id=client.last_lease_id)
            except Exception:
                pass
    return len(new_messages)


def cmd_receive_watch(
    agent_id: str,
    server: str,
    api_key: str,
    inbox: str,
    interval: float = 2.0,
    timeout: int = 15,
    key_dir: Optional[str] = None,
    decrypt: bool = False,
    as_json: bool = False,
    allow_plaintext: bool = False,
) -> int:
    """Daemon mode: long-poll in a loop, durably store raw envelopes, emit new ones.

    The watcher durably appends envelopes to --inbox. If --decrypt is specified
    and local keys are present, it also decrypts incoming messages on the fly.
    """
    inbox_path = Path(inbox)
    try:
        inbox_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print(f"❌ Error: cannot create inbox directory: {e}", file=sys.stderr)
        return 1

    seen = _load_seen_hashes(inbox_path)

    # Best effort: attach the local identity if present, but don't require it.
    kp = None
    try:
        kp = AgentKeypair.load(agent_id=agent_id, directory=Path(key_dir) if key_dir else None)
    except FileNotFoundError:
        pass
    client = AgentLinkClient(server_url=server, api_key=api_key or "", keypair=kp, agent_id=agent_id)

    auth_note = "anonymous" if not client.api_key else "authenticated"
    print(
        f"👁️  watching {server}/api/agents/{agent_id}/poll ({auth_note}) "
        f"-> {inbox_path} [{len(seen)} already seen]"
        f"{' (with real-time decryption)' if decrypt and kp else ''}",
        file=sys.stderr,
    )
    try:
        while True:
            try:
                new_count = _watch_batch(client, inbox_path, seen, timeout, decrypt=decrypt, as_json=as_json, allow_plaintext=allow_plaintext)
                if new_count:
                    print(f"📨 {new_count} new message(s)", file=sys.stderr)
            except (AgentLinkTimeoutError, AgentLinkNetworkError, AgentLinkTruncatedResponseError) as e:
                print(f"⚠️  poll failed ({e}); retrying in {interval}s", file=sys.stderr)
            except AgentLinkError as e:
                print(f"❌ fatal relay error: {e}", file=sys.stderr)
                return 1
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n👋 watch stopped", file=sys.stderr)
        return 0


def decrypt_inbox_file(
    inbox_path: Path,
    kp: AgentKeypair,
    replay_protector: Optional[ReplayProtector] = None,
    peer_key_store: Optional[PeerKeyStore] = None,
    as_json: bool = False,
    allow_plaintext: bool = False,
) -> int:
    """Decrypt and verify envelopes recorded in an offline JSONL inbox file."""
    if not inbox_path.exists():
        print(f"❌ Error: Inbox file not found: {inbox_path}", file=sys.stderr)
        return 1

    decrypted_records: List[Dict[str, Any]] = []
    lines = inbox_path.read_text(encoding="utf-8").splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            raw_entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        m = raw_entry.get("message") if isinstance(raw_entry, dict) and "message" in raw_entry else raw_entry
        if not isinstance(m, dict):
            continue

        result = process_inbound_envelope(
            m=m,
            kp=kp,
            replay_protector=replay_protector,
            peer_key_store=peer_key_store,
            allow_plaintext=allow_plaintext,
        )

        msg_record = {
            "linkId": result["linkId"],
            "senderId": result["senderId"],
            "senderType": result.get("senderType", "agent"),
            "operatorEmail": result.get("operatorEmail"),
            "text": result["text"],
            "plaintext": result.get("plaintext") or result["text"],
            "encrypted": result["encrypted"],
            "signed": result["signed"],
            "verified": result["verified"],
            "status": result["status"],
            "error": result["error"],
            "seq": result.get("seq"),
            "receivedAt": raw_entry.get("received_at") if isinstance(raw_entry, dict) else None,
        }
        decrypted_records.append(msg_record)

        if not as_json:
            print(format_untrusted_box(
                sender_id=result["senderId"],
                link_id=result["linkId"],
                text=result["text"],
                is_e2ee=result["encrypted"],
                is_signed=result["signed"],
            ))

    if as_json:
        print(json.dumps({"status": "ok", "messages": decrypted_records}, indent=2))
    return 0


def cmd_receive(
    agent_id: str,
    server: str,
    api_key: str,
    key_dir: Optional[str] = None,
    once: bool = True,
    timeout: int = 5,
    as_json: bool = False,
    watch: bool = False,
    inbox: Optional[str] = None,
    decrypt: bool = False,
    interval: float = 2.0,
    no_auth: bool = False,
    allow_plaintext: bool = False,
) -> int:
    if watch:
        if not inbox:
            print("❌ Error: --watch requires --inbox PATH for the durable message log.", file=sys.stderr)
            return 1
        return cmd_receive_watch(
            agent_id, server, api_key or "",
            inbox=inbox, interval=interval, timeout=timeout, key_dir=key_dir,
            decrypt=decrypt, as_json=as_json, allow_plaintext=allow_plaintext,
        )

    if inbox:
        directory = Path(key_dir) if key_dir else None
        try:
            kp = AgentKeypair.load(agent_id=agent_id, directory=directory)
        except FileNotFoundError as e:
            print(f"❌ Error: {e}", file=sys.stderr)
            return 1
        client = AgentLinkClient(server_url=server, api_key=api_key or "", keypair=kp, agent_id=agent_id)
        return decrypt_inbox_file(
            Path(inbox),
            kp,
            replay_protector=client.replay_protector,
            peer_key_store=client.peer_key_store,
            as_json=as_json,
            allow_plaintext=allow_plaintext,
        )

    if not api_key and not no_auth:
        print("❌ Error: API key required (or pass --no-auth for anonymous polling).", file=sys.stderr)
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
            result = process_inbound_envelope(
                m=m,
                kp=kp,
                replay_protector=client.replay_protector,
                peer_key_store=client.peer_key_store,
                allow_plaintext=allow_plaintext,
            )

            msg_record = {
                "linkId": result["linkId"],
                "senderId": result["senderId"],
                "senderType": result.get("senderType", "agent"),
                "operatorEmail": result.get("operatorEmail"),
                "text": result["text"],
                "plaintext": result.get("plaintext") or result["text"],
                "encrypted": result["encrypted"],
                "signed": result["signed"],
                "verified": result["verified"],
                "status": result["status"],
                "error": result["error"],
                "seq": result.get("seq"),
            }
            processed_messages.append(msg_record)

            if not as_json:
                print(format_untrusted_box(
                    sender_id=result["senderId"],
                    link_id=result["linkId"],
                    text=result["text"],
                    is_e2ee=result["encrypted"],
                    is_signed=result["signed"],
                ))

        if as_json:
            print(json.dumps({"status": "ok", "messages": processed_messages}, indent=2))

        # Explicit recipient acknowledgement after successful processing
        msg_ids_to_ack = [m.get("msgId") for m in raw_messages if isinstance(m, dict) and m.get("msgId")]
        if msg_ids_to_ack and client.api_key:
            try:
                client.ack_messages(msg_ids_to_ack, lease_id=client.last_lease_id)
            except Exception:
                pass

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
    interactive: bool = False,
) -> int:
    if agent_id == "agent":
        print("💡 Tip: Connecting as default agent ID 'agent'. To use a custom ID (e.g. 'ted'), use: --agent-id ted\n")

    ret = cmd_register(agent_id, server, api_key, key_dir=key_dir)
    if ret != 0 or once:
        return ret

    # Guard autonomous agents against hanging on stdin
    if not interactive and not sys.stdin.isatty():
        print(
            f"\nℹ️  [AUTONOMOUS AGENT DETECTED] Stdin is not a TTY and '--interactive' was not specified.\n"
            f"   Agent registered successfully. Skipping interactive terminal chat loop.\n"
            f"   👉 Check links: python3 -m agent_link.cli links --agent-id \"{agent_id}\"\n"
            f"   👉 To listen continuously in background, use: python3 -m agent_link.cli receive --agent-id \"{agent_id}\" --watch --inbox ~/.agent-link/inbox.jsonl"
        )
        return 0

    if not interactive and sys.stdin.isatty():
        print("\n⚠️  [NOTICE] Entering interactive terminal chat loop. If running as an autonomous agent, use '--once' or 'receive --watch' instead to avoid waiting on stdin.")

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

                result = process_inbound_envelope(
                    m=m,
                    kp=kp,
                    replay_protector=client.replay_protector,
                    peer_key_store=client.peer_key_store,
                    allow_plaintext=allow_plaintext,
                    active_link=last_active_link,
                )

                print(format_untrusted_box(
                    sender_id=result["senderId"],
                    link_id=result["linkId"],
                    text=result["text"],
                    is_e2ee=result["encrypted"],
                    is_signed=result["signed"],
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

    safety_number = server_response.get("safetyNumber") if server_response else None
    agent_prompt = server_response.get("agentPrompt") if server_response else None

    if as_json:
        result = {
            "status": "ok",
            "to": to_email,
            "subject": subject,
            "inviteUrl": invite_url,
            "inviteToken": invite_token,
            "safetyNumber": safety_number,
            "agentPrompt": agent_prompt,
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
    if safety_number:
        print(f"SAFETY:  {safety_number}")
    print("-" * 64)
    print(body)
    if agent_prompt:
        print("=" * 64)
        print("🤖 Prompt for the Collaborator's Agent (Copy & Paste):")
        print("=" * 64)
        print(agent_prompt)
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
    server: str = DEFAULT_SERVER,
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
    server: str = DEFAULT_SERVER,
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
    server: str = DEFAULT_SERVER,
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


def cmd_profile_set(
    name: str,
    server: str,
    agent_id: Optional[str] = None,
    is_default: bool = False,
    as_json: bool = False,
) -> int:
    mgr = ProfileManager()
    try:
        p = mgr.set_profile(name=name, server_url=server, agent_id=agent_id, is_default=is_default)
        if as_json:
            print(json.dumps({"status": "ok", "profile": p}, indent=2))
        else:
            active_p = mgr.get_profile()
            is_active = (active_p and active_p.get("name") == name)
            default_note = " (set as active/default)" if (is_default or is_active) else ""
            print(f"✅ Profile '{name}' saved successfully{default_note}!")
            print(f"   Server URL: {p['server_url']}")
            if p.get("agent_id"):
                print(f"   Agent ID:   {p['agent_id']}")
        return 0
    except Exception as e:
        if as_json:
            print(json.dumps({"status": "error", "error": str(e)}))
        else:
            print(f"❌ Failed to set profile: {e}", file=sys.stderr)
        return 1


def cmd_profile_list(as_json: bool = False) -> int:
    mgr = ProfileManager()
    profiles = mgr.list_profiles()
    if as_json:
        print(json.dumps({"profiles": profiles}, indent=2))
        return 0

    if not profiles:
        print("No profiles configured yet. Create one with: agent-link profile set <NAME> --server <URL>")
        return 0

    print("Configured Connection Profiles:")
    for p in profiles:
        active_marker = "🟢 [ACTIVE]" if p.get("is_active") else "  "
        agent_str = f" (Agent: {p['agent_id']})" if p.get("agent_id") else ""
        print(f" {active_marker} {p['name']}: {p['server_url']}{agent_str}")
    return 0


def cmd_profile_show(name: Optional[str] = None, as_json: bool = False) -> int:
    mgr = ProfileManager()
    p = mgr.get_profile(name)
    if not p:
        if as_json:
            print(json.dumps({"error": "profile_not_found"}))
        else:
            msg = f"Profile '{name}' not found." if name else "No active profile configured."
            print(f"❌ {msg}", file=sys.stderr)
        return 1

    if as_json:
        print(json.dumps(p, indent=2))
        return 0

    active_p = mgr.get_profile()
    is_active = (active_p and active_p.get("name") == p["name"])
    print(f"Profile:       {p['name']}")
    print(f"Server URL:    {p['server_url']}")
    print(f"Agent ID:      {p.get('agent_id') or 'None (defaults to identity or flag)'}")
    print(f"Active:        {'Yes' if is_active else 'No'}")
    return 0


def cmd_profile_use(name: str) -> int:
    mgr = ProfileManager()
    try:
        mgr.use_profile(name)
        print(f"✅ Active profile switched to '{name}'.")
        return 0
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        return 1


def cmd_profile_remove(name: str) -> int:
    mgr = ProfileManager()
    if mgr.remove_profile(name):
        print(f"✅ Profile '{name}' removed.")
        return 0
    else:
        print(f"❌ Profile '{name}' not found.", file=sys.stderr)
        return 1


def main(argv: Optional[List[str]] = None) -> int:
    check_cli_secrets_warning(argv)
    args = parse_args(argv)

    profile_mgr = ProfileManager()
    profile_name = getattr(args, "profile", None)
    profile = profile_mgr.get_profile(profile_name)

    raw_argv = argv if argv is not None else sys.argv[1:]
    if profile and args.command != "profile":
        has_explicit_server = any(a == "--server" or a.startswith("--server=") for a in raw_argv)
        if hasattr(args, "server") and not has_explicit_server and profile.get("server_url"):
            args.server = profile["server_url"]

        has_explicit_agent = any(a == "--agent-id" or a.startswith("--agent-id=") for a in raw_argv)
        if hasattr(args, "agent_id") and not has_explicit_agent and profile.get("agent_id"):
            args.agent_id = profile["agent_id"]

    if args.command == "profile":
        if args.profile_action == "set":
            return cmd_profile_set(
                name=args.name,
                server=args.server,
                agent_id=args.agent_id,
                is_default=args.default,
                as_json=getattr(args, "json", False),
            )
        elif args.profile_action == "list":
            return cmd_profile_list(as_json=getattr(args, "json", False))
        elif args.profile_action == "show":
            return cmd_profile_show(name=args.name, as_json=getattr(args, "json", False))
        elif args.profile_action == "use":
            return cmd_profile_use(name=args.name)
        elif args.profile_action in ("remove", "rm", "delete"):
            return cmd_profile_remove(name=args.name)
    elif args.command == "keygen":
        return cmd_keygen(
            args.agent_id,
            key_dir=args.key_dir,
            as_json=args.json,
            quiet=getattr(args, "quiet", False),
            overwrite=getattr(args, "overwrite", False),
        )
    elif args.command == "register":
        return cmd_register(args.agent_id, args.server, args.api_key, key_dir=args.key_dir, as_json=args.json, quiet=getattr(args, "quiet", False))
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
        return cmd_connect(
            args.agent_id,
            args.server,
            args.api_key,
            key_dir=args.key_dir,
            once=args.once,
            allow_plaintext=args.plaintext,
            interactive=getattr(args, "interactive", False),
        )
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
            watch=args.watch,
            inbox=args.inbox,
            decrypt=getattr(args, "decrypt", False),
            interval=args.interval,
            no_auth=args.no_auth,
            allow_plaintext=getattr(args, "allow_plaintext", False),
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
