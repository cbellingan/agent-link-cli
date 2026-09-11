"""Command Line Interface for AgentLink CLI."""

from __future__ import annotations
import argparse
import os
import sys
from typing import List, Optional

from agent_link.client import AgentLinkClient
from agent_link.crypto import AgentKeypair
from agent_link.qr import display_qr


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="agent-link",
        description="AgentLink: Lightweight Zero-Knowledge Agent Mesh CLI & Optical Anchor",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. keygen
    p_keygen = subparsers.add_parser("keygen", help="Generate or display local Ed25519/X25519 identity keys and QR")
    p_keygen.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Identifier for this agent")

    # 2. register
    p_reg = subparsers.add_parser("register", help="Register agent with AgentLink server using API key")
    p_reg.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Identifier for this agent")
    p_reg.add_argument("--server", default=os.getenv("AGENTLINK_SERVER_URL", "http://localhost:3000"), help="AgentLink server URL")
    p_reg.add_argument("--api-key", default=os.getenv("AGENTLINK_API_KEY", ""), help="Human-provisioned API key")

    # 3. status
    p_status = subparsers.add_parser("status", help="Show local identity status and fingerprints")
    p_status.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Identifier for this agent")

    # 4. connect
    p_connect = subparsers.add_parser("connect", help="Keygen, display optical QR, register, and listen for peer messages")
    p_connect.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Identifier for this agent")
    p_connect.add_argument("--server", default=os.getenv("AGENTLINK_SERVER_URL", "http://localhost:3000"), help="AgentLink server URL")
    p_connect.add_argument("--api-key", default=os.getenv("AGENTLINK_API_KEY", ""), help="Human-provisioned API key")
    p_connect.add_argument("--once", action="store_true", help="Register and exit without long-polling")

    return parser.parse_args(argv)


def cmd_keygen(agent_id: str) -> int:
    kp = AgentKeypair.load(agent_id=agent_id)
    kp.save()
    print(display_qr(kp))
    return 0


def cmd_register(agent_id: str, server: str, api_key: str) -> int:
    if not api_key:
        print("❌ Error: API key required. Provide via --api-key or set AGENTLINK_API_KEY environment variable.", file=sys.stderr)
        return 1

    kp = AgentKeypair.load(agent_id=agent_id)
    kp.save()

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


def cmd_status(agent_id: str) -> int:
    kp = AgentKeypair.load(agent_id=agent_id)
    print(f"Agent ID:       {kp.agent_id}")
    print(f"Signing Pub:    {kp.sign_pub_b64}")
    print(f"Encryption Pub: {kp.enc_pub_b64}")
    print(f"Key ID (kid):   {kp.kid}")
    return 0


def cmd_connect(agent_id: str, server: str, api_key: str, once: bool = False) -> int:
    ret = cmd_register(agent_id, server, api_key)
    if ret != 0 or once:
        return ret

    kp = AgentKeypair.load(agent_id=agent_id)
    client = AgentLinkClient(server_url=server, api_key=api_key, keypair=kp)

    print(f"👂 Listening for peer connection requests and messages on {server} (Ctrl+C to stop)...")
    try:
        while True:
            messages = client.poll_messages(timeout_seconds=10)
            for m in messages:
                print(f"\n📩 [INCOMING] From: {m.get('senderId', 'peer')} | Link: {m.get('linkId', 'unknown')}")
                payload = m.get("payload")
                if isinstance(payload, str):
                    print(f"   Message: {payload}")
                elif isinstance(payload, dict):
                    print(f"   E2EE Ciphertext: {payload.get('data', '')[:32]}...")
    except KeyboardInterrupt:
        print("\n🛑 Stopped listening.")
        return 0


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.command == "keygen":
        return cmd_keygen(args.agent_id)
    elif args.command == "register":
        return cmd_register(args.agent_id, args.server, args.api_key)
    elif args.command == "status":
        return cmd_status(args.agent_id)
    elif args.command == "connect":
        return cmd_connect(args.agent_id, args.server, args.api_key, args.once)
    return 0


if __name__ == "__main__":
    sys.exit(main())
