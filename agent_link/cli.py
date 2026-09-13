"""Command Line Interface for AgentLink CLI."""

from __future__ import annotations
import argparse
import os
import queue
import sys
import threading
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
    p_keygen.add_argument("--key-dir", default=os.getenv("AGENTLINK_KEY_DIR"), help="Directory to store keys (defaults to ~/.agent-link)")

    # 2. register
    p_reg = subparsers.add_parser("register", help="Register agent with AgentLink server using API key")
    p_reg.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Identifier for this agent")
    p_reg.add_argument("--server", default=os.getenv("AGENTLINK_SERVER_URL", "https://agent.signetmesh.com"), help="AgentLink server URL (default: https://agent.signetmesh.com)")
    p_reg.add_argument("--api-key", default=os.getenv("AGENTLINK_API_KEY", ""), help="Human-provisioned API key")
    p_reg.add_argument("--key-dir", default=os.getenv("AGENTLINK_KEY_DIR"), help="Directory to store keys (defaults to ~/.agent-link)")

    # 3. status
    p_status = subparsers.add_parser("status", help="Show local identity status and fingerprints")
    p_status.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Identifier for this agent")
    p_status.add_argument("--key-dir", default=os.getenv("AGENTLINK_KEY_DIR"), help="Directory to store keys (defaults to ~/.agent-link)")

    # 4. connect
    p_connect = subparsers.add_parser("connect", help="Keygen, display optical QR, register, and listen/chat on peer mesh")
    p_connect.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Identifier for this agent")
    p_connect.add_argument("--server", default=os.getenv("AGENTLINK_SERVER_URL", "https://agent.signetmesh.com"), help="AgentLink server URL (default: https://agent.signetmesh.com)")
    p_connect.add_argument("--api-key", default=os.getenv("AGENTLINK_API_KEY", ""), help="Human-provisioned API key")
    p_connect.add_argument("--key-dir", default=os.getenv("AGENTLINK_KEY_DIR"), help="Directory to store keys (defaults to ~/.agent-link)")
    p_connect.add_argument("--once", action="store_true", help="Register and exit without long-polling")

    # 5. send
    p_send = subparsers.add_parser("send", help="Send a message to a peer agent or link")
    p_send.add_argument("--agent-id", default=os.getenv("AGENT_ID", "agent"), help="Sender agent identifier")
    p_send.add_argument("--to", help="Target recipient agent ID")
    p_send.add_argument("--link-id", help="Link ID to dispatch message over")
    p_send.add_argument("--message", "-m", help="Message body to send")
    p_send.add_argument("--server", default=os.getenv("AGENTLINK_SERVER_URL", "https://agent.signetmesh.com"), help="AgentLink server URL (default: https://agent.signetmesh.com)")
    p_send.add_argument("--api-key", default=os.getenv("AGENTLINK_API_KEY", ""), help="Human-provisioned API key")
    p_send.add_argument("--key-dir", default=os.getenv("AGENTLINK_KEY_DIR"), help="Directory to store keys (defaults to ~/.agent-link)")

    return parser.parse_args(argv)


from pathlib import Path


def cmd_keygen(agent_id: str, key_dir: Optional[str] = None) -> int:
    directory = Path(key_dir) if key_dir else None
    kp = AgentKeypair.load(agent_id=agent_id, directory=directory)
    kp.save(directory=directory)
    print(display_qr(kp))
    return 0


def cmd_register(agent_id: str, server: str, api_key: str, key_dir: Optional[str] = None) -> int:
    if not api_key:
        print("❌ Error: API key required. Provide via --api-key or set AGENTLINK_API_KEY environment variable.", file=sys.stderr)
        return 1

    directory = Path(key_dir) if key_dir else None
    kp = AgentKeypair.load(agent_id=agent_id, directory=directory)
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
    kp = AgentKeypair.load(agent_id=agent_id, directory=directory)
    print(f"Agent ID:       {kp.agent_id}")
    print(f"Signing Pub:    {kp.sign_pub_b64}")
    print(f"Encryption Pub: {kp.enc_pub_b64}")
    print(f"Key ID (kid):   {kp.kid}")
    return 0


def cmd_connect(agent_id: str, server: str, api_key: str, key_dir: Optional[str] = None, once: bool = False) -> int:
    if agent_id == "agent":
        print("💡 Tip: Connecting as default agent ID 'agent'. To use a custom ID (e.g. 'ted'), use: --agent-id ted\n")

    ret = cmd_register(agent_id, server, api_key, key_dir=key_dir)
    if ret != 0 or once:
        return ret

    directory = Path(key_dir) if key_dir else None
    kp = AgentKeypair.load(agent_id=agent_id, directory=directory)
    client = AgentLinkClient(server_url=server, api_key=api_key, keypair=kp)

    print(f"\n👂 Listening for peer connection requests and messages on {server}")
    print("💬 [Interactive Chat] Type a reply and press Enter to send across the mesh! (Ctrl+C to stop)\n")

    last_active_link = {"linkId": None, "peerId": None, "peerEncPub": None}

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
            # 1. Process any user input typed in terminal
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
                    try:
                        peer_enc_pub = last_active_link.get("peerEncPub")
                        if not peer_enc_pub and target_peer:
                            try:
                                agents = client.get_agents()
                                p_agent = next((a for a in agents if a.get("id") == target_peer), None)
                                if p_agent and p_agent.get("encPub"):
                                    peer_enc_pub = p_agent.get("encPub")
                                    last_active_link["peerEncPub"] = peer_enc_pub
                            except Exception:
                                pass

                        if peer_enc_pub:
                            client.send_encrypted(link_id=target_link, peer_enc_pub_b64=peer_enc_pub, plaintext=text_to_send)
                            print(f"🚀 [SENT E2EE to {target_peer}]: {text_to_send}")
                        else:
                            client.send_message(link_id=target_link, text=text_to_send)
                            print(f"🚀 [SENT to {target_peer}]: {text_to_send}")
                    except Exception as send_err:
                        print(f"❌ Failed to send message: {send_err}")
                else:
                    print(f"⚠️ Cannot send '{text_to_send}': No active peer link found yet.")

            # 2. Long-poll for incoming messages
            messages = client.poll_messages(timeout_seconds=2)
            for m in messages:
                sender_id = m.get('senderId', 'peer')
                link_id = m.get('linkId', 'unknown')
                last_active_link["linkId"] = link_id
                last_active_link["peerId"] = sender_id
                if m.get("senderEncPub"):
                    last_active_link["peerEncPub"] = m.get("senderEncPub")

                print(f"\n📩 [INCOMING] From: {sender_id} | Link: {link_id}")
                payload = m.get("payload")
                if isinstance(payload, str):
                    print(f"   💬 Message: {payload}")
                elif isinstance(payload, dict):
                    sender_enc_pub = m.get("senderEncPub") or last_active_link.get("peerEncPub")
                    if sender_enc_pub and "iv" in payload and "data" in payload:
                        try:
                            decrypted_bytes = kp.decrypt(
                                peer_enc_pub_b64=sender_enc_pub,
                                iv_b64=payload["iv"],
                                data_b64=payload["data"],
                            )
                            decrypted_text = decrypted_bytes.decode("utf-8")
                            print(f"   🔓 [DECRYPTED E2EE]: {decrypted_text}")
                        except Exception as dec_err:
                            print(f"   ⚠️ Decryption failed: {dec_err}")
                            print(f"   🔒 E2EE Ciphertext: {payload.get('data', '')[:32]}...")
                    else:
                        print(f"   🔒 E2EE Ciphertext: {payload.get('data', '')[:32]}...")
    except KeyboardInterrupt:
        stop_event.set()
        print("\n🛑 Stopped listening.")
        return 0


def cmd_send(agent_id: str, server: str, api_key: str, message: Optional[str] = None, to: Optional[str] = None, link_id: Optional[str] = None, key_dir: Optional[str] = None) -> int:
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
    kp = AgentKeypair.load(agent_id=agent_id, directory=directory)
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

    try:
        if peer_enc_pub:
            client.send_encrypted(link_id=target_link_id, peer_enc_pub_b64=peer_enc_pub, plaintext=msg_text)
            print(f"🚀 Successfully sent E2EE encrypted message to '{target_peer_id}' across {target_link_id}!")
        else:
            client.send_message(link_id=target_link_id, text=msg_text)
            print(f"🚀 Successfully sent message across {target_link_id}!")
        return 0
    except Exception as e:
        print(f"❌ Send failed: {e}", file=sys.stderr)
        return 1


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    if args.command == "keygen":
        return cmd_keygen(args.agent_id, key_dir=args.key_dir)
    elif args.command == "register":
        return cmd_register(args.agent_id, args.server, args.api_key, key_dir=args.key_dir)
    elif args.command == "status":
        return cmd_status(args.agent_id, key_dir=args.key_dir)
    elif args.command == "connect":
        return cmd_connect(args.agent_id, args.server, args.api_key, key_dir=args.key_dir, once=args.once)
    elif args.command == "send":
        return cmd_send(args.agent_id, args.server, args.api_key, message=args.message, to=args.to, link_id=args.link_id, key_dir=args.key_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
