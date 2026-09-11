"""Optical Public-Key QR Payload Generator and ASCII Terminal Renderer.

Enables out-of-band identity verification: humans photograph the QR code
displayed in the agent's terminal to bind public keys to physical identities.
"""

from __future__ import annotations
import datetime
import io
import json
from typing import Any, Dict, Optional

from agent_link.crypto import AgentKeypair


def create_qr_payload(keypair: AgentKeypair, extra_meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Generate canonical compact JSON QR payload."""
    payload = {
        "v": 1,
        "agent": keypair.agent_id,
        "signPub": keypair.sign_pub_b64,
        "encPub": keypair.enc_pub_b64,
        "kid": keypair.kid,
        "iat": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    if extra_meta:
        payload.update(extra_meta)
    return payload


def render_ascii_qr(payload_str: str) -> str:
    """Render high-contrast ASCII/Unicode QR code for terminal display."""
    try:
        import qrcode
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=1,
            border=2,
        )
        qr.add_data(payload_str)
        qr.make(fit=True)

        buf = io.StringIO()
        qr.print_ascii(out=buf, invert=True)
        return buf.getvalue()
    except Exception:
        # Fallback minimal text presentation if qrcode module is unavailable
        border = "═" * 44
        return (
            f"╔{border}╗\n"
            f"║  [AGENTLINK OPTICAL PUBLIC IDENTITY PAYLOAD]  ║\n"
            f"║  Aim camera / paste payload into dashboard    ║\n"
            f"╠{border}╣\n"
            f"{payload_str}\n"
            f"╚{border}╝"
        )


def display_qr(keypair: AgentKeypair) -> str:
    """Format and print public identity payload and ASCII QR to stdout."""
    payload = create_qr_payload(keypair)
    payload_str = json.dumps(payload, separators=(",", ":"))
    ascii_qr = render_ascii_qr(payload_str)

    output = []
    output.append("\n" + "=" * 54)
    output.append(f"  🔐 AgentLink Public Identity Anchor: {keypair.agent_id}")
    output.append(f"  Fingerprint (Key ID): {keypair.kid}")
    output.append("=" * 54)
    output.append("\n" + ascii_qr + "\n")
    output.append("Compact JSON Payload (for manual out-of-band verification):")
    output.append(payload_str)
    output.append("=" * 54 + "\n")
    return "\n".join(output)
