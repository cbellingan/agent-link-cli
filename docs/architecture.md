# agent-link-cli Architecture Specification

## 1. Overview & Responsibilities

`agent-link-cli` is the Python reference implementation for interacting with AgentLink-compatible relay servers (such as SignetMesh and local AgentLink instances). It is designed to be lightweight, secure by default, and fail-closed against cryptographic degradations.

### Core Modules
- **`agent_link/crypto.py`**: Local cryptographic key management (Ed25519 signatures, X25519 ECDH key agreement, HKDF-SHA256 link key derivation, AES-256-GCM encryption/decryption, SHA-256 hashing, and QR generation).
- **`agent_link/security.py`**: Anti-replay monotonic sequence enforcement, peer key pinning (`PeerKeyStore`), and exception hierarchies.
- **`agent_link/client.py`**: HTTP client for relay API interaction with authentication, retry logic, lease management, and explicit ACK/NACK signaling.
- **`agent_link/cli.py`**: Command-line interface and daemon watch loops supporting both interactive and headless autonomous execution.

---

## 2. Key Isolation & Filesystem Security

- **Strict Permissions**: Private keys are generated locally via `AgentKeypair.generate()` and saved with POSIX `0600` permissions (`-rw-------`). Directories are created with `0700` (`drwx------`).
- **Zero Key Exfiltration**: Private keys never leave the agent host. Public keys (`signPub`, `encPub`, `kid`) are published to the relay during registration (`POST /api/agents/register`).

---

## 3. Durable Delivery & Safe Client Retries

`agent-link-cli` implements the client-side protocols for Feature 9 (Durable Delivery & Safe Client Retries):

### 3.1 Stable Client-Generated `msgId` & Idempotent Retries
When sending messages (`send` / `client.send_encrypted`):
1. The client assigns a stable `msgId` (e.g. `msg_<uuid4_hex>`) *before* transmitting over the network.
2. The `msgId` is embedded inside the cryptographic envelope payload and attached as a top-level routing parameter.
3. If a network disruption occurs (HTTP 502/503/504, TCP reset, or client timeout), the client can safely re-send the exact same payload with the identical `msgId`. The relay recognizes the duplicate `msgId` and returns HTTP 200 without creating a duplicate queued envelope.

### 3.2 Acceptance vs. Delivery Semantics
When transmitting messages:
- The relay synchronously returns `{ "status": "ok", "state": "accepted", "accepted": true, "delivered": false, "msgId": "..." }`.
- The CLI displays `🚀 [FAIL-CLOSED E2EE] Message accepted by relay (id: <msgId>, state: accepted, awaiting recipient receipt/ack)`.
- Autonomous workflows must not treat relay acceptance as proof that the recipient has read or processed the message.

### 3.3 Receipt-Before-ACK Invariant (Receiver Daemon)
When listening for messages in daemon mode (`agent-link receive --watch --inbox <path>`):

```
+---------------------------------------------------------------------------------+
|                                RECEIVER DAEMON                                  |
|                                                                                 |
|  1. Long-Poll Batch          GET /api/agents/:id/poll                           |
|                              (Receives messages with leaseId)                   |
|                                     |                                           |
|                                     v                                           |
|  2. Durable Disk Write       Append raw envelope to inbox file                  |
|                              (Flush / commit to persistent storage)             |
|                                     |                                           |
|                                     v                                           |
|  3. Explicit ACK             POST /api/agents/:id/ack                           |
|                              { "messageIds": [...], "leaseId": "..." }          |
+---------------------------------------------------------------------------------+
```

- **Durability Guarantee**: The receiver **always** appends incoming envelopes to the local inbox file *before* sending an acknowledgement to the relay.
- **Crash Recovery**:
  - If the receiver crashes **before** step 2: The relay's 30-second lease expires and the message is automatically redelivered on the next poll. No message is lost.
  - If the receiver crashes **between** step 2 and step 3: On restart, the redelivered message is recognized by its SHA-256 digest (`seen` set), deduplicated locally, and acknowledged cleanly.

### 3.4 Poison Message Handling (`nack`)
If an inbound envelope is corrupt, unparseable, or fails cryptographic validation repeatedly, the client can issue a negative acknowledgement (`POST /api/agents/:id/nack`):
- `action: "requeue"`: Releases the active lease immediately for retry.
- `action: "quarantine"`: Moves the poisoned envelope to dead-letter quarantine on the relay, preventing worker crash loops.
