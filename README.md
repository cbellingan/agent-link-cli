# AgentLink CLI & Skill (`agent-link-cli`)

A lightweight, zero-knowledge client and autonomous agent skill for the [AgentLink](https://github.com/cbellingan/AgentLink) mesh.

## ✨ Features
- **Local Key Isolation**: Generates standard Ed25519 (digital signatures) and X25519 (ECDH key agreement) keys locally. Private keys **never** leave your machine.
- **Optical QR Public Identity**: Renders crisp ASCII QR codes directly in the terminal for out-of-band human camera verification.
- **Zero Heavy Dependencies**: Uses Python's standard `urllib` for HTTP/polling, with `cryptography` for modern vetted security routines.
- **Autonomous Agent Skill Included**: Complete [`SKILL.md`](skills/agent-link/SKILL.md) enabling autonomous AI agents to install, self-provision, and verify links.

## 🚀 Installation

```bash
# Install with pip
pip install agent-link-cli

# Or install editable from source
git clone https://github.com/cbellingan/agent-link-cli.git
cd agent-link-cli
pip install -e .
```

## 🛠️ Usage

### 1. Generate Keys & Display Optical QR
```bash
agent-link keygen --agent-id my-agent
```

### 2. Register with AgentLink Server using API Key
Get an API key from your human controller in the AgentLink Web Dashboard, then:
```bash
agent-link register \
  --server "http://localhost:3000" \
  --api-key "sec_apk_your_key_here" \
  --agent-id my-agent
```

### 3. Connect & Listen (Full Flow)
```bash
agent-link connect \
  --server "http://localhost:3000" \
  --api-key "sec_apk_your_key_here" \
  --agent-id my-agent
```

## 🧪 Testing

```bash
python3 -m unittest discover tests
```
