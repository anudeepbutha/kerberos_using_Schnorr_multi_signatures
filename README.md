# Kerberos Under Partial Compromise — 2-of-3 Schnorr Multi-Signatures

A distributed Kerberos-inspired authentication system that remains secure even when one authentication authority is compromised.

## Architecture

```
Client ──┬──► AS1 (port 5001)  ──┐
         ├──► AS2 (port 5002)  ──┼──► TGT (≥2 AS signatures)
         └──► AS3 (port 5003)  ──┘
                                          │
         ┌──► TGS1 (port 6001) ──┐       │
Client ──┼──► TGS2 (port 6002) ──┼──► Service Ticket (≥2 TGS signatures)
         └──► TGS3 (port 6003) ──┘
                                          │
Client ──────► SERVICE1 (port 7001)  ◄────┘
```

Each authority runs independently with its own Schnorr key pair. A ticket requires **at least 2 valid signatures**.

## Requirements

- Python 3.8+
- `cryptography` library (for AES only — Schnorr is implemented manually)

```bash
pip install cryptography
```

## Quick Start

### Option 1: Full Demo (Automated)

```bash
python run_demo.py
```

This will:
1. Generate all cryptographic keys
2. Start 3 AS nodes + 3 TGS nodes + 1 Service Server
3. Run a client authentication
4. Run all 6 attack scenarios
5. Shut everything down

### Option 2: Manual Setup

#### Step 1: Generate Keys
```bash
python master_keygen.py
```

#### Step 2: Start Servers (each in a separate terminal)
```bash
# Authentication Servers
python as_node.py --id AS1 --port 5001
python as_node.py --id AS2 --port 5002
python as_node.py --id AS3 --port 5003

# Ticket Granting Servers
python tgs_node.py --id TGS1 --port 6001
python tgs_node.py --id TGS2 --port 6002
python tgs_node.py --id TGS3 --port 6003

# Service Server
python service_server.py --id SERVICE1 --port 7001
```

#### Step 3: Run Client
```bash
python client.py --user user1 --service SERVICE1
```

#### Step 4: Run Attack Scenarios
```bash
python attacks.py
```

## File Structure

| File | Description |
|---|---|
| `crypto_utils.py` | Cryptographic primitives (Schnorr, AES, modular arithmetic) |
| `master_keygen.py` | Key generation for all authorities |
| `as_node.py` | Authentication Server node (×3) |
| `tgs_node.py` | Ticket Granting Server node (×3) |
| `service_server.py` | Service Server |
| `client.py` | Client protocol driver |
| `attacks.py` | 6 mandatory attack demonstrations |
| `run_demo.py` | Automated end-to-end demo |
| `SECURITY.md` | Security analysis |

## Default Users

| Username | Password |
|---|---|
| user1 | password1 |
| user2 | password2 |
| user3 | password3 |

## Attack Scenarios

1. **Single Malicious Authority** — Forged ticket with 1 signature → Rejected
2. **Modified Ticket Payload** — Tampered content → Signatures fail
3. **Replay Old Signature** — Stale signature on new ticket → Rejected
4. **Key Leakage** — 1 leaked key → Only 1 valid sig → Rejected
5. **Authority Offline** — System works with 2-of-3 online
6. **Single Signature Ticket** — Ticket with 1 sig → Rejected
