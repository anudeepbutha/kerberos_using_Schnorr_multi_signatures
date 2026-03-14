"""
master_keygen.py — Generates Schnorr key pairs for all authorities.

Creates:
  - keys/params.json          — Domain parameters (p, q, g)
  - keys/public_keys.json     — All authority public keys
  - keys/<id>_private.json    — Each authority's private key
  - keys/tgs_secret.json      — Shared TGS secret key for TGT encryption
  - keys/service_secrets.json — Service secret keys for service ticket encryption
  - keys/user_db.json         — User credentials database
"""

import os
import sys
import json
import base64

from crypto_utils import (
    P, Q, G,
    generate_schnorr_keypair,
    generate_aes_key,
    hash_password,
    save_json,
)

KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")

# All authority IDs
AS_IDS = ["AS1", "AS2", "AS3"]
TGS_IDS = ["TGS1", "TGS2", "TGS3"]
ALL_IDS = AS_IDS + TGS_IDS

# Default services
SERVICES = ["SERVICE1", "SERVICE2"]

# Default users
DEFAULT_USERS = {
    "user1": "password1",
    "user2": "password2",
    "user3": "password3",
}


def generate_all_keys():
    """Generate all cryptographic keys for the system."""
    os.makedirs(KEYS_DIR, exist_ok=True)

    print("=" * 60)
    print("  Kerberos Multi-Signature Key Generation")
    print("=" * 60)

    # 1. Save domain parameters
    params = {
        "p": hex(P),
        "q": hex(Q),
        "g": G,
    }
    save_json(os.path.join(KEYS_DIR, "params.json"), params)
    print(f"\n[+] Domain parameters saved to keys/params.json")
    print(f"    p: {hex(P)[:40]}... ({P.bit_length()} bits)")
    print(f"    q: {hex(Q)[:40]}... ({Q.bit_length()} bits)")
    print(f"    g: {G}")

    # 2. Generate Schnorr key pairs for each authority
    public_keys = {}
    print(f"\n[+] Generating Schnorr key pairs for {len(ALL_IDS)} authorities...")

    for auth_id in ALL_IDS:
        x, y = generate_schnorr_keypair(P, Q, G)

        # Save private key (stays with authority)
        private_data = {
            "authority_id": auth_id,
            "private_key": hex(x),
        }
        save_json(os.path.join(KEYS_DIR, f"{auth_id}_private.json"), private_data)

        # Collect public key
        public_keys[auth_id] = hex(y)

        print(f"    {auth_id}: keypair generated (private key saved to keys/{auth_id}_private.json)")

    # Save all public keys (distributed to everyone)
    save_json(os.path.join(KEYS_DIR, "public_keys.json"), public_keys)
    print(f"\n[+] All public keys saved to keys/public_keys.json")

    # 3. Generate TGS secret key (shared among TGS nodes, used to encrypt TGTs)
    tgs_secret = generate_aes_key()
    tgs_secret_data = {
        "tgs_secret_key": base64.b64encode(tgs_secret).decode('utf-8'),
        "key_version": 1,
    }
    save_json(os.path.join(KEYS_DIR, "tgs_secret.json"), tgs_secret_data)
    print(f"[+] TGS secret key saved to keys/tgs_secret.json")

    # 4. Generate service secret keys
    service_secrets = {}
    for svc in SERVICES:
        svc_key = generate_aes_key()
        service_secrets[svc] = {
            "secret_key": base64.b64encode(svc_key).decode('utf-8'),
            "key_version": 1,
        }
    save_json(os.path.join(KEYS_DIR, "service_secrets.json"), service_secrets)
    print(f"[+] Service secret keys saved to keys/service_secrets.json")

    # 5. Create user database
    user_db = {}
    for username, password in DEFAULT_USERS.items():
        pw_hash, salt = hash_password(password)
        client_key = generate_aes_key()
        user_db[username] = {
            "password_hash": base64.b64encode(pw_hash).decode('utf-8'),
            "salt": base64.b64encode(salt).decode('utf-8'),
            "client_key": base64.b64encode(client_key).decode('utf-8'),
        }
    save_json(os.path.join(KEYS_DIR, "user_db.json"), user_db)
    print(f"[+] User database saved to keys/user_db.json ({len(DEFAULT_USERS)} users)")

    print(f"\n{'=' * 60}")
    print(f"  Key generation complete! All keys stored in keys/")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    generate_all_keys()
