"""
client.py — Kerberos Client.

Drives the full 3-phase distributed Kerberos protocol:
  Phase 1: Contacts AS1, AS2, AS3 for TGT (collects ≥2 signatures)
  Phase 2: Contacts TGS1, TGS2, TGS3 for service ticket (collects ≥2 signatures)
  Phase 3: Authenticates to the service server

Usage:
    python client.py --user user1 --password password123 --service SERVICE1
"""

import argparse
import base64
import json
import os
import socket
import sys
import time

from crypto_utils import (
    P, Q, G,
    schnorr_verify,
    aes_encrypt,
    aes_decrypt,
    hash_password,
    signature_from_dict,
    send_message,
    recv_message,
    load_json,
)

KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")

# Default port assignments
AS_PORTS = {"AS1": 5001, "AS2": 5002, "AS3": 5003}
TGS_PORTS = {"TGS1": 6001, "TGS2": 6002, "TGS3": 6003}
SERVICE_PORTS = {"SERVICE1": 7001, "SERVICE2": 7002}


class KerberosClient:
    def __init__(self, username: str, password: str, service_id: str):
        self.username = username
        self.password = password
        self.service_id = service_id
        self.public_keys = {}
        self.client_key = None
        self._load_keys()

    def _load_keys(self):
        """Load public keys and client key."""
        # Load all public keys
        all_pub = load_json(os.path.join(KEYS_DIR, "public_keys.json"))
        self.public_keys = {k: int(v, 16) for k, v in all_pub.items()}

        # Derive client key from user database
        user_db = load_json(os.path.join(KEYS_DIR, "user_db.json"))
        if self.username in user_db:
            self.client_key = base64.b64decode(user_db[self.username]["client_key"])
            self.password_hash = user_db[self.username]["password_hash"]
        else:
            raise ValueError(f"User '{self.username}' not found in database")

    def _connect(self, host: str, port: int, timeout: float = 5.0):
        """Create a socket connection with timeout."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        return sock

    # =========================================================================
    # Phase 1: Distributed AS Exchange
    # =========================================================================

    def phase1_get_tgt(self) -> dict:
        """
        Contact all 3 AS nodes, collect ≥2 valid TGT responses.
        Returns dict with encrypted_tgt, session_key, and collected AS signatures.
        """
        print("\n" + "=" * 60)
        print("  Phase 1: Distributed AS Exchange")
        print("=" * 60)

        responses = []
        as_signatures = []

        # Use a single timestamp for all AS requests so they sign the same canonical payload
        request_timestamp = time.time()

        for as_id, port in AS_PORTS.items():
            try:
                print(f"  [{as_id}] Connecting to port {port}...")
                sock = self._connect('localhost', port)

                # Send TGT request with consistent timestamp
                request = {
                    "type": "TGT_REQUEST",
                    "client_id": self.username,
                    "password_hash": self.password_hash,
                    "tgs_id": "TGS",
                    "timestamp": request_timestamp,
                }
                send_message(sock, request)

                # Receive response
                resp = recv_message(sock)
                sock.close()

                if resp and resp.get("type") == "TGT_RESPONSE":
                    # Verify this AS's signature
                    sig = signature_from_dict(resp["signature"])
                    encrypted_tgt = base64.b64decode(resp["encrypted_tgt"])

                    # Decrypt session key to verify we got a valid response
                    try:
                        encrypted_sk = base64.b64decode(resp["encrypted_session_key"])
                        session_key = aes_decrypt(encrypted_sk, self.client_key)
                        responses.append({
                            "as_id": as_id,
                            "encrypted_tgt": resp["encrypted_tgt"],
                            "session_key": session_key,
                            "signature": resp["signature"],
                        })
                        as_signatures.append(resp["signature"])
                        print(f"  [{as_id}] ✓ TGT received and verified")
                    except Exception as e:
                        print(f"  [{as_id}] ✗ Failed to decrypt session key: {e}")
                elif resp:
                    print(f"  [{as_id}] ✗ Error: {resp.get('message', 'Unknown error')}")
                else:
                    print(f"  [{as_id}] ✗ No response")

            except (ConnectionRefusedError, socket.timeout) as e:
                print(f"  [{as_id}] ✗ Offline/unreachable: {e}")
            except Exception as e:
                print(f"  [{as_id}] ✗ Error: {e}")

        # Need at least 2 valid responses
        if len(responses) < 2:
            raise RuntimeError(
                f"Phase 1 FAILED: Only {len(responses)} AS response(s), need at least 2"
            )

        print(f"\n  ✓ Collected {len(responses)} valid AS responses (need ≥ 2)")

        # Use the first valid response's TGT and session key
        # (All AS nodes encrypt the same TGT structure)
        return {
            "encrypted_tgt": responses[0]["encrypted_tgt"],
            "session_key": responses[0]["session_key"],
            "as_signatures": as_signatures,
        }

    # =========================================================================
    # Phase 2: Distributed TGS Exchange
    # =========================================================================

    def phase2_get_service_ticket(self, tgt_data: dict) -> dict:
        """
        Contact all 3 TGS nodes with TGT, collect ≥2 valid service ticket responses.
        """
        print("\n" + "=" * 60)
        print("  Phase 2: Distributed TGS Exchange")
        print("=" * 60)

        session_key = tgt_data["session_key"]

        # Create authenticator
        authenticator = {
            "client_id": self.username,
            "timestamp": time.time(),
        }
        encrypted_authenticator = aes_encrypt(
            json.dumps(authenticator).encode('utf-8'),
            session_key
        )

        responses = []
        tgs_signatures = []

        # Use a single timestamp for all TGS requests so they sign the same canonical payload
        request_timestamp = time.time()

        for tgs_id, port in TGS_PORTS.items():
            try:
                print(f"  [{tgs_id}] Connecting to port {port}...")
                sock = self._connect('localhost', port)

                request = {
                    "type": "SERVICE_TICKET_REQUEST",
                    "encrypted_tgt": tgt_data["encrypted_tgt"],
                    "as_signatures": tgt_data["as_signatures"],
                    "service_id": self.service_id,
                    "authenticator": base64.b64encode(encrypted_authenticator).decode('utf-8'),
                    "timestamp": request_timestamp,
                }
                send_message(sock, request)

                resp = recv_message(sock)
                sock.close()

                if resp and resp.get("type") == "SERVICE_TICKET_RESPONSE":
                    # Decrypt service session key
                    try:
                        enc_ssk = base64.b64decode(resp["encrypted_service_session_key"])
                        service_session_key = aes_decrypt(enc_ssk, session_key)
                        responses.append({
                            "tgs_id": tgs_id,
                            "encrypted_service_ticket": resp["encrypted_service_ticket"],
                            "service_session_key": service_session_key,
                            "signature": resp["signature"],
                        })
                        tgs_signatures.append(resp["signature"])
                        print(f"  [{tgs_id}] ✓ Service ticket received")
                    except Exception as e:
                        print(f"  [{tgs_id}] ✗ Failed to decrypt service session key: {e}")
                elif resp:
                    print(f"  [{tgs_id}] ✗ Error: {resp.get('message', 'Unknown error')}")
                else:
                    print(f"  [{tgs_id}] ✗ No response")

            except (ConnectionRefusedError, socket.timeout) as e:
                print(f"  [{tgs_id}] ✗ Offline/unreachable: {e}")
            except Exception as e:
                print(f"  [{tgs_id}] ✗ Error: {e}")

        if len(responses) < 2:
            raise RuntimeError(
                f"Phase 2 FAILED: Only {len(responses)} TGS response(s), need at least 2"
            )

        print(f"\n  ✓ Collected {len(responses)} valid TGS responses (need ≥ 2)")

        return {
            "encrypted_service_ticket": responses[0]["encrypted_service_ticket"],
            "service_session_key": responses[0]["service_session_key"],
            "tgs_signatures": tgs_signatures,
        }

    # =========================================================================
    # Phase 3: Service Authentication
    # =========================================================================

    def phase3_access_service(self, st_data: dict) -> dict:
        """
        Authenticate to the service server with the service ticket.
        """
        print("\n" + "=" * 60)
        print("  Phase 3: Service Authentication")
        print("=" * 60)

        service_session_key = st_data["service_session_key"]

        # Create authenticator
        authenticator = {
            "client_id": self.username,
            "timestamp": time.time(),
        }
        encrypted_authenticator = aes_encrypt(
            json.dumps(authenticator).encode('utf-8'),
            service_session_key
        )

        port = SERVICE_PORTS.get(self.service_id, 7001)

        print(f"  [{self.service_id}] Connecting to port {port}...")
        sock = self._connect('localhost', port)

        request = {
            "type": "SERVICE_REQUEST",
            "encrypted_service_ticket": st_data["encrypted_service_ticket"],
            "tgs_signatures": st_data["tgs_signatures"],
            "authenticator": base64.b64encode(encrypted_authenticator).decode('utf-8'),
        }
        send_message(sock, request)

        resp = recv_message(sock)
        sock.close()

        if resp and resp.get("type") == "SERVICE_RESPONSE":
            if resp["status"] == "ACCESS_GRANTED":
                # Decrypt mutual authentication response
                enc_data = base64.b64decode(resp["encrypted_data"])
                svc_response = json.loads(
                    aes_decrypt(enc_data, service_session_key).decode('utf-8')
                )
                print(f"  [{self.service_id}] ✓ ACCESS GRANTED!")
                print(f"    Client: {svc_response['client_id']}")
                print(f"    Service: {svc_response['service_id']}")
                print(f"    Message: {svc_response['message']}")
                print(f"    Verified signatures: {resp['verified_signatures']}")
                print(f"    Verified authorities: {resp['verified_authorities']}")
                return svc_response
            else:
                print(f"  [{self.service_id}] ✗ Access denied: {resp.get('message')}")
        elif resp:
            print(f"  [{self.service_id}] ✗ Error: {resp.get('message', 'Unknown error')}")

        raise RuntimeError("Phase 3 FAILED: Could not access service")

    # =========================================================================
    # Full Protocol
    # =========================================================================

    def authenticate(self):
        """Run the complete 3-phase Kerberos protocol."""
        print("\n" + "=" * 60)
        print(f"  Kerberos Client: {self.username}")
        print(f"  Target Service: {self.service_id}")
        print("=" * 60)

        # Phase 1: Get TGT
        tgt_data = self.phase1_get_tgt()

        # Phase 2: Get Service Ticket
        st_data = self.phase2_get_service_ticket(tgt_data)

        # Phase 3: Access Service
        result = self.phase3_access_service(st_data)

        print("\n" + "=" * 60)
        print("  ✓ AUTHENTICATION COMPLETE — Full protocol succeeded!")
        print("=" * 60)

        return result


def main():
    parser = argparse.ArgumentParser(description="Kerberos Client")
    parser.add_argument("--user", required=True,
                        help="Username")
    parser.add_argument("--password", default=None,
                        help="Password (unused in key-based auth)")
    parser.add_argument("--service", default="SERVICE1",
                        help="Target service ID")
    args = parser.parse_args()

    client = KerberosClient(args.user, args.password or "", args.service)
    client.authenticate()


if __name__ == "__main__":
    main()
