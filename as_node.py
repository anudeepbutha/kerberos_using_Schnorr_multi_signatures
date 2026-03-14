"""
as_node.py — Authentication Server Node.

Runs as an independent server process. Each AS node (AS1, AS2, AS3)
has its own Schnorr key pair and signs TGTs independently.

Usage:
    python as_node.py --id AS1 --port 5001
    python as_node.py --id AS2 --port 5002
    python as_node.py --id AS3 --port 5003
"""

import argparse
import base64
import json
import os
import socket
import sys
import threading
import time

from crypto_utils import (
    P, Q, G,
    schnorr_sign,
    create_ticket_payload,
    get_signable_payload,
    serialize_ticket,
    aes_encrypt,
    generate_aes_key,
    hash_password,
    signature_to_dict,
    send_message,
    recv_message,
    load_json,
)

KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")


class AuthenticationServer:
    def __init__(self, authority_id: str, port: int):
        self.authority_id = authority_id
        self.port = port
        self.private_key = None
        self.tgs_secret_key = None
        self.key_version = 1
        self.user_db = {}
        self._load_keys()

    def _load_keys(self):
        """Load private key, TGS secret, and user database."""
        # Load own private key
        priv_data = load_json(os.path.join(KEYS_DIR, f"{self.authority_id}_private.json"))
        self.private_key = int(priv_data["private_key"], 16)

        # Load TGS secret key
        tgs_data = load_json(os.path.join(KEYS_DIR, "tgs_secret.json"))
        self.tgs_secret_key = base64.b64decode(tgs_data["tgs_secret_key"])
        self.key_version = tgs_data["key_version"]

        # Load user database
        self.user_db = load_json(os.path.join(KEYS_DIR, "user_db.json"))

        print(f"[{self.authority_id}] Keys loaded successfully")

    def _verify_client(self, client_id: str, password_hash: str) -> bool:
        """Verify client credentials."""
        if client_id not in self.user_db:
            return False
        stored_hash = self.user_db[client_id]["password_hash"]
        return password_hash == stored_hash

    def _handle_client(self, conn, addr):
        """Handle a single client request."""
        try:
            request = recv_message(conn)
            if request is None:
                return

            msg_type = request.get("type")

            if msg_type == "TGT_REQUEST":
                self._handle_tgt_request(conn, request)
            elif msg_type == "PING":
                send_message(conn, {"type": "PONG", "authority_id": self.authority_id})
            else:
                send_message(conn, {"type": "ERROR", "message": "Unknown request type"})

        except Exception as e:
            print(f"[{self.authority_id}] Error handling client {addr}: {e}")
            try:
                send_message(conn, {"type": "ERROR", "message": str(e)})
            except:
                pass
        finally:
            conn.close()

    def _handle_tgt_request(self, conn, request):
        """Process a TGT request from a client."""
        client_id = request.get("client_id")
        password_hash = request.get("password_hash")
        tgs_id = request.get("tgs_id", "TGS")
        request_timestamp = request.get("timestamp", time.time())

        print(f"[{self.authority_id}] TGT request from '{client_id}'")

        # Verify credentials
        if not self._verify_client(client_id, password_hash):
            send_message(conn, {
                "type": "ERROR",
                "message": "Authentication failed: invalid credentials"
            })
            print(f"[{self.authority_id}] Auth FAILED for '{client_id}'")
            return

        # Generate session key
        session_key = generate_aes_key()

        # Build TGT payload (using client-provided timestamp for consistency)
        tgt_payload = create_ticket_payload(
            client_id=client_id,
            service_id=tgs_id,
            session_key=session_key,
            lifetime=3600,
            key_version=self.key_version,
            authority_metadata={"issuer": self.authority_id},
            timestamp=request_timestamp
        )

        # Sign the CANONICAL signable payload (excludes session_key & authority_metadata)
        # This ensures all AS nodes sign the same content
        signable = get_signable_payload(tgt_payload)
        signable_bytes = serialize_ticket(signable)
        R, s = schnorr_sign(signable_bytes, self.private_key, self.authority_id, P, Q, G)

        # Encrypt full TGT with TGS secret key
        full_payload_bytes = serialize_ticket(tgt_payload)
        encrypted_tgt = aes_encrypt(full_payload_bytes, self.tgs_secret_key)

        # Encrypt session key with client's key
        client_key = base64.b64decode(self.user_db[client_id]["client_key"])
        encrypted_session_key = aes_encrypt(session_key, client_key)

        # Build response
        response = {
            "type": "TGT_RESPONSE",
            "authority_id": self.authority_id,
            "encrypted_tgt": base64.b64encode(encrypted_tgt).decode('utf-8'),
            "encrypted_session_key": base64.b64encode(encrypted_session_key).decode('utf-8'),
            "signature": signature_to_dict(R, s, self.authority_id),
        }

        send_message(conn, response)
        print(f"[{self.authority_id}] TGT issued for '{client_id}'")

    def start(self):
        """Start the AS node server."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind(('localhost', self.port))
        except OSError as e:
            print(f"[{self.authority_id}] ERROR: Port {self.port} is busy — {e}")
            server.close()
            sys.exit(1)
        server.listen(5)

        print(f"[{self.authority_id}] Authentication Server listening on port {self.port}")

        try:
            while True:
                conn, addr = server.accept()
                thread = threading.Thread(target=self._handle_client, args=(conn, addr))
                thread.daemon = True
                thread.start()
        except KeyboardInterrupt:
            print(f"\n[{self.authority_id}] Shutting down...")
        finally:
            server.close()


def main():
    parser = argparse.ArgumentParser(description="Kerberos Authentication Server Node")
    parser.add_argument("--id", required=True, choices=["AS1", "AS2", "AS3"],
                        help="Authority ID")
    parser.add_argument("--port", type=int, required=True,
                        help="Port to listen on")
    args = parser.parse_args()

    server = AuthenticationServer(args.id, args.port)
    server.start()


if __name__ == "__main__":
    main()
