"""
tgs_node.py — Ticket Granting Server Node.

Runs as an independent server process. Each TGS node (TGS1, TGS2, TGS3)
has its own Schnorr key pair and signs service tickets independently.

Usage:
    python tgs_node.py --id TGS1 --port 6001
    python tgs_node.py --id TGS2 --port 6002
    python tgs_node.py --id TGS3 --port 6003
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
    schnorr_verify,
    create_ticket_payload,
    get_signable_payload,
    serialize_ticket,
    deserialize_ticket,
    aes_encrypt,
    aes_decrypt,
    generate_aes_key,
    is_ticket_expired,
    signature_to_dict,
    signature_from_dict,
    send_message,
    recv_message,
    load_json,
)

KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")


class TicketGrantingServer:
    def __init__(self, authority_id: str, port: int):
        self.authority_id = authority_id
        self.port = port
        self.private_key = None
        self.tgs_secret_key = None
        self.service_secrets = {}
        self.as_public_keys = {}
        self.key_version = 1
        self._load_keys()

    def _load_keys(self):
        """Load private key, AS public keys, TGS secret key, and service secrets."""
        # Load own private key
        priv_data = load_json(os.path.join(KEYS_DIR, f"{self.authority_id}_private.json"))
        self.private_key = int(priv_data["private_key"], 16)

        # Load all public keys (to verify AS signatures)
        all_pub = load_json(os.path.join(KEYS_DIR, "public_keys.json"))
        self.as_public_keys = {k: int(v, 16) for k, v in all_pub.items() if k.startswith("AS")}

        # Load TGS secret key (to decrypt TGTs)
        tgs_data = load_json(os.path.join(KEYS_DIR, "tgs_secret.json"))
        self.tgs_secret_key = base64.b64decode(tgs_data["tgs_secret_key"])
        self.key_version = tgs_data["key_version"]

        # Load service secrets (to encrypt service tickets)
        self.service_secrets = load_json(os.path.join(KEYS_DIR, "service_secrets.json"))

        print(f"[{self.authority_id}] Keys loaded successfully")

    def _verify_as_signatures(self, payload_bytes: bytes, signatures: list) -> tuple:
        """Verify AS signatures on a TGT payload. Returns (is_valid, count, valid_ids)."""
        valid_count = 0
        valid_ids = []

        for sig_dict in signatures:
            sig = signature_from_dict(sig_dict)
            auth_id = sig["authority_id"]

            if auth_id not in self.as_public_keys:
                continue

            pub_key = self.as_public_keys[auth_id]
            if schnorr_verify(payload_bytes, sig["R"], sig["s"], pub_key, auth_id, P, Q, G):
                valid_count += 1
                valid_ids.append(auth_id)

        return valid_count >= 2, valid_count, valid_ids

    def _handle_client(self, conn, addr):
        """Handle a single client request."""
        try:
            request = recv_message(conn)
            if request is None:
                return

            msg_type = request.get("type")

            if msg_type == "SERVICE_TICKET_REQUEST":
                self._handle_service_ticket_request(conn, request)
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

    def _handle_service_ticket_request(self, conn, request):
        """Process a service ticket request."""
        encrypted_tgt = base64.b64decode(request["encrypted_tgt"])
        as_signatures = request["as_signatures"]
        service_id = request["service_id"]
        authenticator_enc = base64.b64decode(request["authenticator"])
        request_timestamp = request.get("timestamp", time.time())

        print(f"[{self.authority_id}] Service ticket request for '{service_id}'")

        # Step 1: Decrypt TGT
        try:
            tgt = deserialize_ticket(aes_decrypt(encrypted_tgt, self.tgs_secret_key))
        except Exception as e:
            send_message(conn, {"type": "ERROR", "message": f"Failed to decrypt TGT: {e}"})
            return

        # Step 2: Check TGT expiration
        if is_ticket_expired(tgt):
            send_message(conn, {"type": "ERROR", "message": "TGT has expired"})
            return

        # Step 3: Check key version
        if tgt.get("key_version", 0) != self.key_version:
            send_message(conn, {"type": "ERROR", "message": "Outdated key version"})
            return

        # Step 4: Verify at least 2 AS signatures against CANONICAL signable payload
        signable = get_signable_payload(tgt)
        signable_bytes = serialize_ticket(signable)
        is_valid, count, valid_ids = self._verify_as_signatures(signable_bytes, as_signatures)

        if not is_valid:
            send_message(conn, {
                "type": "ERROR",
                "message": f"Insufficient valid AS signatures: {count}/2 required"
            })
            print(f"[{self.authority_id}] Rejected: only {count} valid AS signatures")
            return

        # Step 5: Verify authenticator
        client_id = tgt["client_id"]
        tgt_session_key = base64.b64decode(tgt["session_key"])
        try:
            auth_data = json.loads(aes_decrypt(authenticator_enc, tgt_session_key).decode('utf-8'))
            if auth_data.get("client_id") != client_id:
                send_message(conn, {"type": "ERROR", "message": "Authenticator client_id mismatch"})
                return
        except Exception as e:
            send_message(conn, {"type": "ERROR", "message": f"Invalid authenticator: {e}"})
            return

        # Step 6: Generate service session key
        service_session_key = generate_aes_key()

        # Step 7: Build service ticket (with client-provided timestamp for consistency)
        service_ticket = create_ticket_payload(
            client_id=client_id,
            service_id=service_id,
            session_key=service_session_key,
            lifetime=3600,
            key_version=self.key_version,
            authority_metadata={"issuer": self.authority_id},
            timestamp=request_timestamp
        )

        # Step 8: Sign the CANONICAL signable payload (same across all TGS nodes)
        st_signable = get_signable_payload(service_ticket)
        st_signable_bytes = serialize_ticket(st_signable)
        R, s = schnorr_sign(st_signable_bytes, self.private_key, self.authority_id, P, Q, G)

        # Step 9: Encrypt full service ticket with service secret key
        if service_id not in self.service_secrets:
            send_message(conn, {"type": "ERROR", "message": f"Unknown service: {service_id}"})
            return

        svc_key = base64.b64decode(self.service_secrets[service_id]["secret_key"])
        st_full_bytes = serialize_ticket(service_ticket)
        encrypted_service_ticket = aes_encrypt(st_full_bytes, svc_key)

        # Step 10: Encrypt service session key with TGT session key
        encrypted_service_session_key = aes_encrypt(service_session_key, tgt_session_key)

        # Build response
        response = {
            "type": "SERVICE_TICKET_RESPONSE",
            "authority_id": self.authority_id,
            "encrypted_service_ticket": base64.b64encode(encrypted_service_ticket).decode('utf-8'),
            "encrypted_service_session_key": base64.b64encode(encrypted_service_session_key).decode('utf-8'),
            "signature": signature_to_dict(R, s, self.authority_id),
        }

        send_message(conn, response)
        print(f"[{self.authority_id}] Service ticket issued for '{client_id}' -> '{service_id}' "
              f"(verified {count} AS sigs: {valid_ids})")

    def start(self):
        """Start the TGS node server."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('localhost', self.port))
        server.listen(5)

        print(f"[{self.authority_id}] Ticket Granting Server listening on port {self.port}")

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
    parser = argparse.ArgumentParser(description="Kerberos Ticket Granting Server Node")
    parser.add_argument("--id", required=True, choices=["TGS1", "TGS2", "TGS3"],
                        help="Authority ID")
    parser.add_argument("--port", type=int, required=True,
                        help="Port to listen on")
    args = parser.parse_args()

    server = TicketGrantingServer(args.id, args.port)
    server.start()


if __name__ == "__main__":
    main()
