"""
service_server.py — Service Server.

Accepts service tickets from clients, verifies ≥2 TGS signatures,
decrypts the ticket, and grants access to the service.

Usage:
    python service_server.py --id SERVICE1 --port 7001
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
    schnorr_verify,
    deserialize_ticket,
    get_signable_payload,
    serialize_ticket,
    aes_encrypt,
    aes_decrypt,
    is_ticket_expired,
    signature_from_dict,
    send_message,
    recv_message,
    load_json,
)

KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")


class ServiceServer:
    def __init__(self, service_id: str, port: int):
        self.service_id = service_id
        self.port = port
        self.service_secret_key = None
        self.tgs_public_keys = {}
        self.key_version = 1
        self._load_keys()

    def _load_keys(self):
        """Load service secret key and TGS public keys."""
        # Load all public keys (to verify TGS signatures)
        all_pub = load_json(os.path.join(KEYS_DIR, "public_keys.json"))
        self.tgs_public_keys = {k: int(v, 16) for k, v in all_pub.items() if k.startswith("TGS")}

        # Load service secret key
        svc_secrets = load_json(os.path.join(KEYS_DIR, "service_secrets.json"))
        if self.service_id not in svc_secrets:
            raise ValueError(f"No secret key found for service {self.service_id}")
        self.service_secret_key = base64.b64decode(svc_secrets[self.service_id]["secret_key"])
        self.key_version = svc_secrets[self.service_id]["key_version"]

        print(f"[{self.service_id}] Keys loaded successfully")

    def _verify_tgs_signatures(self, payload_bytes: bytes, signatures: list) -> tuple:
        """Verify TGS signatures on a service ticket. Returns (is_valid, count, valid_ids)."""
        valid_count = 0
        valid_ids = []

        for sig_dict in signatures:
            sig = signature_from_dict(sig_dict)
            auth_id = sig["authority_id"]

            if auth_id not in self.tgs_public_keys:
                continue

            pub_key = self.tgs_public_keys[auth_id]
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

            if msg_type == "SERVICE_REQUEST":
                self._handle_service_request(conn, request)
            elif msg_type == "PING":
                send_message(conn, {"type": "PONG", "service_id": self.service_id})
            else:
                send_message(conn, {"type": "ERROR", "message": "Unknown request type"})

        except Exception as e:
            print(f"[{self.service_id}] Error handling client {addr}: {e}")
            try:
                send_message(conn, {"type": "ERROR", "message": str(e)})
            except:
                pass
        finally:
            conn.close()

    def _handle_service_request(self, conn, request):
        """Process a service request from a client."""
        encrypted_service_ticket = base64.b64decode(request["encrypted_service_ticket"])
        tgs_signatures = request["tgs_signatures"]
        authenticator_enc = base64.b64decode(request["authenticator"])

        print(f"[{self.service_id}] Service request received")

        # Step 1: Decrypt service ticket
        try:
            st_payload_bytes = aes_decrypt(encrypted_service_ticket, self.service_secret_key)
            service_ticket = deserialize_ticket(st_payload_bytes)
        except Exception as e:
            send_message(conn, {"type": "ERROR", "message": f"Failed to decrypt service ticket: {e}"})
            return

        # Step 2: Verify ≥2 TGS signatures against CANONICAL signable payload
        signable = get_signable_payload(service_ticket)
        signable_bytes = serialize_ticket(signable)
        is_valid, count, valid_ids = self._verify_tgs_signatures(signable_bytes, tgs_signatures)

        if not is_valid:
            send_message(conn, {
                "type": "ERROR",
                "message": f"Insufficient valid TGS signatures: {count}/2 required"
            })
            print(f"[{self.service_id}] REJECTED: only {count} valid TGS signatures")
            return

        # Step 3: Verify the ticket is for this service
        if service_ticket.get("service_id") != self.service_id:
            send_message(conn, {"type": "ERROR", "message": "Ticket is not for this service"})
            return

        # Step 4: Check ticket expiration
        if is_ticket_expired(service_ticket):
            send_message(conn, {"type": "ERROR", "message": "Service ticket has expired"})
            print(f"[{self.service_id}] REJECTED: expired ticket")
            return

        # Step 5: Check key version
        if service_ticket.get("key_version", 0) != self.key_version:
            send_message(conn, {"type": "ERROR", "message": "Outdated key version"})
            print(f"[{self.service_id}] REJECTED: outdated key version")
            return

        # Step 6: Verify authenticator
        service_session_key = base64.b64decode(service_ticket["session_key"])
        try:
            auth_data = json.loads(aes_decrypt(authenticator_enc, service_session_key).decode('utf-8'))
            client_id = service_ticket["client_id"]
            if auth_data.get("client_id") != client_id:
                send_message(conn, {"type": "ERROR", "message": "Authenticator mismatch"})
                return
        except Exception as e:
            send_message(conn, {"type": "ERROR", "message": f"Invalid authenticator: {e}"})
            return

        # Step 7: Grant access — send mutual authentication response
        client_id = service_ticket["client_id"]
        response_data = {
            "client_id": client_id,
            "service_id": self.service_id,
            "timestamp": time.time(),
            "message": f"Access granted to {self.service_id}",
        }

        # Encrypt response with service session key for mutual authentication
        encrypted_response = aes_encrypt(
            json.dumps(response_data).encode('utf-8'),
            service_session_key
        )

        response = {
            "type": "SERVICE_RESPONSE",
            "status": "ACCESS_GRANTED",
            "encrypted_data": base64.b64encode(encrypted_response).decode('utf-8'),
            "verified_signatures": count,
            "verified_authorities": valid_ids,
        }

        send_message(conn, response)
        print(f"[{self.service_id}] ACCESS GRANTED to '{client_id}' "
              f"(verified {count} TGS sigs: {valid_ids})")

    def start(self):
        """Start the service server."""
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('localhost', self.port))
        server.listen(5)

        print(f"[{self.service_id}] Service Server listening on port {self.port}")

        try:
            while True:
                conn, addr = server.accept()
                thread = threading.Thread(target=self._handle_client, args=(conn, addr))
                thread.daemon = True
                thread.start()
        except KeyboardInterrupt:
            print(f"\n[{self.service_id}] Shutting down...")
        finally:
            server.close()


def main():
    parser = argparse.ArgumentParser(description="Kerberos Service Server")
    parser.add_argument("--id", required=True,
                        help="Service ID (e.g., SERVICE1)")
    parser.add_argument("--port", type=int, required=True,
                        help="Port to listen on")
    args = parser.parse_args()

    server = ServiceServer(args.id, args.port)
    server.start()


if __name__ == "__main__":
    main()
