"""
crypto_utils.py — Cryptographic primitives for Kerberos multi-signature system.

Implements:
  - Manual modular arithmetic (exponentiation, inverse, etc.)
  - Schnorr signature generation & verification
  - Multi-signature validation (2-of-3)
  - AES-256-CBC encryption/decryption
  - Manual PKCS#7 padding
  - SHA-256 hashing utilities

No asymmetric crypto libraries used — all Schnorr operations are manual.
"""

import hashlib
import json
import os
import secrets
import struct
import time
from typing import Dict, List, Optional, Tuple

# =============================================================================
# Domain Parameters (2048-bit safe prime)
# =============================================================================
# Using a well-known 2048-bit safe prime from RFC 3526 (Group 14)
# p is prime, q = (p-1)/2 is also prime
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)

Q = (P - 1) // 2  # Safe prime: q = (p-1)/2

G = 2  # Generator for the group


# =============================================================================
# Modular Arithmetic (Manual Implementation)
# =============================================================================

def mod_exp(base: int, exp: int, mod: int) -> int:
    """Manual modular exponentiation using square-and-multiply."""
    if mod == 1:
        return 0
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean Algorithm. Returns (gcd, x, y) such that a*x + b*y = gcd."""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def mod_inv(a: int, mod: int) -> int:
    """Modular multiplicative inverse using Extended Euclidean Algorithm."""
    gcd, x, _ = extended_gcd(a % mod, mod)
    if gcd != 1:
        raise ValueError(f"Modular inverse does not exist for {a} mod {mod}")
    return x % mod


def mod_add(a: int, b: int, mod: int) -> int:
    """Modular addition."""
    return (a + b) % mod


def mod_mul(a: int, b: int, mod: int) -> int:
    """Modular multiplication."""
    return (a * b) % mod


def mod_sub(a: int, b: int, mod: int) -> int:
    """Modular subtraction."""
    return (a - b) % mod


# =============================================================================
# Random Number Generation (OS-level secure RNG)
# =============================================================================

def secure_random(n: int) -> int:
    """Generate a cryptographically secure random integer in [1, n-1]."""
    return secrets.randbelow(n - 1) + 1


def generate_random_bytes(length: int) -> bytes:
    """Generate cryptographically secure random bytes."""
    return os.urandom(length)


# =============================================================================
# SHA-256 Hashing
# =============================================================================

def sha256_hash(data: bytes) -> bytes:
    """Compute SHA-256 hash of data."""
    return hashlib.sha256(data).digest()


def sha256_hash_hex(data: bytes) -> str:
    """Compute SHA-256 hash of data, return hex string."""
    return hashlib.sha256(data).hexdigest()


def sha256_hash_int(data: bytes) -> int:
    """Compute SHA-256 hash of data, return as integer."""
    return int(hashlib.sha256(data).hexdigest(), 16)


# =============================================================================
# PKCS#7 Padding (Manual Implementation)
# =============================================================================

BLOCK_SIZE = 16  # AES block size in bytes


def pkcs7_pad(data: bytes) -> bytes:
    """Apply PKCS#7 padding to data."""
    padding_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    padding = bytes([padding_len] * padding_len)
    return data + padding


def pkcs7_unpad(data: bytes) -> bytes:
    """Remove PKCS#7 padding from data."""
    if len(data) == 0:
        raise ValueError("Cannot unpad empty data")
    padding_len = data[-1]
    if padding_len == 0 or padding_len > BLOCK_SIZE:
        raise ValueError(f"Invalid padding length: {padding_len}")
    # Verify all padding bytes are correct
    for i in range(1, padding_len + 1):
        if data[-i] != padding_len:
            raise ValueError("Invalid PKCS#7 padding")
    return data[:-padding_len]


# =============================================================================
# AES-256-CBC Encryption/Decryption (symmetric library allowed)
# =============================================================================

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    AES-256-CBC encryption with manual PKCS#7 padding.
    Returns: IV (16 bytes) || ciphertext
    """
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key")
    iv = generate_random_bytes(16)
    padded = pkcs7_pad(plaintext)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv + ciphertext


def aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    AES-256-CBC decryption with manual PKCS#7 unpadding.
    Expects: IV (16 bytes) || ciphertext
    """
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte key")
    if len(ciphertext) < 32:
        raise ValueError("Ciphertext too short (need at least IV + 1 block)")
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    return pkcs7_unpad(padded)


def generate_aes_key() -> bytes:
    """Generate a random AES-256 key (32 bytes)."""
    return generate_random_bytes(32)


# =============================================================================
# Schnorr Signature Scheme (Manual Implementation)
# =============================================================================

def generate_schnorr_keypair(
    p: int = P, q: int = Q, g: int = G
) -> Tuple[int, int]:
    """
    Generate a Schnorr key pair.
    Returns: (private_key x, public_key y) where y = g^x mod p
    """
    x = secure_random(q)  # Private key: x ∈ Z_q
    y = mod_exp(g, x, p)  # Public key: y = g^x mod p
    return x, y


def schnorr_sign(
    message: bytes,
    private_key: int,
    authority_id: str,
    p: int = P, q: int = Q, g: int = G
) -> Tuple[int, int]:
    """
    Generate a Schnorr signature on a message.
    
    Args:
        message: The message to sign (bytes)
        private_key: The signer's private key x
        authority_id: The authority identifier (e.g., "AS1")
        p, q, g: Domain parameters
    
    Returns:
        (R, s) where R = g^k mod p, s = k + e*x mod q
    
    IMPORTANT: Uses a fresh random nonce k for every signature.
    """
    # Step 1: Generate fresh random nonce
    k = secure_random(q)
    
    # Step 2: Compute commitment
    R = mod_exp(g, k, p)
    
    # Step 3: Compute challenge e = H(m || R || ID)
    hash_input = message + R.to_bytes(256, 'big') + authority_id.encode('utf-8')
    e = sha256_hash_int(hash_input) % q
    
    # Step 4: Compute signature s = k + e * x mod q
    s = mod_add(k, mod_mul(e, private_key, q), q)
    
    return R, s


def schnorr_verify(
    message: bytes,
    R: int,
    s: int,
    public_key: int,
    authority_id: str,
    p: int = P, q: int = Q, g: int = G
) -> bool:
    """
    Verify a Schnorr signature.
    
    Checks: g^s ≡ R * y^e mod p
    where e = H(m || R || ID)
    
    Returns: True if signature is valid
    """
    # Recompute challenge
    hash_input = message + R.to_bytes(256, 'big') + authority_id.encode('utf-8')
    e = sha256_hash_int(hash_input) % q
    
    # Check: g^s ≡ R * y^e mod p
    lhs = mod_exp(g, s, p)
    rhs = mod_mul(R, mod_exp(public_key, e, p), p)
    
    return lhs == rhs


def verify_multi_signatures(
    message: bytes,
    signatures: List[Dict],
    public_keys: Dict[str, int],
    p: int = P, q: int = Q, g: int = G,
    min_valid: int = 2
) -> Tuple[bool, int, List[str]]:
    """
    Verify that at least `min_valid` independent Schnorr signatures are valid.
    
    Args:
        message: The signed message
        signatures: List of {"R": int, "s": int, "authority_id": str}
        public_keys: Dict mapping authority_id → public_key
        min_valid: Minimum number of valid signatures required
    
    Returns:
        (is_valid, num_valid, valid_authority_ids)
    """
    valid_count = 0
    valid_authorities = []
    
    for sig in signatures:
        auth_id = sig["authority_id"]
        R = sig["R"]
        s = sig["s"]
        
        if auth_id not in public_keys:
            continue
        
        y = public_keys[auth_id]
        
        if schnorr_verify(message, R, s, y, auth_id, p, q, g):
            valid_count += 1
            valid_authorities.append(auth_id)
    
    return valid_count >= min_valid, valid_count, valid_authorities


# =============================================================================
# Ticket Utilities
# =============================================================================

def create_ticket_payload(
    client_id: str,
    service_id: str,
    session_key: bytes,
    lifetime: int = 3600,
    key_version: int = 1,
    authority_metadata: Optional[Dict] = None,
    timestamp: Optional[float] = None
) -> Dict:
    """Create a ticket payload dictionary."""
    import base64
    return {
        "client_id": client_id,
        "service_id": service_id,
        "timestamp": timestamp if timestamp is not None else time.time(),
        "lifetime": lifetime,
        "session_key": base64.b64encode(session_key).decode('utf-8'),
        "key_version": key_version,
        "authority_metadata": authority_metadata or {},
    }


def get_signable_payload(ticket: Dict) -> Dict:
    """
    Extract the canonical signable fields from a ticket.
    
    This excludes session_key and authority_metadata which vary per-authority,
    so that all authorities sign the SAME content for a given request.
    """
    return {
        "client_id": ticket["client_id"],
        "service_id": ticket["service_id"],
        "timestamp": ticket["timestamp"],
        "lifetime": ticket["lifetime"],
        "key_version": ticket["key_version"],
    }


def serialize_ticket(ticket: Dict) -> bytes:
    """Serialize a ticket to bytes for signing/encryption."""
    return json.dumps(ticket, sort_keys=True, separators=(',', ':')).encode('utf-8')


def deserialize_ticket(data: bytes) -> Dict:
    """Deserialize ticket from bytes."""
    return json.loads(data.decode('utf-8'))


def encrypt_ticket(ticket: Dict, key: bytes) -> bytes:
    """Serialize and encrypt a ticket."""
    return aes_encrypt(serialize_ticket(ticket), key)


def decrypt_ticket(encrypted: bytes, key: bytes) -> Dict:
    """Decrypt and deserialize a ticket."""
    return deserialize_ticket(aes_decrypt(encrypted, key))


def is_ticket_expired(ticket: Dict) -> bool:
    """Check if a ticket has expired based on timestamp + lifetime."""
    return time.time() > ticket["timestamp"] + ticket["lifetime"]


# =============================================================================
# Signature Serialization Helpers
# =============================================================================

def signature_to_dict(R: int, s: int, authority_id: str) -> Dict:
    """Convert a signature to a serializable dict."""
    return {
        "R": hex(R),
        "s": hex(s),
        "authority_id": authority_id
    }


def signature_from_dict(sig_dict: Dict) -> Dict:
    """Convert a serialized signature dict back to int values."""
    return {
        "R": int(sig_dict["R"], 16),
        "s": int(sig_dict["s"], 16),
        "authority_id": sig_dict["authority_id"]
    }


# =============================================================================
# Password Hashing
# =============================================================================

def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """Hash a password with salt using SHA-256."""
    if salt is None:
        salt = generate_random_bytes(16)
    pw_hash = sha256_hash(salt + password.encode('utf-8'))
    return pw_hash, salt


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte AES key from a password using SHA-256."""
    return sha256_hash(salt + password.encode('utf-8'))


# =============================================================================
# Network Helpers
# =============================================================================

def send_message(sock, data: Dict):
    """Send a JSON message over a socket with length prefix."""
    msg = json.dumps(data).encode('utf-8')
    length = struct.pack('!I', len(msg))
    sock.sendall(length + msg)


def recv_message(sock) -> Optional[Dict]:
    """Receive a JSON message from a socket with length prefix."""
    raw_len = _recv_exact(sock, 4)
    if raw_len is None:
        return None
    msg_len = struct.unpack('!I', raw_len)[0]
    raw_msg = _recv_exact(sock, msg_len)
    if raw_msg is None:
        return None
    return json.loads(raw_msg.decode('utf-8'))


def _recv_exact(sock, n: int) -> Optional[bytes]:
    """Receive exactly n bytes from a socket."""
    data = b''
    while len(data) < n:
        try:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        except Exception:
            return None
    return data


# =============================================================================
# Key I/O Helpers
# =============================================================================

def save_json(filepath: str, data: Dict):
    """Save data as JSON to a file."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)


def load_json(filepath: str) -> Dict:
    """Load JSON data from a file."""
    with open(filepath, 'r') as f:
        return json.load(f)
