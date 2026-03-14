"""
attacks.py — Mandatory attack scenario demonstrations.

Implements 6 attack scenarios to demonstrate that the distributed
Kerberos system with 2-of-3 Schnorr multi-signatures contains
compromise of a single authority.

Each attack is self-contained and prints PASS/FAIL results.

Usage:
    python attacks.py
"""

import base64
import json
import os
import copy
import time
import sys

from crypto_utils import (
    P, Q, G,
    generate_schnorr_keypair,
    schnorr_sign,
    schnorr_verify,
    verify_multi_signatures,
    create_ticket_payload,
    get_signable_payload,
    serialize_ticket,
    deserialize_ticket,
    aes_encrypt,
    aes_decrypt,
    generate_aes_key,
    signature_to_dict,
    signature_from_dict,
    secure_random,
    mod_exp,
    load_json,
)

KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")


def load_system_keys():
    """Load all keys for attack simulations."""
    params = load_json(os.path.join(KEYS_DIR, "params.json"))
    p = int(params["p"], 16)
    q = int(params["q"], 16)
    g = params["g"]

    all_pub = load_json(os.path.join(KEYS_DIR, "public_keys.json"))
    public_keys = {k: int(v, 16) for k, v in all_pub.items()}

    private_keys = {}
    for auth_id in ["AS1", "AS2", "AS3", "TGS1", "TGS2", "TGS3"]:
        priv = load_json(os.path.join(KEYS_DIR, f"{auth_id}_private.json"))
        private_keys[auth_id] = int(priv["private_key"], 16)

    return p, q, g, public_keys, private_keys


def create_test_ticket():
    """Create a test ticket payload."""
    session_key = generate_aes_key()
    return create_ticket_payload(
        client_id="alice",
        service_id="SERVICE1",
        session_key=session_key,
        lifetime=3600,
        key_version=1,
    )


def print_header(title):
    print(f"\n{'=' * 70}")
    print(f"  ATTACK: {title}")
    print(f"{'=' * 70}")


def print_result(passed, description):
    status = "✓ PASS" if passed else "✗ FAIL"
    print(f"\n  [{status}] {description}")


# =============================================================================
# Attack 1: Single Malicious Authority Issuing Forged Ticket
# =============================================================================

def attack_single_malicious_authority():
    """
    Scenario: One AS (AS1) is compromised and tries to issue a forged ticket
    with only its own signature. The system should reject it.
    """
    print_header("Single Malicious Authority Issuing Forged Ticket")
    p, q, g, public_keys, private_keys = load_system_keys()

    # Compromised AS1 creates a forged ticket
    forged_ticket = create_ticket_payload(
        client_id="evil_attacker",
        service_id="SERVICE1",
        session_key=generate_aes_key(),
        lifetime=3600,
        key_version=1,
    )

    payload_bytes = serialize_ticket(get_signable_payload(forged_ticket))

    # AS1 signs it (only 1 signature from the compromised authority)
    R, s = schnorr_sign(payload_bytes, private_keys["AS1"], "AS1", p, q, g)
    single_sig = [{"R": R, "s": s, "authority_id": "AS1"}]

    # Verify: should require 2, but only 1 valid signature present
    as_pub = {k: v for k, v in public_keys.items() if k.startswith("AS")}
    is_valid, count, valid_ids = verify_multi_signatures(
        payload_bytes, single_sig, as_pub, p, q, g, min_valid=2
    )

    print(f"  Forged ticket signed by: AS1 only")
    print(f"  Valid signatures found: {count}")
    print(f"  Minimum required: 2")
    print(f"  Ticket accepted: {is_valid}")

    passed = not is_valid  # Should be REJECTED
    print_result(passed, "Forged ticket with 1 signature is REJECTED")
    return passed


# =============================================================================
# Attack 2: Modified Ticket Payload
# =============================================================================

def attack_modified_payload():
    """
    Scenario: An attacker obtains a valid ticket with 2+ signatures,
    then modifies the payload. Signatures should no longer verify.
    """
    print_header("Modified Ticket Payload")
    p, q, g, public_keys, private_keys = load_system_keys()

    # Create and sign a legitimate ticket with 2 authorities
    original_ticket = create_test_ticket()
    signable_bytes = serialize_ticket(get_signable_payload(original_ticket))

    # AS1 and AS2 sign the canonical signable payload
    R1, s1 = schnorr_sign(signable_bytes, private_keys["AS1"], "AS1", p, q, g)
    R2, s2 = schnorr_sign(signable_bytes, private_keys["AS2"], "AS2", p, q, g)

    signatures = [
        {"R": R1, "s": s1, "authority_id": "AS1"},
        {"R": R2, "s": s2, "authority_id": "AS2"},
    ]

    # Verify original is valid
    as_pub = {k: v for k, v in public_keys.items() if k.startswith("AS")}
    original_valid, _, _ = verify_multi_signatures(
        signable_bytes, signatures, as_pub, p, q, g, min_valid=2
    )

    # Now tamper with the ticket
    tampered_ticket = copy.deepcopy(original_ticket)
    tampered_ticket["client_id"] = "evil_attacker"
    tampered_signable = serialize_ticket(get_signable_payload(tampered_ticket))

    # Try to use original signatures with tampered payload
    tampered_valid, count, _ = verify_multi_signatures(
        tampered_signable, signatures, as_pub, p, q, g, min_valid=2
    )

    print(f"  Original ticket valid: {original_valid}")
    print(f"  Tampered ticket valid: {tampered_valid}")
    print(f"  Signatures verified after tampering: {count}")

    passed = original_valid and not tampered_valid
    print_result(passed, "Tampered ticket is REJECTED — signatures no longer verify")
    return passed


# =============================================================================
# Attack 3: Replay of Old Partial Signature
# =============================================================================

def attack_replay_old_signature():
    """
    Scenario: Attacker replays a signature from a previously valid ticket
    on a new forged ticket. The signature should not verify on the new content.
    """
    print_header("Replay of Old Partial Signature")
    p, q, g, public_keys, private_keys = load_system_keys()

    # Create an old legitimate ticket
    old_ticket = create_ticket_payload(
        client_id="alice",
        service_id="SERVICE1",
        session_key=generate_aes_key(),
        lifetime=3600,
        key_version=1,
    )
    old_signable = serialize_ticket(get_signable_payload(old_ticket))

    # Sign with AS1 and AS2
    R1_old, s1_old = schnorr_sign(old_signable, private_keys["AS1"], "AS1", p, q, g)
    R2_old, s2_old = schnorr_sign(old_signable, private_keys["AS2"], "AS2", p, q, g)

    # Now create a NEW forged ticket
    new_ticket = create_ticket_payload(
        client_id="evil_attacker",
        service_id="SERVICE1",
        session_key=generate_aes_key(),
        lifetime=7200,
        key_version=1,
    )
    new_signable = serialize_ticket(get_signable_payload(new_ticket))

    # Attacker replays old signatures on new ticket
    replayed_sigs = [
        {"R": R1_old, "s": s1_old, "authority_id": "AS1"},
        {"R": R2_old, "s": s2_old, "authority_id": "AS2"},
    ]

    as_pub = {k: v for k, v in public_keys.items() if k.startswith("AS")}
    is_valid, count, _ = verify_multi_signatures(
        new_signable, replayed_sigs, as_pub, p, q, g, min_valid=2
    )

    print(f"  Old signatures replayed on new ticket")
    print(f"  Valid signatures on new content: {count}")
    print(f"  Ticket accepted: {is_valid}")

    passed = not is_valid
    print_result(passed, "Replayed old signatures are REJECTED on new ticket")
    return passed


# =============================================================================
# Attack 4: Leakage of One Authority's Private Signing Key
# =============================================================================

def attack_key_leakage():
    """
    Scenario: An attacker obtains one authority's private key (AS1).
    They can produce valid signatures from that authority, but still
    cannot forge a ticket because they need 2 signatures.
    """
    print_header("Leakage of One Authority's Private Signing Key")
    p, q, g, public_keys, private_keys = load_system_keys()

    # Attacker has AS1's private key (leaked)
    leaked_key = private_keys["AS1"]

    # Attacker creates a forged ticket
    forged_ticket = create_ticket_payload(
        client_id="evil_attacker",
        service_id="SERVICE1",
        session_key=generate_aes_key(),
        lifetime=3600,
        key_version=1,
    )
    payload_bytes = serialize_ticket(get_signable_payload(forged_ticket))

    # Attacker signs with leaked key
    R1, s1 = schnorr_sign(payload_bytes, leaked_key, "AS1", p, q, g)

    # Attacker tries to ALSO sign as AS2 with a random key (wrong key)
    fake_key = secure_random(q)
    R2_fake, s2_fake = schnorr_sign(payload_bytes, fake_key, "AS2", p, q, g)

    sigs = [
        {"R": R1, "s": s1, "authority_id": "AS1"},
        {"R": R2_fake, "s": s2_fake, "authority_id": "AS2"},
    ]

    as_pub = {k: v for k, v in public_keys.items() if k.startswith("AS")}

    # Verify: AS1 sig should be valid, AS2 sig should be invalid
    as1_valid = schnorr_verify(payload_bytes, R1, s1, public_keys["AS1"], "AS1", p, q, g)
    as2_valid = schnorr_verify(payload_bytes, R2_fake, s2_fake, public_keys["AS2"], "AS2", p, q, g)

    is_valid, count, valid_ids = verify_multi_signatures(
        payload_bytes, sigs, as_pub, p, q, g, min_valid=2
    )

    print(f"  Leaked key: AS1")
    print(f"  AS1 signature (with leaked key) valid: {as1_valid}")
    print(f"  AS2 signature (with fake key) valid: {as2_valid}")
    print(f"  Total valid signatures: {count}")
    print(f"  Ticket accepted: {is_valid}")

    passed = as1_valid and not as2_valid and not is_valid
    print_result(passed, "Single leaked key is CONTAINED — cannot forge 2-of-3 ticket")
    return passed


# =============================================================================
# Attack 5: Authority Offline Scenario
# =============================================================================

def attack_authority_offline():
    """
    Scenario: One AS (AS3) is offline. The system should still work
    with the remaining 2 authorities (AS1, AS2).
    """
    print_header("Authority Offline Scenario")
    p, q, g, public_keys, private_keys = load_system_keys()

    # Create a legitimate ticket
    ticket = create_test_ticket()
    signable_bytes = serialize_ticket(get_signable_payload(ticket))

    # Only AS1 and AS2 are online; AS3 is offline
    R1, s1 = schnorr_sign(signable_bytes, private_keys["AS1"], "AS1", p, q, g)
    R2, s2 = schnorr_sign(signable_bytes, private_keys["AS2"], "AS2", p, q, g)

    sigs = [
        {"R": R1, "s": s1, "authority_id": "AS1"},
        {"R": R2, "s": s2, "authority_id": "AS2"},
    ]

    as_pub = {k: v for k, v in public_keys.items() if k.startswith("AS")}
    is_valid, count, valid_ids = verify_multi_signatures(
        signable_bytes, sigs, as_pub, p, q, g, min_valid=2
    )

    print(f"  Online authorities: AS1, AS2")
    print(f"  Offline authority: AS3")
    print(f"  Valid signatures: {count}")
    print(f"  System functional: {is_valid}")

    passed = is_valid
    print_result(passed, "System continues to work with 2-of-3 authorities online")
    return passed


# =============================================================================
# Attack 6: Ticket Containing Only One Valid Signature
# =============================================================================

def attack_single_signature_ticket():
    """
    Scenario: A ticket is submitted with only one valid signature.
    It should be rejected by the verification logic.
    """
    print_header("Ticket Containing Only One Valid Signature")
    p, q, g, public_keys, private_keys = load_system_keys()

    # Create a ticket with only 1 valid signature
    ticket = create_test_ticket()
    signable_bytes = serialize_ticket(get_signable_payload(ticket))

    # Only AS1 signs
    R1, s1 = schnorr_sign(signable_bytes, private_keys["AS1"], "AS1", p, q, g)

    sigs = [
        {"R": R1, "s": s1, "authority_id": "AS1"},
    ]

    as_pub = {k: v for k, v in public_keys.items() if k.startswith("AS")}
    is_valid, count, valid_ids = verify_multi_signatures(
        signable_bytes, sigs, as_pub, p, q, g, min_valid=2
    )

    print(f"  Signatures in ticket: 1 (AS1 only)")
    print(f"  Valid signatures: {count}")
    print(f"  Minimum required: 2")
    print(f"  Ticket accepted: {is_valid}")

    passed = not is_valid
    print_result(passed, "Ticket with only 1 signature is REJECTED")
    return passed


# =============================================================================
# Main
# =============================================================================

def run_all_attacks():
    """Run all 6 mandatory attack scenarios."""
    print("\n" + "#" * 70)
    print("#" + " " * 68 + "#")
    print("#   KERBEROS MULTI-SIGNATURE — ATTACK SCENARIO DEMONSTRATIONS" + " " * 7 + "#")
    print("#" + " " * 68 + "#")
    print("#" * 70)

    results = []

    results.append(("Single Malicious Authority", attack_single_malicious_authority()))
    results.append(("Modified Ticket Payload", attack_modified_payload()))
    results.append(("Replay Old Signature", attack_replay_old_signature()))
    results.append(("Key Leakage (1 authority)", attack_key_leakage()))
    results.append(("Authority Offline", attack_authority_offline()))
    results.append(("Single Signature Ticket", attack_single_signature_ticket()))

    # Summary
    print(f"\n\n{'=' * 70}")
    print(f"  ATTACK RESULTS SUMMARY")
    print(f"{'=' * 70}")

    all_passed = True
    for name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"  [{status}] {name}")
        if not passed:
            all_passed = False

    passed_count = sum(1 for _, p in results if p)
    print(f"\n  Total: {passed_count}/{len(results)} attacks handled correctly")
    print(f"{'=' * 70}")

    if all_passed:
        print("\n  ✓ ALL ATTACK SCENARIOS PASSED — System is resilient to partial compromise!")
    else:
        print("\n  ✗ SOME ATTACKS FAILED — System needs review!")

    return all_passed


if __name__ == "__main__":
    run_all_attacks()
