# Security Analysis — Kerberos Under Partial Compromise

## 1. Why One Compromised Authority Cannot Forge Tickets

In this system, a valid ticket requires **at least two independent Schnorr signatures** from different authorities. Each authority possesses its own private key `xᵢ`, and signatures are verified against the corresponding public key `yᵢ = g^xᵢ mod p`.

If an attacker compromises authority AS₁, they obtain only `x₁`. They can produce valid signatures `(R₁, s₁)` that verify under `y₁`, but they **cannot** produce a signature that verifies under `y₂` or `y₃` without knowing `x₂` or `x₃`.

Since the discrete logarithm problem is computationally infeasible for the chosen parameters (2048-bit safe prime), the attacker cannot derive `x₂` from `y₂ = g^x₂ mod p`.

**Conclusion**: A single compromised authority can only contribute 1 valid signature — insufficient for the 2-of-3 threshold.

## 2. Why Two Compromised Authorities Break Security

If an attacker compromises two authorities (e.g., AS₁ and AS₂), they possess both `x₁` and `x₂`. They can then:

1. Create an arbitrary ticket payload (any client ID, any service, any lifetime)
2. Sign it with `x₁` → valid signature `(R₁, s₁)` verified by `y₁`
3. Sign it with `x₂` → valid signature `(R₂, s₂)` verified by `y₂`
4. The ticket now has 2 valid signatures, meeting the threshold

**Conclusion**: The 2-of-3 scheme provides security only against compromise of at most 1 authority. This is by design — the system's trust assumption is that a majority of authorities remain honest.

## 3. Why Two Independent Schnorr Signatures Prevent Single-Authority Forgery

Each Schnorr signature binds:
- The **message content** (ticket payload)
- The **signer's commitment** `Rᵢ = g^kᵢ mod p`
- The **signer's identity** `IDᵢ`

The challenge is computed as `eᵢ = H(m ‖ Rᵢ ‖ IDᵢ)`, and the signature `sᵢ = kᵢ + eᵢ · xᵢ mod q` is verified by checking `g^sᵢ ≡ Rᵢ · yᵢ^eᵢ mod p`.

Critical properties:
- **Identity binding**: Including `IDᵢ` in the hash means a signature from AS₁ cannot be substituted for AS₂
- **Message binding**: Any modification to the ticket invalidates all existing signatures
- **Independence**: Each authority's signature depends only on its own private key

An attacker with key `x₁` can sign as AS₁ but produces gibberish under `y₂`'s verification equation. The mathematical relationship `g^s₂ ≡ R₂ · y₂^e₂ mod p` holds only when `s₂` was computed using the true `x₂`.

## 4. Nonce Reuse Risks

In Schnorr signatures, the nonce `kᵢ` must be **fresh and random** for every signing operation. If the same nonce is reused for two different messages:

Given:
- `s₁ = k + e₁ · x mod q` (signature on message `m₁`)
- `s₂ = k + e₂ · x mod q` (signature on message `m₂`, same nonce `k`)

An attacker can compute:
```
s₁ - s₂ = (e₁ - e₂) · x mod q
x = (s₁ - s₂) · (e₁ - e₂)⁻¹ mod q
```

This completely recovers the private key `x` from two signatures sharing a nonce.

**Mitigation**: Our implementation uses `secrets.randbelow()` with OS-level entropy to generate a fresh `kᵢ` for every signature, making nonce reuse virtually impossible.

## 5. Key Share Leakage Impact

If one authority's private key `xᵢ` is leaked:

### What the attacker CAN do:
- Produce valid signatures as authority `i`
- Impersonate authority `i` in the signing protocol
- Sign arbitrary payloads that verify under `yᵢ`

### What the attacker CANNOT do:
- Forge a complete valid ticket (needs 2 signatures)
- Derive other authorities' private keys from their public keys
- Break the AES encryption of existing tickets (separate key)
- Modify tickets signed by other authorities

### Remediation:
1. Revoke the compromised authority's key
2. Generate a new key pair for the compromised authority
3. Increment the `key_version` field in tickets
4. All service servers reject tickets signed with the old key version

The system degrades gracefully: even with one key compromised, the remaining 2 honest authorities can continue issuing valid tickets.

## 6. Performance Overhead of Multi-Authority Signing

### Computational Cost
| Operation | Single Authority | 2-of-3 Multi-Authority |
|---|---|---|
| Key Generation | 1 modular exp | 6 modular exp (one-time) |
| Signing (per ticket) | 1 exp + 1 hash | 2-3 exp + 2-3 hashes |
| Verification | 2 exp + 1 hash | 4-6 exp + 2-3 hashes |

### Network Overhead
- Client must contact **2-3 AS nodes** instead of 1 (parallel connections feasible)
- Client must contact **2-3 TGS nodes** instead of 1
- Tickets are **larger** (contain 2+ signatures instead of 1)
- Each signature adds ~512 bytes (256-byte R + 256-byte s + authority ID)

### Latency Analysis
- **Best case** (all authorities online): ~1.5× latency of single-authority Kerberos (parallel requests)
- **One authority offline**: Same as best case (2 of 3 suffice)
- **Two authorities offline**: System fails gracefully

### Trade-off Justification
The 2-3× computational overhead and ~1KB additional ticket size are modest costs for eliminating the single-point-of-failure vulnerability in traditional Kerberos. In traditional Kerberos, compromising the single AS means **game over** — the attacker can issue tickets for any user to any service. In our system, compromising one authority has **zero impact** on ticket validity.
