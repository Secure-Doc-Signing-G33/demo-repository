# Secure Document Signing & Verification System
**Team 33 — Theme 4 | Umm Al-Qura University**

## Overview
A command-line implementation of a digital diploma signing and verification protocol using **ECDSA (SECP256K1)** and **SHA-256**, built with Python's `cryptography` library.

---

## Protocol Summary

```
University                     Student                    Employer (Verifier)
─────────────                  ───────                    ───────────────────
Generate ECDSA key pair
  privKey, pubKey
                               
Diploma → JSON (canonical)
SHA-256(diploma) = H
Sign H with privKey → sig
Bundle (diploma + sig) → cert
                    ──── cert ──────────────────────────>
                                                         Get pubKey (trusted source)
                                                         Re-hash diploma → H'
                                                         Verify sig with pubKey, H'
                                                         If H' matches sig → VALID
```

---

## Requirements

```bash
pip install cryptography
```
Python 3.8+

---

## Quick Start

```bash
# 1. Run the full end-to-end demo
python demo.py

# 2. Run the test suite
python tests/test_protocol.py

# 3. Individual CLI tools
python key_manager.py --generate --id MY_UNIV
python signer.py --university MY_UNIV --student "Jane Doe" --student-id "12345"
python verifier.py --cert signatures/<cert_file>.cert.json --university MY_UNIV
```

---

## File Structure

```
secure_doc_signing/
├── crypto_utils.py       # SHA-256 hashing, key serialization, certificate building
├── key_manager.py        # Key generation, loading, and multi-identity management
├── signer.py             # Diploma signing (university side)
├── verifier.py           # Certificate verification (employer side)
├── demo.py               # Full end-to-end demonstration script
├── keys/                 # Generated PEM key files
├── diplomas/             # Raw diploma JSON files
├── signatures/           # Signed certificate JSON files
└── tests/
    └── test_protocol.py  # 9 test cases covering success and attack scenarios
```

---

## Cryptographic Design

### Why ECDSA + SECP256K1?
- ~128-bit security with a 256-bit key (vs RSA-3072 for equivalent security)
- Faster signing and verification, smaller keys and signatures
- Deterministic nonce generation (RFC 6979) prevents nonce-reuse attacks

### Why SHA-256?
- Collision resistance: computationally infeasible to find two documents with the same hash
- Avalanche effect: one-character change flips ~50% of hash bits
- Binding: the signature is mathematically bound to the hash, hence to the document

### Certificate Envelope
```json
{
  "diploma": { ...all diploma fields... },
  "signature": "<DER-encoded hex>",
  "algorithm": "ECDSA",
  "hash_algorithm": "SHA-256",
  "curve": "SECP256K1",
  "university_id": "UQU",
  "issued_at": "2026-06-09T..."
}
```

### Security Properties
| Property | Mechanism |
|---|---|
| Integrity | SHA-256 + ECDSA signature; any change breaks verification |
| Authenticity | Only the private-key holder can produce a valid signature |
| Non-repudiation | Signature is tied to unique private key |
| No server needed | Verifier only needs the public key (static, distributable) |
| Replay prevention | `diploma_id` + `issued_at` in signed data |

---

## Test Cases

| ID | Scenario | Expected |
|---|---|---|
| TC-01 | Normal sign → verify | ✅ VALID |
| TC-02 | Tampered student name | ❌ INVALID |
| TC-03 | Tampered degree field | ❌ INVALID |
| TC-04 | Wrong university public key | ❌ INVALID |
| TC-05 | Corrupted signature bytes | ❌ INVALID |
| TC-06 | Multiple university identities | ✅ VALID (own), ❌ INVALID (cross) |
| TC-07 | Avalanche effect demonstration | Shown visually |
| TC-08 | Missing signature field | ❌ INVALID (graceful) |
| TC-09 | Envelope metadata changes | ✅ VALID (only diploma is hashed) |

---

## Public Key Distribution
In production, the university publishes `<UNIV_ID>_public.pem` on its official website. Employers download it once and use it for all future verifications — the university needs no uptime for verification to work.
