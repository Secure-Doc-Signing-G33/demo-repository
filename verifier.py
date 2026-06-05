"""
verifier.py — Employer diploma verification module
----------------------------------------------------
Implements the verification side of the protocol.
The verifier needs only the certificate file and the university public key.
No contact with the university is required.

Usage:
    python verifier.py --cert signatures/cert.json --university UQU
    python verifier.py --cert signatures/cert.json --pubkey keys/UQU_public.pem
"""

import argparse
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from crypto_utils import (
    diploma_to_canonical_bytes,
    hash_hex,
    load_public_key_pem,
)
from key_manager import load_public_key, get_public_key_pem

VALID   = "VALID"
INVALID = "INVALID"


# ──────────────────────────────────────────────
# Core verification function
# ──────────────────────────────────────────────

def verify_certificate(certificate: dict, university_id: str = None, pubkey_pem: bytes = None) -> dict:
    """
    Verify a diploma certificate without contacting the university.

    Algorithm:
      1. Re-serialize diploma to canonical bytes (sort_keys=True)
      2. Decode DER signature (r, s) from hex
      3. ECDSA verify:
             w    = s^-1 mod n
             u1   = H(m) * w mod n
             u2   = r * w mod n
             (x,y) = u1*G + u2*K_pub
             Accept if x mod n == r
    """
    result = {
        "status":       INVALID,
        "university_id": certificate.get("university_id"),
        "diploma_id":   certificate.get("diploma", {}).get("diploma_id"),
        "student_name": certificate.get("diploma", {}).get("student_name"),
        "degree":       certificate.get("diploma", {}).get("degree"),
        "issued_at":    certificate.get("issued_at"),
        "errors":       [],
    }

    # Load public key
    try:
        if pubkey_pem:
            public_key = load_public_key_pem(pubkey_pem)
        elif university_id:
            public_key = load_public_key(university_id)
        else:
            uid = certificate.get("university_id")
            if not uid:
                result["errors"].append("No university_id in certificate and no key supplied.")
                return result
            public_key = load_public_key(uid)
    except Exception as e:
        result["errors"].append(f"Public key loading failed: {e}")
        return result

    # Re-serialize diploma
    diploma = certificate.get("diploma")
    if not diploma:
        result["errors"].append("Certificate has no diploma field.")
        return result

    doc_bytes     = diploma_to_canonical_bytes(diploma)
    computed_hash = hash_hex(doc_bytes)
    result["computed_hash"] = computed_hash
    print(f"[Verifier] Recomputed hash (SHA-256): {computed_hash}")

    # Decode signature
    sig_hex = certificate.get("signature")
    if not sig_hex:
        result["errors"].append("Certificate has no signature field.")
        return result

    try:
        signature_bytes = bytes.fromhex(sig_hex)
    except ValueError as e:
        result["errors"].append(f"Invalid signature hex: {e}")
        return result

    # ECDSA verify
    try:
        public_key.verify(signature_bytes, doc_bytes, ec.ECDSA(hashes.SHA256()))
        result["status"] = VALID
        print("[Verifier] Signature is VALID — diploma is authentic and unmodified.")
    except InvalidSignature:
        result["errors"].append("Signature verification FAILED — diploma may have been tampered with.")
        print("[Verifier] Signature is INVALID — diploma has been tampered with or signature is forged.")
    except Exception as e:
        result["errors"].append(f"Unexpected verification error: {e}")
        print(f"[Verifier] Error during verification: {e}")

    return result


def print_result(result: dict):
    print("\n" + "=" * 55)
    print(f"  VERIFICATION RESULT: {result['status']}")
    print("=" * 55)
    print(f"  Diploma ID   : {result.get('diploma_id', 'N/A')}")
    print(f"  Student      : {result.get('student_name', 'N/A')}")
    print(f"  Degree       : {result.get('degree', 'N/A')}")
    print(f"  University   : {result.get('university_id', 'N/A')}")
    print(f"  Issued at    : {result.get('issued_at', 'N/A')}")
    if result.get("computed_hash"):
        print(f"  Doc hash     : {result['computed_hash'][:32]}...")
    if result["errors"]:
        print("  Errors:")
        for e in result["errors"]:
            print(f"    - {e}")
    print("=" * 55 + "\n")


# ──────────────────────────────────────────────
# CLI entry point
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Verify a university diploma certificate")
    parser.add_argument("--cert",       required=True, help="Path to .cert.json file")
    parser.add_argument("--university", default=None,  help="University ID to look up public key")
    parser.add_argument("--pubkey",     default=None,  help="Path to public key PEM file")
    args = parser.parse_args()

    cert_path = Path(args.cert)
    if not cert_path.exists():
        print(f"[Verifier] Certificate file not found: {cert_path}")
        return

    certificate = json.loads(cert_path.read_text())

    pubkey_pem = None
    if args.pubkey:
        pubkey_pem = Path(args.pubkey).read_bytes()

    result = verify_certificate(certificate, university_id=args.university, pubkey_pem=pubkey_pem)
    print_result(result)


if __name__ == "__main__":
    main()
