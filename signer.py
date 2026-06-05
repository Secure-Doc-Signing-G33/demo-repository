"""
signer.py — University diploma signing module
----------------------------------------------
Implements the signing side of the protocol:
  1. Load the university private key
  2. Serialize diploma to canonical JSON bytes (sort_keys=True)
  3. Compute SHA-256 hash
  4. Sign with ECDSA (DER-encoded r, s pair)
  5. Bundle into certificate envelope
"""

import argparse
import json
from datetime import date
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from crypto_utils import (
    diploma_to_canonical_bytes,
    hash_document,
    hash_hex,
    build_certificate,
)
from key_manager import load_private_key

DIPLOMAS_DIR   = Path(__file__).parent / "diplomas"
SIGNATURES_DIR = Path(__file__).parent / "signatures"
DIPLOMAS_DIR.mkdir(exist_ok=True)
SIGNATURES_DIR.mkdir(exist_ok=True)


# ──────────────────────────────────────────────
# Core signing function
# ──────────────────────────────────────────────

def sign_diploma(diploma: dict, university_id: str) -> dict:
    """
    Sign a diploma dictionary and return the complete certificate.

    Cryptographic steps:
      a. Canonical serialization — sort_keys ensures field order is irrelevant
      b. SHA-256 hash — document fingerprint H(m)
      c. ECDSA sign (RFC 6979 deterministic nonce):
             k  = deterministic random scalar
             (x,y) = k * G  ->  r = x mod n
             s  = k^-1 * (H(m) + r * privKey) mod n
      d. DER encode — standard portable format for the (r, s) pair

    The signature is bound to the diploma content: changing even one character
    completely changes H(m) and invalidates the signature.
    """
    doc_bytes    = diploma_to_canonical_bytes(diploma)
    doc_hash_hex = hash_hex(doc_bytes)

    print(f"[Signer] Document hash (SHA-256): {doc_hash_hex}")

    private_key   = load_private_key(university_id)
    signature_der = private_key.sign(doc_bytes, ec.ECDSA(hashes.SHA256()))
    signature_hex = signature_der.hex()

    print(f"[Signer] Signature (DER hex): {signature_hex[:40]}...")

    certificate = build_certificate(diploma, signature_hex, university_id)
    return certificate


# ──────────────────────────────────────────────
# Persistence helpers
# ──────────────────────────────────────────────

def save_certificate(certificate: dict, filename: str = None) -> Path:
    """Persist certificate JSON to the signatures directory."""
    diploma_id = certificate["diploma"].get("diploma_id", "unknown")
    filename   = filename or f"{diploma_id}.cert.json"
    path       = SIGNATURES_DIR / filename
    path.write_text(json.dumps(certificate, indent=2, ensure_ascii=False))
    print(f"[Signer] Certificate saved: {path}")
    return path


def load_certificate(path: str) -> dict:
    """Load a certificate JSON file."""
    return json.loads(Path(path).read_text())


# ──────────────────────────────────────────────
# CLI entry point
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Sign a university diploma")
    parser.add_argument("--university", default="UQU",   help="University ID")
    parser.add_argument("--student",    required=True,    help="Student full name")
    parser.add_argument("--student-id", default="000000000", help="Student ID (9 digits)")
    parser.add_argument("--degree",     default="Bachelor of Science in Computer Science")
    parser.add_argument("--honors",     default="",       help="Honours string (optional)")
    parser.add_argument("--diploma-id", default=None,     help="Diploma ID (auto-generated if omitted)")
    args = parser.parse_args()

    today      = date.today().isoformat()
    diploma_id = args.diploma_id or f"{args.university}-{args.student_id}-{today}"

    diploma = {
        "student_name":    args.student,
        "student_id":      args.student_id,
        "degree":          args.degree,
        "graduation_date": today,
        "university":      args.university,
        "issuer":          "Office of the Registrar",
        "diploma_id":      diploma_id,
    }
    if args.honors:
        diploma["honors"] = args.honors

    cert = sign_diploma(diploma, args.university)
    save_certificate(cert)
    print("[Signer] Diploma signed successfully.")


if __name__ == "__main__":
    main()
