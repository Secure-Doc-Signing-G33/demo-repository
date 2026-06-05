"""
key_manager.py — University key-pair lifecycle
-----------------------------------------------
Handles ECDSA key generation, persistence, and loading.
Supports multiple university identities.

Usage:
    python key_manager.py --generate --id UQU
    python key_manager.py --list
"""

import os
import argparse
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

from crypto_utils import (
    private_key_to_pem,
    public_key_to_pem,
    load_private_key_pem,
    load_public_key_pem,
)

KEYS_DIR = Path(__file__).parent / "keys"
KEYS_DIR.mkdir(exist_ok=True)


# ──────────────────────────────────────────────
# Key generation
# ──────────────────────────────────────────────

def generate_key_pair(university_id: str) -> dict:
    """
    Generate an ECDSA key pair on the SECP256K1 curve for a given university.

    SECP256K1 provides ~128-bit security with much smaller keys than RSA-3072,
    ideal for scalable university systems.
    """
    # Generate private scalar k in [1, n-1] using OS CSPRNG
    private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    public_key = private_key.public_key()

    priv_path = KEYS_DIR / f"{university_id}_private.pem"
    pub_path  = KEYS_DIR / f"{university_id}_public.pem"

    priv_path.write_bytes(private_key_to_pem(private_key))
    pub_path.write_bytes(public_key_to_pem(public_key))

    print(f"[KeyManager] Generated key pair for '{university_id}'")
    print(f"  Private key: {priv_path}  (KEEP SECRET)")
    print(f"  Public  key: {pub_path}  (distribute freely)")

    return {"private_key_path": str(priv_path), "public_key_path": str(pub_path)}


# ──────────────────────────────────────────────
# Key loading
# ──────────────────────────────────────────────

def load_private_key(university_id: str):
    """Load university private key from disk."""
    path = KEYS_DIR / f"{university_id}_private.pem"
    if not path.exists():
        raise FileNotFoundError(f"No private key found for '{university_id}'. Run --generate first.")
    return load_private_key_pem(path.read_bytes())


def load_public_key(university_id: str):
    """Load university public key from disk."""
    path = KEYS_DIR / f"{university_id}_public.pem"
    if not path.exists():
        raise FileNotFoundError(f"No public key found for '{university_id}'.")
    return load_public_key_pem(path.read_bytes())


def get_public_key_pem(university_id: str) -> bytes:
    """Return raw PEM bytes of the public key (for distribution)."""
    path = KEYS_DIR / f"{university_id}_public.pem"
    if not path.exists():
        raise FileNotFoundError(f"No public key found for '{university_id}'.")
    return path.read_bytes()


def list_identities() -> list:
    """Return all university IDs that have a key pair."""
    ids = set()
    for f in KEYS_DIR.glob("*_private.pem"):
        ids.add(f.stem.replace("_private", ""))
    return sorted(ids)


# ──────────────────────────────────────────────
# CLI entry point
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="University Key Manager")
    parser.add_argument("--generate", action="store_true", help="Generate a new key pair")
    parser.add_argument("--id", default="UQU", help="University identifier (default: UQU)")
    parser.add_argument("--list", action="store_true", help="List all university identities")
    args = parser.parse_args()

    if args.list:
        ids = list_identities()
        if ids:
            print("Known university identities:", ", ".join(ids))
        else:
            print("No keys found. Run --generate first.")
        return

    if args.generate:
        generate_key_pair(args.id)
        return

    parser.print_help()


if __name__ == "__main__":
    main()
