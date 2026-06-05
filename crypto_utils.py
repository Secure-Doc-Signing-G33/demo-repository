"""
crypto_utils.py — Shared cryptographic helpers
-------------------------------------------------
Provides low-level primitives used by all other modules:
  - SHA-256 document hashing
  - DER ↔ PEM key serialization helpers
  - Certificate building / parsing
  - Diploma ID smart encoding (university prefix embedded in ID)
"""

import hashlib
import json
import os
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils as ec_utils
from cryptography.hazmat.backends import default_backend


# ──────────────────────────────────────────────
# Hashing
# ──────────────────────────────────────────────

def hash_document(content: bytes) -> bytes:
    """
    Compute SHA-256 digest of raw document bytes.
    Any single-byte change produces a completely different hash (avalanche effect).
    """
    return hashlib.sha256(content).digest()


def hash_hex(content: bytes) -> str:
    """Return hex-encoded SHA-256 for display / storage."""
    return hashlib.sha256(content).hexdigest()


# ──────────────────────────────────────────────
# Key serialization
# ──────────────────────────────────────────────

def private_key_to_pem(private_key) -> bytes:
    """Serialize private key to PEM (PKCS8, no passphrase)."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def public_key_to_pem(public_key) -> bytes:
    """Serialize public key to PEM (SubjectPublicKeyInfo)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_private_key_pem(pem_data: bytes):
    """Deserialize a PEM private key."""
    return serialization.load_pem_private_key(pem_data, password=None, backend=default_backend())


def load_public_key_pem(pem_data: bytes):
    """Deserialize a PEM public key."""
    return serialization.load_pem_public_key(pem_data, backend=default_backend())


# ──────────────────────────────────────────────
# Certificate / signature envelope
# ──────────────────────────────────────────────

def build_certificate(diploma: dict, signature_hex: str, university_id: str) -> dict:
    """
    Wrap the signed diploma into a self-describing certificate envelope.
    """
    return {
        "diploma":          diploma,
        "signature":        signature_hex,
        "algorithm":        "ECDSA",
        "hash_algorithm":   "SHA-256",
        "curve":            "SECP256K1",
        "university_id":    university_id,
        "issued_at":        datetime.now(timezone.utc).isoformat(),
    }


def diploma_to_canonical_bytes(diploma: dict) -> bytes:
    """
    Produce a stable, deterministic byte representation of a diploma dict.
    sort_keys=True ensures field ordering never affects the hash.
    """
    return json.dumps(diploma, sort_keys=True, ensure_ascii=False).encode("utf-8")


# ──────────────────────────────────────────────
# Smart Diploma ID — embeds university code
# ──────────────────────────────────────────────

# Each university code maps to a fixed 2-digit prefix embedded in the diploma_id.
# This lets us auto-detect the university from the ID alone during verification.
# Format: <UNI_PREFIX><YEAR><STUDENT_ID>
# Example: UQU-2026-441193701  → stored internally, but the numeric
#          verification token = "<prefix><year><student_id>" = "04-2026-441193701"

UNIVERSITY_PREFIX_MAP = {
    "KSU":      "01",
    "UQU":      "02",
    "KFUPM":    "03",
    "KAU":      "04",
    "PSU":      "05",
    "PNU":      "06",
    "IMSIU":    "07",
    "KSAU-HS":  "08",
    "SEU":      "09",
    "KFU":      "10",
    "TAIBAH":   "11",
    "JAZANU":   "12",
    "UJ":       "13",
    "UB":       "14",
    "UOH":      "15",
    "NU":       "16",
    "QU":       "17",
    "BU":       "18",
    "JMU":      "19",
    "TU":       "20",
    "SHU":      "21",
    "DU":       "22",
    "REU":      "23",
    "YU":       "24",
    "DAU":      "25",
    "AOU":      "26",
    "AU":       "27",
    "PMU":      "28",
    "BMC":      "29",
}

PREFIX_TO_UNIVERSITY = {v: k for k, v in UNIVERSITY_PREFIX_MAP.items()}


def generate_diploma_id(university_id: str, student_id: str, year: str) -> str:
    """
    Generate a structured Diploma ID that embeds the university prefix.
    Format: <UNI_CODE>-<YEAR>-<STUDENT_ID>
    Example: UQU-2026-441193701

    The prefix is stored implicitly via UNIVERSITY_PREFIX_MAP, so:
    - Users enter the diploma_id exactly as printed on their diploma
    - The system decodes which university issued it automatically
    """
    prefix = UNIVERSITY_PREFIX_MAP.get(university_id, "00")
    return f"{university_id}-{year}-{student_id}"


def decode_university_from_diploma_id(diploma_id: str) -> str | None:
    """
    Extract the university code from a diploma_id automatically.

    Supports two formats:
      1. "UQU-2026-441193701"  → split on '-', first part is the code  (new format)
      2. Legacy: look up by numeric prefix stored in our map

    Returns the university code string (e.g. "UQU") or None if not found.
    """
    if not diploma_id:
        return None

    parts = diploma_id.split("-")

    # Format 1: "UQU-2026-441193701" — first segment is university code
    if len(parts) >= 3:
        candidate = parts[0].upper()
        if candidate in UNIVERSITY_PREFIX_MAP:
            return candidate

    # Format 2: pure numeric prefix "02-2026-441193701"
    if len(parts) >= 1 and parts[0].isdigit():
        prefix = parts[0].zfill(2)
        return PREFIX_TO_UNIVERSITY.get(prefix)

    return None


def short_hash_for_university(full_hash: str, university_id: str) -> str:
    """
    Return a university-tagged verification token: first 16 chars of SHA-256
    prefixed with the university numeric code.

    Example: "02-a3f9c8d1e2b47650"
    This lets a verifier confirm both:
      (a) which university issued it  — from the prefix
      (b) document integrity          — from the hash fragment
    """
    prefix = UNIVERSITY_PREFIX_MAP.get(university_id, "00")
    return f"{prefix}-{full_hash[:16]}"


# ──────────────────────────────────────────────
# Public Registry — قاعدة الهاشات العلنية
# ──────────────────────────────────────────────
# هذا الملف يمثّل ما تنشره الجامعة علنياً:
#   diploma_id  →  SHA-256 hash
# أي شخص يستطيع التحقق بدون الحاجة للجامعة

import json as _json
from pathlib import Path as _Path

REGISTRY_PATH = _Path(__file__).parent / "public_registry.json"


def registry_load() -> dict:
    """Load the public registry (creates empty file if not exists)."""
    if not REGISTRY_PATH.exists():
        REGISTRY_PATH.write_text(_json.dumps({}, indent=2))
    return _json.loads(REGISTRY_PATH.read_text())


def registry_save(data: dict):
    """Persist registry to disk."""
    REGISTRY_PATH.write_text(_json.dumps(data, indent=2, ensure_ascii=False))


def registry_add(diploma_id: str, full_hash: str, university_id: str):
    """
    Register a diploma hash publicly after signing.
    Stores: diploma_id → { hash, university_id, registered_at }
    """
    data = registry_load()
    data[diploma_id] = {
        "hash":          full_hash,
        "university_id": university_id,
        "registered_at": datetime.now(timezone.utc).isoformat(),
    }
    registry_save(data)


def registry_lookup(diploma_id: str) -> dict | None:
    """
    Look up a diploma_id in the public registry.
    Returns the record or None if not found.
    """
    data = registry_load()
    return data.get(diploma_id)


def registry_verify_hash(diploma_id: str, computed_hash: str) -> bool:
    """
    Compare a freshly-computed hash against the registered public hash.
    This is the core of public verification — no private key needed.
    """
    record = registry_lookup(diploma_id)
    if not record:
        return False
    return record["hash"] == computed_hash
