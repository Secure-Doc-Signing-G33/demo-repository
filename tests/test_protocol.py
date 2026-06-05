"""
tests/test_protocol.py — Full protocol test suite
---------------------------------------------------
Covers:
  TC-01  Happy path: sign -> verify (should PASS)
  TC-02  Tampered student name (should FAIL)
  TC-03  Tampered degree field (should FAIL)
  TC-04  Wrong university public key (should FAIL)
  TC-05  Corrupted signature bytes (should FAIL)
  TC-06  Multiple universities, correct routing (should PASS)
  TC-07  Avalanche effect demonstration
  TC-08  Missing signature field (should FAIL gracefully)
  TC-09  Empty diploma fields (edge case)
"""

import sys
import os
import copy
import json

# Allow imports from parent directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from key_manager import generate_key_pair, get_public_key_pem
from signer import sign_diploma
from verifier import verify_certificate, VALID, INVALID
from crypto_utils import diploma_to_canonical_bytes, hash_hex

# ──────────────────────────────────────────────
# Test fixtures
# ──────────────────────────────────────────────

SAMPLE_DIPLOMA = {
    "student_name":    "Sabah Mohamed Alanazi",
    "student_id":      "44411937",
    "degree":          "Bachelor of Science in Computer Science",
    "graduation_date": "2026-06-01",
    "university":      "Umm Al-Qura University",
    "issuer":          "Office of the Registrar",
    "issue_date":      "2026-06-09",
    "diploma_id":      "UQU-2026-CS-001234",
    "honors":          "Magna Cum Laude",
}

# Track pass/fail
results = []

def run_test(name, fn):
    try:
        fn()
        print(f"    PASS  {name}")
        results.append((name, "PASS"))
    except AssertionError as e:
        print(f"    FAIL  {name}: {e}")
        results.append((name, f"FAIL: {e}"))
    except Exception as e:
        print(f"  ERROR  ERROR {name}: {e}")
        results.append((name, f"ERROR: {e}"))


# ──────────────────────────────────────────────
# Setup: generate keys for test universities
# ──────────────────────────────────────────────

def setup():
    print("\n── Setup: Generating key pairs ──────────────────────")
    generate_key_pair("TEST_UNIV_A")
    generate_key_pair("TEST_UNIV_B")
    print()


# ──────────────────────────────────────────────
# Test cases
# ──────────────────────────────────────────────

def tc01_happy_path():
    """Sign a diploma with UNIV_A, verify with UNIV_A's public key -> VALID."""
    cert = sign_diploma(copy.deepcopy(SAMPLE_DIPLOMA), "TEST_UNIV_A")
    result = verify_certificate(cert, university_id="TEST_UNIV_A")
    assert result["status"] == VALID, f"Expected VALID, got {result['status']}"


def tc02_tampered_name():
    """
    Attacker changes student_name after signing.
    Hash of modified content != original -> signature check FAILS.
    """
    cert = sign_diploma(copy.deepcopy(SAMPLE_DIPLOMA), "TEST_UNIV_A")
    # Tamper: change student name
    cert["diploma"]["student_name"] = "Attacker Name"
    result = verify_certificate(cert, university_id="TEST_UNIV_A")
    assert result["status"] == INVALID, "Tampered name should have been detected"


def tc03_tampered_degree():
    """Attacker upgrades degree field -> INVALID."""
    cert = sign_diploma(copy.deepcopy(SAMPLE_DIPLOMA), "TEST_UNIV_A")
    cert["diploma"]["degree"] = "PhD in Computer Science"
    result = verify_certificate(cert, university_id="TEST_UNIV_A")
    assert result["status"] == INVALID, "Tampered degree should have been detected"


def tc04_wrong_university_key():
    """
    Verify UNIV_A's signature using UNIV_B's public key -> INVALID.
    Proves signature is bound to the specific university identity.
    """
    cert = sign_diploma(copy.deepcopy(SAMPLE_DIPLOMA), "TEST_UNIV_A")
    # Provide UNIV_B's public key instead
    pubkey_pem = get_public_key_pem("TEST_UNIV_B")
    result = verify_certificate(cert, pubkey_pem=pubkey_pem)
    assert result["status"] == INVALID, "Wrong key should have failed verification"


def tc05_corrupted_signature():
    """Flip a byte in the signature hex -> INVALID."""
    cert = sign_diploma(copy.deepcopy(SAMPLE_DIPLOMA), "TEST_UNIV_A")
    # Corrupt the first byte of the signature
    sig_bytes = bytes.fromhex(cert["signature"])
    corrupted = bytes([sig_bytes[0] ^ 0xFF]) + sig_bytes[1:]
    cert["signature"] = corrupted.hex()
    result = verify_certificate(cert, university_id="TEST_UNIV_A")
    assert result["status"] == INVALID, "Corrupted signature should have failed"


def tc06_multiple_universities():
    """
    UNIV_A and UNIV_B each sign different diplomas.
    Each verifies correctly only with its own key.
    """
    diploma_a = {**SAMPLE_DIPLOMA, "diploma_id": "TEST-A-001", "university": "TEST_UNIV_A"}
    diploma_b = {**SAMPLE_DIPLOMA, "diploma_id": "TEST-B-001", "university": "TEST_UNIV_B",
                 "student_name": "Reem Abdullah"}

    cert_a = sign_diploma(diploma_a, "TEST_UNIV_A")
    cert_b = sign_diploma(diploma_b, "TEST_UNIV_B")

    r_a = verify_certificate(cert_a, university_id="TEST_UNIV_A")
    r_b = verify_certificate(cert_b, university_id="TEST_UNIV_B")

    assert r_a["status"] == VALID,   "UNIV_A diploma should be VALID"
    assert r_b["status"] == VALID,   "UNIV_B diploma should be VALID"

    # Cross-verify (should fail)
    r_cross = verify_certificate(cert_a, university_id="TEST_UNIV_B")
    assert r_cross["status"] == INVALID, "Cross-key verification should FAIL"


def tc07_avalanche_effect():
    """
    Demonstrate that a 1-character change produces a completely different hash.
    Visually confirm SHA-256 avalanche property.
    """
    original  = "Sabah Mohamed Alanazi"
    modified  = "Sabah Mohamed Alanazj"   # last letter i -> j

    h_orig = hash_hex(original.encode())
    h_mod  = hash_hex(modified.encode())

    print(f"\n    Original : '{original}'  ->  {h_orig[:16]}...")
    print(f"    Modified : '{modified}'  ->  {h_mod[:16]}...")

    # Count differing hex characters
    diffs = sum(a != b for a, b in zip(h_orig, h_mod))
    print(f"    Hex characters that differ: {diffs}/64  ({diffs/64*100:.1f}%)")

    assert h_orig != h_mod, "Hashes should differ"
    assert diffs > 20, f"Avalanche effect weak: only {diffs} chars differ"


def tc08_missing_signature():
    """Certificate with no signature field -> INVALID, no crash."""
    cert = sign_diploma(copy.deepcopy(SAMPLE_DIPLOMA), "TEST_UNIV_A")
    del cert["signature"]
    result = verify_certificate(cert, university_id="TEST_UNIV_A")
    assert result["status"] == INVALID
    assert any("signature" in e.lower() for e in result["errors"])


def tc09_extra_metadata_field():
    """
    Verifier adds metadata (e.g., issuer field) to the certificate envelope —
    only the diploma sub-object is hashed, so envelope-level changes don't matter.
    """
    cert = sign_diploma(copy.deepcopy(SAMPLE_DIPLOMA), "TEST_UNIV_A")
    # Adding fields to the outer envelope (not diploma) should NOT affect verification
    cert["verified_by"] = "employer_system_v1"
    cert["note"] = "Checked 2026-07-01"
    result = verify_certificate(cert, university_id="TEST_UNIV_A")
    assert result["status"] == VALID, "Envelope metadata changes should not break verification"


# ──────────────────────────────────────────────
# Runner
# ──────────────────────────────────────────────

def main():
    setup()

    tests = [
        ("TC-01: Happy path (sign -> verify)",         tc01_happy_path),
        ("TC-02: Tampered student name",               tc02_tampered_name),
        ("TC-03: Tampered degree field",               tc03_tampered_degree),
        ("TC-04: Wrong university public key",         tc04_wrong_university_key),
        ("TC-05: Corrupted signature bytes",           tc05_corrupted_signature),
        ("TC-06: Multiple university identities",      tc06_multiple_universities),
        ("TC-07: SHA-256 avalanche effect",            tc07_avalanche_effect),
        ("TC-08: Missing signature field",             tc08_missing_signature),
        ("TC-09: Envelope metadata changes",           tc09_extra_metadata_field),
    ]

    print("── Running test suite ───────────────────────────────")
    for name, fn in tests:
        run_test(name, fn)

    passed = sum(1 for _, r in results if r == "PASS")
    total  = len(results)

    print(f"\n── Summary: {passed}/{total} tests passed ──────────────────")
    for name, r in results:
        icon = "" if r == "PASS" else ""
        print(f"  {icon}  {name}: {r}")

    if passed < total:
        sys.exit(1)


if __name__ == "__main__":
    main()
