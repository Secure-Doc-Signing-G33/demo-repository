"""
main.py — Secure Diploma Signing and Verification System v4
-------------------------------------------------------------
Changes in v4:
  - Diploma ID is AUTO-GENERATED (university code embedded) — user never types it
  - Verification has TWO modes:
      Mode A: Enter Diploma ID → university auto-detected → full verification
      Mode B: Enter Hash Token → university auto-detected from prefix → verify
  - Verification no longer asks user to pick a university manually
  - University list shown only during signing (to pick issuing university)
  - Short hash token displayed on every certificate for quick employer checks

Menu:
  1. Sign a diploma
  2. Verify a certificate
  3. List registered universities
  4. Exit
"""

import json
import os
import re
from datetime import date, datetime
from pathlib import Path

from key_manager import generate_key_pair, list_identities
from signer import sign_diploma, save_certificate
from verifier import verify_certificate, print_result, VALID
from crypto_utils import (
    hash_hex,
    diploma_to_canonical_bytes,
    generate_diploma_id,
    decode_university_from_diploma_id,
    short_hash_for_university,
    UNIVERSITY_PREFIX_MAP,
)


# ──────────────────────────────────────────────────────────────
# University registry
# ──────────────────────────────────────────────────────────────

SAUDI_UNIVERSITIES = {
    "KSU":      "King Saud University",
    "UQU":      "Umm Al-Qura University",
    "KFUPM":    "King Fahd University of Petroleum and Minerals",
    "KAU":      "King Abdulaziz University",
    "PSU":      "Prince Sultan University",
    "PNU":      "Princess Nourah bint Abdulrahman University",
    "IMSIU":    "Imam Mohammad Ibn Saud Islamic University",
    "KSAU-HS":  "King Saud bin Abdulaziz University for Health Sciences",
    "SEU":      "Saudi Electronic University",
    "KFU":      "King Faisal University",
    "TAIBAH":   "Taibah University",
    "JAZANU":   "Jazan University",
    "UJ":       "University of Jeddah",
    "UB":       "University of Bisha",
    "UOH":      "University of Hail",
    "NU":       "Najran University",
    "QU":       "Qassim University",
    "BU":       "Al Baha University",
    "JMU":      "Jouf University",
    "TU":       "Tabuk University",
    "SHU":      "Shaqra University",
    "DU":       "University of Dammam",
    "REU":      "Riyadh Elm University",
    "YU":       "Al Yamamah University",
    "DAU":      "Dar Al Uloom University",
    "AOU":      "Arab Open University",
    "AU":       "Alfaisal University",
    "PMU":      "Prince Mohammad Bin Fahd University",
    "BMC":      "Batterjee Medical College",
}

STUDENT_ID_LENGTH = 9


# ──────────────────────────────────────────────────────────────
# Display helpers
# ──────────────────────────────────────────────────────────────

def clear_screen():
    os.system("clear" if os.name != "nt" else "cls")


def print_header():
    print("\n" + "=" * 70)
    print("         SECURE DIPLOMA SIGNING AND VERIFICATION SYSTEM  v4")
    print("=" * 70)
    print("  ECDSA (SECP256K1) + SHA-256  |  29 Saudi Universities")
    print("  Auto-detect university from Diploma ID — no manual entry needed")
    print("=" * 70 + "\n")


def section(title: str):
    print("\n" + "-" * 70)
    print(f"  {title}")
    print("-" * 70)


# ──────────────────────────────────────────────────────────────
# Input helpers
# ──────────────────────────────────────────────────────────────

def get_input(prompt, default=None, required=True):
    display = f"  {prompt}"
    if default:
        display += f" [{default}]"
    display += ": "
    while True:
        val = input(display).strip()
        if val:
            return val
        if default is not None:
            return default
        if not required:
            return ""
        print("  ERROR: This field is required.")


def get_date_input(prompt, default=None):
    default = default or date.today().isoformat()
    while True:
        val = get_input(prompt, default)
        try:
            datetime.fromisoformat(val)
            return val
        except ValueError:
            print("  ERROR: Invalid date format. Use YYYY-MM-DD (e.g. 2026-06-01).")


def get_student_id():
    while True:
        val = get_input(f"Student ID ({STUDENT_ID_LENGTH} digits)")
        if re.fullmatch(r"\d{" + str(STUDENT_ID_LENGTH) + r"}", val):
            return val
        print(f"  ERROR: Student ID must be exactly {STUDENT_ID_LENGTH} digits, numbers only.")
        print(f"         Example: 441193701")


# ──────────────────────────────────────────────────────────────
# University selection (signing only)
# ──────────────────────────────────────────────────────────────

def print_university_table():
    codes = list(SAUDI_UNIVERSITIES.keys())
    print()
    print(f"  {'No.':<5} {'Code':<10} {'University'}")
    print(f"  {'-'*4} {'-'*9} {'-'*42}")
    for i, code in enumerate(codes, 1):
        prefix = UNIVERSITY_PREFIX_MAP.get(code, "??")
        print(f"  {i:<5} {code:<10} {SAUDI_UNIVERSITIES[code]}  [prefix: {prefix}]")
    print()


def get_university_choice():
    """Used during SIGNING only — user picks the issuing university."""
    section("UNIVERSITY SELECTION")
    print_university_table()

    codes = list(SAUDI_UNIVERSITIES.keys())

    while True:
        val = get_input("Enter university number (1-29) or code (e.g. UQU)").upper()

        if val.isdigit():
            idx = int(val) - 1
            if 0 <= idx < len(codes):
                code = codes[idx]
                break
            print(f"  ERROR: Number must be between 1 and {len(codes)}.")
            continue

        if val in SAUDI_UNIVERSITIES:
            code = val
            break

        print(f"  ERROR: '{val}' not found. Enter a number (1-{len(codes)}) or a valid code.")

    full_name = SAUDI_UNIVERSITIES[code]
    print(f"\n  Selected: {code} — {full_name}")

    existing = list_identities()
    if code not in existing:
        print(f"\n  First use of {code} — generating ECDSA key pair...")
        generate_key_pair(code)
        print(f"  Keys saved to keys/ directory.")
    else:
        print(f"  Using existing keys for {code}.")

    return code, full_name


# ──────────────────────────────────────────────────────────────
# Diploma data collection
# ──────────────────────────────────────────────────────────────

def collect_diploma_data(university_id: str, university_full: str) -> dict:
    section("STUDENT INFORMATION")

    student_name = get_input("Student full name")
    student_id   = get_student_id()

    section("DEGREE INFORMATION")

    degree          = get_input("Degree name", "Bachelor of Science in Computer Science")
    graduation_date = get_date_input("Graduation date (YYYY-MM-DD)")
    issuer          = get_input("Issuing office", "Office of the Registrar")

    # ✅ Diploma ID is FULLY AUTO-GENERATED — user never types it
    # Format: <UNI_CODE>-<YEAR>-<STUDENT_ID>
    # Example: UQU-2026-441193701
    diploma_id = generate_diploma_id(university_id, student_id, graduation_date[:4])
    print(f"\n  Diploma ID (auto-generated): {diploma_id}")
    print(f"  University prefix embedded:  {UNIVERSITY_PREFIX_MAP.get(university_id, '??')}")

    honors = get_input("Honors (optional, press Enter to skip)", required=False)

    diploma = {
        "student_name":    student_name,
        "student_id":      student_id,
        "degree":          degree,
        "graduation_date": graduation_date,
        "university":      university_full,
        "issuer":          issuer,
        "diploma_id":      diploma_id,
    }
    if honors:
        diploma["honors"] = honors

    return diploma


# ──────────────────────────────────────────────────────────────
# Display
# ──────────────────────────────────────────────────────────────

def display_diploma(diploma: dict):
    section("DIPLOMA PREVIEW")
    rows = [
        ("Student Name",    diploma["student_name"]),
        ("Student ID",      diploma["student_id"]),
        ("Degree",          diploma["degree"]),
        ("Graduation Date", diploma["graduation_date"]),
        ("University",      diploma["university"]),
        ("Issuer",          diploma["issuer"]),
        ("Diploma ID",      diploma["diploma_id"]),
    ]
    if "honors" in diploma:
        rows.append(("Honors", diploma["honors"]))
    for label, value in rows:
        print(f"  {label:<18}: {value}")


def display_cert_details(certificate: dict, short_token: str = None):
    section("CERTIFICATE METADATA")
    print(f"  Algorithm        : {certificate['algorithm']}")
    print(f"  Hash Algorithm   : {certificate['hash_algorithm']}")
    print(f"  Curve            : {certificate['curve']}")
    print(f"  University ID    : {certificate['university_id']}")
    print(f"  Issued At        : {certificate['issued_at']}")
    print(f"  Diploma ID       : {certificate['diploma'].get('diploma_id', 'N/A')}")
    print(f"  Signature        : {certificate['signature'][:60]}...")
    if short_token:
        print(f"\n  ★ Quick Verify Token: {short_token}")
        print(f"    (Share this with employers — encodes university + hash fragment)")


# ──────────────────────────────────────────────────────────────
# SIGN flow
# ──────────────────────────────────────────────────────────────

def flow_sign():
    print_header()

    university_id, university_full = get_university_choice()
    diploma = collect_diploma_data(university_id, university_full)

    display_diploma(diploma)

    confirm = get_input("\n  Proceed with signing? (yes/no)", "yes").lower()
    if confirm not in ("yes", "y"):
        print("\n  Signing cancelled.")
        return

    section("CRYPTOGRAPHIC SIGNING")
    doc_bytes  = diploma_to_canonical_bytes(diploma)
    doc_hash   = hash_hex(doc_bytes)
    short_tok  = short_hash_for_university(doc_hash, university_id)

    print(f"\n  SHA-256 Document Hash:")
    print(f"  {doc_hash}\n")
    print(f"  Quick Verify Token (16-char fragment + university prefix):")
    print(f"  {short_tok}\n")
    print(f"  Signing with {university_id} private key (ECDSA / SECP256K1)...")

    certificate = sign_diploma(diploma, university_id)

    # Save with structured filename: <UNI>_<STUDENTID>_diploma.cert.json
    slug      = f"{university_id.lower()}_{diploma['student_id']}_diploma"
    cert_path = save_certificate(certificate, f"{slug}.cert.json")

    print(f"\n  Certificate saved: {cert_path}")

    display_cert_details(certificate, short_tok)

    section("AUTO-VERIFICATION")
    print(f"\n  Verifying with {university_id} public key...")
    result = verify_certificate(certificate, university_id=university_id)
    print_result(result)

    if result["status"] == VALID:
        print("  Result: Certificate is AUTHENTIC and UNMODIFIED.\n")
    else:
        print("  Result: Verification FAILED.\n")

    input("  Press Enter to return to main menu...")


# ──────────────────────────────────────────────────────────────
# VERIFY flow — smart auto-detection
# ──────────────────────────────────────────────────────────────

def flow_verify():
    print_header()
    section("CERTIFICATE VERIFICATION")

    print("""
  You can verify a diploma in TWO ways:

    [A] Enter the Diploma ID  (e.g. UQU-2026-441193701)
        → University is detected automatically from the ID

    [B] Load a .cert.json file from disk
        → University is detected from the embedded ID or certificate field
""")

    mode = get_input("Choose mode (A / B)", "A").upper()

    if mode == "A":
        _verify_by_diploma_id()
    else:
        _verify_by_file()

    input("\n  Press Enter to return to main menu...")


def _resolve_university_from_cert(certificate: dict) -> str | None:
    """
    Try to auto-detect university from certificate without user input.
    Priority:
      1. decode from diploma_id embedded in the diploma dict
      2. use university_id field in certificate envelope
    Returns university code or None.
    """
    diploma    = certificate.get("diploma", {})
    diploma_id = diploma.get("diploma_id", "")

    # Priority 1: decode from diploma_id structure
    detected = decode_university_from_diploma_id(diploma_id)
    if detected:
        return detected

    # Priority 2: read from certificate envelope field
    uid = certificate.get("university_id", "")
    if uid in SAUDI_UNIVERSITIES:
        return uid

    return None


def _verify_by_diploma_id():
    """
    Verify mode A: user types diploma_id → auto detect university → verify.
    Does NOT require the cert.json file — only the diploma_id is needed
    to locate the stored certificate, then verification proceeds automatically.
    """
    section("VERIFY BY DIPLOMA ID")

    diploma_id = get_input("Enter Diploma ID (e.g. UQU-2026-441193701)")

    # Auto-detect university
    university_id = decode_university_from_diploma_id(diploma_id)

    if university_id:
        uni_name = SAUDI_UNIVERSITIES.get(university_id, university_id)
        print(f"\n  ✓ University auto-detected: {university_id} — {uni_name}")
    else:
        print(f"\n  WARNING: Could not detect university from Diploma ID '{diploma_id}'.")
        print(f"  Available formats: UQU-2026-441193701  or  02-2026-441193701")
        return

    # Locate the certificate file for this diploma_id
    sig_dir = Path(__file__).parent / "signatures"
    matching = []
    if sig_dir.exists():
        for cf in sig_dir.glob("*.cert.json"):
            try:
                cert = json.loads(cf.read_text())
                if cert.get("diploma", {}).get("diploma_id") == diploma_id:
                    matching.append((cf, cert))
            except Exception:
                continue

    if not matching:
        print(f"\n  ERROR: No certificate found for Diploma ID: {diploma_id}")
        print(f"  Make sure the .cert.json file is in the signatures/ directory.")
        return

    if len(matching) == 1:
        cert_path, certificate = matching[0]
        print(f"\n  Certificate found: {cert_path.name}")
    else:
        print(f"\n  Multiple certificates found for this Diploma ID:")
        for i, (p, _) in enumerate(matching, 1):
            print(f"    {i}. {p.name}")
        idx = get_input(f"Select (1-{len(matching)})", "1")
        cert_path, certificate = matching[int(idx) - 1]

    _run_verification(certificate, university_id)


def _verify_by_file():
    """
    Verify mode B: load .cert.json → auto-detect university from diploma_id → verify.
    """
    section("VERIFY BY FILE")

    sig_dir = Path(__file__).parent / "signatures"
    certs   = sorted(sig_dir.glob("*.cert.json")) if sig_dir.exists() else []

    if certs:
        print("\n  Available certificates:")
        for i, c in enumerate(certs, 1):
            try:
                cert_tmp = json.loads(c.read_text())
                did = cert_tmp.get("diploma", {}).get("diploma_id", "?")
                print(f"    {i}. {c.name}  [{did}]")
            except Exception:
                print(f"    {i}. {c.name}")
        print()
        val = get_input("Enter certificate number or full file path")
        if val.isdigit() and 1 <= int(val) <= len(certs):
            cert_path = certs[int(val) - 1]
        else:
            cert_path = Path(val)
    else:
        val = get_input("Enter full path to .cert.json file")
        cert_path = Path(val)

    if not cert_path.exists():
        print(f"\n  ERROR: File not found: {cert_path}")
        return

    try:
        certificate = json.loads(cert_path.read_text())
    except Exception as e:
        print(f"\n  ERROR: Could not read certificate: {e}")
        return

    # Auto-detect university
    university_id = _resolve_university_from_cert(certificate)

    if university_id:
        uni_name = SAUDI_UNIVERSITIES.get(university_id, university_id)
        print(f"\n  ✓ University auto-detected: {university_id} — {uni_name}")
    else:
        print("\n  WARNING: Could not auto-detect university.")
        print("  Please select manually:")
        print_university_table()
        codes = list(SAUDI_UNIVERSITIES.keys())
        val = get_input("Enter university number or code").upper()
        if val.isdigit():
            idx = int(val) - 1
            university_id = codes[idx] if 0 <= idx < len(codes) else None
        elif val in SAUDI_UNIVERSITIES:
            university_id = val
        if not university_id:
            print("  ERROR: Invalid university selection.")
            return

    _run_verification(certificate, university_id)


def _run_verification(certificate: dict, university_id: str):
    """Core verification step — shared by both verify modes."""
    diploma = certificate.get("diploma", {})
    print(f"\n  Diploma contents:")
    print(f"    Student   : {diploma.get('student_name', 'N/A')}")
    print(f"    Student ID: {diploma.get('student_id', 'N/A')}")
    print(f"    Degree    : {diploma.get('degree', 'N/A')}")
    print(f"    Diploma ID: {diploma.get('diploma_id', 'N/A')}")
    print(f"    Issued at : {certificate.get('issued_at', 'N/A')}")

    # Ensure public key exists
    existing = list_identities()
    if university_id not in existing:
        print(f"\n  WARNING: No keys found for '{university_id}'.")
        print(f"  Cannot verify without the university's public key.")
        return

    print(f"\n  Verifying with {university_id} public key...")
    result = verify_certificate(certificate, university_id=university_id)
    print_result(result)

    if result["status"] == VALID:
        # Show quick token for reference
        computed = result.get("computed_hash", "")
        if computed:
            token = short_hash_for_university(computed, university_id)
            print(f"  Quick Verify Token: {token}")
        print("  Result: Diploma is AUTHENTIC and has NOT been tampered with.\n")
    else:
        print("  Result: VERIFICATION FAILED — diploma may be forged or tampered.\n")


# ──────────────────────────────────────────────────────────────
# List identities
# ──────────────────────────────────────────────────────────────

def flow_list_identities():
    section("REGISTERED UNIVERSITY IDENTITIES")
    ids = list_identities()
    if ids:
        print(f"\n  {len(ids)} registered:\n")
        print(f"  {'Code':<12} {'Prefix':<8} {'University'}")
        print(f"  {'-'*10} {'-'*6} {'-'*40}")
        for uid in ids:
            name   = SAUDI_UNIVERSITIES.get(uid, "Unknown")
            prefix = UNIVERSITY_PREFIX_MAP.get(uid, "??")
            print(f"  {uid:<12} {prefix:<8} {name}")
    else:
        print("\n  No universities registered yet.")
        print("  Sign a diploma to register a university.")
    print()
    input("  Press Enter to continue...")


# ──────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────


# ──────────────────────────────────────────────────────────────
# View Public Registry
# ──────────────────────────────────────────────────────────────

def flow_view_registry():
    section("PUBLIC HASH REGISTRY")
    data = registry_load()
    if not data:
        print("\n  Registry is empty. Sign a diploma first.")
        input("  Press Enter to continue...")
        return
    print(f"\n  {len(data)} diploma(s) registered:")
    print(f"\n  {'Diploma ID':<30} {'Uni':<10} {'SHA-256 (first 32 chars)'}")
    print(f"  {'-'*28} {'-'*8} {'-'*32}")
    for did, rec in data.items():
        h   = rec.get("hash", "")[:32]
        uni = rec.get("university_id", "?")
        ts  = rec.get("registered_at", "?")[:19].replace("T", " ")
        print(f"  {did:<30} {uni:<10} {h}  [{ts}]")
    print()
    input("  Press Enter to continue...")

def main():
    try:
        clear_screen()
        print_header()
        print("  This system issues and verifies digital diplomas using")
        print("  ECDSA cryptography (SECP256K1 curve, SHA-256 hashing).\n")
        print(f"  - 29 Saudi universities supported")
        print(f"  - Diploma ID auto-generated (university code embedded)")
        print(f"  - Verification auto-detects university — no manual selection")
        print(f"  - Quick Verify Token for fast employer checks\n")
        input("  Press Enter to continue...")

        while True:
            clear_screen()
            print_header()
            print("  MAIN MENU\n")
            print("    1.  Sign a diploma")
            print("    2.  Verify a certificate")
            print("    3.  List registered universities")
            print("    4.  Exit\n")

            choice = get_input("Select option (1-5)", "1")

            if   choice == "1": flow_sign()
            elif choice == "2": flow_verify()
            elif choice == "3": flow_list_identities()
            elif choice == "4": flow_view_registry()
            elif choice == "5":
                print("\n  Exiting.\n")
                break
            else:
                print("  ERROR: Invalid choice. Enter 1-5.")
                input("  Press Enter to try again...")

    except KeyboardInterrupt:
        print("\n\n  Interrupted.\n")
    except Exception as e:
        print(f"\n  ERROR: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
