"""
server.py — Flask web server for the Diploma Signing System
-------------------------------------------------------------
Bridges the web interface (web_interface.html) to the real Python
cryptographic backend (signer.py, verifier.py, key_manager.py).

Routes:
    GET  /                   Serve the web interface
    GET  /api/universities   List all registered university keys
    POST /api/sign           Sign a diploma (real ECDSA)
    POST /api/verify         Verify a certificate (real ECDSA)
    GET  /api/certificates   List saved certificate files

Usage:
    pip install flask cryptography
    python server.py

Then open http://localhost:5000 in your browser.
"""

import json
import traceback
from pathlib import Path
from datetime import date

from flask import Flask, request, jsonify, send_from_directory

from key_manager import generate_key_pair, list_identities
from signer import sign_diploma, save_certificate
from verifier import verify_certificate, VALID, INVALID
from crypto_utils import hash_hex, diploma_to_canonical_bytes

app = Flask(__name__, static_folder=".")

BASE_DIR       = Path(__file__).parent
SIGNATURES_DIR = BASE_DIR / "signatures"
SIGNATURES_DIR.mkdir(exist_ok=True)

SAUDI_UNIVERSITIES = {
    "KSU":     "King Saud University",
    "UQU":     "Umm Al-Qura University",
    "KFUPM":   "King Fahd University of Petroleum and Minerals",
    "KAU":     "King Abdulaziz University",
    "PSU":     "Prince Sultan University",
    "PNU":     "Princess Nourah bint Abdulrahman University",
    "IMSIU":   "Imam Mohammad Ibn Saud Islamic University",
    "KSAU-HS": "King Saud bin Abdulaziz University for Health Sciences",
    "SEU":     "Saudi Electronic University",
    "KFU":     "King Faisal University",
    "TAIBAH":  "Taibah University",
    "JAZANU":  "Jazan University",
    "UJ":      "University of Jeddah",
    "UB":      "University of Bisha",
    "UOH":     "University of Hail",
    "NU":      "Najran University",
    "QU":      "Qassim University",
    "BU":      "Al Baha University",
    "JMU":     "Jouf University",
    "TU":      "Tabuk University",
    "SHU":     "Shaqra University",
    "DU":      "University of Dammam",
    "REU":     "Riyadh Elm University",
    "YU":      "Al Yamamah University",
    "DAU":     "Dar Al Uloom University",
    "AOU":     "Arab Open University",
    "AU":      "Alfaisal University",
    "PMU":     "Prince Mohammad Bin Fahd University",
    "BMC":     "Batterjee Medical College",
}


# ──────────────────────────────────────────────────────────────
# Static routes
# ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the web interface."""
    return send_from_directory(str(BASE_DIR), "web_interface.html")


# ──────────────────────────────────────────────────────────────
# API: universities
# ──────────────────────────────────────────────────────────────

@app.route("/api/universities", methods=["GET"])
def api_universities():
    """Return list of all universities and which ones have keys registered."""
    registered = list_identities()
    universities = [
        {
            "code":       code,
            "name":       name,
            "registered": code in registered,
        }
        for code, name in SAUDI_UNIVERSITIES.items()
    ]
    return jsonify({"universities": universities})


# ──────────────────────────────────────────────────────────────
# API: sign
# ──────────────────────────────────────────────────────────────

@app.route("/api/sign", methods=["POST"])
def api_sign():
    """
    Sign a diploma using real ECDSA.

    Expected JSON body:
    {
        "university_id":   "UQU",
        "student_name":    "Sabah Alanazi",
        "student_id":      "441193701",
        "degree":          "Bachelor of Science in Computer Science",
        "graduation_date": "2026-06-01",
        "issuer":          "Office of the Registrar",
        "diploma_id":      "UQU-2026-441193701",
        "honors":          "Magna Cum Laude"   (optional)
    }
    """
    try:
        data = request.get_json(force=True)

        university_id = data.get("university_id", "").strip().upper()
        if not university_id:
            return jsonify({"error": "university_id is required"}), 400

        if university_id not in SAUDI_UNIVERSITIES:
            return jsonify({"error": f"Unknown university code: {university_id}"}), 400

        # Validate student ID
        student_id = str(data.get("student_id", "")).strip()
        if not student_id.isdigit() or len(student_id) != 9:
            return jsonify({"error": "student_id must be exactly 9 digits"}), 400

        # Auto-generate keys for this university if not yet done
        registered = list_identities()
        if university_id not in registered:
            print(f"[Server] Generating keys for {university_id}...")
            generate_key_pair(university_id)

        # Build diploma dict
        diploma = {
            "student_name":    data.get("student_name", "").strip(),
            "student_id":      student_id,
            "degree":          data.get("degree", "").strip(),
            "graduation_date": data.get("graduation_date", date.today().isoformat()),
            "university":      SAUDI_UNIVERSITIES[university_id],
            "issuer":          data.get("issuer", "Office of the Registrar").strip(),
            "diploma_id":      data.get("diploma_id", f"{university_id}-{student_id}").strip(),
        }

        honors = data.get("honors", "").strip()
        if honors:
            diploma["honors"] = honors

        # Validate required fields
        for field in ("student_name", "degree", "graduation_date", "diploma_id"):
            if not diploma[field]:
                return jsonify({"error": f"Field '{field}' is required"}), 400

        # Real ECDSA signing
        certificate = sign_diploma(diploma, university_id)

        # Compute document hash for display
        doc_bytes = diploma_to_canonical_bytes(diploma)
        doc_hash  = hash_hex(doc_bytes)

        # Save certificate to disk
        slug      = diploma["student_name"].lower().replace(" ", "_")
        cert_file = f"{slug}_{student_id}_diploma.cert.json"
        save_certificate(certificate, cert_file)

        return jsonify({
            "success":     True,
            "certificate": certificate,
            "doc_hash":    doc_hash,
            "cert_file":   cert_file,
        })

    except FileNotFoundError as e:
        return jsonify({"error": str(e)}), 500
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"Signing failed: {str(e)}"}), 500


# ──────────────────────────────────────────────────────────────
# API: verify
# ──────────────────────────────────────────────────────────────

@app.route("/api/verify", methods=["POST"])
def api_verify():
    """
    Verify a certificate using real ECDSA.

    Expected JSON body:
    {
        "certificate": { ... full cert JSON ... }
    }
    OR:
    {
        "cert_file": "sabah_diploma.cert.json"
    }
    """
    try:
        data = request.get_json(force=True)

        # Get certificate — either inline or from file
        if "certificate" in data:
            certificate = data["certificate"]
        elif "cert_file" in data:
            cert_path = SIGNATURES_DIR / data["cert_file"]
            if not cert_path.exists():
                return jsonify({"error": f"Certificate file not found: {data['cert_file']}"}), 404
            certificate = json.loads(cert_path.read_text())
        else:
            return jsonify({"error": "Provide 'certificate' or 'cert_file' in request body"}), 400

        university_id = certificate.get("university_id", "")
        if not university_id:
            return jsonify({"error": "Certificate has no university_id field"}), 400

        # Auto-generate keys if missing (demo mode: should not happen in production)
        registered = list_identities()
        if university_id not in registered:
            print(f"[Server] WARNING: No keys for {university_id}. Generating demo keys.")
            generate_key_pair(university_id)

        # Real ECDSA verification
        result = verify_certificate(certificate, university_id=university_id)

        return jsonify({
            "success":     True,
            "status":      result["status"],
            "valid":       result["status"] == VALID,
            "diploma_id":  result.get("diploma_id"),
            "student_name": result.get("student_name"),
            "degree":      result.get("degree"),
            "university_id": result.get("university_id"),
            "issued_at":   result.get("issued_at"),
            "doc_hash":    result.get("computed_hash"),
            "errors":      result.get("errors", []),
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"Verification failed: {str(e)}"}), 500


# ──────────────────────────────────────────────────────────────
# API: list certificates
# ──────────────────────────────────────────────────────────────

@app.route("/api/certificates", methods=["GET"])
def api_certificates():
    """List all saved certificate files."""
    certs = []
    for f in sorted(SIGNATURES_DIR.glob("*.cert.json")):
        try:
            cert = json.loads(f.read_text())
            certs.append({
                "filename":     f.name,
                "student_name": cert.get("diploma", {}).get("student_name", ""),
                "university_id": cert.get("university_id", ""),
                "issued_at":    cert.get("issued_at", ""),
                "diploma_id":   cert.get("diploma", {}).get("diploma_id", ""),
            })
        except Exception:
            pass
    return jsonify({"certificates": certs})


# ──────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  Diploma Signing System — Web Server")
    print("=" * 60)
    print("  Open in your browser: http://localhost:5000")
    print("  Press Ctrl+C to stop\n")
    app.run(debug=False, host="0.0.0.0", port=5000)
