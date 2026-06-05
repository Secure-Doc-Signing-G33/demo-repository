# Interactive Diploma Signing System

## Overview

This enhanced version allows you to generate signatures and certificates **dynamically** based on user input - no hardcoded users or signatures! Enter information through either a command-line interface or a web interface, and the system will generate cryptographic signatures in real-time.

## 🆕 New Interactive Features

### 1. Command-Line Interactive Interface
**File:** `interactive_signer.py`

A full-featured terminal application that guides you through the diploma signing process step-by-step.

**Features:**
- ✅ Interactive prompts for all diploma information
- ✅ No hardcoded data - everything from user input
- ✅ Create new university identities on-the-fly
- ✅ Real-time signature generation
- ✅ Automatic verification after signing
- ✅ Professional formatted output

**Usage:**
```bash
python interactive_signer.py
```

**What it does:**
1. Prompts you to select or create a university identity
2. Collects student information (name, ID, etc.)
3. Collects degree information (degree name, graduation date, etc.)
4. Generates a diploma preview for confirmation
5. Creates cryptographic signature using ECDSA
6. Saves the certificate to a JSON file
7. Automatically verifies the signature

**Example Session:**
```
══════════════════════════════════════════════════════════════════════
           🎓 INTERACTIVE DIPLOMA SIGNING SYSTEM 🎓
══════════════════════════════════════════════════════════════════════

📚 UNIVERSITY SELECTION
──────────────────────────────────────────────────────────────────────
🆕 Creating new university identity...
  Enter university ID (e.g., UQU, KAU, MIT): MIT
  
🔐 Generating cryptographic keys for MIT...
✅ University 'MIT' created successfully!

📋 STUDENT INFORMATION
──────────────────────────────────────────────────────────────────────
  Student full name: Sarah Johnson
  Student ID number: 12345678

🎓 DEGREE INFORMATION
──────────────────────────────────────────────────────────────────────
  Degree name [Bachelor of Science in Computer Science]: 
  Graduation date (YYYY-MM-DD) [2026-05-23]: 
  University full name [Massachusetts Institute of Technology]: 
  Issuing office [Office of the Registrar]: 
  Diploma ID [MIT-2026-12345678]: 
  Honors (optional, press Enter to skip): Summa Cum Laude

📜 DIPLOMA PREVIEW
──────────────────────────────────────────────────────────────────────
  Student Name     : Sarah Johnson
  Student ID       : 12345678
  Degree           : Bachelor of Science in Computer Science
  Graduation Date  : 2026-05-23
  University       : Massachusetts Institute of Technology
  Issuer           : Office of the Registrar
  Diploma ID       : MIT-2026-12345678
  Honors           : Summa Cum Laude

✓ Proceed with signing? (yes/no) [yes]: yes

🔐 CRYPTOGRAPHIC SIGNING
──────────────────────────────────────────────────────────────────────
📊 Document SHA-256 Hash:
  a3f2b8c9d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1

🔏 Signing with MIT's private key...
✅ SIGNATURE GENERATED SUCCESSFULLY!
📄 Certificate saved to: signatures/sarah_johnson_diploma.cert.json

✓ VERIFICATION
──────────────────────────────────────────────────────────────────────
🔍 Verifying certificate with MIT's public key...
✅ CERTIFICATE IS AUTHENTIC AND VALID!
```

### 2. Web Interface
**File:** `web_interface.html`

A modern, user-friendly web interface for generating diploma signatures.

**Features:**
- ✅ Beautiful, responsive design
- ✅ Form validation
- ✅ Auto-fill suggestions for common universities
- ✅ Real-time preview
- ✅ Mobile-friendly
- ✅ No server required (pure client-side demo)

**Usage:**
```bash
# Simply open in a web browser
open web_interface.html
# or
firefox web_interface.html
```

**Note:** The web interface provides a demo simulation. For production use with actual cryptographic signatures, integrate it with the Python backend.

## Original Demo (Hardcoded Data)

The original `demo.py` file contains hardcoded examples for testing the cryptographic protocol:

```bash
python demo.py
```

This runs automated tests with pre-defined diplomas for Sabah and Reem.

## Command-Line Signer (One-time Use)

The `signer.py` can also be used directly from command line for quick one-off signatures:

```bash
python signer.py --university MIT --student "Sarah Johnson" \
                 --student-id "12345678" \
                 --degree "B.Sc. Computer Science" \
                 --honors "Summa Cum Laude"
```

## Architecture

### Files Structure
```
secure_doc_signing/
├── interactive_signer.py       # NEW: Interactive CLI interface
├── web_interface.html          # NEW: Web-based interface
├── demo.py                     # Original: Hardcoded demo
├── signer.py                   # Core signing logic + CLI
├── verifier.py                 # Signature verification
├── key_manager.py              # Cryptographic key management
├── crypto_utils.py             # Cryptographic utilities
├── attack_demo.py              # Security attack demonstrations
├── keys/                       # Directory for public/private keys
├── signatures/                 # Directory for signed certificates
└── tests/                      # Unit tests
```

### How It Works

1. **Key Generation** (One-time per university)
   - Generates ECDSA private key (SECP256K1 curve)
   - Derives corresponding public key
   - Stores keys securely in `keys/` directory

2. **Diploma Creation** (From user input)
   - User enters student and degree information
   - System builds diploma dictionary
   - No hardcoded data - everything dynamic

3. **Signing Process**
   - Serializes diploma to canonical JSON format
   - Computes SHA-256 hash of the content
   - Signs hash with university's private key using ECDSA
   - Produces DER-encoded signature

4. **Certificate Generation**
   - Bundles diploma + signature + metadata
   - Saves as JSON file
   - Each certificate is unique to the input data

5. **Verification**
   - Anyone with the public key can verify
   - Re-computes hash from diploma content
   - Verifies signature matches using public key
   - Detects any tampering

## Security Features

- ✅ **ECDSA** (Elliptic Curve Digital Signature Algorithm)
- ✅ **SHA-256** for cryptographic hashing
- ✅ **SECP256K1** elliptic curve (same as Bitcoin)
- ✅ **Deterministic signatures** (RFC 6979)
- ✅ **Tamper detection** - Any change invalidates signature
- ✅ **Avalanche effect** - Small change → completely different hash

## Example Output

### Generated Certificate Structure
```json
{
  "diploma": {
    "student_name": "Sarah Johnson",
    "student_id": "12345678",
    "degree": "Bachelor of Science in Computer Science",
    "graduation_date": "2026-05-23",
    "university": "Massachusetts Institute of Technology",
    "issuer": "Office of the Registrar",
    "diploma_id": "MIT-2026-12345678",
    "honors": "Summa Cum Laude"
  },
  "signature": "3045022100ab3f2e8c9d4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b022056c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6",
  "algorithm": "ECDSA",
  "hash_algorithm": "SHA-256",
  "curve": "SECP256K1",
  "university_id": "MIT",
  "issued_at": "2026-05-23T10:30:00.123456+00:00"
}
```

## Requirements

```bash
pip install cryptography
```

## Quick Start

### Interactive CLI
```bash
# Start the interactive system
python interactive_signer.py

# Follow the prompts to:
# 1. Select/create a university
# 2. Enter student information
# 3. Generate signature
# 4. View and verify certificate
```

### Web Interface
```bash
# Open in browser
open web_interface.html

# Fill in the form
# Click "Generate Signature"
# View the generated certificate
```

## Differences from Original Demo

| Feature | Original Demo | Interactive Version |
|---------|--------------|-------------------|
| Data Source | Hardcoded in `demo.py` | User input |
| User Interface | Command output only | CLI + Web interface |
| Flexibility | Fixed examples | Unlimited custom diplomas |
| User Experience | Developer-focused | End-user friendly |
| Certificate Generation | Batch (2 certificates) | On-demand per user |

## Use Cases

1. **Educational Institutions** - Issue digital diplomas to students
2. **Verification Services** - Employers verify diploma authenticity
3. **Learning Cryptography** - Understand digital signatures
4. **Blockchain Applications** - Similar to cryptocurrency signing
5. **Document Authentication** - General document verification

## Next Steps

1. **Database Integration** - Store certificates in database
2. **API Development** - REST API for remote signing
3. **Mobile App** - iOS/Android interface
4. **QR Code Generation** - Embed signature in QR code
5. **Blockchain Integration** - Store hashes on blockchain
6. **Revocation System** - Certificate revocation list

## Security Notes

- 🔒 Private keys should be stored securely (HSM in production)
- 🔒 Use HTTPS for web interface in production
- 🔒 Add authentication for signing operations
- 🔒 Implement rate limiting to prevent abuse
- 🔒 Regular key rotation policies

## Contributing

Feel free to extend this system with:
- Additional interfaces (mobile, desktop)
- More cryptographic algorithms
- Integration with existing systems
- Enhanced security features

## License

This is an educational implementation demonstrating cryptographic signing.

---

**Created by:** Dynamic Input System
**Last Updated:** May 2026
**Purpose:** Educational demonstration of digital signatures with user-generated content
