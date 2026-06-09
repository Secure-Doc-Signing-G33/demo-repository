

# Launching
#Put file inside the "signing_v4" folder next to crypto_utils.py
#run python3 -m pip install cryptography
#run python diploma_gui.py


import io
import json
import contextlib
from datetime import date
from pathlib import Path

import tkinter as tk
from tkinter import ttk, filedialog, messagebox


from crypto_utils import (
    diploma_to_canonical_bytes,
    hash_hex,
    generate_diploma_id,
    short_hash_for_university,
    decode_university_from_diploma_id,
    registry_add,
    registry_lookup,
)
from signer import sign_diploma, save_certificate, SIGNATURES_DIR
from verifier import verify_certificate, VALID
from key_manager import generate_key_pair, list_identities


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

BG       = "#0f1c2e"   # deep navy
PANEL    = "#16263d"
ACCENT   = "#2e8b8b"   # teal
ACCENT2  = "#1f6f6f"
OK       = "#1faa59"
BAD      = "#d64545"
TEXT     = "#e8eef5"
MUTED    = "#9fb0c3"
MONO     = ("Courier New", 10)
H1       = ("Segoe UI", 18, "bold")
H2       = ("Segoe UI", 11, "bold")
BODY     = ("Segoe UI", 10)


def capture_stdout(fn, *args, **kwargs):
    """Run fn, returning (result, captured_console_text). The crypto modules
    print [Signer]/[Verifier] lines; we surface those in the GUI log."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        result = fn(*args, **kwargs)
    return result, buf.getvalue()


class DiplomaApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Diploma Signing & Verification — ECDSA / SECP256K1 + SHA-256")
        self.geometry("860x720")
        self.configure(bg=BG)
        self.minsize(760, 640)

        self._init_style()
        self._build_header()

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        self.sign_tab   = ttk.Frame(nb, style="Card.TFrame")
        self.verify_tab = ttk.Frame(nb, style="Card.TFrame")
        self.manage_tab = ttk.Frame(nb, style="Card.TFrame")
        nb.add(self.sign_tab,   text="  ✍  Sign  ")
        nb.add(self.verify_tab, text="  ✔  Verify  ")
        nb.add(self.manage_tab, text="  🔑  Keys & Certificates  ")

        self._build_sign_tab()
        self._build_verify_tab()
        self._build_manage_tab()
        self.refresh_manage()

    # styling 
    def _init_style(self):
        s = ttk.Style(self)
        try:
            s.theme_use("clam")
        except tk.TclError:
            pass
        s.configure("TFrame", background=BG)
        s.configure("Card.TFrame", background=PANEL)
        s.configure("TLabel", background=PANEL, foreground=TEXT, font=BODY)
        s.configure("Muted.TLabel", background=PANEL, foreground=MUTED, font=("Segoe UI", 9))
        s.configure("H2.TLabel", background=PANEL, foreground=ACCENT, font=H2)
        s.configure("TNotebook", background=BG, borderwidth=0)
        s.configure("TNotebook.Tab", background=PANEL, foreground=MUTED,
                    padding=(14, 8), font=H2)
        s.map("TNotebook.Tab", background=[("selected", ACCENT2)],
              foreground=[("selected", TEXT)])
        s.configure("TEntry", fieldbackground="#0c1726", foreground=TEXT,
                    insertcolor=TEXT, bordercolor=ACCENT2)
        s.configure("TCombobox", fieldbackground="#0c1726", foreground=TEXT,
                    background=PANEL)
        s.configure("Accent.TButton", background=ACCENT, foreground="white",
                    font=H2, borderwidth=0, padding=10)
        s.map("Accent.TButton", background=[("active", ACCENT2)])
        s.configure("Ghost.TButton", background=PANEL, foreground=ACCENT,
                    font=BODY, borderwidth=1, padding=6)
        s.map("Ghost.TButton", background=[("active", "#1c3350")])

    def _build_header(self):
        head = tk.Frame(self, bg=BG)
        head.pack(fill="x", padx=16, pady=(14, 10))
        tk.Label(head, text="Secure Diploma Signing", font=H1,
                 bg=BG, fg=TEXT).pack(anchor="w")
        tk.Label(head,
                 text="ECDSA · SECP256K1 · SHA-256 · canonical JSON — identical crypto to the CLI & server",
                 font=("Segoe UI", 9), bg=BG, fg=MUTED).pack(anchor="w")

    # helpers
    def _field(self, parent, label, row, default="", width=46):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w",
                                            padx=(0, 12), pady=6)
        var = tk.StringVar(value=default)
        ent = ttk.Entry(parent, textvariable=var, width=width, font=BODY)
        ent.grid(row=row, column=1, sticky="we", pady=6)
        return var

    def _mono_box(self, parent, height=8):
        txt = tk.Text(parent, height=height, font=MONO, bg="#0c1726", fg=TEXT,
                      insertbackground=TEXT, relief="flat", wrap="word",
                      padx=10, pady=8, highlightthickness=1,
                      highlightbackground=ACCENT2)
        return txt

    def log(self, box, text, clear=True):
        box.configure(state="normal")
        if clear:
            box.delete("1.0", "end")
        box.insert("end", text)
        box.configure(state="disabled")

    # SIGN TAB 
    def _build_sign_tab(self):
        f = self.sign_tab
        for i in range(2):
            f.grid_columnconfigure(i, weight=1 if i == 1 else 0)

        ttk.Label(f, text="Issue a new signed diploma", style="H2.TLabel"
                  ).grid(row=0, column=0, columnspan=2, sticky="w",
                         padx=20, pady=(18, 4))

        body = ttk.Frame(f, style="Card.TFrame")
        body.grid(row=1, column=0, columnspan=2, sticky="we", padx=20)
        body.grid_columnconfigure(1, weight=1)

        ttk.Label(body, text="University").grid(row=0, column=0, sticky="w",
                                                padx=(0, 12), pady=6)
        self.uni_var = tk.StringVar()
        uni_values = [f"{c} — {n}" for c, n in SAUDI_UNIVERSITIES.items()]
        self.uni_combo = ttk.Combobox(body, textvariable=self.uni_var,
                                      values=uni_values, state="readonly",
                                      font=BODY)
        self.uni_combo.current(1)  # UQU default
        self.uni_combo.grid(row=0, column=1, sticky="we", pady=6)
        self.uni_combo.bind("<<ComboboxSelected>>", lambda e: self._autofill_id())

        self.name_var    = self._field(body, "Student name", 1, "Sabah Alanazi")
        self.sid_var     = self._field(body, "Student ID (9 digits)", 2, "441193701")
        self.degree_var  = self._field(body, "Degree", 3,
                                       "Bachelor of Science in Computer Science")
        self.grad_var    = self._field(body, "Graduation date", 4, date.today().isoformat())
        self.honors_var  = self._field(body, "Honors (optional)", 5, "")
        self.issuer_var  = self._field(body, "Issuer", 6, "Office of the Registrar")
        self.did_var     = self._field(body, "Diploma ID", 7, "")
        self.sid_var.trace_add("write", lambda *a: self._autofill_id())
        self.grad_var.trace_add("write", lambda *a: self._autofill_id())
        self._autofill_id()

        self.reg_var = tk.BooleanVar(value=True)
        tk.Checkbutton(body, text="Publish hash to public registry",
                       variable=self.reg_var, bg=PANEL, fg=TEXT,
                       selectcolor=PANEL, activebackground=PANEL,
                       activeforeground=TEXT, font=BODY).grid(
            row=8, column=1, sticky="w", pady=(4, 2))

        ttk.Button(f, text="Sign diploma", style="Accent.TButton",
                   command=self.do_sign).grid(row=2, column=0, columnspan=2,
                                              sticky="we", padx=20, pady=14)

        ttk.Label(f, text="Result", style="H2.TLabel").grid(
            row=3, column=0, columnspan=2, sticky="w", padx=20)
        self.sign_out = self._mono_box(f, height=11)
        self.sign_out.grid(row=4, column=0, columnspan=2, sticky="nsew",
                           padx=20, pady=(4, 18))
        f.grid_rowconfigure(4, weight=1)
        self.log(self.sign_out, "Signed certificate details will appear here.")

    def _selected_code(self):
        return self.uni_var.get().split(" — ")[0].strip().upper()

    def _autofill_id(self):
        code = self._selected_code()
        sid  = self.sid_var.get().strip()
        year = (self.grad_var.get().strip() or date.today().isoformat())[:4]
        if code and sid:
            self.did_var.set(generate_diploma_id(code, sid, year))

    def do_sign(self):
        code = self._selected_code()
        name = self.name_var.get().strip()
        sid  = self.sid_var.get().strip()
        deg  = self.degree_var.get().strip()
        grad = self.grad_var.get().strip()
        did  = self.did_var.get().strip()

        if code not in SAUDI_UNIVERSITIES:
            return messagebox.showerror("Invalid", f"Unknown university: {code}")
        if not (sid.isdigit() and len(sid) == 9):
            return messagebox.showerror("Invalid", "Student ID must be exactly 9 digits.")
        for label, val in (("Student name", name), ("Degree", deg),
                           ("Graduation date", grad), ("Diploma ID", did)):
            if not val:
                return messagebox.showerror("Missing", f"{label} is required.")

        
        diploma = {
            "student_name":    name,
            "student_id":      sid,
            "degree":          deg,
            "graduation_date": grad,
            "university":      SAUDI_UNIVERSITIES[code],
            "issuer":          self.issuer_var.get().strip() or "Office of the Registrar",
            "diploma_id":      did,
        }
        honors = self.honors_var.get().strip()
        if honors:
            diploma["honors"] = honors

        try:
            if code not in list_identities():
                generate_key_pair(code)  # auto-create keys for first-time issuer

            cert, console = capture_stdout(sign_diploma, diploma, code)

            doc_hash = hash_hex(diploma_to_canonical_bytes(diploma))
            token    = short_hash_for_university(doc_hash, code)

            slug      = name.lower().replace(" ", "_")
            cert_file = f"{slug}_{sid}_diploma.cert.json"
            path      = save_certificate(cert, cert_file)

            if self.reg_var.get():
                registry_add(did, doc_hash, code)
        except Exception as e:
            return messagebox.showerror("Signing failed", str(e))

        out = (
            f"STATUS        : SIGNED ✓\n"
            f"Diploma ID    : {did}\n"
            f"Student       : {name}  (ID {sid})\n"
            f"University     : {code} — {SAUDI_UNIVERSITIES[code]}\n\n"
            f"SHA-256 hash  : {doc_hash}\n"
            f"Verify token  : {token}\n"
            f"Signature(DER): {cert['signature']}\n\n"
            f"Saved to      : {path}\n"
            f"Registry      : {'published' if self.reg_var.get() else 'not published'}\n\n"
            f"--- crypto console ---\n{console.strip()}"
        )
        self.log(self.sign_out, out)
        self.refresh_manage()
        messagebox.showinfo("Signed", f"Diploma signed and saved:\n{cert_file}")

    # VERIFY TAB 
    def _build_verify_tab(self):
        f = self.verify_tab
        f.grid_columnconfigure(0, weight=1)

        ttk.Label(f, text="Verify a certificate", style="H2.TLabel").grid(
            row=0, column=0, sticky="w", padx=20, pady=(18, 4))
        ttk.Label(f, text="Load a .cert.json file or paste the certificate JSON below.",
                  style="Muted.TLabel").grid(row=1, column=0, sticky="w", padx=20)

        btns = ttk.Frame(f, style="Card.TFrame")
        btns.grid(row=2, column=0, sticky="w", padx=20, pady=8)
        ttk.Button(btns, text="Load .cert.json…", style="Ghost.TButton",
                   command=self.load_cert).pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="Clear", style="Ghost.TButton",
                   command=lambda: self.log(self.cert_in, "", clear=True)
                   ).pack(side="left")

        self.cert_in = self._mono_box(f, height=12)
        self.cert_in.grid(row=3, column=0, sticky="nsew", padx=20, pady=(0, 8))
        self.cert_in.configure(state="normal")

        ttk.Button(f, text="Verify signature", style="Accent.TButton",
                   command=self.do_verify).grid(row=4, column=0, sticky="we",
                                                padx=20, pady=4)

        self.verdict = tk.Label(f, text="", font=("Segoe UI", 14, "bold"),
                                bg=PANEL, fg=MUTED)
        self.verdict.grid(row=5, column=0, sticky="we", padx=20, pady=(10, 4))

        self.verify_out = self._mono_box(f, height=9)
        self.verify_out.grid(row=6, column=0, sticky="nsew", padx=20, pady=(0, 18))
        f.grid_rowconfigure(3, weight=1)
        f.grid_rowconfigure(6, weight=1)
        self.log(self.verify_out, "Verification details will appear here.")

    def load_cert(self):
        start = str(SIGNATURES_DIR) if Path(SIGNATURES_DIR).exists() else "."
        p = filedialog.askopenfilename(
            initialdir=start, title="Select certificate",
            filetypes=[("Certificate JSON", "*.cert.json *.json"), ("All", "*.*")])
        if not p:
            return
        try:
            self.cert_in.delete("1.0", "end")
            self.cert_in.insert("end", Path(p).read_text())
        except Exception as e:
            messagebox.showerror("Read error", str(e))

    def do_verify(self):
        raw = self.cert_in.get("1.0", "end").strip()
        if not raw:
            return messagebox.showwarning("Empty", "Load or paste a certificate first.")
        try:
            cert = json.loads(raw)
        except json.JSONDecodeError as e:
            self._set_verdict(False, "MALFORMED JSON")
            return self.log(self.verify_out, f"Could not parse JSON:\n{e}")

        uid = cert.get("university_id")
        if not uid:
            self._set_verdict(False, "NO UNIVERSITY ID")
            return self.log(self.verify_out, "Certificate is missing 'university_id'.")
        if uid not in list_identities():
            self._set_verdict(False, "UNKNOWN ISSUER")
            return self.log(self.verify_out,
                            f"No public key on file for '{uid}'. "
                            f"This issuer's key was never registered, so the "
                            f"signature cannot be trusted.")

        result, console = capture_stdout(verify_certificate, cert, university_id=uid)
        ok = result["status"] == VALID
        self._set_verdict(ok, "VALID ✓" if ok else "INVALID ✗")

        dip = cert.get("diploma", {})
        reg = registry_lookup(dip.get("diploma_id", ""))
        reg_line = ("matches public registry"
                    if reg and reg.get("hash") == result.get("computed_hash")
                    else "not in public registry" if not reg
                    else "DOES NOT MATCH registry")
        out = (
            f"Result        : {result['status']}\n"
            f"Diploma ID    : {result.get('diploma_id')}\n"
            f"Student       : {result.get('student_name')}\n"
            f"Degree        : {result.get('degree')}\n"
            f"University     : {uid} — {SAUDI_UNIVERSITIES.get(uid, '?')}\n"
            f"Issued at     : {result.get('issued_at')}\n"
            f"Computed hash : {result.get('computed_hash')}\n"
            f"Registry      : {reg_line}\n"
        )
        if result.get("errors"):
            out += "\nErrors:\n" + "\n".join(f"  - {e}" for e in result["errors"])
        out += f"\n\n--- crypto console ---\n{console.strip()}"
        self.log(self.verify_out, out)

    def _set_verdict(self, ok, text):
        self.verdict.configure(text=text, fg=OK if ok else BAD)

    # MANAGE TAB 
    def _build_manage_tab(self):
        f = self.manage_tab
        f.grid_columnconfigure(0, weight=1)

        ttk.Label(f, text="Registered university keys", style="H2.TLabel").grid(
            row=0, column=0, sticky="w", padx=20, pady=(18, 4))
        self.keys_box = self._mono_box(f, height=8)
        self.keys_box.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 6))

        gen = ttk.Frame(f, style="Card.TFrame")
        gen.grid(row=2, column=0, sticky="w", padx=20, pady=4)
        ttk.Label(gen, text="Generate key pair for:").pack(side="left", padx=(0, 8))
        self.gen_var = tk.StringVar()
        gc = ttk.Combobox(gen, textvariable=self.gen_var, width=14, state="readonly",
                          values=list(SAUDI_UNIVERSITIES.keys()))
        gc.current(0)
        gc.pack(side="left", padx=(0, 8))
        ttk.Button(gen, text="Generate", style="Ghost.TButton",
                   command=self.do_generate).pack(side="left")

        ttk.Label(f, text="Saved certificates", style="H2.TLabel").grid(
            row=3, column=0, sticky="w", padx=20, pady=(14, 4))
        self.certs_box = self._mono_box(f, height=10)
        self.certs_box.grid(row=4, column=0, sticky="nsew", padx=20, pady=(0, 18))
        f.grid_rowconfigure(1, weight=1)
        f.grid_rowconfigure(4, weight=1)

    def do_generate(self):
        code = self.gen_var.get().strip().upper()
        if code in list_identities():
            return messagebox.showinfo("Exists", f"Keys for {code} already exist.")
        try:
            generate_key_pair(code)
        except Exception as e:
            return messagebox.showerror("Error", str(e))
        self.refresh_manage()
        messagebox.showinfo("Done", f"Generated key pair for {code}.")

    def refresh_manage(self):
        ids = list_identities()
        if ids:
            lines = [f"{c:<8} {SAUDI_UNIVERSITIES.get(c, '(unknown)')}" for c in ids]
            self.log(self.keys_box, "\n".join(lines))
        else:
            self.log(self.keys_box, "No keys yet — sign a diploma or generate one above.")

        certs = []
        for p in sorted(Path(SIGNATURES_DIR).glob("*.cert.json")):
            try:
                c = json.loads(p.read_text())
                d = c.get("diploma", {})
                certs.append(f"{p.name}\n    {d.get('student_name','?')}  |  "
                             f"{d.get('diploma_id','?')}  |  {c.get('university_id','?')}")
            except Exception:
                certs.append(f"{p.name}  (unreadable)")
        self.log(self.certs_box, "\n".join(certs) if certs else "No certificates saved yet.")


if __name__ == "__main__":
    DiplomaApp().mainloop()
