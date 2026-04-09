"""
Minimal Tkinter GUI for FATCA Crypto Utility.

Provides a 2-tab interface:
- Encrypt: Sign + encrypt FATCA XML → IDES ZIP
- Decrypt: Decrypt IRS feedback files

Professional dark theme. No external dependencies beyond tkinter.
"""

import os
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path

from . import __version__, __app_name__


# ---------------------------------------------------------------------------
# Color palette (dark professional theme)
# ---------------------------------------------------------------------------
COLORS = {
    "bg": "#1a1a2e",
    "bg_secondary": "#16213e",
    "bg_input": "#0f3460",
    "fg": "#e6e6e6",
    "fg_muted": "#8a8a9a",
    "accent": "#e94560",
    "accent_hover": "#ff6b6b",
    "success": "#00d2d3",
    "error": "#ee5a24",
    "border": "#2a2a4a",
    "button": "#e94560",
    "button_text": "#ffffff",
}


class FatcaCryptoGUI:
    """Main GUI application window."""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title(f"{__app_name__} v{__version__}")
        self.root.geometry("720x620")
        self.root.resizable(True, True)
        self.root.configure(bg=COLORS["bg"])

        # Configure styles
        self._setup_styles()

        # Build UI
        self._build_header()
        self._build_tabs()
        self._build_status_bar()

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("Dark.TFrame", background=COLORS["bg"])
        style.configure("DarkSec.TFrame", background=COLORS["bg_secondary"])
        style.configure(
            "Dark.TLabel",
            background=COLORS["bg"],
            foreground=COLORS["fg"],
            font=("Helvetica", 11),
        )
        style.configure(
            "Header.TLabel",
            background=COLORS["bg"],
            foreground=COLORS["accent"],
            font=("Helvetica", 18, "bold"),
        )
        style.configure(
            "Sub.TLabel",
            background=COLORS["bg"],
            foreground=COLORS["fg_muted"],
            font=("Helvetica", 9),
        )
        style.configure(
            "Dark.TNotebook",
            background=COLORS["bg"],
            borderwidth=0,
        )
        style.configure(
            "Dark.TNotebook.Tab",
            background=COLORS["bg_secondary"],
            foreground=COLORS["fg"],
            padding=[20, 10],
            font=("Helvetica", 11, "bold"),
        )
        style.map(
            "Dark.TNotebook.Tab",
            background=[("selected", COLORS["accent"])],
            foreground=[("selected", COLORS["button_text"])],
        )
        style.configure(
            "Action.TButton",
            background=COLORS["button"],
            foreground=COLORS["button_text"],
            font=("Helvetica", 12, "bold"),
            padding=[20, 10],
        )
        style.map(
            "Action.TButton",
            background=[("active", COLORS["accent_hover"])],
        )

    def _build_header(self):
        header = ttk.Frame(self.root, style="Dark.TFrame")
        header.pack(fill="x", padx=20, pady=(15, 5))

        ttk.Label(
            header, text="🔐 FATCA Crypto Utility",
            style="Header.TLabel",
        ).pack(side="left")

        ttk.Label(
            header, text=f"v{__version__}",
            style="Sub.TLabel",
        ).pack(side="right", padx=10, pady=5)

    def _build_tabs(self):
        notebook = ttk.Notebook(self.root, style="Dark.TNotebook")
        notebook.pack(fill="both", expand=True, padx=20, pady=10)

        # Encrypt tab
        enc_frame = ttk.Frame(notebook, style="Dark.TFrame")
        notebook.add(enc_frame, text="  ⬆ Encrypt  ")
        self._build_encrypt_tab(enc_frame)

        # Decrypt tab
        dec_frame = ttk.Frame(notebook, style="Dark.TFrame")
        notebook.add(dec_frame, text="  ⬇ Decrypt  ")
        self._build_decrypt_tab(dec_frame)

    def _build_encrypt_tab(self, parent):
        # XML file
        self.enc_xml_var = tk.StringVar()
        self._file_picker_row(
            parent, "FATCA XML file:", self.enc_xml_var, 0,
            filetypes=[("XML files", "*.xml"), ("All files", "*.*")],
        )
        # Auto-detect GIIN when XML file is selected
        self.enc_xml_var.trace_add("write", self._on_xml_changed)

        # Bank certificate
        self.enc_cert_var = tk.StringVar()
        self._file_picker_row(
            parent, "Bank certificate (.crt/.pem/.p12):", self.enc_cert_var, 1,
            filetypes=[
                ("Certificates", "*.crt *.pem *.p12 *.pfx"),
                ("All files", "*.*"),
            ],
        )

        # Certificate password
        self.enc_password_var = tk.StringVar()
        self._password_entry_row(
            parent, "Certificate password (.p12):", self.enc_password_var, 2,
        )

        # IRS certificate
        self.enc_irs_cert_var = tk.StringVar()
        self._file_picker_row(
            parent, "IRS public certificate:", self.enc_irs_cert_var, 3,
            filetypes=[
                ("PEM", "*.pem *.crt *.cer"),
                ("All files", "*.*"),
            ],
        )

        # GIIN override
        self.enc_giin_var = tk.StringVar()
        self._entry_row(parent, "GIIN (auto-detected if empty):", self.enc_giin_var, 4)

        # Output directory
        self.enc_output_var = tk.StringVar(value="./output")
        self._dir_picker_row(parent, "Output directory:", self.enc_output_var, 5)

        # Encrypt button
        btn_frame = ttk.Frame(parent, style="Dark.TFrame")
        btn_frame.grid(row=6, column=0, columnspan=3, pady=20)
        ttk.Button(
            btn_frame, text="🔒  Encrypt & Package",
            style="Action.TButton",
            command=self._on_encrypt,
        ).pack()

    def _on_xml_changed(self, *_args):
        """Auto-detect GIIN from the FATCA XML file (SendingCompanyIN tag)."""
        xml_path = self.enc_xml_var.get().strip()
        if not xml_path or not os.path.isfile(xml_path):
            return

        def detect():
            try:
                from .xml.parser import extract_giin_from_xml
                giin = extract_giin_from_xml(xml_path)
                if giin:
                    self.root.after(0, lambda g=giin: self._set_giin(g))
                else:
                    self.root.after(
                        0,
                        lambda: self.status_var.set(
                            "⚠ GIIN non trouvé dans le XML — "
                            "veuillez le saisir manuellement"
                        ),
                    )
            except Exception:
                pass  # Silently ignore — user can still type GIIN manually

        threading.Thread(target=detect, daemon=True).start()

    def _set_giin(self, giin: str):
        """Set the GIIN field and update the status bar."""
        self.enc_giin_var.set(giin)
        self.status_var.set(f"✅ GIIN détecté : {giin}")

    def _build_decrypt_tab(self, parent):
        # Encrypted file or IRS feedback ZIP
        self.dec_payload_var = tk.StringVar()
        self._file_picker_row(
            parent, "IRS feedback ZIP or payload file:", self.dec_payload_var, 0,
            filetypes=[
                ("ZIP / Payload", "*.zip *_Payload *.*"),
                ("All files", "*.*"),
            ],
        )

        # Key file (optional — not needed if ZIP)
        self.dec_key_var = tk.StringVar()
        self._file_picker_row(
            parent, "Wrapped key file (optional, si non-ZIP):", self.dec_key_var, 1,
            filetypes=[("All files", "*.*")],
        )

        # Bank certificate
        self.dec_cert_var = tk.StringVar()
        self._file_picker_row(
            parent, "Bank certificate (.crt/.pem/.p12):", self.dec_cert_var, 2,
            filetypes=[
                ("Certificates", "*.crt *.pem *.p12 *.pfx"),
                ("All files", "*.*"),
            ],
        )

        # Certificate password
        self.dec_password_var = tk.StringVar()
        self._password_entry_row(
            parent, "Certificate password (.p12):", self.dec_password_var, 3,
        )

        # Output file
        self.dec_output_var = tk.StringVar()
        self._save_picker_row(
            parent, "Output XML file:", self.dec_output_var, 4,
            filetypes=[("XML files", "*.xml"), ("All files", "*.*")],
            defaultextension=".xml",
        )

        # Decrypt button
        btn_frame = ttk.Frame(parent, style="Dark.TFrame")
        btn_frame.grid(row=5, column=0, columnspan=3, pady=20)
        ttk.Button(
            btn_frame, text="🔓  Decrypt Feedback",
            style="Action.TButton",
            command=self._on_decrypt,
        ).pack()

    def _build_status_bar(self):
        self.status_var = tk.StringVar(value="Ready")
        status_frame = ttk.Frame(self.root, style="DarkSec.TFrame")
        status_frame.pack(fill="x", side="bottom")

        self.status_label = ttk.Label(
            status_frame,
            textvariable=self.status_var,
            style="Sub.TLabel",
        )
        self.status_label.configure(background=COLORS["bg_secondary"])
        self.status_label.pack(side="left", padx=10, pady=5)

        self.progress = ttk.Progressbar(
            status_frame, mode="indeterminate", length=150,
        )
        self.progress.pack(side="right", padx=10, pady=5)

    # -----------------------------------------------------------------------
    # UI builder helpers
    # -----------------------------------------------------------------------

    def _file_picker_row(self, parent, label, var, row, filetypes=None):
        ttk.Label(parent, text=label, style="Dark.TLabel").grid(
            row=row, column=0, sticky="w", padx=10, pady=8,
        )
        entry = tk.Entry(
            parent, textvariable=var, width=40,
            bg=COLORS["bg_input"], fg=COLORS["fg"],
            insertbackground=COLORS["fg"],
            relief="flat", font=("Helvetica", 10),
        )
        entry.grid(row=row, column=1, padx=5, pady=8, sticky="ew")

        btn = tk.Button(
            parent, text="Browse",
            bg=COLORS["bg_secondary"], fg=COLORS["fg"],
            relief="flat", cursor="hand2",
            command=lambda: var.set(
                filedialog.askopenfilename(filetypes=filetypes or [])
            ),
        )
        btn.grid(row=row, column=2, padx=5, pady=8)
        parent.columnconfigure(1, weight=1)

    def _dir_picker_row(self, parent, label, var, row):
        ttk.Label(parent, text=label, style="Dark.TLabel").grid(
            row=row, column=0, sticky="w", padx=10, pady=8,
        )
        entry = tk.Entry(
            parent, textvariable=var, width=40,
            bg=COLORS["bg_input"], fg=COLORS["fg"],
            insertbackground=COLORS["fg"],
            relief="flat", font=("Helvetica", 10),
        )
        entry.grid(row=row, column=1, padx=5, pady=8, sticky="ew")

        btn = tk.Button(
            parent, text="Browse",
            bg=COLORS["bg_secondary"], fg=COLORS["fg"],
            relief="flat", cursor="hand2",
            command=lambda: var.set(filedialog.askdirectory() or var.get()),
        )
        btn.grid(row=row, column=2, padx=5, pady=8)

    def _save_picker_row(self, parent, label, var, row, filetypes=None,
                         defaultextension=None):
        ttk.Label(parent, text=label, style="Dark.TLabel").grid(
            row=row, column=0, sticky="w", padx=10, pady=8,
        )
        entry = tk.Entry(
            parent, textvariable=var, width=40,
            bg=COLORS["bg_input"], fg=COLORS["fg"],
            insertbackground=COLORS["fg"],
            relief="flat", font=("Helvetica", 10),
        )
        entry.grid(row=row, column=1, padx=5, pady=8, sticky="ew")

        btn = tk.Button(
            parent, text="Browse",
            bg=COLORS["bg_secondary"], fg=COLORS["fg"],
            relief="flat", cursor="hand2",
            command=lambda: var.set(
                filedialog.asksaveasfilename(
                    filetypes=filetypes or [],
                    defaultextension=defaultextension,
                ) or var.get()
            ),
        )
        btn.grid(row=row, column=2, padx=5, pady=8)

    def _password_entry_row(self, parent, label, var, row):
        ttk.Label(parent, text=label, style="Dark.TLabel").grid(
            row=row, column=0, sticky="w", padx=10, pady=8,
        )
        entry = tk.Entry(
            parent, textvariable=var, show="*", width=40,
            bg=COLORS["bg_input"], fg=COLORS["fg"],
            insertbackground=COLORS["fg"],
            relief="flat", font=("Helvetica", 10),
        )
        entry.grid(row=row, column=1, padx=5, pady=8, sticky="ew")

        def toggle_visibility():
            if entry.cget("show") == "*":
                entry.config(show="")
                btn.config(text="🙈")
            else:
                entry.config(show="*")
                btn.config(text="👁")

        btn = tk.Button(
            parent, text="👁", width=3,
            bg=COLORS["bg_secondary"], fg=COLORS["fg"],
            relief="flat", cursor="hand2",
            command=toggle_visibility,
        )
        btn.grid(row=row, column=2, padx=5, pady=8)

    def _entry_row(self, parent, label, var, row):
        ttk.Label(parent, text=label, style="Dark.TLabel").grid(
            row=row, column=0, sticky="w", padx=10, pady=8,
        )
        entry = tk.Entry(
            parent, textvariable=var, width=40,
            bg=COLORS["bg_input"], fg=COLORS["fg"],
            insertbackground=COLORS["fg"],
            relief="flat", font=("Helvetica", 10),
        )
        entry.grid(row=row, column=1, padx=5, pady=8, sticky="ew")

    # -----------------------------------------------------------------------
    # Actions
    # -----------------------------------------------------------------------

    def _on_encrypt(self):
        xml = self.enc_xml_var.get().strip()
        cert = self.enc_cert_var.get().strip()
        irs_cert = self.enc_irs_cert_var.get().strip()
        giin = self.enc_giin_var.get().strip() or None
        output = self.enc_output_var.get().strip() or "./output"
        password = self.enc_password_var.get() or None

        if not xml or not cert or not irs_cert:
            messagebox.showerror(
                "Missing Fields",
                "Please provide the XML file, bank certificate, "
                "and IRS certificate.",
            )
            return

        self._run_async(
            "Signing & Encrypting...",
            lambda: self._do_encrypt(xml, cert, irs_cert, giin, output, password),
        )

    def _do_encrypt(self, xml, cert, irs_cert, giin, output, password):
        from .crypto.certificates import (
            load_certificate, load_public_certificate,
        )
        from .crypto.signer import sign_xml_bytes
        from .crypto.encryptor import encrypt_xml_bytes
        from .crypto.packaging import package_for_ides
        from .utils.validators import validate_certificate_expiry
        from pathlib import Path

        sender = load_certificate(cert, giin_override=giin, password=password)
        validate_certificate_expiry(sender.not_after)
        irs = load_public_certificate(irs_cert)
        validate_certificate_expiry(irs.not_after)

        if not sender.giin:
            raise ValueError(
                "GIIN introuvable dans le certificat. "
                "Veuillez le saisir manuellement dans le champ GIIN."
            )

        # Signer puis chiffrer (ordre requis par l'IRS)
        xml_bytes = Path(xml).read_bytes()
        signed_xml = sign_xml_bytes(xml_bytes, sender)
        payload = encrypt_xml_bytes(signed_xml, sender.giin, irs)
        zip_path = package_for_ides(payload, output)

        return str(zip_path)

    def _on_decrypt(self):
        payload = self.dec_payload_var.get().strip()
        key = self.dec_key_var.get().strip() or None
        cert = self.dec_cert_var.get().strip()
        output = self.dec_output_var.get().strip()
        password = self.dec_password_var.get() or None

        if not payload or not cert or not output:
            messagebox.showerror(
                "Missing Fields",
                "Please provide the encrypted file, bank certificate, "
                "and output path.",
            )
            return

        self._run_async(
            "Decrypting...",
            lambda: self._do_decrypt(payload, key, cert, output, password),
        )

    def _do_decrypt(self, payload_path, key_path, cert, output, password):
        from .crypto.certificates import load_certificate
        from .crypto.decryptor import (
            decrypt_feedback, decrypt_feedback_single_file,
        )

        bundle = load_certificate(cert, password=password)

        if key_path:
            result = decrypt_feedback(
                encrypted_path=payload_path,
                key_path=key_path,
                cert_bundle=bundle,
                output_path=output,
            )
        else:
            result = decrypt_feedback_single_file(
                encrypted_path=payload_path,
                cert_bundle=bundle,
                output_path=output,
            )

        return f"Status: {result.status}\nOutput: {output}"

    # -----------------------------------------------------------------------
    # Async runner
    # -----------------------------------------------------------------------

    def _run_async(self, status_msg, operation):
        """Run an operation in a background thread with progress indicator."""
        self.status_var.set(status_msg)
        self.progress.start(10)

        def worker():
            try:
                result = operation()
                self.root.after(0, lambda r=result: self._on_complete(r))
            except Exception as e:
                err_msg = str(e)
                self.root.after(0, lambda m=err_msg: self._on_error(m))

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()

    def _on_complete(self, result):
        self.progress.stop()
        self.status_var.set("✅ Operation complete!")
        messagebox.showinfo("Success", f"Operation completed!\n\n{result}")

    def _on_error(self, error_msg):
        self.progress.stop()
        self.status_var.set("❌ Error occurred")
        messagebox.showerror("Error", error_msg)

    # -----------------------------------------------------------------------
    # Run
    # -----------------------------------------------------------------------

    def run(self):
        """Start the GUI event loop."""
        self.root.mainloop()


def launch_gui():
    """Entry point for launching the GUI."""
    app = FatcaCryptoGUI()
    app.run()


if __name__ == "__main__":
    launch_gui()
