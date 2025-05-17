# src/gui/interface.py

import tkinter as tk
from tkinter import filedialog, messagebox, ttk


class EncryptionInterface(ttk.Frame):
    def __init__(self, master, encrypt_callback, decrypt_callback):
        super().__init__(master)
        self.encrypt_callback = encrypt_callback
        self.decrypt_callback = decrypt_callback
        self.grid(padx=10, pady=10)
        self.create_widgets()

    def create_widgets(self):
        # Input field
        ttk.Label(self, text="Input File:").grid(row=0, column=0, sticky="w")
        self.input_path = tk.StringVar()
        ttk.Entry(self, textvariable=self.input_path, width=50).grid(row=0, column=1)
        ttk.Button(self, text="Browse", command=self.browse_input).grid(row=0, column=2)

        # Output field
        ttk.Label(self, text="Output File:").grid(row=1, column=0, sticky="w")
        self.output_path = tk.StringVar()
        ttk.Entry(self, textvariable=self.output_path, width=50).grid(row=1, column=1)
        ttk.Button(self, text="Browse", command=self.browse_output).grid(row=1, column=2)

        # Key field
        ttk.Label(self, text="Key (hex):").grid(row=2, column=0, sticky="w")
        self.key_input = tk.StringVar()
        ttk.Entry(self, textvariable=self.key_input, width=60, show='*').grid(row=2, column=1, columnspan=2)

        # Buttons
        ttk.Button(self, text="Encrypt", command=self.encrypt_file).grid(row=3, column=1, pady=10)
        ttk.Button(self, text="Decrypt", command=self.decrypt_file).grid(row=3, column=2, pady=10)

    def browse_input(self):
        path = filedialog.askopenfilename(title="Select Input File")
        if path:
            self.input_path.set(path)

    def browse_output(self):
        path = filedialog.asksaveasfilename(title="Select Output File")
        if path:
            self.output_path.set(path)

    def encrypt_file(self):
        self._process_file(self.encrypt_callback, "Encryption")

    def decrypt_file(self):
        self._process_file(self.decrypt_callback, "Decryption")

    def _process_file(self, callback, operation):
        try:
            key = bytes.fromhex(self.key_input.get().strip())
            input_path = self.input_path.get()
            output_path = self.output_path.get()

            if not key or not input_path or not output_path:
                raise ValueError("All fields must be filled.")

            callback(key, input_path, output_path)
            messagebox.showinfo(f"{operation} Successful", f"{operation} completed successfully.")
        except Exception as e:
            messagebox.showerror(f"{operation} Error", str(e))