# main.py
import sys
import argparse
import tkinter as tk
from aes_gcm import EncryptionEngine
from interface import EncryptionInterface

# Instantiate the encryption engine
engine = EncryptionEngine()

def run_gui():
    root = tk.Tk()
    root.title("AES-256 GCM Encryption Tool")

    app = EncryptionInterface(
        master=root,
        encrypt_callback=engine.encrypt_file,
        decrypt_callback=engine.decrypt_file
    )
    app.mainloop()

def run_cli():
    parser = argparse.ArgumentParser(description="AES-256 GCM Encryption Tool")
    parser.add_argument("mode", choices=["encrypt", "decrypt"], help="Operation mode")
    parser.add_argument("key", help="Encryption key (hex)")
    parser.add_argument("input", help="Input file path")
    parser.add_argument("output", help="Output file path")

    args = parser.parse_args()
    key = bytes.fromhex(args.key)

    if args.mode == "encrypt":
        engine.encrypt_file(args.input, args.output, key)
        print("[+] File encrypted successfully.")
    else:
        engine.decrypt_file(args.input, args.output, key)
        print("[+] File decrypted successfully.")

if __name__ == "__main__":
    if len(sys.argv) == 1:
        run_gui()
    else:
        run_cli()
