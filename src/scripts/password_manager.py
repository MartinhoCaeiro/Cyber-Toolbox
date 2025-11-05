#!/usr/bin/env python3
"""
Simple password manager

Stores records with fields: url, user, pass
Each record is encrypted using a randomly generated symmetric key (Fernet).
The symmetric key is encrypted with an RSA public key (asymmetric keys).

Accessing/decrypting records requires a TOTP code (2FA) using `pyotp`.

Usage:
    python3 password_manager.py --init
    python3 password_manager.py --create --url example.com --user alice --pass s3cr3t
    python3 password_manager.py --list --otp 123456
    python3 password_manager.py --view <id> --otp 123456
    python3 password_manager.py --update <id> [--url ..] [--user ..] [--pass ..] --otp 123456
    python3 password_manager.py --delete <id> --otp 123456

Files created (in the same folder):
  - private_key.pem  (PEM, kept secret)
  - public_key.pem   (PEM)
  - totp_secret.txt  (base32 secret for TOTP)
  - records.json     (encrypted records database)

Note: This is a simple educational implementation. Do not use for production secrets.
"""

import argparse
import base64
import json
import os
import sys
import uuid
from datetime import datetime

def _ensure_package_local(package_name, import_name=None, prompt=True):
    """Minimal local helper to prompt+install a pip package at runtime.

    Returns the imported module on success or None on failure/decline.
    """
    import importlib
    import subprocess
    import sys as _sys

    mod_name = import_name or package_name
    try:
        return importlib.import_module(mod_name)
    except Exception:
        pass

    if not prompt:
        return None

    try:
        ans = input(f"Dependency '{package_name}' is missing. Install now? [Y/n]: ").strip().lower()
    except Exception:
        return None

    if ans not in ("", "y", "yes"):
        return None

    cmd = [_sys.executable, "-m", "pip", "install", package_name]
    print(f"Running: {' '.join(cmd)}")
    try:
        res = subprocess.run(cmd)
    except Exception as e:
        print(f"Failed to run pip: {e}")
        return None

    if res.returncode != 0:
        print(f"pip install exited with code {res.returncode}")
        return None

    try:
        return importlib.import_module(mod_name)
    except Exception as e:
        print(f"Installed but failed to import {mod_name}: {e}")
        return None


# Prompt/install commonly-used packages used in this script
_ensure_package_local("cryptography")
_ensure_package_local("pyotp")

BASE_DIR = os.path.dirname(__file__)
KEY_PRIVATE = os.path.join(BASE_DIR, "private_key.pem")
KEY_PUBLIC = os.path.join(BASE_DIR, "public_key.pem")
TOTP_FILE = os.path.join(BASE_DIR, "totp_secret.txt")
DB_FILE = os.path.join(BASE_DIR, "records.json")


def ensure_files_dir():
    # Ensure script directory exists as working dir
    return os.path.dirname(__file__)


def init_keys_and_totp():
    """Generate RSA keypair and a new TOTP secret."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
    except Exception as e:
        print("Missing cryptography package. Install with: pip install cryptography")
        raise

    # Generate RSA private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(KEY_PRIVATE, "wb") as f:
        f.write(priv_pem)
    with open(KEY_PUBLIC, "wb") as f:
        f.write(pub_pem)

    # Generate TOTP secret
    try:
        import pyotp
    except Exception:
        print("Missing pyotp package. Install with: pip install pyotp")
        raise

    secret = pyotp.random_base32()
    with open(TOTP_FILE, "w") as f:
        f.write(secret)

    # Create empty DB if not exists
    if not os.path.exists(DB_FILE):
        with open(DB_FILE, "w") as f:
            json.dump([], f)

    print("Initialized keys and TOTP secret.")
    print(f"Public key: {KEY_PUBLIC}")
    print(f"Private key: {KEY_PRIVATE} (keep secret!)")
    print(f"TOTP secret written to: {TOTP_FILE}")
    print("Add the TOTP secret to your authenticator app (base32 secret). You can also use the provisioning URI below:")
    try:
        import pyotp
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name="password_manager", issuer_name="Cyber-Toolbox")
        print(uri)
    except Exception:
        pass


def load_public_key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    if not os.path.exists(KEY_PUBLIC):
        raise FileNotFoundError("Public key not found. Run --init first.")
    with open(KEY_PUBLIC, "rb") as f:
        data = f.read()
    return serialization.load_pem_public_key(data, backend=default_backend())


def load_private_key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    if not os.path.exists(KEY_PRIVATE):
        raise FileNotFoundError("Private key not found. Run --init first.")
    with open(KEY_PRIVATE, "rb") as f:
        data = f.read()
    return serialization.load_pem_private_key(data, password=None, backend=default_backend())


def load_records():
    if not os.path.exists(DB_FILE):
        return []
    with open(DB_FILE, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except Exception:
            return []


def save_records(recs):
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(recs, f, indent=2, ensure_ascii=False)


def encrypt_record_plaintext(plaintext_bytes):
    """Encrypt plaintext bytes using Fernet and encrypt the key with RSA public key."""
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes

    pub = load_public_key()
    fkey = Fernet.generate_key()
    f = Fernet(fkey)
    cipher = f.encrypt(plaintext_bytes)

    # Encrypt the fernet key with RSA public key
    enc_key = pub.encrypt(
        fkey,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    return base64.b64encode(cipher).decode(), base64.b64encode(enc_key).decode()


def decrypt_record(enc_cipher_b64, enc_key_b64):
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes

    priv = load_private_key()
    enc_key = base64.b64decode(enc_key_b64)
    fkey = priv.decrypt(
        enc_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    f = Fernet(fkey)
    cipher = base64.b64decode(enc_cipher_b64)
    plain = f.decrypt(cipher)
    return plain


def require_otp(code):
    import pyotp
    if not os.path.exists(TOTP_FILE):
        print("TOTP not initialized. Run --init first.")
        return False
    with open(TOTP_FILE, "r") as f:
        secret = f.read().strip()
    totp = pyotp.TOTP(secret)
    try:
        return totp.verify(code, valid_window=1)
    except Exception:
        return False


def cmd_create(args):
    url = args.url
    user = args.user
    passwd = args.passwd

    if not (url and user and passwd):
        print("Missing fields. Provide --url, --user and --pass.")
        return

    payload = json.dumps({"url": url, "user": user, "pass": passwd}, ensure_ascii=False).encode("utf-8")
    cipher_b64, enc_key_b64 = encrypt_record_plaintext(payload)

    rec = {
        "id": str(uuid.uuid4()),
        "created": datetime.utcnow().isoformat() + "Z",
        "cipher": cipher_b64,
        "enc_key": enc_key_b64,
    }
    recs = load_records()
    recs.append(rec)
    save_records(recs)
    print(f"Record created with id: {rec['id']}")


def cmd_list(args):
    if not args.otp:
        print("Listing requires an OTP code (--otp <code>).")
        return
    if not require_otp(args.otp):
        print("Invalid OTP code.")
        return

    recs = load_records()
    if not recs:
        print("No records.")
        return
    print(f"{len(recs)} records:")
    for r in recs:
        try:
            plain = decrypt_record(r["cipher"], r["enc_key"])
            data = json.loads(plain.decode("utf-8"))
            print(f"- id: {r['id']} | url: {data.get('url')} | user: {data.get('user')}")
        except Exception as e:
            print(f"- id: {r['id']} | <decryption error: {e}>")


def cmd_view(args):
    if not args.id or not args.otp:
        print("Usage: --view <id> --otp <code>")
        return
    if not require_otp(args.otp):
        print("Invalid OTP code.")
        return
    recs = load_records()
    for r in recs:
        if r["id"] == args.id:
            try:
                plain = decrypt_record(r["cipher"], r["enc_key"])
                data = json.loads(plain.decode("utf-8"))
                print(json.dumps(data, indent=2, ensure_ascii=False))
                return
            except Exception as e:
                print(f"Decryption error: {e}")
                return
    print("Record not found.")


def cmd_delete(args):
    if not args.id or not args.otp:
        print("Usage: --delete <id> --otp <code>")
        return
    if not require_otp(args.otp):
        print("Invalid OTP code.")
        return
    recs = load_records()
    new = [r for r in recs if r["id"] != args.id]
    if len(new) == len(recs):
        print("Record not found.")
        return
    save_records(new)
    print("Record deleted.")


def cmd_update(args):
    if not args.id or not args.otp:
        print("Usage: --update <id> --otp <code> [--url ..] [--user ..] [--pass ..]")
        return
    if not require_otp(args.otp):
        print("Invalid OTP code.")
        return
    recs = load_records()
    for i, r in enumerate(recs):
        if r["id"] == args.id:
            try:
                plain = decrypt_record(r["cipher"], r["enc_key"])
                data = json.loads(plain.decode("utf-8"))
            except Exception as e:
                print(f"Decryption error: {e}")
                return
            if args.url:
                data["url"] = args.url
            if args.user:
                data["user"] = args.user
            if args.passwd:
                data["pass"] = args.passwd

            payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
            cipher_b64, enc_key_b64 = encrypt_record_plaintext(payload)
            recs[i]["cipher"] = cipher_b64
            recs[i]["enc_key"] = enc_key_b64
            save_records(recs)
            print("Record updated.")
            return
    print("Record not found.")


def parse_args():
    p = argparse.ArgumentParser(description="Simple password manager with RSA+Fernet + TOTP 2FA")
    p.add_argument("--init", action="store_true", help="Initialize keys, totp and database")
    sub = p.add_argument_group("operations")
    sub.add_argument("--create", action="store_true", help="Create a record (non-interactive with --url/--user/--pass)")
    sub.add_argument("--list", action="store_true", help="List records (requires --otp)")
    sub.add_argument("--view", action="store_true", help="View a record (--id and --otp required)")
    sub.add_argument("--delete", action="store_true", help="Delete a record (--id and --otp required)")
    sub.add_argument("--update", action="store_true", help="Update a record (--id and --otp required)")

    p.add_argument("--id", help="Record id for view/update/delete")
    p.add_argument("--url", help="URL for create/update")
    p.add_argument("--user", help="User for create/update")
    p.add_argument("--pass", dest="passwd", help="Password for create/update")
    p.add_argument("--otp", help="TOTP code for operations that require 2FA")

    return p.parse_args()


def main():
    args = parse_args()
    if args.init:
        init_keys_and_totp()
        return

    # Ensure DB file exists
    if not os.path.exists(DB_FILE):
        with open(DB_FILE, "w") as f:
            json.dump([], f)

    if args.create:
        cmd_create(args)
    elif args.list:
        cmd_list(args)
    elif args.view:
        cmd_view(args)
    elif args.delete:
        cmd_delete(args)
    elif args.update:
        cmd_update(args)
    else:
        # Interactive menu
        run_interactive_menu()


def run_interactive_menu():
    print("Password Manager — interactive mode")
    print("Note: viewing/deleting/updating records requires OTP 2FA.")
    while True:
        print("\nOptions:\n 1) Create\n 2) List (requires OTP)\n 3) View (requires OTP)\n 4) Update (requires OTP)\n 5) Delete (requires OTP)\n 6) Exit")
        choice = input("Choice: ").strip()
        if choice == "1":
            url = input("URL: ").strip()
            user = input("User: ").strip()
            passwd = input("Password: ").strip()
            class A:
                pass
            a = A()
            a.url = url; a.user = user; a.passwd = passwd
            cmd_create(a)
        elif choice == "2":
            otp = input("OTP: ").strip()
            class A: pass
            a = A(); a.otp = otp
            cmd_list(a)
        elif choice == "3":
            rid = input("Record id: ").strip()
            otp = input("OTP: ").strip()
            class A: pass
            a = A(); a.id = rid; a.otp = otp
            cmd_view(a)
        elif choice == "4":
            rid = input("Record id: ").strip()
            otp = input("OTP: ").strip()
            url = input("New URL (enter to skip): ").strip() or None
            user = input("New User (enter to skip): ").strip() or None
            passwd = input("New Pass (enter to skip): ").strip() or None
            class A: pass
            a = A(); a.id = rid; a.otp = otp; a.url = url; a.user = user; a.passwd = passwd
            cmd_update(a)
        elif choice == "5":
            rid = input("Record id: ").strip()
            otp = input("OTP: ").strip()
            class A: pass
            a = A(); a.id = rid; a.otp = otp
            cmd_delete(a)
        elif choice == "6":
            print("Bye")
            return
        else:
            print("Invalid choice")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("Error:", e)
        sys.exit(1)
