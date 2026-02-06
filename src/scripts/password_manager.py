#!/usr/bin/env python3
"""
Master's in Computer Security Engineering
Dynamic Programming Languages - Password Manager

Author: Martinho Caeiro (23917)

Description:
    Simple password manager with RSA + Fernet encryption and TOTP 2FA.
    Supports interactive mode and command-line operations.

Usage:
    python3 password_manager.py [--init] [--create|--list|--view|--update|--delete] [OPTIONS]

Example:
    python3 password_manager.py --init
    python3 password_manager.py --create --url example.com --user alice --pass s3cr3t
    python3 password_manager.py --list --otp 123456
    python3 password_manager.py (interactive mode if no arguments)

Security:
    - RSA 2048-bit encryption for key storage
    - Fernet (AES-128) encryption for records
    - TOTP 2FA authentication for sensitive operations
    - All files stored in src/data/ directory

Note:
    Educational implementation. Do not use for production secrets.
"""

import argparse
import base64
import json
import os
import sys
import uuid
from datetime import datetime

from package_manager import ensure_package



# Section: Dependencies

def ensure_runtime_deps():
    """Ensure optional dependencies are available when running the script."""
    ensure_package("cryptography")
    ensure_package("pyotp")
    ensure_package("qrcode")



# Section: Paths

# Store keys in project root data folder, not in scripts folder
SCRIPT_DIR = os.path.dirname(__file__)
PROJECT_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR))  # Go up two levels from scripts
DATA_DIR = os.path.join(PROJECT_ROOT, "src/data")

KEY_PRIVATE = os.path.join(DATA_DIR, "private_key.pem")
KEY_PUBLIC = os.path.join(DATA_DIR, "public_key.pem")
TOTP_SECRET_FILE = os.path.join(DATA_DIR, "totp_secret.txt")  # TOTP secret for 2FA
DB_FILE = os.path.join(DATA_DIR, "password_records.json")



# Section: Key management

def ensure_files_dir():
    # Ensure script directory exists as working dir
    return os.path.dirname(__file__)


def init_keys_and_totp():
    """Generate RSA keypair and setup TOTP 2FA with QR code."""
    ensure_runtime_deps()
    # Ensure data directory exists
    os.makedirs(DATA_DIR, exist_ok=True)
    
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
    except Exception as e:
        print("Pacote cryptography em falta. Instale com: pip install cryptography")
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
        print("Pacote pyotp em falta. Instale com: pip install pyotp")
        raise

    secret = pyotp.random_base32()
    with open(TOTP_SECRET_FILE, "w") as f:
        f.write(secret)

    # Create empty DB if not exists
    if not os.path.exists(DB_FILE):
        with open(DB_FILE, "w") as f:
            json.dump([], f)

    print("\n=== Inicialização completa ===")
    print(f"Chave pública: {KEY_PUBLIC}")
    print(f"Chave privada: {KEY_PRIVATE} (mantenha em segredo!)")
    print(f"Base de dados: {DB_FILE}")
    print("\n=== Autenticação TOTP 2FA ===")
    print("✓ TOTP 2FA ativado (autenticação de dois fatores por código temporário)")
    print("\nAdicione o segredo TOTP à sua app autenticadora (Google Authenticator, Authy, etc.)")
    print(f"\nSegredo Base32: {secret}")
    
    # Generate and display QR code
    try:
        import pyotp
        import qrcode
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name="password_manager", issuer_name="Cyber-Toolbox")
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        
        # Display in terminal
        print("\nCódigo QR (escaneie com a sua app autenticadora):")
        qr.print_ascii(invert=True)
        
        # Save QR code image
        qr_path = os.path.join(DATA_DIR, "totp_qr.png")
        with open(qr_path, "wb") as qr_file:
            qr.make_image().save(qr_file)
        print(f"\nCódigo QR também guardado em: {qr_path}")
    except Exception as e:
        print(f"Aviso: Não foi possível gerar o código QR: {e}")
    
    print("\n✓ Sistema pronto para utilização.\n")


def load_public_key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend

    if not os.path.exists(KEY_PUBLIC):
        raise FileNotFoundError("Chave pública não encontrada. Execute --init primeiro.")
    with open(KEY_PUBLIC, "rb") as f:
        data = f.read()
    key = serialization.load_pem_public_key(data, backend=default_backend())
    if not isinstance(key, rsa.RSAPublicKey):
        raise TypeError("Expected RSA public key")
    return key


def load_private_key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend

    if not os.path.exists(KEY_PRIVATE):
        raise FileNotFoundError("Chave privada não encontrada. Execute --init primeiro.")
    with open(KEY_PRIVATE, "rb") as f:
        data = f.read()
    key = serialization.load_pem_private_key(data, password=None, backend=default_backend())
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("Expected RSA private key")
    return key


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
    """Verify TOTP code for 2FA authentication.
    
    Args:
        code: The 6-digit TOTP code from the authenticator app
        
    Returns:
        True if code is valid, False otherwise
    """
    import pyotp
    if not os.path.exists(TOTP_SECRET_FILE):
        print("TOTP não inicializado. Execute --init primeiro.")
        return False
    with open(TOTP_SECRET_FILE, "r") as f:
        secret = f.read().strip()
    totp = pyotp.TOTP(secret)
    try:
        return totp.verify(code, valid_window=1)
    except Exception:
        return False



# Section: Commands

def cmd_create(args):
    url = args.url
    user = args.user
    passwd = args.passwd

    if not (url and user and passwd):
        print("Campos em falta. Indique --url, --user e --pass.")
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
    print(f"Registo criado com id: {rec['id']}")


def cmd_list(args):
    if not args.otp:
        print("A listagem requer um código OTP (--otp <código>).")
        return
    if not require_otp(args.otp):
        print("Código OTP inválido.")
        return

    recs = load_records()
    if not recs:
        print("Sem registos.")
        return
    print(f"{len(recs)} registos:")
    for r in recs:
        try:
            plain = decrypt_record(r["cipher"], r["enc_key"])
            data = json.loads(plain.decode("utf-8"))
            print(f"- id: {r['id']} | url: {data.get('url')} | user: {data.get('user')}")
        except Exception as e:
                print(f"- id: {r['id']} | <erro de desencriptação: {e}>")


def cmd_view(args):
    if not args.id or not args.otp:
        print("Uso: --view <id> --otp <código>")
        return
    if not require_otp(args.otp):
        print("Código OTP inválido.")
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
                print(f"Erro de desencriptação: {e}")
                return
    print("Registo não encontrado.")


def cmd_delete(args):
    if not args.id or not args.otp:
        print("Uso: --delete <id> --otp <código>")
        return
    if not require_otp(args.otp):
        print("Código OTP inválido.")
        return
    recs = load_records()
    new = [r for r in recs if r["id"] != args.id]
    if len(new) == len(recs):
        print("Registo não encontrado.")
        return
    save_records(new)
    print("Registo apagado.")


def cmd_update(args):
    if not args.id or not args.otp:
        print("Uso: --update <id> --otp <código> [--url ..] [--user ..] [--pass ..]")
        return
    if not require_otp(args.otp):
        print("Código OTP inválido.")
        return
    recs = load_records()
    for i, r in enumerate(recs):
        if r["id"] == args.id:
            try:
                plain = decrypt_record(r["cipher"], r["enc_key"])
                data = json.loads(plain.decode("utf-8"))
            except Exception as e:
                print(f"Erro de desencriptação: {e}")
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
            print("Registo atualizado.")
            return
    print("Registo não encontrado.")



# Section: CLI

def parse_args():
    p = argparse.ArgumentParser(description="Gestor de palavras-passe simples com RSA+Fernet + TOTP 2FA")
    p.add_argument("--init", action="store_true", help="Inicializar chaves, TOTP e base de dados")
    sub = p.add_argument_group("operations")
    sub.add_argument("--create", action="store_true", help="Criar um registo (não interativo com --url/--user/--pass)")
    sub.add_argument("--list", action="store_true", help="Listar registos (requer --otp)")
    sub.add_argument("--view", action="store_true", help="Ver um registo (--id e --otp obrigatórios)")
    sub.add_argument("--delete", action="store_true", help="Apagar um registo (--id e --otp obrigatórios)")
    sub.add_argument("--update", action="store_true", help="Atualizar um registo (--id e --otp obrigatórios)")

    p.add_argument("--id", help="ID do registo para ver/atualizar/apagar")
    p.add_argument("--url", help="URL para criar/atualizar")
    p.add_argument("--user", help="Utilizador para criar/atualizar")
    p.add_argument("--pass", dest="passwd", help="Palavra-passe para criar/atualizar")
    p.add_argument("--otp", help="Código TOTP para operações que requerem 2FA")

    return p.parse_args()


def check_and_auto_init():
    """Check if initialization is needed and perform it automatically."""
    needs_init = not os.path.exists(KEY_PRIVATE) or not os.path.exists(KEY_PUBLIC) or not os.path.exists(TOTP_SECRET_FILE)
    
    if needs_init:
        print("\n⚠️  Inicialização necessária (chaves não encontradas).")
        print("A inicializar automaticamente...\n")
        init_keys_and_totp()
        return True
    return False


def main():
    ensure_runtime_deps()
    args = parse_args()
    if args.init:
        init_keys_and_totp()
        return

    # Auto-initialize if needed
    check_and_auto_init()

    # Ensure DB file exists
    if not os.path.exists(DB_FILE):
        os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
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
    print("Gestor de Palavras-passe — modo interativo")
    print("Nota: ver/apagar/atualizar registos requer OTP 2FA.")
    while True:
        print("\nOpções:\n 1) Criar\n 2) Listar (requer 2FA)\n 3) Ver (requer 2FA)\n 4) Atualizar (requer 2FA)\n 5) Apagar (requer 2FA)\n 6) Sair")
        choice = input("Escolha: ").strip()
        if choice == "1":
            url = input("URL: ").strip()
            user = input("Utilizador: ").strip()
            passwd = input("Palavra-passe: ").strip()
            a = argparse.Namespace(url=url, user=user, passwd=passwd)
            cmd_create(a)
        elif choice == "2":
            otp = input("OTP: ").strip()
            a = argparse.Namespace(otp=otp)
            cmd_list(a)
        elif choice == "3":
            rid = input("ID do registo: ").strip()
            otp = input("OTP: ").strip()
            a = argparse.Namespace(id=rid, otp=otp)
            cmd_view(a)
        elif choice == "4":
            rid = input("ID do registo: ").strip()
            otp = input("OTP: ").strip()
            url = input("Novo URL (Enter para ignorar): ").strip() or None
            user = input("Novo utilizador (Enter para ignorar): ").strip() or None
            passwd = input("Nova palavra-passe (Enter para ignorar): ").strip() or None
            a = argparse.Namespace(id=rid, otp=otp, url=url, user=user, passwd=passwd)
            cmd_update(a)
        elif choice == "5":
            rid = input("ID do registo: ").strip()
            otp = input("OTP: ").strip()
            a = argparse.Namespace(id=rid, otp=otp)
            cmd_delete(a)
        elif choice == "6":
            print("Adeus")
            return
        else:
            print("Opção inválida")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("Erro:", e)
        sys.exit(1)
