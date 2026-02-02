#!/usr/bin/env python3
"""
Master's in Computer Security Engineering
Dynamic Programming Languages - Messenger

Author: Martinho Caeiro (23917)

Description:
    Simple secure messenger (server + client CLI) for the Cyber-Toolbox project.

Features:
    - Server generates an RSA keypair (data/keys/) with init-keys.
    - Clients connect to the server (TCP) and send JSON commands.
    - Messages are stored on the server only, in data/messages/.
    - Each message is hybrid-encrypted: a Fernet payload + the Fernet key
      encrypted with the server RSA public key.
    - Clients can list/download/delete messages where they are participants.
    - Server can produce backups (symmetric password-protected or asymmetric).

Usage:
    python messenger.py init-keys
    python messenger.py serve --host 127.0.0.1 --port 9009
    python messenger.py send --from alice --to bob --message "Olá"

Example:
    python messenger.py list --user alice

Note:
    This script is intentionally simple and synchronous. It is meant for local
    testing and demonstration, not production use.
"""
import argparse
import base64
import json
import os
import sys
import socket
import socketserver
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

def _ensure_package_local(package_name, import_name=None, prompt=True):
    """Local helper: prompt+install a package via pip and import it.

    Returns imported module or None.
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
        ans = input(f"Dependência '{package_name}' em falta. Instalar agora? [s/N]: ").strip().lower()
    except Exception:
        return None

    if ans not in ("", "s", "sim", "y", "yes"):
        return None

    cmd = [_sys.executable, "-m", "pip", "install", package_name]
    print(f"A executar: {' '.join(cmd)}")
    try:
        res = subprocess.run(cmd)
    except Exception as e:
        print(f"Falha ao executar o pip: {e}")
        return None

    if res.returncode != 0:
        print(f"pip install terminou com o código {res.returncode}")
        return None

    try:
        return importlib.import_module(mod_name)
    except Exception as e:
        print(f"Instalado, mas falhou ao importar {mod_name}: {e}")
        return None


    
# Section: Dependencies
    
# Prompt/install cryptography before importing
_ensure_package_local("cryptography")

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "src" / "data"
KEYS_DIR = DATA_DIR / "keys"
MESSAGES_DIR = DATA_DIR / "messages"
BACKUPS_DIR = DATA_DIR / "backups"



# Section: Key management

def ensure_dirs():
    for p in (KEYS_DIR, MESSAGES_DIR, BACKUPS_DIR):
        p.mkdir(parents=True, exist_ok=True)


def generate_rsa_keys(key_size=2048):
    ensure_dirs()
    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    pub = priv.public_key()

    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    (KEYS_DIR / "private.pem").write_bytes(priv_pem)
    (KEYS_DIR / "public.pem").write_bytes(pub_pem)
    print(f"Chaves geradas em {KEYS_DIR}")


def load_private_key():
    p = KEYS_DIR / "private.pem"
    if not p.exists():
        raise FileNotFoundError("Chave privada não encontrada. Execute init-keys primeiro.")
    return serialization.load_pem_private_key(p.read_bytes(), password=None)


def load_public_key():
    p = KEYS_DIR / "public.pem"
    if not p.exists():
        raise FileNotFoundError("Chave pública não encontrada. Execute init-keys primeiro.")
    return serialization.load_pem_public_key(p.read_bytes())


def hybrid_encrypt(plaintext: bytes) -> Dict[str, str]:
    """Encrypt plaintext with a fresh Fernet key, then encrypt that key with RSA public key.

    Returns a dict with base64-encoded 'key' (encrypted symmetric key) and 'payload' (fernet ciphertext).
    """
    pub = load_public_key()
    fkey = Fernet.generate_key()
    f = Fernet(fkey)
    payload = f.encrypt(plaintext)

    enc_sym_key = pub.encrypt(
        fkey,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    return {
        "key": base64.b64encode(enc_sym_key).decode("ascii"),
        "payload": base64.b64encode(payload).decode("ascii"),
    }


def hybrid_decrypt(b64_enc_sym_key: str, b64_payload: str) -> bytes:
    priv = load_private_key()
    enc_sym_key = base64.b64decode(b64_enc_sym_key)
    sym_key = priv.decrypt(
        enc_sym_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    f = Fernet(sym_key)
    payload = base64.b64decode(b64_payload)
    return f.decrypt(payload)



# Section: Message storage

def store_message(sender: str, recipients: List[str], text: str) -> str:
    ensure_dirs()
    mid = str(uuid.uuid4())
    ts = datetime.utcnow().isoformat() + "Z"
    entry = {
        "id": mid,
        "timestamp": ts,
        "participants": sorted(set([sender] + recipients)),
        "plaintext_hint": text[:64],
    }
    enc = hybrid_encrypt(text.encode("utf-8"))
    entry.update(enc)
    path = MESSAGES_DIR / f"{mid}.msg"
    path.write_text(json.dumps(entry, ensure_ascii=False))
    return mid


def list_messages_for(user: str) -> List[Dict[str, Any]]:
    out = []
    for p in sorted(MESSAGES_DIR.glob("*.msg")):
        try:
            j = json.loads(p.read_text())
        except Exception:
            continue
        if user in j.get("participants", []):
            out.append({"id": j["id"], "timestamp": j.get("timestamp"), "participants": j.get("participants"), "hint": j.get("plaintext_hint")})
    return out


def load_message_file(mid: str) -> Dict[str, Any]:
    p = MESSAGES_DIR / f"{mid}.msg"
    if not p.exists():
        raise FileNotFoundError("mensagem não encontrada")
    return json.loads(p.read_text())


def delete_message(mid: str, actor: str) -> bool:
    j = load_message_file(mid)
    if actor not in j.get("participants", []):
        raise PermissionError("apenas participantes podem apagar uma mensagem")
    p = MESSAGES_DIR / f"{mid}.msg"
    p.unlink()
    return True


def backup_all_sym(password: str) -> Path:
    """Create a password-protected backup file (Fernet with key derived from password).
    Returns path to backup file.
    """
    ensure_dirs()
    # Collect all messages
    archive = {}
    for p in sorted(MESSAGES_DIR.glob("*.msg")):
        archive[p.name] = p.read_text()

    raw = json.dumps(archive, ensure_ascii=False).encode("utf-8")

    # Derive key
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
    f = Fernet(key)
    token = f.encrypt(raw)
    out = {"salt": base64.b64encode(salt).decode("ascii"), "token": base64.b64encode(token).decode("ascii")}
    fname = BACKUPS_DIR / f"backup_sym_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.bk"
    fname.write_text(json.dumps(out))
    return fname


def backup_all_asym() -> Path:
    """Create an asymmetric backup encrypted with server public key."""
    ensure_dirs()
    archive = {}
    for p in sorted(MESSAGES_DIR.glob("*.msg")):
        archive[p.name] = p.read_text()
    raw = json.dumps(archive, ensure_ascii=False).encode("utf-8")
    # Reuse hybrid scheme: encrypt raw with new Fernet, encrypt Fernet key with RSA pub
    pub = load_public_key()
    fkey = Fernet.generate_key()
    f = Fernet(fkey)
    token = f.encrypt(raw)
    enc_sym_key = pub.encrypt(
        fkey,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    out = {"key": base64.b64encode(enc_sym_key).decode("ascii"), "token": base64.b64encode(token).decode("ascii")}
    fname = BACKUPS_DIR / f"backup_asym_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.bk"
    fname.write_text(json.dumps(out))
    return fname


class ThreadedTCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        # Simple line-based JSON protocol
        line = self.rfile.readline().strip()
        if not line:
            return
        try:
            req = json.loads(line.decode("utf-8"))
        except Exception as e:
            self.wfile.write((json.dumps({"status": "error", "error": "json inválido"}) + "\n").encode())
            return

        action = req.get("action")
        try:
            if action == "send":
                sender = req["from"]
                recipients = req.get("to")
                if isinstance(recipients, str):
                    recipients = [recipients]
                text = req["message"]
                mid = store_message(sender, recipients, text)
                resp = {"status": "ok", "id": mid}

            elif action == "list":
                user = req["user"]
                lst = list_messages_for(user)
                resp = {"status": "ok", "messages": lst}

            elif action == "download":
                user = req["user"]
                mid = req["id"]
                j = load_message_file(mid)
                if user not in j.get("participants", []):
                    raise PermissionError("não é participante")
                resp = {"status": "ok", "file": j}

            elif action == "delete":
                user = req["user"]
                mid = req["id"]
                delete_message(mid, user)
                resp = {"status": "ok"}

            elif action == "backup_sym":
                # Admin operation - password supplied
                passwd = req.get("password")
                if not passwd:
                    raise ValueError("palavra-passe obrigatória")
                path = backup_all_sym(passwd)
                resp = {"status": "ok", "path": str(path)}

            elif action == "backup_asym":
                path = backup_all_asym()
                resp = {"status": "ok", "path": str(path)}

            else:
                resp = {"status": "error", "error": "ação desconhecida"}

        except Exception as e:
            resp = {"status": "error", "error": str(e)}

        self.wfile.write((json.dumps(resp, ensure_ascii=False) + "\n").encode("utf-8"))


    
# Section: Server
    
def run_server(host: str, port: int):
    ensure_dirs()
    with socketserver.ThreadingTCPServer((host, port), ThreadedTCPHandler) as srv:
        print(f"Servidor a ouvir em {host}:{port}")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("A encerrar")
            srv.shutdown()



# Section: Client & CLI

def client_send(host: str, port: int, payload: Dict[str, Any]) -> Dict[str, Any]:
    with socket.create_connection((host, port), timeout=10) as s:
        s.sendall((json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8"))
        # read response line
        f = s.makefile("rb")
        line = f.readline()
        if not line:
            raise ConnectionError("sem resposta")
        return json.loads(line.decode("utf-8"))


def print_response(resp: Dict[str, Any]) -> None:
    """Print a response payload in pt-PT."""
    out = dict(resp)
    status = out.pop("status", None)
    if status is not None:
        out["estado"] = "sucesso" if status == "ok" else "erro"
    if "error" in out:
        out["erro"] = out.pop("error")
    print(json.dumps(out, ensure_ascii=False, indent=2))


def main():
    parser = argparse.ArgumentParser(description="Mensageiro seguro simples (servidor+cliente)")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("init-keys", help="gerar par de chaves RSA para o servidor (guarda em data/keys)")

    srv = sub.add_parser("serve", help="executar o servidor")
    srv.add_argument("--host", default="127.0.0.1")
    srv.add_argument("--port", type=int, default=9009)

    send = sub.add_parser("send", help="enviar uma mensagem para o servidor")
    send.add_argument("--host", default="127.0.0.1")
    send.add_argument("--port", type=int, default=9009)
    send.add_argument("--from", dest="from_user", required=True)
    send.add_argument("--to", required=True, help="destinatário ou lista separada por vírgulas")
    send.add_argument("--message", required=True)

    lst = sub.add_parser("list", help="listar mensagens de um utilizador via servidor")
    lst.add_argument("--host", default="127.0.0.1")
    lst.add_argument("--port", type=int, default=9009)
    lst.add_argument("--user", required=True)

    dl = sub.add_parser("download", help="descarregar uma mensagem via servidor")
    dl.add_argument("--host", default="127.0.0.1")
    dl.add_argument("--port", type=int, default=9009)
    dl.add_argument("--user", required=True)
    dl.add_argument("--id", required=True)

    rm = sub.add_parser("delete", help="apagar uma mensagem via servidor")
    rm.add_argument("--host", default="127.0.0.1")
    rm.add_argument("--port", type=int, default=9009)
    rm.add_argument("--user", required=True)
    rm.add_argument("--id", required=True)

    bsym = sub.add_parser("backup-sym", help="criar backup protegido por palavra-passe via servidor")
    bsym.add_argument("--host", default="127.0.0.1")
    bsym.add_argument("--port", type=int, default=9009)
    bsym.add_argument("--password", required=True)

    basym = sub.add_parser("backup-asym", help="criar backup assimétrico via servidor")
    basym.add_argument("--host", default="127.0.0.1")
    basym.add_argument("--port", type=int, default=9009)

    args = parser.parse_args()

    if args.cmd == "init-keys":
        generate_rsa_keys()

    elif args.cmd == "serve":
        run_server(args.host, args.port)

    elif args.cmd == "send":
        recipients = [r.strip() for r in args.to.split(",")]
        payload = {"action": "send", "from": args.from_user, "to": recipients, "message": args.message}
        resp = client_send(args.host, args.port, payload)
        print_response(resp)

    elif args.cmd == "list":
        payload = {"action": "list", "user": args.user}
        print_response(client_send(args.host, args.port, payload))

    elif args.cmd == "download":
        payload = {"action": "download", "user": args.user, "id": args.id}
        print_response(client_send(args.host, args.port, payload))

    elif args.cmd == "delete":
        payload = {"action": "delete", "user": args.user, "id": args.id}
        print_response(client_send(args.host, args.port, payload))

    elif args.cmd == "backup-sym":
        payload = {"action": "backup_sym", "password": args.password}
        print_response(client_send(args.host, args.port, payload))

    elif args.cmd == "backup-asym":
        payload = {"action": "backup_asym"}
        print_response(client_send(args.host, args.port, payload))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
