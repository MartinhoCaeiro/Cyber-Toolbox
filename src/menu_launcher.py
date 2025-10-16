#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
menu_launcher.py
Menu launcher simples para gerir/lançar scripts na pasta ./scripts

Uso:
    python3 menu_launcher.py
Coloca os teus scripts em ./scripts (ex: tcp_scanner.py).
ATENÇÃO: usa apenas em alvos com autorização explícita.
"""

import os
import shlex
import subprocess
from datetime import datetime

SCRIPTS_DIR = "src/scripts"
LOGS_DIR = "src/logs"

last_result = None  # (script_path, timestamp, stdout, stderr, returncode, duration)

def ensure_dirs():
    os.makedirs(SCRIPTS_DIR, exist_ok=True)
    os.makedirs(LOGS_DIR, exist_ok=True)

def list_scripts():
    files = []
    if not os.path.isdir(SCRIPTS_DIR):
        return files
    for fn in sorted(os.listdir(SCRIPTS_DIR)):
        path = os.path.join(SCRIPTS_DIR, fn)
        if os.path.isfile(path) and (fn.endswith(".py") or os.access(path, os.X_OK)):
            files.append((fn, path))
    return files

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def prompt_index(prompt, max_i):
    while True:
        s = input(prompt).strip()
        if s == "":
            return None
        try:
            i = int(s)
            if 1 <= i <= max_i:
                return i-1
        except ValueError:
            pass
        print("Escolha inválida. Introduz um número da lista ou Enter para cancelar.")

def run_script(path, args):
    global last_result
    base = os.path.basename(path)
    if base.endswith(".py"):
        cmd = ["python3", path] + args
    else:
        cmd = [path] + args

    print(f"\nExecutando: {' '.join(shlex.quote(c) for c in cmd)}\n(CTRL-C para interromper)\n")
    t0 = datetime.now()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except KeyboardInterrupt:
        print("\nExecução interrompida pelo utilizador.")
        return
    except Exception as e:
        print(f"Erro a executar: {e}")
        return
    duration = (datetime.now() - t0).total_seconds()
    last_result = (path, datetime.now(), proc.stdout, proc.stderr, proc.returncode, duration)

    print("--- STDOUT ---")
    print(proc.stdout or "(vazio)")
    if proc.stderr:
        print("--- STDERR ---")
        print(proc.stderr)
    print(f"--- return code: {proc.returncode}  duração: {duration:.2f}s ---\n")

def save_last_result():
    if not last_result:
        print("Nenhum resultado para guardar.")
        return
    path, ts, stdout, stderr, rc, duration = last_result
    base = os.path.basename(path)
    fname = f"{ts.strftime('%Y%m%d_%H%M%S')}__{base}.log"
    out = os.path.join(LOGS_DIR, fname)
    with open(out, "w", encoding="utf-8") as f:
        f.write(f"# Script: {path}\n# Timestamp: {ts.isoformat()}\n# Return code: {rc}\n# Duração: {duration:.2f}s\n\n")
        f.write("=== STDOUT ===\n")
        f.write(stdout or "")
        f.write("\n\n=== STDERR ===\n")
        f.write(stderr or "")
    print(f"Guardado em: {out}")

def show_last_result():
    if not last_result:
        print("Nenhum resultado disponível.")
        return
    path, ts, stdout, stderr, rc, duration = last_result
    print(f"Último: {path}  Timestamp: {ts.isoformat()}  RC: {rc}  Duração: {duration:.2f}s")
    print("\n--- STDOUT ---")
    print(stdout or "(vazio)")
    if stderr:
        print("\n--- STDERR ---")
        print(stderr)

def main_menu():
    ensure_dirs()
    while True:
        clear_screen()
        print("="*60)
        print(" MENU launcher — scripts em ./scripts")
        print(" ATENÇÃO: usa apenas em alvos com autorização explícita.")
        print("="*60)
        print("1) Listar scripts")
        print("2) Executar script")
        print("3) Ver último resultado")
        print("4) Guardar último resultado em ./logs/")
        print("5) Ver ficheiros em ./logs/")
        print("6) Sair")
        print()
        choice = input("Escolhe opção [1-6]: ").strip()
        if choice == "1":
            scripts = list_scripts()
            print("\nScripts encontrados:")
            if not scripts:
                print("  (nenhum). Coloca ficheiros em ./scripts/")
            else:
                for i, (fn, p) in enumerate(scripts, start=1):
                    print(f"  {i}) {fn}")
            input("\nEnter para voltar ao menu...")
        elif choice == "2":
            scripts = list_scripts()
            if not scripts:
                print("\nNenhum script em ./scripts/. Coloca um ficheiro e tenta de novo.")
                input("Enter...")
                continue
            print("\nEscolhe um script:")
            for i, (fn, p) in enumerate(scripts, start=1):
                print(f"  {i}) {fn}")
            idx = prompt_index("Número (enter para cancelar): ", len(scripts))
            if idx is None:
                continue
            fn, path = scripts[idx]
            raw = input("Argumentos (ex: 127.0.0.1 1 1024) — enter = sem argumentos:\n> ").strip()
            args = shlex.split(raw) if raw else []
            run_script(path, args)
            input("Enter para continuar...")
        elif choice == "3":
            print()
            show_last_result()
            input("\nEnter...")
        elif choice == "4":
            save_last_result()
            input("\nEnter...")
        elif choice == "5":
            logs = sorted(os.listdir(LOGS_DIR)) if os.path.isdir(LOGS_DIR) else []
            print("\nLogs em ./logs/:")
            if not logs:
                print("  (nenhum)")
            else:
                for fn in logs:
                    print("  -", fn)
            input("\nEnter...")
        elif choice == "6":
            print("Adeus.")
            break
        else:
            print("Escolha inválida. Tenta outra vez.")
            input("Enter...")

if __name__ == "__main__":
    try:
        main_menu()
    except Exception as e:
        print("Erro inesperado:", e)
