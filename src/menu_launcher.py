#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
menu_launcher.py
Menu launcher simples para gerir/lançar scripts na pasta ./scripts

Uso:
    python3 menu_launcher.py
"""

import os
import shlex
import subprocess
import sys
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
        # Use the same Python interpreter as the launcher for portability
        py = sys.executable or "python3"
        cmd = [py, path] + args
    else:
        cmd = [path] + args

    # If no args are passed, assume the script may be interactive and attach
    # stdin/stdout/stderr to the terminal so prompts are visible. If args are
    # present, capture output so we can store the last_result.
    interactive = len(args) == 0

    print(f"\nExecutando: {' '.join(shlex.quote(c) for c in cmd)}\n(CTRL-C para interromper)\n")
    t0 = datetime.now()
    try:
        if interactive:
            proc = subprocess.run(cmd)
            stdout = None
            stderr = None
        else:
            proc = subprocess.run(cmd, capture_output=True, text=True)
            stdout = proc.stdout
            stderr = proc.stderr
    except KeyboardInterrupt:
        print("\nExecução interrompida pelo utilizador.")
        return
    except Exception as e:
        print(f"Erro a executar: {e}")
        return

    duration = (datetime.now() - t0).total_seconds()
    last_result = (path, datetime.now(), stdout, stderr, proc.returncode, duration)

    if not interactive:
        print("--- STDOUT ---")
        print(stdout or "(vazio)")
        if stderr:
            print("--- STDERR ---")
            print(stderr)
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
        print("    ======== MENU PRINCIPAL - CYBER-TOOLBOX =========")
        print("    1 - Port Scanner")
        print("    2 - UDP Flooder")
        print("    3 - SYN Flooder")
        print("    4 - Log Analyzer")
        print("    5 - Messenger")
        print("    6 - Port Knocker")
        print("    7 - Password Manager")
        print("    0 - Sair")
        print("    ==================================================")
        choice = input("    Escolha uma opção: ").strip()

        if choice == "0":
            print("Adeus.")
            break

        menu_map = {
            "1": ("Port Scanner", "port_scanner.py"),
            "2": ("UDP Flooder", "udp_flooder.py"),
            "3": ("SYN Flooder", "syn_flooder.py"),
            "4": ("Log Analyzer", "log_analyzer.py"),
            "5": ("Messenger", "messenger.py"),
            "6": ("Port Knocker", "port_knocker.py"),
            "7": ("Password Manager", "password_manager.py"),
        }

        if choice in menu_map:
            display_name, fname = menu_map[choice]
            script_path = os.path.join(SCRIPTS_DIR, fname)
            if not os.path.isfile(script_path):
                print(f"\nScript '{fname}' não encontrado em {SCRIPTS_DIR}.")
                print("Coloca o ficheiro correspondente na pasta ./src/scripts/ e tenta de novo.")
                input("\nEnter para continuar...")
                continue

            # Special-case the log analyzer so we can collect file arguments and options
            if fname == "log_analyzer.py":
                # list available logs
                log_files = []
                if os.path.isdir(LOGS_DIR):
                    for fn in sorted(os.listdir(LOGS_DIR)):
                        p = os.path.join(LOGS_DIR, fn)
                        if os.path.isfile(p):
                            log_files.append(p)

                print(f"\nLançar {display_name} — prepara argumentos")
                if log_files:
                    print("Ficheiros disponíveis em src/logs:")
                    for i, p in enumerate(log_files, start=1):
                        print(f"  {i}. {os.path.basename(p)}")
                    s = input("Escolhe ficheiros por número (ex: 1,3) ou escreve caminhos separados por espaço (Enter para cancelar): ").strip()
                    if not s:
                        print("Operação cancelada.")
                        input("Enter para continuar...")
                        continue
                    args_files = []
                    # try parse as indices
                    if all(ch.isdigit() or ch in ", " for ch in s):
                        nums = [x.strip() for x in s.split(",") if x.strip()]
                        for n in nums:
                            try:
                                idx = int(n)-1
                                if 0 <= idx < len(log_files):
                                    args_files.append(log_files[idx])
                            except ValueError:
                                pass
                    if not args_files:
                        # treat as paths separated by space
                        parts = shlex.split(s)
                        for p in parts:
                            if os.path.isfile(p):
                                args_files.append(p)
                            else:
                                # try relative to repo root
                                rp = os.path.join(os.getcwd(), p)
                                if os.path.isfile(rp):
                                    args_files.append(rp)
                    if not args_files:
                        print("Nenhum ficheiro válido selecionado.")
                        input("Enter para continuar...")
                        continue
                else:
                    # no logs folder or empty, ask for manual path
                    s = input("Nenhum ficheiro em src/logs. Escreve caminho para o ficheiro de log (Enter para cancelar): ").strip()
                    if not s:
                        print("Operação cancelada.")
                        input("Enter para continuar...")
                        continue
                    if os.path.isfile(s):
                        args_files = [s]
                    else:
                        rp = os.path.join(os.getcwd(), s)
                        if os.path.isfile(rp):
                            args_files = [rp]
                        else:
                            print("Ficheiro não encontrado.")
                            input("Enter para continuar...")
                            continue

                outdir = input("Diretório de saída (default: reports): ").strip() or "reports"
                # propose default geoip DB if exists
                default_geo = os.path.join("src", "data", "GeoLite2-City.mmdb")
                if os.path.isfile(default_geo):
                    geo_suggest = default_geo
                else:
                    geo_suggest = ""
                geo = input(f"Caminho para GeoIP DB (opcional) [default: {geo_suggest}]: ").strip() or geo_suggest

                args = []
                args.extend(args_files)
                args.extend(["-o", outdir])
                if geo:
                    args.extend(["--geoip-db", geo])

                run_script(script_path, args)
                input("\nEnter para continuar...")
            else:
                run_script(script_path, [])
                input("\nEnter para continuar...")
        else:
            print("Escolha inválida. Tenta outra vez.")
            input("Enter...")

if __name__ == "__main__":
    try:
        main_menu()
    except Exception as e:
        print("Erro inesperado:", e)
