#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Master's in Computer Security Engineering
Dynamic Programming Languages - Menu Launcher

Author: Martinho Caeiro (23917)

Description:
    Simple menu launcher to manage/run scripts in the ./scripts folder.

Usage:
    python3 menu_launcher.py

Example:
    python3 menu_launcher.py
"""

import os
import sys
import subprocess

from scripts_config import SCRIPTS

SCRIPTS_DIR = "src/scripts"


# Section: Helpers

def ensure_dirs():
    os.makedirs(SCRIPTS_DIR, exist_ok=True)


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def show_menu():
    print("======== MENU PRINCIPAL - CYBER TOOLBOX ========")
    for key, cfg in sorted(SCRIPTS.items()):
        print(f"{key} - {cfg['name']}")
    print("0 - Sair")
    print("===============================================")


def prompt_args(arg_defs):
    args = []

    for _, label in arg_defs:
        value = input(f"{label}: ").strip()
        if not value:
            print("Argumento obrigatório não fornecido.")
            return None

        args.extend(value.replace(",", " ").split())

    return args



# Section: Script execution

def run_script(path, args):
    py = sys.executable or "python3"
    cmd = [py, path] + args

    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\nExecução interrompida.")



# Section: Main loop

def main_menu():
    ensure_dirs()

    while True:
        clear_screen()
        show_menu()

        choice = input("Escolha uma opção: ").strip()

        if choice == "0":
            print("Adeus.")
            break

        cfg = SCRIPTS.get(choice)
        if not cfg:
            input("Opção inválida. Enter para continuar...")
            continue

        script_path = os.path.join(SCRIPTS_DIR, cfg["file"])
        if not os.path.isfile(script_path):
            input(f"Script não encontrado: {cfg['file']}\nEnter...")
            continue

        args = prompt_args(cfg.get("args", []))
        if args is None:
            input("Operação cancelada. Enter...")
            continue

        run_script(script_path, args)
        input("\nEnter para continuar...")


if __name__ == "__main__":
    try:
        main_menu()
    except Exception as e:
        print("Erro inesperado:", e)
