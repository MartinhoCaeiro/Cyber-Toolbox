#!/usr/bin/env python3
"""
Mestrado de Engenharia em Segurança Informatica
Linguagens de Programação Dinamicas - Port Knocker

Martinho Caeiro (23917)

Este script envia uma sequência de pacotes para portas específicas de um servidor remoto para ativar o acesso SSH.

Uso:
    python3 port_knocker.py <host> <porta1> <porta2> <porta3>

Exemplo:
    python3 port_knocker.py 192.168.1.100 7000 8000 9000
"""

import socket
import sys
import time

# =====================
# Port knocking

def send_knock(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"knock", (host, port))
        print(f"Knock enviado para {host}:{port}")
    except Exception as e:
        print(f"Erro ao enviar knock para {host}:{port} - {e}")

# =====================
# Main loop

def main():
    try:
        if len(sys.argv) < 3:
            print("Uso: python3 port_knocker.py <host> <porta1> [porta2 porta3 ...]")
            sys.exit(1)

        host = sys.argv[1]
        try:
            ports = list(map(int, sys.argv[2:]))
        except ValueError:
            print("Uma ou mais portas fornecidas não são válidas (devem ser inteiros).")
            sys.exit(1)

        if not ports:
            print("Nenhuma porta fornecida. Abortando.")
            sys.exit(1)

        for port in ports:
            send_knock(host, port)
            time.sleep(1)  # Pequeno atraso entre os knocks

        print("Sequência de knocks concluída.")
    except KeyboardInterrupt:
        print("\nInterrompido pelo utilizador.")
        sys.exit(1)

if __name__ == "__main__":
    main()
