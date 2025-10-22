#!/usr/bin/env python3
"""
Mestrado de Engenharia em Segurança Informatica
Linguagens de Programação Dinamicas - Port Knocking

Martinho Caeiro (23917)

Este script envia uma sequência de pacotes para portas específicas de um servidor remoto para ativar o acesso SSH.

Uso:
    python3 port_knocking.py <host> <porta1> <porta2> <porta3>

Exemplo:
    python3 port_knocking.py 192.168.1.100 7000 8000 9000
"""

import socket
import sys
import time

def send_knock(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"knock", (host, port))
        print(f"Knock enviado para {host}:{port}")
    except Exception as e:
        print(f"Erro ao enviar knock para {host}:{port} - {e}")

def main():
    if len(sys.argv) < 5:
        print("Uso: python3 port_knocking.py <host> <porta1> <porta2> <porta3>")
        sys.exit(1)

    host = sys.argv[1]
    ports = list(map(int, sys.argv[2:]))

    for port in ports:
        send_knock(host, port)
        time.sleep(1)  # Pequeno atraso entre os knocks

    print("Sequência de knocks concluída.")

if __name__ == "__main__":
    main()
