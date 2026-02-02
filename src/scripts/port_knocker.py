#!/usr/bin/env python3
"""
Master's in Computer Security Engineering
Dynamic Programming Languages - Port Knocker

Author: Martinho Caeiro (23917)

Description:
    Sends a sequence of packets to specific ports of a remote server to enable SSH access.

Usage:
    python3 port_knocker.py <host> <port1> <port2> <port3>

Example:
    python3 port_knocker.py 192.168.1.100 7000 8000 9000
"""

import socket
import sys
import time


# Section: Port knocking

def send_knock(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"knock", (host, port))
        print(f"Knock enviado para {host}:{port}")
    except Exception as e:
        print(f"Erro ao enviar knock para {host}:{port} - {e}")


# Section: Main loop

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
            time.sleep(1)  # Small delay between knocks

        print("Sequência de knocks concluída.")
    except KeyboardInterrupt:
        print("\nInterrompido pelo utilizador.")
        sys.exit(1)

if __name__ == "__main__":
    main()
