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
    try:
        # If called with arguments, preserve original CLI behavior
        if len(sys.argv) >= 3:
            host = sys.argv[1]
            try:
                ports = list(map(int, sys.argv[2:]))
            except ValueError:
                print("Uma ou mais portas fornecidas não são válidas (devem ser inteiros).")
                sys.exit(1)
        else:
            # Interactive mode (used when invoked from the menu without args)
            print("Modo interativo: fornece o host e as portas para o Port Knocker.")
            host = input("Host (ex: 192.168.1.100): ").strip()
            if not host:
                print("Host não fornecido. Abortando.")
                sys.exit(1)
            raw = input("Portas (separadas por espaços ou vírgulas, ex: 7000 8000 9000): ").strip()
            if not raw:
                print("Nenhuma porta fornecida. Abortando.")
                sys.exit(1)
            parts = [p for p in raw.replace(',', ' ').split() if p]
            ports = []
            for p in parts:
                try:
                    ports.append(int(p))
                except ValueError:
                    print(f"Porta inválida ignorada: {p}")
            if not ports:
                print("Nenhuma porta válida fornecida. Abortando.")
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
