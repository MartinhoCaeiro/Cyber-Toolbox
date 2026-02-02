#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Master's in Computer Security Engineering
Dynamic Programming Languages - Port Scanner

Author: Martinho Caeiro (23917)

Description:
    Scans ports on multiple targets to identify which are open.

Usage:
    python3 port_scanner.py <target1,target2,...> <start_port> <end_port>

Example:
    python3 port_scanner.py target1.com,target2.com,127.0.0.1 1 1024
"""

import socket
import sys
import argparse
from datetime import datetime
from pathlib import Path



# Section: Scanner

def scan_host(host, start_port, end_port, timeout=2):
    """Scan ports on a specific host."""
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"Hostname '{host}' não pode ser resolvido")
        return None, []

    open_ports = []
    print(f"\nVarrendo {host} ({ip}) - Portas {start_port} a {end_port}")
    print("-" * 60)

    socket.setdefaulttimeout(timeout)
    
    for port in range(start_port, end_port + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "desconhecido"
                print(f"Porta {port:<6} aberta ({service})")
                open_ports.append(port)
            sock.close()
        except socket.error as e:
            print(f"Erro ao verificar porta {port}: {e}")

    return ip, open_ports



# Section: CLI

def main():
    parser = argparse.ArgumentParser(
        description="Port Scanner - Varre portas em múltiplos hosts remotos",
        epilog="Exemplo: python3 port_scanner.py alvo1.com,alvo2.com 1 1024"
    )
    parser.add_argument("targets", nargs="?", help="Alvos (ex: host1.com,host2.com,192.168.1.1)")
    parser.add_argument("start_port", nargs="?", type=int, help="Porta inicial")
    parser.add_argument("end_port", nargs="?", type=int, help="Porta final")
    parser.add_argument("--timeout", type=float, default=2, help="Timeout de conexão (default: 2)")
    parser.add_argument("--output", "-o", help="Ficheiro de output (relatório)")

    args = parser.parse_args()

    if not args.targets:
        targets_input = input("\nAlvos (ex: host1.com,host2.com,127.0.0.1): ").strip()
        if not targets_input:
            print("Nenhum alvo fornecido. Abortando.")
            sys.exit(1)
        args.targets = targets_input

    if args.start_port is None:
        while True:
            try:
                args.start_port = int(input("Porta inicial: ").strip())
                break
            except ValueError:
                print("Por favor, introduza um número válido.")

    if args.end_port is None:
        while True:
            try:
                args.end_port = int(input("Porta final: ").strip())
                break
            except ValueError:
                print("Por favor, introduza um número válido.")

    # Validation
    if args.start_port < 1 or args.start_port > 65535:
        print(f"Porta inicial deve estar entre 1 e 65535")
        sys.exit(1)
    if args.end_port < 1 or args.end_port > 65535:
        print(f"Porta final deve estar entre 1 e 65535")
        sys.exit(1)
    if args.start_port > args.end_port:
        print(f"Porta inicial não pode ser maior que porta final")
        sys.exit(1)

    # Parse targets (comma-separated list)
    targets = [t.strip() for t in args.targets.split(",")]

    print("=" * 60)
    print("CYBER-TOOLBOX - VARREDOR DE PORTAS")
    print("=" * 60)

    t_start = datetime.now()
    results = {}

    try:
        for target in targets:
            ip, open_ports = scan_host(target, args.start_port, args.end_port, args.timeout)
            if ip:
                results[target] = {"ip": ip, "open_ports": open_ports}
    except KeyboardInterrupt:
        print("\n\nVarrimento interrompido pelo utilizador.")

    # Final report
    print("\n" + "=" * 60)
    print("RELATÓRIO FINAL")
    print("=" * 60)

    for target, data in results.items():
        print(f"\n{target} ({data['ip']})")
        if data["open_ports"]:
            print(f"   Portas abertas: {', '.join(map(str, data['open_ports']))}")
        else:
            print(f"   Nenhuma porta aberta (intervalo: {args.start_port}-{args.end_port})")

    # Total time
    duration = (datetime.now() - t_start).total_seconds()
    print(f"\n Varrimento concluído em {duration:.2f}s")

    # Save to file if requested
    if args.output:
        try:
            import json
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                json.dump({
                    "timestamp": datetime.now().isoformat(),
                    "targets": args.targets,
                    "port_range": [args.start_port, args.end_port],
                    "results": results,
                    "duration_seconds": duration
                }, f, indent=2)
            print(f"Relatório guardado em: {output_path}")
        except Exception as e:
            print(f"Erro ao guardar relatório: {e}")


if __name__ == "__main__":
    main()
