#!/usr/bin/env python3
"""
Mestrado de Engenharia em Segurança Informatica
Linguagens de Programação Dinamicas - Port Scanner

Martinho Caeiro (23917)

Este script varre portas em múltiplos alvos para identificar quais estão abertas.

Uso:
    python3 port_scanner.py <alvo1,alvo2,...> <porta_inicial> <porta_final>

Exemplo:
    python3 port_scanner.py alvo1.com,alvo2.com 1 1024
"""

import asyncio
import sys

async def scan_port(target, port):
    try:
        reader, writer = await asyncio.open_connection(target, port)
        writer.close()
        await writer.wait_closed()
        return port
    except:
        return None

async def scan_target(target, start_port, end_port):
    """Varre um intervalo de portas em um alvo."""
    print(f"\nScanning {target} (ports {start_port}-{end_port})...")
    open_ports = []

    tasks = [scan_port(target, port) for port in range(start_port, end_port + 1)]
    results = await asyncio.gather(*tasks)

    open_ports = [port for port in results if port]

    if open_ports:
        print(f"Portas abertas em {target}: {', '.join(map(str, open_ports))}")
    else:
        print(f"Nenhuma porta aberta encontrada em {target}.")

async def main():
    try:
        # CLI mode: expect exactly 3 args (targets, start_port, end_port)
        if len(sys.argv) == 4:
            targets = sys.argv[1].split(",")
            try:
                start_port = int(sys.argv[2])
                end_port = int(sys.argv[3])
            except ValueError:
                print("As portas devem ser números inteiros.")
                sys.exit(1)
        else:
            # Interactive mode for menu compatibility
            print("Modo interativo: fornece alvos e intervalo de portas.")
            raw_targets = input("Alvos (separados por vírgula, ex: 127.0.0.1,localhost): ").strip()
            if not raw_targets:
                print("Nenhum alvo fornecido. Abortando.")
                sys.exit(1)
            targets = [t.strip() for t in raw_targets.split(",") if t.strip()]

            raw_start = input("Porta inicial (ex: 1): ").strip()
            raw_end = input("Porta final (ex: 1024): ").strip()
            try:
                start_port = int(raw_start)
                end_port = int(raw_end)
            except ValueError:
                print("Portas inválidas. Devem ser números inteiros.")
                sys.exit(1)

        if start_port < 1 or end_port < 1 or start_port > 65535 or end_port > 65535:
            print("Portas devem estar no intervalo 1-65535.")
            sys.exit(1)
        if start_port > end_port:
            print("Porta inicial maior que porta final. Abortando.")
            sys.exit(1)

        for target in targets:
            await scan_target(target, start_port, end_port)
    except KeyboardInterrupt:
        print("\nInterrompido pelo utilizador.")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())