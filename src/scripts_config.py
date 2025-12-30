"""
Mestrado de Engenharia em Segurança Informatica
Linguagens de Programação Dinamicas - Scripts Configuration

Martinho Caeiro (23917)

Este módulo define a configuração dos scripts disponíveis, incluindo nomes, ficheiros e argumentos necessários.

"""

SCRIPTS = {
    "1": {
        "name": "Port Scanner",
        "file": "port_scanner.py",
        "args": [
            ("targets", "Alvos (ex: 127.0.0.1,localhost)"),
            ("start_port", "Porta inicial"),
            ("end_port", "Porta final"),
        ],
    },
    "2": {
        "name": "UDP Flooder",
        "file": "udp_flooder.py",
        "args": [],
    },
    "3": {
        "name": "SYN Flooder",
        "file": "syn_flooder.py",
        "args": [],
    },
    "4": {
        "name": "Log Analyzer",
        "file": "log_analyzer.py",
        "args": [
            ("logs", "Ficheiros de log (ex: a.log b.log)"),
        ],
    },
    "5": {
        "name": "Messenger",
        "file": "messenger.py",
        "args": [],
    },
    "6": {
        "name": "Port Knocker",
        "file": "port_knocker.py",
        "args": [
            ("host", "Host (ex: 192.168.1.100)"),
            ("ports", "Portas (7000 8000 9000)"),
        ],
    },
    "7": {
        "name": "Password Manager",
        "file": "password_manager.py",
        "args": [],
    },
}
