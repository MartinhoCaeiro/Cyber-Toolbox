"""
Master's in Computer Security Engineering
Dynamic Programming Languages - Scripts Configuration

Author: Martinho Caeiro (23917)

Description:
    Defines the configuration of available scripts, including names, files,
    and required arguments.
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
        "args": [
            ("target", "Alvo (IP ou hostname)"),
            ("duration", "Duração em segundos"),
        ],
    },
    "3": {
        "name": "SYN Flooder",
        "file": "syn_flooder.py",
        "args": [
            ("target", "Alvo (IP ou hostname)"),
            ("duration", "Duração em segundos"),
        ],
    },
    "4": {
        "name": "Log Analyzer",
        "file": "log_analyzer.py",
        "args": [
            ("logs", "Ficheiros de log (ex: a.log b.log)"),
        ],
    },
    "5": {
        "name": "Port Knocker",
        "file": "port_knocker.py",
        "args": [
            ("host", "Host (ex: 192.168.1.100)"),
            ("ports", "Portas (7000 8000 9000)"),
        ],
    },
    "6": {
        "name": "Password Manager",
        "file": "password_manager.py",
        "args": [],
    },
}
