# Cyber Toolbox — Cybersecurity Application

Description
-----------
Cyber Toolbox is a collection of cybersecurity utilities implemented in Python. It was developed as a coursework project for the "Dynamic Programming Languages" course. The project gathers several network testing and security utilities behind a simple command-line interface (CLI).

Note: this repository was previously named "LPD-Tool"; it has been renamed to "Cyber Toolbox".

This repository contains:
- `Relatorio.tex` — the project report (LaTeX) with theoretical background and screenshots.
- Python scripts — the CLI menu (`menu.py`) and individual tool scripts.
- `Recursos/` — resources used by the report (images, logos, bibliography).

Main Features
-------------
- Port Scanner
- UDP Flooder
- SYN Flooder
- Logger (event logging)
- Messenger (simple messaging)
- Port Knocker
- Password Manager

Important — Legal & Ethical Notice
---------------------------------
The tools in this repository include active network testing and attack simulations (e.g., UDP/SYN flooding, port scanning). Using these tools against networks, services, or systems for which you do not have explicit permission is illegal and unethical.

Only use these tools:
- In isolated lab environments (virtual machines, test networks),
- Against systems you own or where you have explicit written authorization,
- For educational or authorized research/testing purposes.

Requirements
------------
- Python 3.8+ (Python 3.10+ recommended)
- pip
- Linux is recommended (Kali Linux was used for development)
- Root/administrator privileges may be required for features that use raw sockets (flooders, packet crafting, low-level port knocking)

Quick Setup
-----------
1. Clone the repository:

```bash
git clone https://github.com/MartinhoCaeiro/LPD-Tool.git
cd LPD-Tool
```

2. (Optional) Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies:
- If a `requirements.txt` file exists:

```bash
pip install -r requirements.txt
```
- If not, the scripts are written to check for required packages at runtime and will offer to install missing dependencies automatically.

Running the Application
-----------------------
Start the main menu:

```bash
python menu.py
# or
python3 menu.py
```

The main menu presents options to run each tool individually:
1 - Port Scanner
2 - UDP Flooder
3 - SYN Flooder
4 - Logger
5 - Messenger
6 - Port Knocker
7 - Password Manager
0 - Exit

You can also run individual tool scripts directly (for example, `python port_scanner.py`) depending on how scripts are organized in the repository.

Permissions
-----------
Some features interact with low-level network interfaces or craft raw packets; these typically require root privileges. To run with elevated permissions:

```bash
sudo python3 menu.py
```

Repository Structure (expected)
-------------------------------
- Relatorio.tex              — Project report (LaTeX)
- Recursos/                  — Images, logos, bibliography
- menu.py                    — CLI entry point
- scripts/                   — Individual tool scripts (port scanner, flooders, logger, etc.)
- requirements.txt (optional) — Python dependencies

Best Practices
--------------
- Test and run tools only in isolated/test environments.
- Use version control (forks/branches) for changes.
- Document changes thoroughly in commits and PRs.

Contributing
------------
Contributions are welcome:
1. Open an issue describing the feature or fix.
2. Fork the repository and create a branch for your changes.
3. Submit a pull request with a clear description and tests when applicable.

Report & References
-------------------
The full project report with theoretical background and screenshots is in `Relatorio.tex`. See the `Recursos/` folder for images and the bibliography file.

Author
------
Martinho José Novo Caeiro — 23917  
Repository: MartinhoCaeiro/LPD-Tool

License
-------
No license file is included in the repository currently. Before using or redistributing the code, confirm the intended license with the author. If you want, a permissive MIT license can be added.

Support / Contact
-----------------
Open an issue on GitHub for questions, feature requests, or bug reports, or consult the project report for author contact details.