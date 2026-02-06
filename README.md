# Cyber Toolbox — Cybersecurity Application

Description
-----------
Cyber Toolbox is a collection of cybersecurity utilities implemented in Python. It was developed as a coursework project for the "Dynamic Programming Languages" course. The project gathers several network testing and security utilities behind a simple command-line interface (CLI).

This repository contains:
- `src/` — Python scripts including the CLI menu launcher and individual tool scripts.
- `docs/` — Sphinx documentation and PDF build scripts.
- `LaTeX Report/` — the project report (LaTeX) with theoretical background and screenshots.
- `presentation/` — project presentation slides.
- `manual/` — manual documentation (LaTeX).
- `logs/` — log files directory.
- `reports/` — generated reports directory.

Main Features
-------------
- Port Scanner — Network port scanning and discovery
- UDP Flooder — UDP-based network flooding simulation
- SYN Flooder — TCP SYN-based network flooding simulation
- Log Analyzer — Parse and analyze log files
- Port Knocker — Port knocking utility for network access
- Password Manager — Secure password management with encryption
- Package Manager — System package management utility

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

Dependencies
------------
The project requires the following Python packages (see `src/requirements.txt`):
- geoip2>=4.5.0 — GeoIP geolocation database support
- cryptography>=3.4 — Cryptographic operations for password manager
- pyotp>=2.8.0 — One-Time Password (TOTP/HOTP) support
- scapy>=2.4.5 — Network packet crafting and analysis
- reportlab>=3.6.0 — PDF report generation
- qrcode>=7.3 — QR code generation

Quick Setup
-----------
1. Clone the repository:

```bash
git clone https://github.com/MartinhoCaeiro/Cyber-Toolbox.git
cd Cyber-Toolbox
```

2. Install dependencies:

```bash
pip install -r src/requirements.txt
```

3. (Optional) Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r src/requirements.txt
```

Running the Application
-----------------------
Start the main menu from the project root:

```bash
python src/menu_launcher.py
# or
python3 src/menu_launcher.py
```

The main menu presents options to run each tool individually:
1 - Port Scanner
2 - UDP Flooder
3 - SYN Flooder
4 - Log Analyzer
5 - Port Knocker
6 - Password Manager
0 - Sair (Exit)

Permissions
-----------
Some features interact with low-level network interfaces or craft raw packets; these typically require root privileges. To run with elevated permissions:

```bash
sudo python3 src/menu_launcher.py
```

Repository Structure
--------------------
```
Cyber-Toolbox/
├── README.md                        — This file
├── LICENSE                          — License information
├── docs/                            — Sphinx documentation
│   ├── conf.py                      — Sphinx configuration
│   ├── index.rst                    — Documentation index
│   ├── modules.rst                  — Modules documentation
│   ├── build_pdf.ps1                — PDF build script
│   ├── srcdocs.pdf                  — Generated PDF documentation
│   ├── requirements.txt             — Documentation dependencies
│   ├── _build/                      — Build output directory
│   ├── _static/                     — Static assets
│   └── _templates/                  — Documentation templates
├── presentation/                    — Project presentation
│   └── apresentação.pptx            — PowerPoint presentation
├── LaTeX Report/                    — Project report (LaTeX source)
│   ├── Relatorio.tex                — Main report file
│   └── Recursos/                    — Images, logos, bibliography
├── manual/                          — Manual documentation (LaTeX)
├── logs/                            — Log files directory
├── reports/                         — Generated reports directory
└── src/
    ├── menu_launcher.py             — CLI entry point / main menu
    ├── scripts_config.py            — Script configuration and definitions
    ├── requirements.txt             — Python package dependencies
    ├── data/
    │   └── GeoLite2-City.mmdb       — GeoIP geolocation database
    └── scripts/
        ├── port_scanner.py          — Network port scanning utility
        ├── udp_flooder.py           — UDP flooding simulation
        ├── syn_flooder.py           — TCP SYN flooding simulation
        ├── log_analyzer.py          — Log file parsing and analysis
        ├── port_knocker.py          — Port knocking utility
        ├── password_manager.py      — Secure password manager
        └── package_manager.py       — System package management
```

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

Documentation
-------------
- **Project Report**: Full LaTeX report with theoretical background in `LaTeX Report/Relatorio.tex`
- **API Documentation**: Sphinx-generated documentation in `docs/` (build with `docs/build_pdf.ps1`)
- **Manual**: User manual in `manual/manual.tex`
- **Presentation**: Project presentation in `presentation/apresentação.pptx`

Author
------
Martinho José Novo Caeiro — 23917  

Support / Contact
-----------------
Open an issue on GitHub for questions, feature requests, or bug reports, or consult the project report for author contact details.

License
-------
This repository is licensed under the GNU General Public License v3.0 (GPL-3.0).
