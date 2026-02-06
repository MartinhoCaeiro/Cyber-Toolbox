import os
import sys

project = "Cyber-Toolbox"
author = "Martinho Caeiro"
release = "1.0"

sys.path.insert(0, os.path.abspath("../src"))
sys.path.insert(0, os.path.abspath("../src/scripts"))

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
]

templates_path = ["_templates"]
exclude_patterns = []

html_theme = "alabaster"
html_static_path = ["_static"]

language = "pt"

autodoc_default_options = {
    "members": True,
    "undoc-members": False,
    "show-inheritance": True,
}

autodoc_mock_imports = [
    "geoip2",
    "reportlab",
    "scapy",
    "cryptography",
    "pyotp",
    "qrcode",
]

latex_engine = "pdflatex"
latex_elements = {
    "preamble": r"""
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
""",
}
latex_documents = [
    ("index", "srcdoc.tex", "srcdoc", "Martinho Caeiro", "manual"),
]
