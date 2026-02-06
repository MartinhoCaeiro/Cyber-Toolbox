#!/usr/bin/env python3
"""
Shared package dependency manager.

Provides a centralized function for ensuring required packages are installed.
"""

import importlib
import subprocess
import sys


def ensure_package(package_name, import_name=None, prompt=True):
    """Ensure a package is installed, optionally prompting for installation.
    
    Args:
        package_name: The package name for pip install
        import_name: The module name for import (if different from package_name)
        prompt: Whether to prompt user for installation if missing
        
    Returns:
        The imported module on success, or None on failure/decline.
    """
    mod_name = import_name or package_name
    
    # Try to import first
    try:
        return importlib.import_module(mod_name)
    except ImportError:
        pass
    
    if not prompt:
        return None
    
    # Ask user if they want to install
    try:
        ans = input(f"Dependência '{package_name}' em falta. Instalar agora? [s/N]: ").strip().lower()
    except Exception:
        return None
    
    if ans not in ("s", "sim", "y", "yes"):
        return None
    
    # Install via pip
    cmd = [sys.executable, "-m", "pip", "install", package_name]
    print(f"A executar: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, check=False)
    except Exception as e:
        print(f"Falha ao executar o pip: {e}")
        return None
    
    if result.returncode != 0:
        print(f"pip install terminou com o código {result.returncode}")
        return None
    
    # Try importing again
    try:
        return importlib.import_module(mod_name)
    except ImportError as e:
        print(f"Instalado, mas falhou ao importar {mod_name}: {e}")
        return None
