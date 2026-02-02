#!/usr/bin/env python3
"""
Generate LaTeX documentation from Python source files.

This script extracts docstrings, function signatures, and section comments
from Python files and generates a LaTeX document (srcdoc.tex) that can be
compiled to PDF.
"""

import ast
import os
import re
from pathlib import Path
from typing import List, Dict, Tuple


def escape_latex(text: str) -> str:
    """Escape special LaTeX characters in text."""
    replacements = {
        '\\': r'\textbackslash{}',
        '{': r'\{',
        '}': r'\}',
        '$': r'\$',
        '&': r'\&',
        '%': r'\%',
        '#': r'\#',
        '_': r'\_',
        '~': r'\textasciitilde{}',
        '^': r'\textasciicircum{}',
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text


def extract_module_docstring(filepath: Path) -> str:
    """Extract the module-level docstring from a Python file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read(), filename=str(filepath))
            docstring = ast.get_docstring(tree)
            return docstring or ""
    except Exception as e:
        print(f"Error parsing {filepath}: {e}")
        return ""


def parse_docstring(docstring: str) -> Dict[str, str]:
    """Parse structured docstring into sections."""
    sections = {
        'description': '',
        'author': '',
        'usage': '',
        'example': '',
        'features': '',
        'note': ''
    }
    
    lines = docstring.split('\n')
    current_section = 'description'
    current_content = []
    
    for line in lines:
        line_lower = line.strip().lower()
        
        if line_lower.startswith('author:'):
            if current_content:
                sections[current_section] = '\n'.join(current_content).strip()
            current_section = 'author'
            current_content = [line.strip()[7:].strip()]
        elif line_lower.startswith('description:'):
            if current_content:
                sections[current_section] = '\n'.join(current_content).strip()
            current_section = 'description'
            current_content = []
        elif line_lower.startswith('usage:'):
            if current_content:
                sections[current_section] = '\n'.join(current_content).strip()
            current_section = 'usage'
            current_content = []
        elif line_lower.startswith('example:') or line_lower.startswith('examples:'):
            if current_content:
                sections[current_section] = '\n'.join(current_content).strip()
            current_section = 'example'
            current_content = []
        elif line_lower.startswith('features:'):
            if current_content:
                sections[current_section] = '\n'.join(current_content).strip()
            current_section = 'features'
            current_content = []
        elif line_lower.startswith('note:'):
            if current_content:
                sections[current_section] = '\n'.join(current_content).strip()
            current_section = 'note'
            current_content = []
        else:
            if line.strip():
                current_content.append(line.strip())
    
    if current_content:
        sections[current_section] = '\n'.join(current_content).strip()
    
    return sections


def extract_functions_and_classes(filepath: Path) -> List[Tuple[str, str, str]]:
    """Extract function and class definitions with their docstrings."""
    items = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read(), filename=str(filepath))
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    name = node.name
                    # Skip private functions
                    if name.startswith('_') and not name.startswith('__'):
                        continue
                    
                    # Get signature
                    args = []
                    for arg in node.args.args:
                        args.append(arg.arg)
                    signature = f"{name}({', '.join(args)})"
                    
                    # Get docstring
                    docstring = ast.get_docstring(node) or ""
                    
                    items.append(('function', signature, docstring))
                    
                elif isinstance(node, ast.ClassDef):
                    name = node.name
                    docstring = ast.get_docstring(node) or ""
                    items.append(('class', name, docstring))
    except Exception as e:
        print(f"Error extracting from {filepath}: {e}")
    
    return items


def extract_sections(filepath: Path) -> List[str]:
    """Extract section comments from source file."""
    sections = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                # Look for section headers
                if '# Section:' in line or '# =============' in line:
                    match = re.search(r'# Section:\s*(.+)', line)
                    if match:
                        sections.append(match.group(1).strip())
    except Exception:
        pass
    return sections


def generate_latex_for_file(filepath: Path, relative_path: str) -> str:
    """Generate LaTeX content for a single Python file."""
    latex = []
    
    # Extract module docstring
    docstring = extract_module_docstring(filepath)
    if not docstring:
        return ""
    
    # Parse docstring
    sections = parse_docstring(docstring)
    
    # Title
    filename = filepath.stem
    latex.append(f"\\subsection{{{escape_latex(filename)}}}")
    latex.append(f"\\label{{sec:{filename}}}")
    latex.append("")
    
    # File path
    latex.append(f"\\textbf{{Ficheiro:}} \\texttt{{{escape_latex(relative_path)}}}")
    latex.append("")
    
    # Author
    if sections['author']:
        latex.append(f"\\textbf{{Autor:}} {escape_latex(sections['author'])}")
        latex.append("")
    
    # Description
    if sections['description']:
        latex.append(f"\\textbf{{Descrição:}}")
        latex.append("")
        for line in sections['description'].split('\n'):
            if line.strip():
                latex.append(escape_latex(line.strip()))
        latex.append("")
    
    # Features
    if sections['features']:
        latex.append(f"\\textbf{{Funcionalidades:}}")
        latex.append("\\begin{itemize}")
        for line in sections['features'].split('\n'):
            line = line.strip()
            if line.startswith('-'):
                latex.append(f"    \\item {escape_latex(line[1:].strip())}")
            elif line:
                latex.append(f"    \\item {escape_latex(line)}")
        latex.append("\\end{itemize}")
        latex.append("")
    
    # Usage
    if sections['usage']:
        latex.append(f"\\textbf{{Uso:}}")
        latex.append("\\begin{verbatim}")
        latex.append(sections['usage'])
        latex.append("\\end{verbatim}")
        latex.append("")
    
    # Example
    if sections['example']:
        latex.append(f"\\textbf{{Exemplo:}}")
        latex.append("\\begin{verbatim}")
        latex.append(sections['example'])
        latex.append("\\end{verbatim}")
        latex.append("")
    
    # Note
    if sections['note']:
        latex.append(f"\\textbf{{Nota:}}")
        latex.append("")
        for line in sections['note'].split('\n'):
            if line.strip():
                latex.append(escape_latex(line.strip()))
        latex.append("")
    
    # Sections in code
    code_sections = extract_sections(filepath)
    if code_sections:
        latex.append(f"\\textbf{{Secções do código:}}")
        latex.append("\\begin{itemize}")
        for section in code_sections:
            latex.append(f"    \\item {escape_latex(section)}")
        latex.append("\\end{itemize}")
        latex.append("")
    
    # Functions and classes
    items = extract_functions_and_classes(filepath)
    public_items = [(t, s, d) for t, s, d in items if not s.startswith('_')]
    
    if public_items:
        latex.append(f"\\textbf{{Funções e Classes principais:}}")
        latex.append("\\begin{itemize}")
        for item_type, signature, docstring in public_items:
            if item_type == 'function':
                latex.append(f"    \\item \\texttt{{{escape_latex(signature)}}}")
            else:
                latex.append(f"    \\item Classe: \\texttt{{{escape_latex(signature)}}}")
            if docstring:
                first_line = docstring.split('\n')[0].strip()
                if first_line:
                    latex.append(f"    \\\\ {escape_latex(first_line)}")
        latex.append("\\end{itemize}")
        latex.append("")
    
    latex.append("\\newpage")
    return '\n'.join(latex)


def generate_srcdoc():
    """Generate the complete LaTeX source documentation."""
    
    # Project root
    project_root = Path(__file__).parent
    src_dir = project_root / "src"
    scripts_dir = src_dir / "scripts"
    
    # LaTeX document start
    latex_doc = [
        r"\documentclass[a4paper,11pt]{article}",
        r"\usepackage[utf8]{inputenc}",
        r"\usepackage[T1]{fontenc}",
        r"\usepackage[portuguese]{babel}",
        r"\usepackage{geometry}",
        r"\geometry{a4paper, margin=2.5cm}",
        r"\usepackage{hyperref}",
        r"\usepackage{listings}",
        r"\usepackage{xcolor}",
        r"\usepackage{graphicx}",
        r"\usepackage{setspace}",
        r"\onehalfspacing",
        r"",
        r"% Hyperlink colors",
        r"\hypersetup{",
        r"    colorlinks=true,",
        r"    linkcolor=blue,",
        r"    urlcolor=blue,",
        r"    citecolor=blue",
        r"}",
        r"",
        r"\title{Cyber-Toolbox \\ Documentação do Código-Fonte}",
        r"\author{Martinho Caeiro (23917) \\ Mestrado de Engenharia em Segurança Informática}",
        r"\date{\today}",
        r"",
        r"\begin{document}",
        r"",
        r"\maketitle",
        r"\tableofcontents",
        r"\newpage",
        r"",
        r"\section{Introdução}",
        r"Este documento contém a documentação técnica extraída do código-fonte do projeto Cyber-Toolbox.",
        r"Todos os scripts foram desenvolvidos em Python 3 com comentários em inglês e mensagens de saída em português (pt-PT).",
        r"",
        r"\section{Menu Principal}",
        r"",
    ]
    
    # Process menu_launcher.py
    menu_file = src_dir / "menu_launcher.py"
    if menu_file.exists():
        content = generate_latex_for_file(menu_file, "src/menu_launcher.py")
        if content:
            latex_doc.append(content)
    
    # Process scripts_config.py
    config_file = src_dir / "scripts_config.py"
    if config_file.exists():
        content = generate_latex_for_file(config_file, "src/scripts_config.py")
        if content:
            latex_doc.append(content)
    
    latex_doc.append(r"\section{Scripts Individuais}")
    latex_doc.append("")
    
    # Process all scripts in scripts directory
    if scripts_dir.exists():
        script_files = sorted(scripts_dir.glob("*.py"))
        for script_file in script_files:
            if script_file.name == "__init__.py":
                continue
            
            relative_path = f"src/scripts/{script_file.name}"
            content = generate_latex_for_file(script_file, relative_path)
            if content:
                latex_doc.append(content)
    
    # End document
    latex_doc.append(r"\end{document}")
    
    # Write to file
    output_file = project_root / "docs" / "srcdoc.tex"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(latex_doc))
    
    print(f"✓ Documentação LaTeX gerada: {output_file}")
    print(f"\nPara compilar para PDF, execute:")
    print(f"  cd \"{project_root / 'docs'}\"")
    print(f"  pdflatex srcdoc.tex")
    print(f"  pdflatex srcdoc.tex  (segunda vez para gerar o índice)")
    print(f"\nOu use um editor LaTeX como TeXstudio, Overleaf, ou VS Code com extensão LaTeX Workshop.")


if __name__ == "__main__":
    generate_srcdoc()
