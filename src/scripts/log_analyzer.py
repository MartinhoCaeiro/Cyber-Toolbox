#!/usr/bin/env python3
"""
Master's in Computer Security Engineering
Dynamic Programming Languages - Log Analyzer

Author: Martinho Caeiro (23917)

Description:
    Analyze Apache/Nginx access logs and OpenSSH auth logs.
    Extracts IP, timestamp, service, status, and details.
    Optionally resolves country via GeoLite2 database and generates JSON/CSV/PDF reports.

Usage:
    python3 log_analyzer.py --files LOG_FILE ... --outdir OUTPUT_DIR [--geoip-db MMDB_PATH]

Example:
    python3 log_analyzer.py --files access.log auth.log --outdir reports
    python3 log_analyzer.py --files access.log --outdir reports --geoip-db data/GeoLite2-City.mmdb

Formats:
    - Apache/Nginx combined log format
    - OpenSSH auth.log syslog format
    - UFW (Uncomplicated Firewall) log format
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional

from package_manager import ensure_package


# Section: Dependencies

geoip2 = None
reportlab = None
colors = None
A4 = None
landscape = None
getSampleStyleSheet = None
inch = None
SimpleDocTemplate = None
Table = None
TableStyle = None
Paragraph = None
Spacer = None


def init_optional_deps():
    """Load optional dependencies only when executing the script."""
    global geoip2
    global reportlab, colors, A4, landscape, getSampleStyleSheet, inch
    global SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer

    if geoip2 is None:
        ensure_package("geoip2")
        try:
            import geoip2 as geoip2_module  # type: ignore
            import geoip2.database  # type: ignore
            geoip2 = geoip2_module
        except Exception:
            geoip2 = None

    if reportlab is None:
        ensure_package("reportlab")
        try:
            from reportlab.lib import colors as colors_lib
            from reportlab.lib.pagesizes import A4 as A4_size, landscape as landscape_func
            from reportlab.lib.styles import getSampleStyleSheet as get_style_sheet
            from reportlab.lib.units import inch as inch_unit
            from reportlab.platypus import SimpleDocTemplate as doc_template, Table as table_class, TableStyle as table_style, Paragraph as paragraph_class, Spacer as spacer_class
            
            colors = colors_lib
            A4 = A4_size
            landscape = landscape_func
            getSampleStyleSheet = get_style_sheet
            inch = inch_unit
            SimpleDocTemplate = doc_template
            Table = table_class
            TableStyle = table_style
            Paragraph = paragraph_class
            Spacer = spacer_class
            reportlab = True
        except Exception:
            reportlab = None



# Section: Patterns

APACHE_RE = re.compile(r"(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<request>[^\"]*)\" (?P<status>\d{3}) (?P<size>\S+)(?: \"(?P<referrer>[^\"]*)\" \"(?P<agent>[^\"]*)\")?")

SSH_RE = re.compile(r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<svc>sshd)\[\d+\]:\s+(?P<msg>.*)")
IP_IN_MSG_RE = re.compile(r"from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)")

# UFW / kernel firewall log lines (SRC/DST/PROTO/SPT/DPT etc.)
UFW_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<proc>[^:]+):\s*(?:\[[^\]]+\]\s*)*\[UFW\s+(?P<action>\w+)\](?P<rest>.*)$"
)
UFW_KV_RE = re.compile(r"(SRC|DST|PROTO|SPT|DPT)=([^\s]+)")



# Section: Resolvers

class GeoIPResolver:
    def __init__(self, db_path: Optional[str] = None):
        self.reader = None
        if db_path and geoip2:
            try:
                self.reader = geoip2.database.Reader(db_path)
            except Exception:
                print(f"Aviso: não foi possível abrir a BD GeoIP em {db_path}", file=sys.stderr)

    def country_for(self, ip: str) -> str:
        if self.reader:
            try:
                rec = self.reader.country(ip)
                name = rec.country.name or rec.country.iso_code or "DESCONHECIDO"
                return name
            except Exception:
                return "DESCONHECIDO"
        return "DESCONHECIDO"



# Section: Parsers

def parse_apache_line(line: str) -> Optional[Dict]:
    m = APACHE_RE.search(line)
    if not m:
        return None
    gd = m.groupdict()
    # Example time: 10/Oct/2000:13:55:36 -0700
    try:
        dt = datetime.strptime(gd["time"], "%d/%b/%Y:%H:%M:%S %z")
        ts = dt.isoformat()
    except Exception:
        ts = gd["time"]
    request = gd.get("request") or ""
    method, path = (None, None)
    if request:
        parts = request.split()
        if len(parts) >= 2:
            method, path = parts[0], parts[1]
    return {
        "service": "http",
        "ip": gd.get("ip"),
        "timestamp": ts,
        "method": method,
        "path": path,
        "status": gd.get("status"),
        "size": gd.get("size"),
        "raw": line.strip(),
    }


def parse_ssh_line(line: str) -> Optional[Dict]:
    m = SSH_RE.search(line)
    if not m:
        return None
    gd = m.groupdict()
    ip = None
    im = IP_IN_MSG_RE.search(gd.get("msg", ""))
    if im:
        ip = im.group("ip")
    # Build timestamp: syslog entries don't include year; assume current year
    year = datetime.now(timezone.utc).year
    ts_str = f"{gd['month']} {gd['day']} {year} {gd['time']}"
    try:
        ts = datetime.strptime(ts_str, "%b %d %Y %H:%M:%S").isoformat()
    except Exception:
        ts = ts_str
    msg = gd.get("msg", "")
    status = "unknown"
    if "Failed password" in msg or "Invalid user" in msg:
        status = "failed"
    if "Accepted" in msg:
        status = "success"
    return {
        "service": "ssh",
        "ip": ip,
        "timestamp": ts,
        "status": status,
        "raw": line.strip(),
        "msg": msg,
    }


def parse_ufw_line(line: str) -> Optional[Dict]:
    m = UFW_RE.search(line)
    if not m:
        return None
    gd = m.groupdict()
    rest = gd.get("rest", "")
    kv = { }
    for km, mv in UFW_KV_RE.findall(rest):
        kv[km] = mv
    # Build timestamp: syslog entries don't include year; assume current year
    year = datetime.now(timezone.utc).year
    ts_str = f"{gd['month']} {gd['day']} {year} {gd['time']}"
    try:
        ts = datetime.strptime(ts_str, "%b %d %Y %H:%M:%S").isoformat()
    except Exception:
        ts = ts_str
    return {
        "service": "ufw",
        "ip": kv.get("SRC"),
        "dst": kv.get("DST"),
        "proto": kv.get("PROTO"),
        "spt": kv.get("SPT"),
        "dpt": kv.get("DPT"),
        "action": gd.get("action"),
        "timestamp": ts,
        "raw": line.strip(),
    }



# Section: Reporting

def create_pdf_report(events: List[Dict], pdf_path: str, title: str):
    """Generate a PDF report from events using reportlab."""
    if not reportlab:
        print(f"Aviso: reportlab não está disponível, a saltar criação do PDF {pdf_path}", file=sys.stderr)
        return

    # Type assertions for IDE/checker - reportlab is confirmed to be loaded above
    assert SimpleDocTemplate is not None
    assert landscape is not None
    assert A4 is not None
    assert getSampleStyleSheet is not None
    assert Paragraph is not None
    assert Spacer is not None
    assert inch is not None
    assert Table is not None
    assert TableStyle is not None
    assert colors is not None

    doc = SimpleDocTemplate(pdf_path, pagesize=landscape(A4))
    elements = []
    styles = getSampleStyleSheet()

    # Title
    title_para = Paragraph(f"<b>{title}</b>", styles['Title'])
    elements.append(title_para)
    elements.append(Spacer(1, 0.3*inch))

    if not events:
        no_data = Paragraph("Sem eventos para apresentar", styles['Normal'])
        elements.append(no_data)
        doc.build(elements)
        return

    # Prepare table data
    keys = ["service", "ip", "country", "timestamp", "status", "action", "method", "path"]
    headers = ["Serviço", "IP", "País", "Timestamp", "Estado", "Ação", "Método", "Caminho"]
    
    data = [headers]
    for ev in events:
        row = []
        for k in keys:
            val = ev.get(k, "")
            if val is None:
                val = ""
            # Truncate long values
            val_str = str(val)
            if len(val_str) > 40:
                val_str = val_str[:37] + "..."
            row.append(val_str)
        data.append(row)

    # Create table
    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
    ]))

    elements.append(table)
    doc.build(elements)


def analyze_files(file_paths: List[str], geoip_db: Optional[str], outdir: str) -> List[Dict]:
    resolver = GeoIPResolver(geoip_db)
    # We'll produce one report per input file (name derived from original filename)
    os.makedirs(outdir, exist_ok=True)
    all_events: List[Dict] = []

    for path in file_paths:
        if not os.path.isfile(path):
            print(f"A ignorar ficheiro em falta: {path}", file=sys.stderr)
            continue
        events: List[Dict] = []
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                e = parse_apache_line(line)
                if not e:
                    e = parse_ssh_line(line)
                if not e:
                    e = parse_ufw_line(line)
                if not e:
                    continue
                ip = e.get("ip")
                country = resolver.country_for(ip) if ip else "DESCONHECIDO"
                e["country"] = country
                events.append(e)
                all_events.append(e)

        # Write per-file reports named after the original file
        base = os.path.basename(path)
        name = os.path.splitext(base)[0]
        pdf_path = os.path.join(outdir, f"{name}_report.pdf")
        
        create_pdf_report(events, pdf_path, f"Relatório de Log: {name}")
        
        print(f"PDF gravado  -> {pdf_path}")

    # Also return aggregate events for summary
    return all_events


def find_default_geoip_db() -> Optional[str]:
    """Look for GeoLite2 DB files inside the repository `src/data` folder.

    Checks, in order:
    - src/data/GeoLite2-City.mmdb
    - src/data/GeoLite2-Country.mmdb
    Returns the first existing absolute path, or None.
    """
    here = os.path.abspath(os.path.dirname(__file__))
    # Script is in src/scripts/, data is expected at src/data/
    candidates = [
        os.path.join(here, "..", "data", "GeoLite2-City.mmdb"),
        os.path.join(here, "..", "data", "GeoLite2-Country.mmdb"),
    ]
    for p in candidates:
        pnorm = os.path.abspath(p)
        if os.path.isfile(pnorm):
            return pnorm
    return None


def summarize_events(events):
    """Print a small summary: counts per service and top countries."""
    from collections import Counter

    svc = Counter()
    country = Counter()
    for e in events:
        svc[e.get("service", "unknown")] += 1
        country[e.get("country", "UNKNOWN")] += 1

    print("\nResumo:")
    print("Serviços:")
    for k, v in svc.most_common():
        print(f"  {k}: {v}")
    print("Top países:")
    for k, v in country.most_common(10):
        print(f"  {k}: {v}")



# Section: CLI

def main(argv=None):
    p = argparse.ArgumentParser(description="Analisa logs web e ssh e produz relatórios por país/timestamp")
    p.add_argument("files", nargs="+", help="Ficheiros de log de entrada a analisar")
    p.add_argument("--geoip-db", help="Caminho para GeoLite2-Country.mmdb (opcional)")
    p.add_argument("--outdir", "-o", default="reports", help="Diretório de output")
    args = p.parse_args(argv)
    init_optional_deps()
    files = args.files or []
    if not files:
        p.error("Indique pelo menos um ficheiro de log para analisar")
    geoip_db = args.geoip_db
    if not geoip_db:
        auto = find_default_geoip_db()
        if auto:
            geoip_db = auto
            print(f"A usar BD GeoIP: {geoip_db}")
        else:
            # Continue without GeoIP but note it
            print("Sem BD GeoIP fornecida e nenhuma encontrada em src/data/ — os países serão DESCONHECIDO")

    events = analyze_files(files, geoip_db, args.outdir)
    summarize_events(events)


if __name__ == "__main__":
    main()
