#!/usr/bin/env python3
"""Log analyzer for Apache/Nginx access logs and OpenSSH auth logs.

Features:
- Parse Apache/Nginx combined log lines and OpenSSH auth.log lines
- Extract IP, timestamp, service, status (success/fail), and details
- Optionally resolve country via GeoLite2 DB (pass --geoip-db)
- Emit JSON and CSV reports grouped per event

Usage: python log_analyzer.py --files access.log auth.log --outdir reports --geoip-db /path/GeoLite2-Country.mmdb
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional

def _ensure_package_local(package_name, import_name=None, prompt=True):
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


# Try to ensure geoip2 is available; if the user declines installation the
# existing fallback (geoip2 set to None) remains.
_ensure_package_local("geoip2")
try:
    import geoip2.database
except Exception:
    geoip2 = None


APACHE_RE = re.compile(r"(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<request>[^\"]*)\" (?P<status>\d{3}) (?P<size>\S+)(?: \"(?P<referrer>[^\"]*)\" \"(?P<agent>[^\"]*)\")?")

SSH_RE = re.compile(r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<svc>sshd)\[\d+\]:\s+(?P<msg>.*)")
IP_IN_MSG_RE = re.compile(r"from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)")

# UFW / kernel firewall log lines (SRC/DST/PROTO/SPT/DPT etc.)
UFW_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<proc>[^:]+):\s*(?:\[[^\]]+\]\s*)*\[UFW\s+(?P<action>\w+)\](?P<rest>.*)$"
)
UFW_KV_RE = re.compile(r"(SRC|DST|PROTO|SPT|DPT)=([^\s]+)")


class GeoIPResolver:
    def __init__(self, db_path: Optional[str] = None):
        self.reader = None
        if db_path and geoip2:
            try:
                self.reader = geoip2.database.Reader(db_path)
            except Exception:
                print(f"Warning: couldn't open GeoIP DB at {db_path}", file=sys.stderr)

    def country_for(self, ip: str) -> str:
        if self.reader:
            try:
                rec = self.reader.country(ip)
                name = rec.country.name or rec.country.iso_code or "UNKNOWN"
                return name
            except Exception:
                return "UNKNOWN"
        return "UNKNOWN"


def parse_apache_line(line: str) -> Optional[Dict]:
    m = APACHE_RE.search(line)
    if not m:
        return None
    gd = m.groupdict()
    # example time: 10/Oct/2000:13:55:36 -0700
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


def analyze_files(file_paths: List[str], geoip_db: Optional[str], outdir: str) -> List[Dict]:
    resolver = GeoIPResolver(geoip_db)
    # We'll produce one report per input file (name derived from original filename)
    os.makedirs(outdir, exist_ok=True)
    all_events: List[Dict] = []
    keys = [
        "service",
        "ip",
        "dst",
        "country",
        "timestamp",
        "status",
        "action",
        "proto",
        "spt",
        "dpt",
        "method",
        "path",
        "size",
        "msg",
    ]

    for path in file_paths:
        if not os.path.isfile(path):
            print(f"Skipping missing file: {path}", file=sys.stderr)
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
                country = resolver.country_for(ip) if ip else "UNKNOWN"
                e["country"] = country
                events.append(e)
                all_events.append(e)

        # write per-file reports named after the original file
        base = os.path.basename(path)
        name = os.path.splitext(base)[0]
        json_path = os.path.join(outdir, f"{name}_report.json")
        csv_path = os.path.join(outdir, f"{name}_report.csv")
        with open(json_path, "w", encoding="utf-8") as jfh:
            json.dump(events, jfh, indent=2, ensure_ascii=False)
        with open(csv_path, "w", newline="", encoding="utf-8") as cfh:
            writer = csv.DictWriter(cfh, fieldnames=keys, extrasaction="ignore")
            writer.writeheader()
            for ev in events:
                writer.writerow({k: ev.get(k, "") for k in keys})
        print(f"Wrote JSON -> {json_path}")
        print(f"Wrote CSV  -> {csv_path}")

    # also return aggregate events for summary
    return all_events


def find_default_geoip_db() -> Optional[str]:
    """Look for GeoLite2 DB files inside the repository `src/data` folder.

    Checks, in order:
    - src/data/GeoLite2-City.mmdb
    - src/data/GeoLite2-Country.mmdb
    Returns the first existing absolute path, or None.
    """
    here = os.path.abspath(os.path.dirname(__file__))
    # script is in src/scripts/, data is expected at src/data/
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

    print("\nSummary:")
    print("Services:")
    for k, v in svc.most_common():
        print(f"  {k}: {v}")
    print("Top countries:")
    for k, v in country.most_common(10):
        print(f"  {k}: {v}")


def main(argv=None):
    p = argparse.ArgumentParser(description="Analyze web and ssh logs and produce country/timestamp reports")
    p.add_argument("files", nargs="+", help="Input log file(s) to analyze")
    p.add_argument("--geoip-db", help="Path to GeoLite2-Country.mmdb (optional)")
    p.add_argument("--outdir", "-o", default="reports", help="Output directory")
    args = p.parse_args(argv)
    files = args.files or []
    if not files:
        p.error("Please provide at least one log file to analyze")
    geoip_db = args.geoip_db
    if not geoip_db:
        auto = find_default_geoip_db()
        if auto:
            geoip_db = auto
            print(f"Using GeoIP DB: {geoip_db}")
        else:
            # continue without GeoIP but note it
            print("No GeoIP DB provided and none found in src/data/ — country fields will be UNKNOWN")

    events = analyze_files(files, geoip_db, args.outdir)
    summarize_events(events)


if __name__ == "__main__":
    main()
