#!/usr/bin/env python3
"""
ReconFlow - a lightweight recon pipeline orchestrator.

Chains: Subfinder + Amass (passive subdomain enumeration) -> live-host
HTTP(S) probing -> Nmap (active port scan, opt-in target only) ->
theHarvester (public OSINT / email enumeration).

Only ever point this at assets you are authorised to test.
"""
import argparse
import concurrent.futures
import datetime
import shutil
import subprocess
import sys
from pathlib import Path

import requests


def check_tool(name):
    return shutil.which(name) is not None


def run_cmd(cmd, timeout=120):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"[!] {cmd[0]} failed: {e}", file=sys.stderr)
        return ""


def subdomain_enum(domain):
    subs = set()

    if check_tool("subfinder"):
        print("[*] Running subfinder (passive)...")
        out = run_cmd(["subfinder", "-d", domain, "-silent"], timeout=90)
        subs.update(line.strip() for line in out.splitlines() if line.strip())
    else:
        print("[!] subfinder not found, skipping")

    if check_tool("amass"):
        print("[*] Running amass (passive)...")
        out = run_cmd(["amass", "enum", "-passive", "-d", domain], timeout=180)
        subs.update(
            line.strip() for line in out.splitlines()
            if line.strip() and domain in line
        )
    else:
        print("[!] amass not found, skipping")

    return sorted(subs)


def probe_live(hosts, workers=20):
    live = []

    def check(h):
        for scheme in ("https://", "http://"):
            try:
                r = requests.head(scheme + h, timeout=4, allow_redirects=True)
                return (h, scheme + h, r.status_code)
            except requests.RequestException:
                continue
        return None

    if not hosts:
        return live

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for res in ex.map(check, hosts):
            if res:
                live.append(res)
    return live


def port_scan(host, top_ports=100):
    if not check_tool("nmap"):
        print("[!] nmap not found, skipping port scan")
        return ""
    print(f"[*] Running nmap top-{top_ports} against {host} (explicit opt-in target)...")
    return run_cmd(["nmap", "-Pn", "--top-ports", str(top_ports), "-T4", host], timeout=300)


def harvest_osint(domain):
    if not check_tool("theHarvester"):
        print("[!] theHarvester not found, skipping")
        return []
    print("[*] Running theHarvester (public sources)...")
    out = run_cmd(["theHarvester", "-d", domain, "-b", "crtsh"], timeout=120)
    emails = sorted(set(
        line.strip() for line in out.splitlines()
        if "@" in line and domain in line
    ))
    return emails


def generate_report(domain, subs, live, scan_host, scan_output, emails):
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    lines = [
        f"# ReconFlow Report — {domain}",
        f"Generated: {ts}",
        "",
        "## Subdomains (passive: Subfinder + Amass)",
        f"{len(subs)} found",
        "",
    ]
    lines += [f"- {s}" for s in subs[:50]]
    if len(subs) > 50:
        lines.append(f"...and {len(subs) - 50} more")

    lines += ["", "## Live Hosts (HTTP/HTTPS probe)", f"{len(live)} responded", ""]
    lines += [f"- {url} ({status})" for _, url, status in live[:50]]

    if scan_host:
        lines += ["", f"## Port Scan — {scan_host}", "```", scan_output.strip() or "(no output)", "```"]

    lines += ["", "## Public OSINT — Emails (theHarvester)", f"{len(emails)} found", ""]
    lines += [f"- {e}" for e in emails[:30]]

    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(
        description="ReconFlow: passive + active recon pipeline orchestrator.",
        epilog="Only scan assets you are explicitly authorised to test.",
    )
    ap.add_argument("domain", help="Target domain for passive enumeration")
    ap.add_argument(
        "--scan-host",
        help="Explicit host to actively port-scan with nmap (opt-in, defaults to none)",
    )
    ap.add_argument("--top-ports", type=int, default=100)
    ap.add_argument("--out", default="reconflow_report.md")
    args = ap.parse_args()

    subs = subdomain_enum(args.domain)
    print(f"[+] {len(subs)} candidate subdomains")

    live = probe_live(subs)
    print(f"[+] {len(live)} live hosts")

    scan_output = ""
    if args.scan_host:
        scan_output = port_scan(args.scan_host, args.top_ports)

    emails = harvest_osint(args.domain)
    print(f"[+] {len(emails)} OSINT emails")

    report = generate_report(args.domain, subs, live, args.scan_host, scan_output, emails)
    Path(args.out).write_text(report)
    print(f"[+] Report written to {args.out}")


if __name__ == "__main__":
    main()
