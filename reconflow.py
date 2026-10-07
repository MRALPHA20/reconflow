#!/usr/bin/env python3
"""
ReconFlow - a lightweight recon pipeline orchestrator.

Chains: Subfinder + Amass (passive subdomain enumeration) -> live-host
probing (httpx, or a requests-based fallback) -> Nuclei vulnerability scan
(opt-in) -> Nmap port scan (opt-in) -> theHarvester (public OSINT), into a
Markdown, HTML or JSON report.

Only ever point this at assets you are authorised to test. The Nuclei and
Nmap stages only ever run against a host you explicitly pass via
--scan-host; nothing is actively scanned by default.
"""
import argparse
import concurrent.futures
import datetime
import json
import shutil
import subprocess
import sys
from html import escape
from pathlib import Path

import requests


# ---------------------------------------------------------------------------
# Tool availability / execution helpers
# ---------------------------------------------------------------------------

def check_tool(name):
    return shutil.which(name) is not None


def is_projectdiscovery_httpx():
    """`httpx` is a name collision: ProjectDiscovery's recon prober and the
    Python HTTP client's CLI (encode/httpx) share the binary name. Only the
    former supports -silent/-json/-tech-detect bulk probing, so verify
    identity before relying on it instead of assuming by name alone."""
    if not check_tool("httpx"):
        return False
    out = run_cmd(["httpx", "-version"], timeout=10)
    return "projectdiscovery" in out.lower()


def run_cmd(cmd, timeout=120):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"[!] {cmd[0]} failed: {e}", file=sys.stderr)
        return ""


# ---------------------------------------------------------------------------
# Pipeline stages
# ---------------------------------------------------------------------------

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

    return merge_dedupe(subs)


def merge_dedupe(items):
    """Pure helper: dedupe + sort. Split out so it's unit-testable."""
    return sorted(set(items))


def probe_live_httpx(hosts, timeout=10):
    """Preferred live-host probe: httpx gives status, title and tech in one pass."""
    if not hosts:
        return []
    try:
        proc = subprocess.run(
            ["httpx", "-silent", "-json", "-title", "-tech-detect", "-timeout", str(timeout)],
            input="\n".join(hosts),
            capture_output=True, text=True, timeout=max(60, len(hosts) * 2),
        )
        out = proc.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"[!] httpx failed: {e}", file=sys.stderr)
        return []

    results = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        results.append({
            "host": rec.get("input", rec.get("host", "")),
            "url": rec.get("url", ""),
            "status": rec.get("status_code", rec.get("status-code")),
            "title": rec.get("title", ""),
            "tech": rec.get("tech", []),
        })
    return results


def probe_live_requests(hosts, workers=20, timeout=4):
    """Fallback live-host probe using plain HTTP HEAD requests."""
    def check(h):
        for scheme in ("https://", "http://"):
            try:
                r = requests.head(scheme + h, timeout=timeout, allow_redirects=True)
                return {"host": h, "url": scheme + h, "status": r.status_code, "title": "", "tech": []}
            except requests.RequestException:
                continue
        return None

    if not hosts:
        return []

    live = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for res in ex.map(check, hosts):
            if res:
                live.append(res)
    return live


def probe_live(hosts):
    if not hosts:
        return []
    if is_projectdiscovery_httpx():
        print("[*] Probing live hosts with httpx...")
        results = probe_live_httpx(hosts)
        if results:
            return results
        print("[!] httpx returned no results, falling back to requests-based probe...")
    else:
        print("[*] ProjectDiscovery httpx not found (or name collision with another "
              "tool), using requests-based probe...")
    return probe_live_requests(hosts)


def nuclei_scan(host, severity="info,low", tags="tech"):
    """Opt-in vulnerability scan. Defaults to pure technology fingerprinting
    (low noise, no pattern-matching templates) so this stays recon-grade.
    Widen with --nuclei-tags if you want more coverage."""
    if not check_tool("nuclei"):
        print("[!] nuclei not found, skipping")
        return []
    print(f"[*] Running nuclei ({tags}, severity={severity}) against {host} (explicit opt-in target)...")
    out = run_cmd(
        ["nuclei", "-u", host, "-tags", tags, "-severity", severity, "-silent", "-jsonl"],
        timeout=300,
    )
    seen = set()
    findings = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = rec.get("info", {})
        key = (rec.get("template-id", ""), rec.get("matched-at", rec.get("host", "")))
        if key in seen:
            continue
        seen.add(key)
        findings.append({
            "template": rec.get("template-id", ""),
            "name": info.get("name", ""),
            "severity": info.get("severity", ""),
            "matched": rec.get("matched-at", rec.get("host", "")),
        })
    return findings


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
    return sorted(set(
        line.strip() for line in out.splitlines()
        if "@" in line and domain in line
    ))


# ---------------------------------------------------------------------------
# Report data model + renderers (pure functions, unit-testable without network)
# ---------------------------------------------------------------------------

def build_report_data(domain, subs, live, scan_host, scan_output, nuclei_findings, emails):
    return {
        "domain": domain,
        "generated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "subdomains": subs,
        "live_hosts": live,
        "scan_host": scan_host,
        "port_scan": scan_output,
        "nuclei_findings": nuclei_findings,
        "emails": emails,
    }


def render_markdown(data):
    lines = [
        f"# ReconFlow Report — {data['domain']}",
        f"Generated: {data['generated']}",
        "",
        "## Subdomains (passive: Subfinder + Amass)",
        f"{len(data['subdomains'])} found",
        "",
    ]
    lines += [f"- {s}" for s in data["subdomains"][:50]]
    if len(data["subdomains"]) > 50:
        lines.append(f"...and {len(data['subdomains']) - 50} more")

    lines += ["", "## Live Hosts", f"{len(data['live_hosts'])} responded", ""]
    for h in data["live_hosts"][:50]:
        tech = f" [{', '.join(h['tech'])}]" if h.get("tech") else ""
        title = f" — {h['title']}" if h.get("title") else ""
        lines.append(f"- {h['url']} ({h['status']}){title}{tech}")

    if data["scan_host"]:
        lines += ["", f"## Port Scan — {data['scan_host']}", "```", (data["port_scan"] or "(no output)").strip(), "```"]

    if data["nuclei_findings"]:
        lines += ["", f"## Nuclei Findings — {data['scan_host']}", f"{len(data['nuclei_findings'])} found", ""]
        for f in data["nuclei_findings"][:50]:
            lines.append(f"- **[{f['severity']}]** {f['name']} ({f['template']}) — {f['matched']}")
        if len(data["nuclei_findings"]) > 50:
            lines.append(f"...and {len(data['nuclei_findings']) - 50} more")

    lines += ["", "## Public OSINT — Emails (theHarvester)", f"{len(data['emails'])} found", ""]
    lines += [f"- {e}" for e in data["emails"][:30]]

    return "\n".join(lines) + "\n"


def render_json(data):
    return json.dumps(data, indent=2)


def render_html(data):
    def esc(s):
        return escape(str(s))

    rows_sub = "".join(f"<li>{esc(s)}</li>" for s in data["subdomains"][:50])
    rows_live = "".join(
        f"<tr><td>{esc(h['url'])}</td><td>{esc(h['status'])}</td>"
        f"<td>{esc(h.get('title', ''))}</td><td>{esc(', '.join(h.get('tech', [])))}</td></tr>"
        for h in data["live_hosts"][:50]
    )
    nuclei_rows = "".join(
        f"<tr><td>{esc(f['severity'])}</td><td>{esc(f['name'])}</td>"
        f"<td>{esc(f['template'])}</td><td>{esc(f['matched'])}</td></tr>"
        for f in data["nuclei_findings"]
    )
    emails_rows = "".join(f"<li>{esc(e)}</li>" for e in data["emails"][:30])
    scan_block = (
        f"<h2>Port Scan — {esc(data['scan_host'])}</h2><pre>{esc(data['port_scan'])}</pre>"
        if data["scan_host"] else ""
    )
    nuclei_header = "<tr><th>Severity</th><th>Name</th><th>Template</th><th>Matched</th></tr>"
    nuclei_block = (
        f"<h2>Nuclei Findings</h2><table>{nuclei_header}{nuclei_rows}</table>"
        if data["nuclei_findings"] else ""
    )

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>ReconFlow — {esc(data['domain'])}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }}
h1 {{ border-bottom: 2px solid #333; padding-bottom: .3rem; }}
table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
th, td {{ border: 1px solid #ccc; padding: 6px 10px; text-align: left; font-size: .9rem; }}
th {{ background: #f0f0f0; }}
pre {{ background: #f5f5f5; padding: 1rem; overflow-x: auto; }}
</style></head>
<body>
<h1>ReconFlow Report — {esc(data['domain'])}</h1>
<p>Generated: {esc(data['generated'])}</p>
<h2>Subdomains ({len(data['subdomains'])})</h2><ul>{rows_sub}</ul>
<h2>Live Hosts ({len(data['live_hosts'])})</h2>
<table><tr><th>URL</th><th>Status</th><th>Title</th><th>Tech</th></tr>{rows_live}</table>
{scan_block}
{nuclei_block}
<h2>OSINT Emails ({len(data['emails'])})</h2><ul>{emails_rows}</ul>
</body></html>
"""


RENDERERS = {"md": render_markdown, "html": render_html, "json": render_json}
EXTENSIONS = {"md": ".md", "html": ".html", "json": ".json"}


def write_reports(data, out_base, fmt):
    formats = ["md", "html", "json"] if fmt == "all" else [fmt]
    written = []
    for f in formats:
        path = Path(out_base).with_suffix(EXTENSIONS[f])
        path.write_text(RENDERERS[f](data))
        written.append(str(path))
    return written


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="ReconFlow: passive + active recon pipeline orchestrator.",
        epilog="Only scan assets you are explicitly authorised to test.",
    )
    ap.add_argument("domain", help="Target domain for passive enumeration")
    ap.add_argument(
        "--scan-host",
        help="Explicit host to actively port-scan / nuclei-scan (opt-in, defaults to none)",
    )
    ap.add_argument("--top-ports", type=int, default=100)
    ap.add_argument("--nuclei", action="store_true", help="Run nuclei against --scan-host (requires --scan-host)")
    ap.add_argument("--nuclei-severity", default="info,low")
    ap.add_argument("--nuclei-tags", default="tech", help="Nuclei template tags (default: tech only, low noise)")
    ap.add_argument("--format", choices=["md", "html", "json", "all"], default="md")
    ap.add_argument("--out", default="reconflow_report")
    args = ap.parse_args()

    subs = subdomain_enum(args.domain)
    print(f"[+] {len(subs)} candidate subdomains")

    live = probe_live(subs)
    print(f"[+] {len(live)} live hosts")

    scan_output = ""
    nuclei_findings = []
    if args.scan_host:
        scan_output = port_scan(args.scan_host, args.top_ports)
        if args.nuclei:
            nuclei_findings = nuclei_scan(args.scan_host, severity=args.nuclei_severity, tags=args.nuclei_tags)
    elif args.nuclei:
        print("[!] --nuclei requires --scan-host, skipping")

    emails = harvest_osint(args.domain)
    print(f"[+] {len(emails)} OSINT emails")

    data = build_report_data(args.domain, subs, live, args.scan_host, scan_output, nuclei_findings, emails)
    written = write_reports(data, args.out, args.format)
    for path in written:
        print(f"[+] Report written to {path}")


if __name__ == "__main__":
    main()
