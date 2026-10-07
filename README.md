# ReconFlow

A lightweight recon pipeline orchestrator that chains together the OSINT and
scanning tools I use day-to-day into a single pass: passive subdomain
enumeration, live-host probing, an opt-in active port scan, and public OSINT
collection — with one Markdown report out the other end.

I built this to cut down the manual back-and-forth of running Subfinder,
Amass, Nmap and theHarvester separately and stitching the results together by
hand during the recon phase of an engagement.

## Pipeline

1. **Subdomain enumeration (passive)** — runs Subfinder and Amass (`-passive`)
   against the target domain and merges/dedupes the results. Passive only:
   this stage never touches the target's own infrastructure, it only queries
   public third-party sources (certificate transparency logs, etc.).
2. **Live-host probing** — concurrently checks every discovered subdomain
   over HTTP/HTTPS and records which ones actually respond, and with what
   status code.
3. **Port scan (explicit opt-in)** — Nmap only runs against a host you pass
   with `--scan-host`. Nothing gets actively scanned by default.
4. **Public OSINT** — runs theHarvester against the domain to pull publicly
   indexed email addresses tied to it.
5. **Report** — everything gets written out to a single Markdown report.

## Usage

```bash
pip install -r requirements.txt

# Passive recon only
python3 reconflow.py example.com

# Passive recon + explicit active port scan of one host you're authorised to test
python3 reconflow.py example.com --scan-host example.com --top-ports 100

# Custom output path
python3 reconflow.py example.com --out my_report.md
```

## Example output

Run against [`scanme.nmap.org`](https://nmap.org/book/testing.html), the host
the Nmap project publishes specifically for testing scanners against:

- [`examples/scanme_portscan_report.md`](examples/scanme_portscan_report.md) — full pipeline including an active port scan
- [`examples/nmap_org_subdomain_report.md`](examples/nmap_org_subdomain_report.md) — passive subdomain enumeration against `nmap.org`, showing 16 discovered subdomains and live-host probing results

## Stack

Python 3, `requests` for concurrent HTTP probing, and shells out to
Subfinder, Amass, Nmap and theHarvester — the same toolset listed under
Recon/OSINT in my skillset.

## Responsible use

This tool is for authorised security testing only — engagements you have
explicit permission to test, your own infrastructure, or hosts that are
publicly documented as scan-permitted (like `scanme.nmap.org`). The active
port-scan stage is opt-in by design (`--scan-host`) specifically so it's
never run against a target by accident.
