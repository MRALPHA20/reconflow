# ReconFlow

[![CI](https://github.com/MRALPHA20/reconflow/actions/workflows/ci.yml/badge.svg)](https://github.com/MRALPHA20/reconflow/actions/workflows/ci.yml)

A recon pipeline orchestrator that chains together the OSINT, probing and
scanning tools I use day-to-day into a single pass: passive subdomain
enumeration, live-host probing with tech detection, an opt-in active port
scan, an opt-in low-noise vulnerability scan, and public OSINT collection —
with Markdown, HTML or JSON out the other end.

I built this to cut down the manual back-and-forth of running Subfinder,
Amass, Nmap, Nuclei and theHarvester separately and stitching the results
together by hand during the recon phase of an engagement.

## Pipeline

1. **Subdomain enumeration (passive)** — runs Subfinder and Amass (`-passive`)
   against the target domain and merges/dedupes the results. Passive only:
   this stage never touches the target's own infrastructure, it only queries
   public third-party sources (certificate transparency logs, etc.).
2. **Live-host probing** — concurrently checks every discovered subdomain
   over HTTP/HTTPS, recording status code, page title and detected
   technologies. Prefers ProjectDiscovery's `httpx` when it's actually
   present (verified by version string, not just by binary name — `httpx` is
   a naming collision with the unrelated Python HTTP client CLI, and this
   tool detects and falls back automatically rather than silently losing
   results if the wrong one is on `PATH`), with a concurrent
   `requests`-based prober as a fallback.
3. **Port scan (explicit opt-in)** — Nmap only runs against a host you pass
   with `--scan-host`. Nothing gets actively scanned by default.
4. **Vulnerability scan (explicit opt-in)** — Nuclei, also gated behind
   `--scan-host`, enabled with `--nuclei`. Defaults to `-tags tech` at
   `info,low` severity — pure technology/version fingerprinting, not
   exploit-grade templates — so the default stays recon-grade. Widen with
   `--nuclei-tags` / `--nuclei-severity` if you want broader coverage.
   Findings are deduplicated by template + matched location.
5. **Public OSINT** — runs theHarvester against the domain to pull publicly
   indexed email addresses tied to it.
6. **Report** — everything gets written out as Markdown, HTML, JSON, or all
   three (`--format all`).

## Usage

```bash
pip install -r requirements.txt

# Passive recon only
python3 reconflow.py example.com

# Passive recon + explicit active port scan of one host you're authorised to test
python3 reconflow.py example.com --scan-host example.com --top-ports 100

# + vulnerability fingerprinting, all three report formats
python3 reconflow.py example.com --scan-host example.com --nuclei --format all

# Custom output path (extension added automatically per format)
python3 reconflow.py example.com --out my_report
```

## Example output

Run against [`scanme.nmap.org`](https://nmap.org/book/testing.html), the host
the Nmap project publishes specifically for testing scanners against:

- [`examples/scanme_full_report.md`](examples/scanme_full_report.md) / [`.html`](examples/scanme_full_report.html) / [`.json`](examples/scanme_full_report.json) — full pipeline: active port scan + nuclei tech-detection
- [`examples/nmap_org_subdomain_report.md`](examples/nmap_org_subdomain_report.md) / [`.html`](examples/nmap_org_subdomain_report.html) / [`.json`](examples/nmap_org_subdomain_report.json) — passive subdomain enumeration against `nmap.org`, 16 discovered subdomains with live-host probing

## Testing

```bash
pip install pytest
pytest tests/ -v
```

9 unit tests cover report building and all three renderers (including HTML
escaping) without touching the network, so they run the same in CI as
locally. GitHub Actions runs flake8 + pytest on every push.

## Stack

Python 3, `requests` for concurrent HTTP probing, stdlib `json`/`html` for
the report renderers, and shells out to Subfinder, Amass, Nmap, Nuclei,
httpx and theHarvester — the same toolset listed under Recon/OSINT and
Scanning & Defence in my skillset.

## Responsible use

This tool is for authorised security testing only — engagements you have
explicit permission to test, your own infrastructure, or hosts that are
publicly documented as scan-permitted (like `scanme.nmap.org`). The active
port-scan and vulnerability-scan stages are opt-in by design (`--scan-host`,
`--nuclei`) specifically so they're never run against a target by accident,
and the default Nuclei template set is deliberately restricted to low-noise
technology fingerprinting rather than exploit-grade checks.
