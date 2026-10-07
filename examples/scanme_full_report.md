# ReconFlow Report — scanme.nmap.org
Generated: 2026-10-07T06:39:24.604222+00:00

## Subdomains (passive: Subfinder + Amass)
0 found


## Live Hosts
0 responded


## Port Scan — scanme.nmap.org
```
Starting Nmap 7.95 ( https://nmap.org ) at 2026-10-07 12:08 IST
Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.26s latency).
Other addresses for scanme.nmap.org (not scanned): 2600:3c01::f03c:91ff:fe18:bb2f
Not shown: 39 closed tcp ports (reset)
PORT     STATE    SERVICE
21/tcp   open     ftp
22/tcp   open     ssh
25/tcp   filtered smtp
80/tcp   open     http
135/tcp  filtered msrpc
139/tcp  filtered netbios-ssn
179/tcp  filtered bgp
445/tcp  filtered microsoft-ds
554/tcp  open     rtsp
646/tcp  filtered ldp
1723/tcp open     pptp

Nmap done: 1 IP address (1 host up) scanned in 3.90 seconds
```

## Nuclei Findings — scanme.nmap.org
2 found

- **[info]** WAF Detection (waf-detect) — http://scanme.nmap.org
- **[info]** Apache Detection (apache-detect) — http://scanme.nmap.org

## Public OSINT — Emails (theHarvester)
0 found

