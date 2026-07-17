# ReconSurface

A lightweight attack-surface reconnaissance tool for domains and hosts, similar in spirit to DNSDumpster.com. It combines DNS analysis, subdomain discovery (brute force + 14 free OSINT sources), WHOIS, SSL certificate checks, HTTP header inspection, and optional Nmap port scanning, with results exported to CSV, JSON, XML, and a consolidated Excel workbook.

Current version: v2.8

## Features

- **Three analysis modes:**
  - Analyze domain (DNS + subdomain discovery, no port scan)
  - Analyze domain with ports (DNS + subdomain discovery + Nmap port scan)
  - Analyze URL/Site with ports (Nmap port scan only, no OSINT)
- Full DNS analysis (A, AAAA, MX, NS, TXT, CNAME, SOA)
- Subdomain discovery via 49 common brute-force patterns plus 14 free OSINT sources, queried in parallel
- Nmap port scanning with 5 modes: single port, range, group, mixed, or all ports (`-p-`)
- Real-time progress bar with automatic timing calibration across 5 scan phases
- Robust CONTROL-C handling at any point during execution (sudo prompt, scanning, OSINT queries, menu input)
- Open and closed ports both included in results and exports
- Full export to CSV, JSON, XML, and a consolidated Excel workbook
- WHOIS lookup (registrant, creation/expiration dates, name servers, status)
- SSL certificate validation with expiration alerts (critical <30 days, warning 30-90 days, safe >90 days)
- HTTP header inspection (protocol, status code, server, security headers)
- Execution logging with automatic rotation (last 20 runs kept) and an end-of-run statistics summary

## OSINT Sources

ReconSurface queries 14 free sources for subdomain discovery, all in parallel (each source is hit exactly once per scan, so no individual rate limit is exceeded):

| # | Source | Type | Notes |
|---|--------|------|-------|
| 1 | crt.sh | REST API | Certificate Transparency, no API key |
| 2 | ThreatCrowd | REST API | No API key |
| 3 | RapidDNS | HTML scraping | No API key |
| 4 | Netcraft | HTML scraping | No API key |
| 5 | CertSpotter | REST API | 10 queries/hour |
| 6 | HackerTarget | REST API | 50 queries/day |
| 7 | ThreatMiner | REST API | 10 queries/minute |
| 8 | THC (ip.thc.org) | REST API | 249 req, 0.5/sec replenish |
| 9 | SubdomainCenter | REST API | 3 queries/minute |
| 10 | DNSDumpster | POST + CSRF | No API key |
| 11 | DuckDuckGo | HTML scraping | `site:` search |
| 12 | Bing | HTML scraping | `site:` search |
| 13 | Qwant | HTML scraping | `site:` search |
| 14 | robots.txt / sitemap.xml | HTTP | Target's own site |

Results from every source are verified with a real DNS lookup before being added to the final subdomain table.

## Installation

### Prerequisites

- Python 3.8+
- macOS, Linux, or Windows
- System commands: `whois`, `dig`, `nslookup`, `curl`, `nmap`

### Setup

```bash
cd ReconSurface

python3 -m venv venv
source venv/bin/activate   # Linux/macOS
# venv\Scripts\activate    # Windows

pip install requests colorama pandas openpyxl
```

`pandas` and `openpyxl` are optional — without them, the consolidated Excel export is skipped but CSV/JSON/XML export still works.

Verify system dependencies:

```bash
python3 -c "from ReconSurface import verify_dependencies; verify_dependencies()"
```

## Usage

```bash
source venv/bin/activate
python3 ReconSurface.py
```

### Menu options

**1. Analyze domain** — DNS records, subdomain discovery (brute force + OSINT), reverse DNS, WHOIS, SSL, HTTP headers. No port scan. Example: `example.com`

**2. Analyze domain with ports** — Everything from option 1, plus an interactive submenu to scan ports on every discovered subdomain. Example: `example.com`

**3. Analyze URL/Site with ports** — Port scan only, no subdomain discovery. Accepts a bare domain (`example.com`) or a full URL (`https://example.com/path`). Example: `https://example.com`

Port scan submenu (options 2 and 3):

1. Single port (e.g. `80`)
2. Port range (e.g. `1-1000`)
3. Port group (e.g. `80,443,8080`)
4. Mixed (e.g. `1-1000,8080,9000`)
5. All ports (`-p-`)

Nmap requires elevated privileges; the program prompts for the sudo password interactively (up to 3 attempts) and never stores it.

### CONTROL-C handling

CONTROL-C can interrupt the program at any point:

- During the sudo password prompt: returns to the main menu, terminal is restored automatically.
- During an Nmap scan: kills the entire Nmap process group and cleans up.
- During OSINT queries or reverse-DNS lookups: cancels cleanly and returns to the menu.
- During any menu input: cancels the current operation without exiting the program.

### Output

Results are written to `RESULTS/<domain>_<DD-MM-YYYY>_<HH:MM>/` next to the script, with a `Consolidated/` subfolder containing the merged CSV, JSON, XML, and Excel files for that session. Only the 3 most recent result folders are kept; older ones are pruned automatically. Execution logs are written to `LOGS/` (last 20 kept).

## Architecture

```
main() -> menu() -> [option 1 / 2 / 3]

Option 1: analyze_domain()             -> DNS + subdomains + export
Option 2: analyze_domain_with_ports()  -> DNS + subdomains + select_ports_interactive() -> run_flow_scan_ports()
Option 3: analyze_url_site_with_ports()-> select_ports_interactive() -> run_flow_scan_ports()
```

| Module | Responsibility |
|--------|-----------------|
| UI | Colored output, ASCII banner, menus, tables, progress bars |
| Core | DNS, WHOIS, SSL analysis via system commands |
| OSINT | `search_subdomains_osint()` — 14 free sources, run in parallel |
| Nmap | `run_nmap_stream()`, `run_scan_ports()` — real-time scan progress |
| Export | CSV, JSON, XML, consolidated Excel |
| Utils | `sleep_interruptible()`, `verify_dependencies()`, signal handling |

### Key functions

| Function | Description |
|----------|-------------|
| `analyze_domain(domain)` | Option 1: DNS + subdomains, no ports |
| `analyze_domain_with_ports(domain)` | Option 2: OSINT + port scan |
| `analyze_url_site_with_ports(domain)` | Option 3: port scan only |
| `search_subdomains_osint(domain)` | Queries all 14 OSINT sources in parallel |
| `detect_subdomains(domain, ...)` | Brute force + OSINT + DNS pattern detection |
| `select_ports_interactive()` | Port-scan submenu (1-5) |
| `run_flow_scan_ports(...)` | Shared flow: sudo, Nmap, export, display |
| `run_nmap_stream(...)` | Runs Nmap with real-time progress parsing |
| `parse_nmap_xml(...)` | Parses Nmap XML output (open and closed ports) |
| `create_output_directory(domain)` | Creates the dated result folder, prunes old ones |
| `consolidate_xml_session(out_dir)` | Merges per-target Nmap XML into one file |
| `create_excel_consolidated(out_dir)` | Builds the multi-sheet Excel workbook |
| `verify_dns_existence(domain)` | Checks whether a domain resolves |

### Nmap progress phases

Nmap scan progress is tracked across 5 phases, each independently going from 0% to 100%:

| Phase | Description |
|-------|-------------|
| 0. Initialization | DNS resolution, setup |
| 1. Port discovery (`-sS`) | SYN scan |
| 2. Service detection (`-sV`) | Service/version fingerprinting |
| 3. NSE scripts | Default script scan |
| 4. Finalization | Report assembly |

### Timing calibration

`NmapTimingMeter` estimates progress using timing constants that are refined automatically over successive runs. Measurements are stored in `reconsurface_nmap_mediciones.json` (in the output folder) — the class loads the average of the last 5 measurements at startup, falling back to built-in defaults on first use, and records real timings when a scan completes. Estimated-vs-real accuracy per phase is written to the execution log for review. To calibrate manually for a specific network, edit that JSON file or the `DEFAULT_VALUES` in the `NmapTimingMeter` class.

## Known limitations / roadmap

- **Port scan progress can sit at 95% for a while** during the `-sS` phase before Nmap reports "Completed SYN Stealth Scan" and the progress jumps to 100%.
- **Port retest** is not implemented — a confirmation re-scan of detected open ports would improve result confidence.
- **Additional OSINT sources** are documented but not implemented: Google dorking (aggressive anti-bot protection makes it low value relative to the 14 sources already covered) and sources requiring a paid/registered API key (SecurityTrails, Shodan, Censys, VirusTotal, URLScan, OTX/AlienVault, Hunter.io, IntelX, Spyse, BufferOverrun, SubdomainfinderC99).

## Disclaimer

This tool is intended for educational purposes and authorized security research only. Users are responsible for complying with all applicable laws and regulations, and must have explicit permission to scan any target that is not their own.

## License

This project is licensed under the GNU General Public License (latest version) — see the [LICENSE](LICENSE) file for details.
