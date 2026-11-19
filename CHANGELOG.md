# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- IP selection menu, asked once per group of domains that share IPs: scan only the most shared IP or all IPs of the group
- Colored table of the shared IPs of a group, with the share of domains per IP
- CDN detection (CloudFront, Cloudflare, Akamai, Fastly and others) by CNAME, reverse DNS, Cloudflare's published ranges or HTTP response headers (`cf-ray`, `x-amz-cf-id`...), reported as a finding. The headers catch CDNs that DNS cannot reveal, such as Cloudflare in front of hosting IPs outside its published ranges. Before a port scan the program asks whether to skip the CDN domains (recommended) or scan them anyway. Skipped domains appear in the results table as `Skipped (CDN)`
- Findings: wildcard DNS, CDN providers and IPs shared by several names are reported in a Findings table and exported (`*_findings.csv/json`, `*_wildcard_matches.csv/json`, Excel sheets)
- Wildcard DNS detection: random names are resolved before the scan. Brute-force and pattern matches that only resolve through the wildcard are set apart from Table 1 and reported as findings, never deleted. Names confirmed by OSINT stay in the table
- Warning `[nmap silent MM:SS]` in the progress bar when Nmap prints nothing for 10 minutes
- IPv6 scanning: IPv6 addresses are scanned with Nmap `-6`. The program announces them before scanning and skips them, with a notice, if the machine has no IPv6 connectivity
- Full table of the group's domains; groups of 200 or more domains are saved to `RESULTS/` and the file path is shown

### Changed
- Each unique IP is scanned once; its results are copied to every domain that resolves to it
- Shared-IP tables use the same colors as the port results table: blue borders, colored text
- Result folders in `RESULTS/` are no longer deleted automatically (before, only the 3 most recent were kept)
- Execution logs keep the last 100 (before, 20), and the program reports when it removes old ones
- The IP selection happens before the sudo prompt and before the output folder is created

### Changed
- Security policy moved from `SECURITY.md` into the README, and the shell injection issue in DNS lookups is documented as a known limitation

### Fixed
- Table borders: the cyan tables (subdomains, reverse DNS, port results, shared IPs, findings and CDN) used loose lines on top and bottom, so they did not meet the column bars. They now draw proper corners and junctions, like the menus. The "Without results" row of the port table was also two columns shorter than the table
- Real subdomains were silently missed under load: a DNS query that timed out was counted as "the name does not exist", and an empty answer as "no addresses". A failed query is now retried (up to 3 passes), and only a real NXDOMAIN counts as absent
- CDN edge IPs were reported as "Shared IP" findings. They are shared by design and are no longer listed there
- IP order was random between runs, so "first IP" could change or be an IPv6 address. IPs are now sorted: IPv4 first, then IPv6
- Domains with several scanned IPs got a "Without DETECTION" row for each IP without ports. Now only a domain with no port rows at all gets it
- Shell injection in DNS lookups: `dig` and `nslookup` now run with argument lists instead of `shell=True`, so names from DNS responses cannot run commands
- Frozen timer during an Nmap scan: when Nmap sat at 95% for 90 seconds, the stuck-progress watchdog marked the port scan as completed and the progress thread exited for good. The thread now only ends when the scan ends, and an unexpected error in one iteration no longer stops it
- CONTROL-C during an Nmap scan hung the program: the logger lock was not reentrant, so the signal handler blocked trying to take it again. The lock is now an `RLock`
- CONTROL-C did not work in the IP menu and other inputs: the global handler exited the program. Inputs now raise `KeyboardInterrupt` and return to the menu
- A cancelled IP selection now returns to the main menu without creating a folder

## [2.8] - 2025-07-16

### Added
- Parallelized OSINT source queries: all 14 sources now run concurrently instead of sequentially, reducing discovery phase from ~40-60s to ~10-20s
- Robust CONTROL-C handling at every execution point: sudo prompt, Nmap scans, OSINT queries, menu input, DNS lookups
- Terminal raw mode helper functions: centralized `_enter_raw_no_echo_mode()` and `_restore_terminal_mode()` to eliminate duplication
- Execution logging with automatic rotation: keeps last 20 runs in `LOGS/` folder with end-of-run statistics summary
- Comprehensive project documentation: README with screenshots, features, installation, usage, and architecture

### Fixed
- Ctrl-C not working during Nmap execution: killed only sudo, not the Nmap process group; now uses `os.killpg()` to terminate entire process tree
- Enter key buffering (repeating blank lines) during progress display: added `termios.tcflush(TCIFLUSH)` before terminal restoration in 5 locations
- Silent OSINT DNS verification (195 candidates): replaced with parallel-threaded progress bar matching existing patterns
- Slow analysis completion: parallelized reverse DNS lookups from sequential to ThreadPoolExecutor (25 workers)
- Terminal left in raw mode between progress threads: increased `join()` timeout and added `_ensure_terminal_sane()` fallback
- Frozen timer during Nmap scan: recalculate elapsed time immediately before printing (was stale if stdout.flush() blocked on slow terminals)

### Removed
- 26 redundant local imports of os, sys, re, time, threading, subprocess (already imported globally)
- 5 unused `import tty` statements
- 3 dead functions: `center_text()`, `show_status_explanation()`, `parse_nmap_output()`
- 46 bare `except:` statements: converted to `except Exception:` to prevent swallowing Ctrl-C

### Changed
- Refactored duplicated terminal mode setup/restoration into 2 reusable helper functions, eliminating 10 redundant code blocks
- Consolidated `_build_consolidated_folder()` helper: eliminates 30 lines of duplication in result export flow
- Improved error reporting: replaced silent `except: pass` with informative messages (e.g., folder cleanup failures)
- Fixed false-positive OSINT logs: crt.sh and ThreatCrowd now use before/after counters like other sources
- Added countable output for all OSINT sources: "X subdomains found" format instead of generic "subdomains found"
- Renamed parameter `list` to `values` in `_calculate_average_dynamic()` to avoid shadowing Python builtin

## [2.7] - 2025-07-14

### Changed
- Ultra-simplified progress display: removed per-source counters (A:, C:, F:, D:), now shows only `(ports_scanned/total)`
- Eliminated all NSE phase messages (too fast to be useful)
- System of attempts: 3 tries before returning to main menu
- Removed blinking cursor during progress (solved erratic cursor behavior)
- Unified terminal restoration across all progress threads

## [2.0 - 2.6] - 2025-02-14

Earlier releases focused on:
- Nmap progress tracking across 5 phases with automatic timing calibration (NmapTimingMeter)
- Subdomain detection via 49 brute-force patterns + 14 free OSINT sources
- Port scanning with 5 mode options and real-time progress
- Export to CSV, JSON, XML, and consolidated Excel
- DNS analysis, WHOIS lookup, SSL certificate validation, HTTP header inspection
- Robust error handling and logging system

