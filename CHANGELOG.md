# Changelog

All notable changes to this project will be documented in this file.

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

