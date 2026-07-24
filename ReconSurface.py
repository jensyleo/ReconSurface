#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ReconSurface.py - Attack Surface Exploration Tool v2.8

Specialized tool for performing surface reconnaissance of networks and systems.
Uses system commands for greater efficiency and fewer dependencies.

================================================================================
MAIN FEATURES
================================================================================

ANALYSIS OPTIONS:
  - Option 1: Analyze domain (OSINT only, not port scanning)
  - Option 2: Analyze domain with ports (OSINT + port scanning with submenu)
  - Option 3: Analyze URL/Site with ports (port scanning only, not OSINT)

NMAP PROGRESS SYSTEM (5 phases):
  1. Initialization (0-5%): DNS, ping, setup
  2. Scan -sS (5-80%): SYN port discovery
  3. Detection -sV (80-97%): Services and versions
  4. NSE scripts (97-99%): Detection scripts
  5. Completion (99-100%): Final report

  - Real-time progress with percentages and counters
  - Watchdog: if progress is stuck at 95%+ for 90s, forces it to 100%
  - Parsing of "NSE Timing" and real nmap percentages
  - Dynamic variables: NmapTimingMeter uses real measurements or default values

TIMING METER (NmapTimingMeter):
  - Fallback system: default values if there are not previous measurements
  - Stores measurements in reconsurface_nmap_mediciones.json
  - Derives time_per_filtered_port and time_per_closed_port from stats
  - Accuracy measurement: estimated vs actual per phase (for development)
  - detect_nmap_phase(): detects phase from nmap output

OSINT SOURCES (14 free):
  crt.sh, ThreatCrowd, RapidDNS, Netcraft, CertSpotter, HackerTarget, ThreatMiner,
  THC, SubdomainCenter, DNSDumpster, DuckDuckGo, Bing, Qwant, robots.txt/sitemap

OTHER FEATURES:
  - CONTROL-C: Stop at any time; during sudo it returns to the menu (does not exit); terminal restored
  - sleep_interruptible() and poll()-based loops for interruptible delays
  - Attempt system: 3 attempts before returning to the menu
  - domain_error vs abort return: sudo/cancel is not treated as "Domain error"
  - Closed ports: included in processing, export, and display
  - Export: CSV, JSON, XML, consolidated Excel
  - Logging: TeeLogger in LOGS/ (max. 20 files, deletes the oldest)
  - Accuracy: logged at the end (estimated vs actual per phase)

GENERATED FILES:
  - reconsurface_nmap_mediciones.json: timing measurements for fallback
  - LOGS/reconsurface_execution_*.log: complete execution log (max. 20 files)
  - nmap_debug_*.log: nmap progress debug log
  - Consolidated/: CSV, JSON, *_consolidated.xml, *_consolidated.xlsx per session

CURRENT PENDING ITEMS (see SESSION_NOTES.md):
  - High priority: REVIEW -sS progress, remove NSE duplication (optional)
  - Medium priority: Validate NSE without ports, implement port retest

VERSIONING: All changes will be v2.1 and later (v2.8 = Feb 2025 debugging).
"""

import os
import sys
import shutil
import requests
import socket
import subprocess
import re
import json
import csv
import concurrent.futures
import time
import getpass
import threading
import datetime
from io import StringIO
from urllib.parse import urlparse

try:
    from colorama import Fore, Style, init
except ImportError:
    print("Error: Missing dependency 'colorama'.\nPlease run:\npip install colorama")
    sys.exit(1)

# Initialize colorama
init(autoreset=True)

# Standard colorama colors used globally (same palette as WebMonitor / MonWhoisSSL)
RGB_GREEN = Fore.GREEN                # green for the marco
RGB_SUCCESS = Fore.GREEN              # specific green for messages of success
RGB_BLUE = Fore.CYAN                  # blue elements
RGB_YELLOW = Fore.YELLOW              # Amarillo elements
RGB_RED = Fore.RED                    # Errors

RGB_ASCII_GREEN = Fore.LIGHTGREEN_EX  # green for ASCII art
RGB_ORANGE = Fore.LIGHTRED_EX         # orange for N/A
RESET_COLOR = Fore.RESET

# Codes of color ANSI (keep compatibility)
class Colors:
    RED = RGB_RED
    GREEN = RGB_GREEN
    YELLOW = RGB_YELLOW
    BLUE = RGB_BLUE
    PURPLE = Fore.WHITE
    CYAN = Fore.CYAN
    WHITE = Fore.WHITE
    BOLD = Style.BRIGHT
    UNDERLINE = ''  # colorama not has underline standard; is keeps for compatibility of API
    END = RESET_COLOR
    ASCII_GREEN = RGB_ASCII_GREEN
    ORANGE = RGB_ORANGE


def sleep_interruptible(seconds):
    """Sleep that allows interruption with CONTROL-C in any moment.
    Divide the time in intervalos of 0.1s for that the signal SIGINT is processes.
    Used in: search_subdomains_osint, delays long, etc.
    """
    interval = 0.1
    elapsed = 0.0
    while elapsed < seconds:
        remaining = min(interval, seconds - elapsed)
        time.sleep(remaining)
        elapsed += remaining


# ============================================================================
# FALLBACK SYSTEM - Dynamic values with fallback to default constants
# ============================================================================
#
# NmapTimingMeter: Automatic measurement system for progress calculation.
#
# Flow:
#   1. At scan start: meter.get_time_*() returns the average of the last 5
#      measurements, or DEFAULT_VALUES if there is no data
#   2. Upon scan completion: meter.record_measurement(stats) saves actual times,
#      derives time_per_port_filtered and time_per_port_closed, calculates precision
#   3. File: reconsurface_nmap_mediciones.json (in the session folder, not in Consolidated)
#
# Location: session folder (out_dir). It is not copied to Consolidated (it is internal calibration).
# Manual adjustment: edit the JSON or DEFAULT_VALUES if calibration is needed
# for very specific networks. See METODOLOGIA_MEDICION_NMAP.md.
# ============================================================================

class NmapTimingMeter:
    """
    Automatic Nmap timing measurement system used to calculate scan progress.

    Uses actual measurements when available, with a fallback to default values.
    Measurements are stored in reconsurface_nmap_mediciones.json.

    Class attributes:
        FILE_MEASUREMENTS: name of the JSON file
        MAX_MEASUREMENTS: max measurements kept per phase (20)
        LAST_N_FOR_AVERAGE: how many of the last measurements to average (5)
        DEFAULT_VALUES: constants used when there are no measurements yet

    Main methods:
        get_time_*(): returns the value for each phase (average or default)
        record_measurement(stats): saves measurements and calculates accuracy
        detect_nmap_phase(line): detects the phase from nmap output (static)
    """
    FILE_MEASUREMENTS = "reconsurface_nmap_mediciones.json"
    MAX_MEASUREMENTS = 20  # Keep last N measurements for phase
    LAST_N_FOR_AVERAGE = 5  # Use last N for calculate average

    DEFAULT_VALUES = {
        'time_dns_initialization': 0.5,
        'time_per_port': 0.98,
        'time_per_port_closed': 0.2,
        'time_per_port_filtered': 20.0,  # For lote of 1000 ports filtered
        'time_nse': 1.0,
        'time_completion': 0.3,
    }

    # Phases detectable in the output of nmap (for detect_nmap_phase)
    PHASES_NMAP = {
        'dns_initialization': ['Initiating Ping Scan', 'Initiating Parallel DNS'],
        'scan_ports': ['Initiating SYN Stealth Scan', 'Discovered open port'],
        'service_detection': ['Initiating Service scan'],
        'nse_scripts': ['Initiating NSE', 'Initiating NSE Script'],
        'completion': ['Completed NSE', 'Nmap scan report'],
    }

    def __init__(self, directory=None):
        self.directory = directory or os.getcwd()
        self.file = os.path.join(self.directory, self.FILE_MEASUREMENTS)
        self.measurements = self._load()

    def _load(self):
        """Loads measurements from JSON. In case of error, returns structure empty."""
        try:
            if os.path.exists(self.file):
                with open(self.file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return {
                        'time_initialization': data.get('time_initialization', []),
                        'time_per_port': data.get('time_per_port', []),
                        'time_per_port_closed': data.get('time_per_port_closed', []),
                        'time_per_port_filtered': data.get('time_per_port_filtered', []),
                        'time_nse': data.get('time_nse', []),
                        'time_completion': data.get('time_completion', []),
                    }
        except (json.JSONDecodeError, IOError, OSError):
            pass
        return {
            'time_initialization': [],
            'time_per_port': [],
            'time_per_port_closed': [],
            'time_per_port_filtered': [],
            'time_nse': [],
            'time_completion': [],
        }

    def _save(self):
        """Saves measurements in JSON."""
        try:
            with open(self.file, 'w', encoding='utf-8') as f:
                json.dump(self.measurements, f, indent=2)
        except (IOError, OSError):
            pass

    def _calculate_average_dynamic(self, values, value_per_default):
        """Returns average of last measurements or value for default if not there is data."""
        if not values:
            return value_per_default
        recent = values[-self.LAST_N_FOR_AVERAGE:] if len(values) >= self.LAST_N_FOR_AVERAGE else values
        return sum(recent) / len(recent)

    @staticmethod
    def detect_nmap_phase(output_line):
        """
        Detects the phase current of Nmap based on in the output.
        Useful for measurement automatic and record of transitions.
        Returns name of phase or None if none is detected.
        """
        if not output_line:
            return None
        line = str(output_line)
        if 'Initiating Ping Scan' in line or 'Initiating Parallel DNS' in line:
            return 'dns_initialization'
        if 'Initiating SYN Stealth Scan' in line or 'Discovered open port' in line:
            return 'scan_ports'
        if 'Initiating Service scan' in line:
            return 'service_detection'
        if 'Initiating NSE' in line or 'Initiating NSE Script' in line:
            return 'nse_scripts'
        if 'Completed NSE' in line:
            return 'completion'
        return None

    def get_time_dns_initialization(self):
        return self._calculate_average_dynamic(
            self.measurements['time_initialization'],
            self.DEFAULT_VALUES['time_dns_initialization']
        )

    def get_time_per_port(self):
        return self._calculate_average_dynamic(
            self.measurements['time_per_port'],
            self.DEFAULT_VALUES['time_per_port']
        )

    def get_time_per_port_closed(self):
        """Time estimated for port closed (seconds)."""
        return self._calculate_average_dynamic(
            self.measurements['time_per_port_closed'],
            self.DEFAULT_VALUES['time_per_port_closed']
        )

    def get_time_nse(self):
        return self._calculate_average_dynamic(
            self.measurements['time_nse'],
            self.DEFAULT_VALUES['time_nse']
        )

    def get_time_completion(self):
        return self._calculate_average_dynamic(
            self.measurements['time_completion'],
            self.DEFAULT_VALUES['time_completion']
        )

    def get_time_per_port_filtered(self):
        """Time for lote of 1000 ports filtered (seconds). Uses measurements derived or value for default."""
        return self._calculate_average_dynamic(
            self.measurements['time_per_port_filtered'],
            self.DEFAULT_VALUES['time_per_port_filtered']
        )

    def _calculate_precision(self, stats):
        """
        Calculates precision: estimated vs real for phase.
        Returns dict with metrics for development (to fine-tune the algorithm if needed).
        """
        precision = {}
        open = stats.get('ports_open', 0)
        closed = stats.get('ports_closed', 0)
        filtered = stats.get('ports_filtered', 0)

        # Initialization
        est_init = self.get_time_dns_initialization()
        real_init = stats.get('time_initialization')
        if real_init is not None and real_init > 0:
            error_pct = ((est_init - real_init) / real_init) * 100
            precision['initialization'] = {'estimated_s': est_init, 'real_s': real_init, 'error_pct': round(error_pct, 2)}

        # Scan of ports (-sS)
        est_ss = closed * 0.2 + open * 0.1 + (filtered / 1000.0) * self.get_time_per_port_filtered()
        real_ss = stats.get('time_scan_ports')
        if real_ss is not None and real_ss > 0:
            error_pct = ((est_ss - real_ss) / real_ss) * 100
            precision['scan_ports'] = {'estimated_s': round(est_ss, 2), 'real_s': real_ss, 'error_pct': round(error_pct, 2)}

        # Detection of services (-sV)
        ports_sv = max(1, open)
        est_sv = ports_sv * self.get_time_per_port()
        real_sv = stats.get('time_service_detection')
        if real_sv is not None and real_sv > 0:
            error_pct = ((est_sv - real_sv) / real_sv) * 100
            precision['service_detection'] = {'estimated_s': round(est_sv, 2), 'real_s': real_sv, 'error_pct': round(error_pct, 2)}

        # NSE
        est_nse = self.get_time_nse()
        real_nse = stats.get('time_nse')
        if real_nse is not None and real_nse > 0:
            error_pct = ((est_nse - real_nse) / real_nse) * 100
            precision['nse'] = {'estimated_s': est_nse, 'real_s': real_nse, 'error_pct': round(error_pct, 2)}

        # Completion
        est_fin = self.get_time_completion()
        real_fin = stats.get('time_completion')
        if real_fin is not None and real_fin > 0:
            error_pct = ((est_fin - real_fin) / real_fin) * 100
            precision['completion'] = {'estimated_s': est_fin, 'real_s': real_fin, 'error_pct': round(error_pct, 2)}

        return precision

    def record_measurement(self, stats):
        """
        Records measurements of a completed scan.
        Calculates precision (estimated vs real) and adds it to stats for the log.
        Derives time_per_port_filtered and time_per_port_closed when there is enough data.
        stats: dict with time_initialization, time_scan_ports, time_service_detection,
               time_nse, time_completion, ports_open, ports_closed, ports_filtered.
        """
        try:
            # Measurement of precision: for development (to fine-tune the algorithm if needed)
            stats['precision'] = self._calculate_precision(stats)
            if stats.get('time_initialization') is not None and stats['time_initialization'] > 0:
                self.measurements['time_initialization'].append(float(stats['time_initialization']))
                self.measurements['time_initialization'] = self.measurements['time_initialization'][-self.MAX_MEASUREMENTS:]

            if stats.get('time_service_detection') is not None and stats.get('ports_open', 0) > 0:
                time_per_port = stats['time_service_detection'] / stats['ports_open']
                if 0.01 < time_per_port < 60.0:
                    self.measurements['time_per_port'].append(time_per_port)
                    self.measurements['time_per_port'] = self.measurements['time_per_port'][-self.MAX_MEASUREMENTS:]

            if stats.get('time_nse') is not None and stats['time_nse'] > 0:
                self.measurements['time_nse'].append(float(stats['time_nse']))
                self.measurements['time_nse'] = self.measurements['time_nse'][-self.MAX_MEASUREMENTS:]

            if stats.get('time_completion') is not None and stats['time_completion'] > 0:
                self.measurements['time_completion'].append(float(stats['time_completion']))
                self.measurements['time_completion'] = self.measurements['time_completion'][-self.MAX_MEASUREMENTS:]

            # Derive time_per_port_filtered from time_scan_ports
            # Formula: time_scan ≈ closed*0.2 + open*0.1 + (filtered/1000)*time_filtered
            time_ss = stats.get('time_scan_ports')
            open = stats.get('ports_open', 0)
            closed = stats.get('ports_closed', 0)
            filtered = stats.get('ports_filtered', 0)
            if time_ss is not None and time_ss > 0 and filtered > 100:
                filtered_batches = filtered / 1000.0
                time_base = closed * 0.2 + open * 0.1
                time_filtered_derived = (time_ss - time_base) / max(0.001, filtered_batches)
                if 5.0 <= time_filtered_derived <= 60.0:
                    self.measurements['time_per_port_filtered'].append(time_filtered_derived)
                    self.measurements['time_per_port_filtered'] = self.measurements['time_per_port_filtered'][-self.MAX_MEASUREMENTS:]

            # Derive time_per_port_closed when there is many closed
            if time_ss is not None and closed > 100 and filtered > 0:
                time_filtered = self.get_time_per_port_filtered()
                filtered_batches = filtered / 1000.0
                time_closed_derived = (time_ss - open * 0.1 - filtered_batches * time_filtered) / closed
                if 0.05 <= time_closed_derived <= 2.0:
                    self.measurements['time_per_port_closed'].append(time_closed_derived)
                    self.measurements['time_per_port_closed'] = self.measurements['time_per_port_closed'][-self.MAX_MEASUREMENTS:]

            self._save()
        except (TypeError, ZeroDivisionError, KeyError):
            pass


# ============================================================================
# SYSTEM Of LOGGING COMPLETE - captures all output in real time
# ============================================================================
#
# TeeLogger: redirects stdout/stderr to a file while showing it on screen.
# - stats: time for phase, ports, nmap_debug_logs
# - _write_summary(): writes summary to the end (time, phases, ports, precision)
# - set_nmap_debug_log(): links nmap_debug_*.log to the summary
# - update_stats(): updates statistics during the scan
# - Log limit: keeps max 20 files in LOGS/ (removes the oldest)
# ============================================================================

# Max log files to keep in LOGS/ (the oldest ones are removed)
MAX_LOGS_EXECUTION = 20


def _clear_logs_old(logs_dir):
    """
    Keeps as max MAX_LOGS_EXECUTION files of log in the folder.
    Removes the oldest ones (by modification date) when the limit is exceeded.
    
    Args:
        logs_dir (str): Path of the folder LOGS.
    """
    try:
        files = [os.path.join(logs_dir, f) for f in os.listdir(logs_dir)
                    if f.startswith("reconsurface_execution_") and f.endswith(".log")]
        if len(files) < MAX_LOGS_EXECUTION:
            return
        # Sort for date of modification (more old first)
        files_con_mtime = [(f, os.path.getmtime(f)) for f in files]
        files_con_mtime.sort(key=lambda x: x[1])
        # Remove the oldest ones until only MAX-1 remain (the new one will be created afterward)
        a_remove = len(files_con_mtime) - (MAX_LOGS_EXECUTION - 1)
        for i in range(a_remove):
            try:
                os.remove(files_con_mtime[i][0])
            except OSError:
                pass
    except (OSError, IOError):
        pass


class TeeLogger:
    """
    Class that captures ALL the output (stdout and stderr) and the saves in a file
    while the shows in screen. captures also the lines that is overwrite.
    
    Policy of retention: Keeps max 20 files of log in LOGS/.
    The oldest ones are removed automatically when a new one is created.
    """
    def __init__(self, log_file_path=None):
        """
        initializes the logger.
        
        Args:
            log_file_path: Path from the file of log. If is None, is creates in LOGS/
                          together to the script. Is applies limit of MAX_LOGS_EXECUTION (20).
        """
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr
        self.log_file = None
        self.log_file_path = log_file_path
        self.lock = threading.Lock()
        self.last_line_was_carriage_return = False
        self.current_line_buffer = ""
        
        # Statistics for the summary (Tarea #24)
        self.stats = {
            'start': datetime.datetime.now(),
            'fin': None,
            'time_initialization': None,
            'time_scan_ports': None,
            'time_service_detection': None,
            'time_nse': None,
            'time_completion': None,
            'ports_total': 0,
            'ports_open': 0,
            'ports_closed': 0,
            'ports_filtered': 0,
            'nmap_debug_logs': []  # List of logs of nmap linked (Tarea #25)
        }
        
        # Create file of log if none is specified (in the LOGS subfolder next to the script)
        if self.log_file_path is None:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            script_dir = os.path.dirname(os.path.abspath(__file__))
            logs_dir = os.path.join(script_dir, "LOGS")
            os.makedirs(logs_dir, exist_ok=True)
            # Keep max 20 logs: remove the oldest before creating the new one
            _clear_logs_old(logs_dir)
            self.log_file_path = os.path.join(logs_dir, f"reconsurface_execution_{timestamp}.log")
        
        # open file of log
        try:
            self.log_file = open(self.log_file_path, 'w', encoding='utf-8')
            self.log_file.write(f"=== LOG Of EXECUTION RECONSURFACE ===\n")
            self.log_file.write(f"Start: {self.stats['start'].strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.log_file.write(f"{'='*60}\n\n")
            self.log_file.flush()
        except Exception as e:
            print(f"[ERROR] Could not create the log file: {e}", file=self.original_stderr)
            self.log_file = None
    
    def _strip_ansi(self, text):
        """Removes codes ANSI of color from the text for the log."""
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)
    
    def _write_to_log(self, text, is_stderr=False):
        """Escribe text to the file of log with timestamp."""
        if self.log_file is None:
            return
        
        try:
            with self.lock:
                # Remove codes ANSI for the log
                clean_text = self._strip_ansi(text)
                
                # If not there is content after of clear, not write nothing
                if not clean_text.strip() and not clean_text:
                    return
                
                # Detect if there is a \r (carriage return) that indicates overwrite
                if '\r' in clean_text:
                    # split for \r for get the updates
                    parts = clean_text.split('\r')
                    
                    for i, part in enumerate(parts):
                        # Clear codes of control additional as \033[K (clear line)
                        part = re.sub(r'\033\[K', '', part)
                        part = part.strip()
                        
                        if part:  # If there is content after of clear
                            timestamp = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
                            
                            # If is the first part and the last line not was \r, is start of line
                            if i == 0 and not self.last_line_was_carriage_return:
                                prefix = "[STDERR]" if is_stderr else "[STDOUT]"
                                self.log_file.write(f"[{timestamp}] {prefix} {part}\n")
                            else:
                                # Is a update of progress
                                self.log_file.write(f"[{timestamp}] [UPDATE] {part}\n")
                    
                    # If there is parts after from the \r, mark that the last was \r
                    if len(parts) > 1 and any(p.strip() for p in parts[1:]):
                        self.last_line_was_carriage_return = True
                    else:
                        self.last_line_was_carriage_return = False
                    
                    # Clear the buffer if it had anything
                    self.current_line_buffer = ""
                else:
                    # Line normal without \r
                    # Add to the buffer if not ends with \n
                    if not clean_text.endswith('\n'):
                        self.current_line_buffer += clean_text
                    else:
                        # Line complete (ends with \n)
                        full_line = self.current_line_buffer + clean_text
                        self.current_line_buffer = ""
                        
                        if full_line.strip():  # Only write if there is content
                            timestamp = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
                            prefix = "[STDERR]" if is_stderr else "[STDOUT]"
                            self.log_file.write(f"[{timestamp}] {prefix} {full_line}")
                    
                    self.last_line_was_carriage_return = False
                
                self.log_file.flush()
        except Exception:
            # If there is error writing to the log, not interrupt the execution
            pass
    
    def write(self, text):
        """Intercepta writes a stdout."""
        # write to the original console
        self.original_stdout.write(text)
        self.original_stdout.flush()
        
        # write to the log
        self._write_to_log(text, is_stderr=False)
    
    def write_stderr(self, text):
        """Intercepta writes a stderr."""
        # write to the original console
        self.original_stderr.write(text)
        self.original_stderr.flush()
        
        # write to the log
        self._write_to_log(text, is_stderr=True)
    
    def flush(self):
        """Flush both stdout as the file of log."""
        self.original_stdout.flush()
        if self.log_file:
            try:
                self.log_file.flush()
            except Exception:
                pass
    
    def start(self):
        """starts the captures of stdout and stderr."""
        # Create wrappers for stdout and stderr
        class StdoutWrapper:
            def __init__(self, tee_logger):
                self.tee_logger = tee_logger
            def write(self, text):
                self.tee_logger.write(text)
            def flush(self):
                self.tee_logger.flush()
            def __getattr__(self, name):
                return getattr(self.tee_logger.original_stdout, name)
        
        class StderrWrapper:
            def __init__(self, tee_logger):
                self.tee_logger = tee_logger
            def write(self, text):
                self.tee_logger.write_stderr(text)
            def flush(self):
                self.tee_logger.original_stderr.flush()
            def __getattr__(self, name):
                return getattr(self.tee_logger.original_stderr, name)
        
        sys.stdout = StdoutWrapper(self)
        sys.stderr = StderrWrapper(self)
    
    def set_nmap_debug_log(self, debug_log_path):
        """
        Links a log of debug of nmap to the summary (Tarea #25).
        
        Args:
            debug_log_path: Path from the file of log of debug of nmap.
        """
        if debug_log_path:
            # Add to the list even if it does not exist yet (it will be checked when writing the summary)
            if debug_log_path not in self.stats['nmap_debug_logs']:
                self.stats['nmap_debug_logs'].append(debug_log_path)
    
    def update_stats(self, stats_update):
        """
        Updates the statistics from the scan (Tarea #24).
        
        Args:
            stats_update: Dictionary with the statistics a update.
        """
        self.stats.update(stats_update)
    
    def _write_summary(self):
        """
        Escribe the summary statistical to the final from the log (Tarea #24 and #25).
        """
        if self.log_file is None:
            return
        
        try:
            with self.lock:
                self.stats['fin'] = datetime.datetime.now()
                time_total = (self.stats['fin'] - self.stats['start']).total_seconds()
                
                self.log_file.write(f"\n{'='*60}\n")
                self.log_file.write(f"📊 SUMMARY STATISTICAL\n")
                self.log_file.write(f"{'='*60}\n\n")
                
                # Time total
                hours = int(time_total // 3600)
                minutes = int((time_total % 3600) // 60)
                seconds = int(time_total % 60)
                self.log_file.write(f"⏱️  Time total of execution: {hours:02d}:{minutes:02d}:{seconds:02d}\n\n")
                
                # Time for phase
                self.log_file.write(f"📋 Time for phase:\n")
                if self.stats.get('time_initialization'):
                    self.log_file.write(f"   - Initialization: {self.stats['time_initialization']:.2f}s\n")
                if self.stats.get('time_scan_ports'):
                    self.log_file.write(f"   - Scan of ports (-sS): {self.stats['time_scan_ports']:.2f}s\n")
                if self.stats.get('time_service_detection'):
                    self.log_file.write(f"   - Detection of services (-sV): {self.stats['time_service_detection']:.2f}s\n")
                if self.stats.get('time_nse'):
                    self.log_file.write(f"   - Scripts NSE: {self.stats['time_nse']:.2f}s\n")
                if self.stats.get('time_completion'):
                    self.log_file.write(f"   - Completion: {self.stats['time_completion']:.2f}s\n")
                self.log_file.write("\n")
                
                # Statistics of ports
                if self.stats.get('ports_total', 0) > 0:
                    self.log_file.write(f"🔌 Statistics of ports:\n")
                    self.log_file.write(f"   - Total scanned: {self.stats['ports_total']}\n")
                    if self.stats.get('ports_open', 0) > 0:
                        self.log_file.write(f"   - Ports open: {self.stats['ports_open']}\n")
                    if self.stats.get('ports_closed', 0) > 0:
                        self.log_file.write(f"   - Ports closed: {self.stats['ports_closed']}\n")
                    if self.stats.get('ports_filtered', 0) > 0:
                        self.log_file.write(f"   - Ports filtered: {self.stats['ports_filtered']}\n")
                    self.log_file.write("\n")
                
                # Measurement of precision (estimated vs real)
                # Use: Development - metrics to fine-tune the algorithm if needed
                if self.stats.get('precision'):
                    self.log_file.write(f"📐 Precision estimated vs real:\n")
                    for phase, data in self.stats['precision'].items():
                        est = data.get('estimated_s', 0)
                        real = data.get('real_s', 0)
                        err = data.get('error_pct', 0)
                        self.log_file.write(f"   - {phase}: estimated {est}s, real {real}s (error {err:+.1f}%)\n")
                    self.log_file.write("\n")

                # Logs of nmap linked (Tarea #25)
                if self.stats['nmap_debug_logs']:
                    self.log_file.write(f"📎 Logs of nmap linked:\n")
                    for i, nmap_log in enumerate(self.stats['nmap_debug_logs'], 1):
                        if os.path.exists(nmap_log):
                            size = os.path.getsize(nmap_log)
                            size_kb = size / 1024
                            self.log_file.write(f"   {i}. {os.path.basename(nmap_log)} ({size_kb:.2f} KB)\n")
                        else:
                            self.log_file.write(f"   {i}. {os.path.basename(nmap_log)} (not found)\n")
                    self.log_file.write("\n")
                
                self.log_file.write(f"{'='*60}\n")
                self.log_file.flush()
        except Exception:
            # If there is error writing the summary, not interrupt
            pass
    
    def stop(self):
        """stops the captures and restores stdout/stderr original."""
        # write any content pending in the buffer
        if self.log_file and self.current_line_buffer:
            try:
                with self.lock:
                    timestamp = datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
                    self.log_file.write(f"[{timestamp}] [STDOUT] {self.current_line_buffer}\n")
                    self.current_line_buffer = ""
            except Exception:
                pass
        
        sys.stdout = self.original_stdout
        sys.stderr = self.original_stderr
        
        if self.log_file:
            try:
                with self.lock:
                    # write summary statistical before of close (Tarea #24 and #25)
                    self._write_summary()
                    
                    self.log_file.write(f"\n{'='*60}\n")
                    self.log_file.write(f"End: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    self.log_file.write(f"{'='*60}\n")
                    self.log_file.close()
                print(f"\n[INFO] Log saved in: {self.log_file_path}", file=self.original_stdout)
            except Exception:
                pass
    
    def get_log_path(self):
        """Returns the path from the file of log."""
        return self.log_file_path

# Variable global for the logger
_tee_logger = None
_exit_with_q = False  # Flag to indicate exit via Q
_nmap_process_current = None  # process nmap current (for that signal_handler can terminate it with CONTROL-C)

def get_tee_logger():
    """Gets the instance global from the logger."""
    return _tee_logger

def _ensure_terminal_sane():
    """
    Forces the terminal back to sane (canonical, echoing) mode.

    Progress-bar threads put the terminal in raw/no-echo mode and restore it
    themselves when they stop, but the main thread only waits up to a short
    join() timeout for them to finish. If the thread is still asleep in its
    0.1s poll interval when the timeout expires, the terminal can be left in
    raw mode right when the next input() (e.g. "Press ENTER to continue") is
    about to run, making ENTER/CONTROL-C behave incorrectly. Calling `stty
    sane` here is independent of that race and always restores it.
    """
    try:
        subprocess.run(['stty', 'sane'], check=False, capture_output=True, timeout=1)
    except Exception:
        pass

def _enter_raw_no_echo_mode():
    """
    Puts the terminal in raw mode (ICANON+ECHO off) so a progress-bar thread can
    poll for CONTROL-C without a blocking line-buffered read, without echoing
    keys pressed in the meantime (e.g. ENTER) to the screen.

    Returns the previous termios settings to pass to _restore_terminal_mode(),
    or None if they could not be read (e.g. no real tty attached to stdin).
    """
    try:
        import termios
        old_settings = termios.tcgetattr(sys.stdin)
        new_settings = old_settings[:]
        new_settings[3] = new_settings[3] & ~termios.ICANON & ~termios.ECHO
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, new_settings)
        return old_settings
    except Exception:
        return None

def _restore_terminal_mode(old_settings):
    """
    Restores terminal settings captured by _enter_raw_no_echo_mode().

    Discards any keystrokes buffered while in raw mode (e.g. ENTER pressed
    during a scan) first, so they don't leak into the next input() call.
    """
    if not old_settings:
        return
    try:
        import termios
        termios.tcflush(sys.stdin, termios.TCIFLUSH)
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
    except Exception:
        pass

def get_terminal_width():
    """
    Gets the width of the terminal current.
    
    Returns:
        int: Width of the terminal in characters, or 80 for default if it cannot be determined.
    """
    try:
        return shutil.get_terminal_size().columns
    except Exception:
        return 80  # Default width if it cannot be obtained

def get_display_width(text):
    """
    Calculate the visual width (in terminal columns) of a string, treating
    emoji as double-width like most terminal emulators render them.
    """
    width = 0
    for ch in text:
        code = ord(ch)
        if code in (0xFE0F, 0x200D):  # variation selector-16, zero-width joiner: no extra width
            continue
        if (0x1F300 <= code <= 0x1FAFF) or (0x2600 <= code <= 0x27BF) or (0x2B00 <= code <= 0x2BFF):
            width += 2
        else:
            width += 1
    return width

def pad_menu_line(text, width):
    """Right-pad text with spaces so its visual width matches the target column width"""
    padding = max(width - get_display_width(text), 0)
    return text + (' ' * padding)

def show_ascii_art():
    """
    Shows the ASCII art from the banner with centered dynamic.

    The banner is centers automatically according to the width of the terminal current
    (same style of letters of block that WebMonitor/MonWhoisSSL).
    """
    terminal_width = get_terminal_width()

    ascii_art = [
        " ____                      ____              __                ",
        "|  _ \\ ___  ___ ___  _ __ / ___| _   _ _ __ / _| __ _  ___ ___ ",
        "| |_) / _ \\/ __/ _ \\| '_ \\\\___ \\| | | | '__| |_ / _` |/ __/ _ \\",
        "|  _ <  __/ (_| (_) | | | |___) | |_| | |  |  _| (_| | (_|  __/",
        "|_| \\_\\___|\\___\\___/|_| |_|____/ \\__,_|_|  |_|  \\__,_|\\___\\___|",
    ]
    ascii_margin = max((terminal_width - max(len(line) for line in ascii_art)) // 2, 0)

    print()
    for line in ascii_art:
        print(f"{RGB_ASCII_GREEN}{' ' * ascii_margin}{line}{RESET_COLOR}")

def print_colored(text, color=Colors.WHITE, end="\n"):
    """
    Prints text with color in the terminal.
    
    Args:
        text (str): Text a print.
        color (str): Code of color ANSI.
        end (str): Character final (for default "\\n").
    """
    print(f"{color}{text}{Colors.END}", end=end)

def safe_filename(name):
    """
    Generates a name of file secure replacing characters not valid.
    
    Args:
        name (str): Name original from the file.
    
    Returns:
        str: Name of file secure for use in the system of files.
    """
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._-") or "out"

def consolidate_xml_session(out_dir):
    """consolidates all the files XML of nmap of the session in a only XML.

    Combines the hosts of all the *_nmap_*.xml in a unique file.
    Generates <base_tag>_consolidated.xml in Consolidated/.
    If not there is XMLs, returns None.
    """
    try:
        import glob
        import xml.etree.ElementTree as ET
        session_tag = os.path.basename(out_dir)
        # Use only the name of domain (without date/hour) for the name of file
        base_tag = re.sub(r"_\d{2}-\d{2}-\d{4}_\d{2}:\d{2}$", "", session_tag)
        # Ensure folder Consolidated as destination from the XML consolidated
        consolidated_dir = os.path.join(out_dir, "Consolidated")
        try:
            os.makedirs(consolidated_dir, exist_ok=True)
        except Exception:
            pass
        xml_paths = glob.glob(os.path.join(out_dir, "*.xml"))
        if not xml_paths:
            return None

        # Use the primer XML as base and collect all the hosts
        base_path = xml_paths[0]
        try:
            base_tree = ET.parse(base_path)
        except Exception:
            return None
        base_root = base_tree.getroot()

        # collect all the hosts of all the files
        all_hosts = []
        for path in xml_paths:
            try:
                tree = ET.parse(path)
                root = tree.getroot()
                for host in root.findall('host'):
                    all_hosts.append(host)
            except Exception:
                continue

        # Sort hosts alphabetically for hostname (or IP if not there is hostname)
        def key_host(h):
            name = None
            try:
                for hostnames in h.findall('hostnames'):
                    for hn in hostnames.findall('hostname'):
                        n = hn.get('name')
                        if n:
                            name = n
                            break
                    if name:
                        break
                if not name:
                    for addr in h.findall('address'):
                        a = addr.get('addr')
                        if a:
                            name = a
                            break
            except Exception:
                pass
            return (name or '').lower()

        all_hosts_sorted = sorted(all_hosts, key=key_host)

        # Remove hosts current from the root base and reinsert sorted
        for existing in list(base_root.findall('host')):
            try:
                base_root.remove(existing)
            except Exception:
                pass
        for h in all_hosts_sorted:
            base_root.append(h)

        output_path = os.path.join(consolidated_dir, f"{base_tag}_consolidated.xml")
        try:
            base_tree.write(output_path, encoding='utf-8', xml_declaration=True)
        except Exception:
            return None
        return output_path
    except Exception:
        return None

def create_excel_consolidated(out_dir):
    """Creates a consolidated Excel file with tabs for each CSV/JSON.

    If Consolidated exists, reads from there and saves the Excel there.
    If not, uses the session folder (out_dir).
    """
    try:
        import pandas as pd
        import glob
        session_tag = os.path.basename(out_dir)
        # Use only the name of domain (without date/hour) for the name from the Excel
        base_tag = re.sub(r"_\d{2}-\d{2}-\d{4}_\d{2}:\d{2}$", "", session_tag)
        consolidated_dir = os.path.join(out_dir, "Consolidated")
        usar_consolidated = os.path.exists(consolidated_dir)
        source_dir = consolidated_dir if usar_consolidated else out_dir
        excel_path = os.path.join(source_dir, f"{base_tag}_consolidated.xlsx")
        tabs_created = 0

        # Sanitizer of sheet names for Excel
        # Replaces invalid characters, limits length a 31 and ensures uniqueness
        invalid_chars_pattern = re.compile(r"[:\\\\/\?\*\[\]]")

        def sanitize_name_sheet(name_original: str, used: set) -> str:
            name = os.path.splitext(os.path.basename(name_original))[0]
            # Remover segment of date and hour from the type _DD-MM-YYYY_HH:MM in any part
            try:
                name = re.sub(r"_\d{2}-\d{2}-\d{4}_\d{2}[:\-]\d{2}", "", name)
            except Exception:
                pass
            # Replace invalid characters for '-'
            name = invalid_chars_pattern.sub('-', name)
            # Replace spaces multiple and trim
            name = re.sub(r"\s+", " ", name).strip()
            if not name:
                name = "Sheet"
            # limit a 31 characters
            name = name[:31]
            # Ensure uniqueness
            base = name
            counter = 2
            while name in used or not name:
                suffix = f" ({counter})"
                max_base = 31 - len(suffix)
                name = (base[:max_base] if max_base > 0 else base) + suffix
                counter += 1
            used.add(name)
            return name

        names_sheets_used = set()
        names_logical_added = set()

        with pd.ExcelWriter(excel_path, engine='openpyxl') as writer:
            # process CSVs
            csv_files = glob.glob(os.path.join(source_dir, "*.csv"))
            for csv_path in csv_files:
                try:
                    # Evitar duplicates between CSV/JSON with same name logical
                    base_logic = re.sub(r"_\d{2}-\d{2}-\d{4}_\d{2}[:\-]\d{2}", "", os.path.splitext(os.path.basename(csv_path))[0])
                    if base_logic in names_logical_added:
                        continue
                    df = pd.read_csv(csv_path)
                    # Remover column not useful if exists
                    if 'target_original' in df.columns:
                        try:
                            df = df.drop(columns=['target_original'])
                        except Exception:
                            pass
                    sheet_name_var = sanitize_name_sheet(os.path.basename(csv_path), names_sheets_used)
                    df.to_excel(writer, sheet_name=sheet_name_var, index=False)
                    tabs_created += 1
                    names_logical_added.add(base_logic)
                except Exception:
                    continue
            # process JSONs (exclude reconsurface_nmap_mediciones.json: calibration, not result)
            json_files = [f for f in glob.glob(os.path.join(source_dir, "*.json"))
                          if os.path.basename(f) != "reconsurface_nmap_mediciones.json"]
            for json_path in json_files:
                try:
                    base_logic = re.sub(r"_\d{2}-\d{2}-\d{4}_\d{2}[:\-]\d{2}", "", os.path.splitext(os.path.basename(json_path))[0])
                    if base_logic in names_logical_added:
                        continue
                    with open(json_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    if isinstance(data, list) and data:
                        df = pd.DataFrame(data)
                        if 'target_original' in df.columns:
                            try:
                                df = df.drop(columns=['target_original'])
                            except Exception:
                                pass
                        sheet_name_var = sanitize_name_sheet(os.path.basename(json_path), names_sheets_used)
                        df.to_excel(writer, sheet_name=sheet_name_var, index=False)
                        tabs_created += 1
                        names_logical_added.add(base_logic)
                except Exception:
                    continue
        
        return excel_path
    except Exception as e:
        try:
            print_colored(f"[!] Error creating Excel consolidated: {str(e)}", Colors.RED)
        except Exception:
            pass
        return None

def _build_consolidated_folder(out_dir):
    """
    Creates the Consolidated/ subfolder inside a session's out_dir and copies
    every CSV/JSON there (skipping the nmap timing calibration file), so
    create_excel_consolidated() can read from a single, predictable source.
    """
    try:
        import glob
        consolidated_dir = os.path.join(out_dir, "Consolidated")
        os.makedirs(consolidated_dir, exist_ok=True)
        for pattern in ("*.csv", "*.json"):
            for path in glob.glob(os.path.join(out_dir, pattern)):
                try:
                    if os.path.isfile(path) and os.path.basename(path) != "reconsurface_nmap_mediciones.json":
                        shutil.copy2(path, consolidated_dir)
                except Exception:
                    pass
    except Exception:
        pass

def create_output_directory(domain):
    """
    Creates and returns a output directory with format DD-MM-YYYY.
    Keeps only the 3 most recent folders in RESULTS/.
    
    Args:
        domain (str): Name from the domain for create the folder.
    
    Returns:
        str: Path from the output directory created.
    """
    # Format of date DD-MM-YYYY and hour HH:MM
    date_current = time.strftime("%d-%m-%Y")
    hour_current = time.strftime("%H:%M")
    
    # Get the directory where is the script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.join(script_dir, "RESULTS")
    try:
        os.makedirs(base_dir, exist_ok=True)
    except Exception:
        pass
    
    # Name of folder with format domain_DD-MM-YYYY_HH:MM
    folder = f"{safe_filename(domain)}_{date_current}_{hour_current}"
    out_dir = os.path.join(base_dir, folder)
    os.makedirs(out_dir, exist_ok=True)
    
    # Clear folders old AFTER of create the new: keep only the 3 more recent
    try:
        folders_existing = []
        for item in os.listdir(base_dir):
            item_path = os.path.join(base_dir, item)
            if os.path.isdir(item_path):
                # Get timestamp of modification
                mtime = os.path.getmtime(item_path)
                folders_existing.append((mtime, item_path))
        
        # Sort by modification date (most recent first)
        folders_existing.sort(reverse=True)
        
        # Remove extra folders (keep only 3)
        if len(folders_existing) > 3:
            folders_a_remove = folders_existing[3:]
            for _, folder_path in folders_a_remove:
                try:
                    shutil.rmtree(folder_path)
                    print_colored(f"[+] Removed old result folder: {os.path.basename(folder_path)}", Colors.YELLOW)
                except Exception as e:
                    print_colored(f"[!] Could not remove old folder {os.path.basename(folder_path)}: {str(e)}", Colors.YELLOW)
            print_colored(f"[+] Keeping max 3 folders in RESULTS/", Colors.GREEN)
    except Exception:
        pass
    
    return out_dir

def save_json(path, data):
    """Saves a dict/list in JSON UTF-8 with indentation."""
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False

def save_csv(path, headers, rows):
    """Saves rows in CSV with headers (list of dicts or lists)."""
    try:
        with open(path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            for row in rows:
                if isinstance(row, dict):
                    writer.writerow([row.get(h, "") for h in headers])
                else:
                    writer.writerow(list(row))
        return True
    except Exception:
        return False

def verify_dependencies():
    """
    Verifies that all the dependencies are installed.
    
    Verifies both dependencies of Python as commands from the system.
    
    Returns:
        bool: True if all the dependencies are available, False in case otherwise.
    """
    dependencies = {
        'curl': 'Command curl for queries HTTP',
        'dig': 'Command dig for queries DNS',
        'nslookup': 'Command nslookup for queries DNS',
        'nmap': 'Command nmap for scan of ports'
    }
    
    # Verify dependencies of Python
    python_deps = {
        'requests': 'For queries HTTP',
        'pandas': 'For generate files Excel (optional)',
        'openpyxl': 'For generate files Excel (optional)'
    }
    
    python_missing = []
    for dep, desc in python_deps.items():
        try:
            if dep == 'requests':
                import requests
            elif dep == 'pandas':
                import pandas
            elif dep == 'openpyxl':
                import openpyxl
        except ImportError:
            python_missing.append((dep, desc))
    
    if python_missing:
        print_colored(f"\n[!] Dependencies of Python missing:", Colors.YELLOW)
        for dep, desc in python_missing:
            print_colored(f"[-] {dep}: MISSING - {desc}", Colors.RED)
        
        if 'requests' in [d[0] for d in python_missing]:
            print_colored("💡 For install requests: pip install requests", Colors.YELLOW)
            return False
        else:
            print_colored("💡 For install pandas and openpyxl: pip install pandas openpyxl", Colors.YELLOW)
            print_colored("⚠️  Without these dependencies, the consolidated Excel file will not be generated", Colors.YELLOW)
    
    missing = []
    
    for cmd, description in dependencies.items():
        try:
            result = subprocess.run(['which', cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode != 0:
                missing.append(cmd)
        except Exception:
            missing.append(cmd)
    
    if missing:
        print_colored(f"\n[!] Install the missing dependencies:", Colors.YELLOW)

        # Installation instructions by operating system
        print_colored("\n🐧 Ubuntu/Debian:", Colors.CYAN)
        if 'curl' in missing:
            print_colored("   sudo apt update && sudo apt install curl", Colors.WHITE)
        if 'dig' in missing:
            print_colored("   sudo apt update && sudo apt install dnsutils", Colors.WHITE)
        if 'nmap' in missing:
            print_colored("   sudo apt update && sudo apt install nmap", Colors.WHITE)
        
        print_colored("\n🍎 macOS:", Colors.CYAN)
        if 'curl' in missing:
            print_colored("   curl already comes installed in macOS", Colors.GREEN)
        if 'dig' in missing:
            print_colored("   dig already comes installed in macOS", Colors.GREEN)
        if 'nmap' in missing:
            print_colored("   brew install nmap", Colors.WHITE)
        
        print_colored(f"\n{'='*60}", Colors.RED)
        print_colored("❌ Please install the missing dependencies and run the program again.", Colors.RED)
        print_colored(f"{'='*60}", Colors.RED)
        
        return False
    
    return True

def verify_dns_existence(domain):
    """
    Verifies if the domain exists in DNS (A, AAAA or CNAME) using commands from the system.
    
    Utiliza dig, nslookup and socket for verify the existence from the domain.
    
    Args:
        domain (str): Domain a verify.
    
    Returns:
        bool: True if the domain exists, False in case otherwise.
    """
    try:
        # 1) A
        cmd = f"dig +short A {domain}"
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=8)
        if result.returncode == 0 and result.stdout.strip():
            return True

        # 2) AAAA
        cmd = f"dig +short AAAA {domain}"
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=8)
        if result.returncode == 0 and result.stdout.strip():
            return True

        # 3) CNAME (and resolve its destination)
        cmd = f"dig +short CNAME {domain}"
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=8)
        cname = result.stdout.strip()
        if result.returncode == 0 and cname:
            # If there is a CNAME, consider it existing even if it does not resolve A at this moment
            # Additionally try A/AAAA from the CNAME
            cmd_a = f"dig +short A {cname}"
            res_a = subprocess.run(cmd_a, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=8)
            if res_a.returncode == 0 and res_a.stdout.strip():
                return True
            cmd_aaaa = f"dig +short AAAA {cname}"
            res_aaaa = subprocess.run(cmd_aaaa, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=8)
            if res_aaaa.returncode == 0 and res_aaaa.stdout.strip():
                return True
            # Otherwise, still consider it existing because of the CNAME
            return True

        # Fallback with nslookup (A and AAAA)
        cmd = f"nslookup -type=A {domain}"
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=8)
        if result.returncode == 0 and result.stdout.strip():
            output = result.stdout.lower()
            if "can't find" not in output and "not found" not in output and "nxdomain" not in output:
                return True

        cmd = f"nslookup -type=AAAA {domain}"
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=8)
        if result.returncode == 0 and result.stdout.strip():
            output = result.stdout.lower()
            if "can't find" not in output and "not found" not in output and "nxdomain" not in output:
                return True

        return False
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False

def resolve_dns_record_command(domain, type_record):
    """Resuelve a type specific of record DNS using commands from the system"""
    try:
        # try with dig first
        cmd = f"dig +short {type_record} {domain}"
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        
        if result.returncode == 0 and result.stdout.strip():
            records = [line.strip() for line in result.stdout.strip().split('\n') if line.strip()]
            
            # If is a record A and found CNAMEs, resolve the actual IPs
            if type_record == 'A':
                ips_actual = []
                for record in records:
                    # If the record looks like a CNAME (not an IP)
                    if not record.replace('.', '').replace('-', '').isdigit() and not record.replace('.', '').isdigit():
                        # Is a CNAME, resolve its IP
                        try:
                            cmd_ip = f"dig +short A {record}"
                            result_ip = subprocess.run(cmd_ip, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
                            if result_ip.returncode == 0 and result_ip.stdout.strip():
                                ips_cname = [ip.strip() for ip in result_ip.stdout.strip().split('\n') if ip.strip()]
                                ips_actual.extend(ips_cname)
                        except Exception:
                            pass
                    else:
                        # It is a direct IP
                        ips_actual.append(record)
                
                # If actual IPs were found, return them; otherwise return the original records
                if ips_actual:
                    return list(set(ips_actual))  # Remove duplicates
                else:
                    return records
            
            return records
        
        # If dig fails, try with nslookup
        cmd = f"nslookup -type={type_record} {domain}"
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        
        if result.returncode == 0 and result.stdout.strip():
            # parse nslookup output
            lines = result.stdout.strip().split('\n')
            records = []
            for line in lines:
                if type_record in line and not line.startswith('Server:') and not line.startswith('Address:'):
                    # Extract the value from the record
                    parts = line.split()
                    if len(parts) >= 2:
                        records.append(parts[-1])
            
            # Apply the same logic of resolution of CNAMEs
            if type_record == 'A':
                ips_actual = []
                for record in records:
                    if not record.replace('.', '').replace('-', '').isdigit() and not record.replace('.', '').isdigit():
                        try:
                            cmd_ip = f"dig +short A {record}"
                            result_ip = subprocess.run(cmd_ip, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
                            if result_ip.returncode == 0 and result_ip.stdout.strip():
                                ips_cname = [ip.strip() for ip in result_ip.stdout.strip().split('\n') if ip.strip()]
                                ips_actual.extend(ips_cname)
                        except Exception:
                            pass
                    else:
                        ips_actual.append(record)
                
                if ips_actual:
                    return list(set(ips_actual))
                else:
                    return records
            
            return records
        
        return []
        
    except subprocess.TimeoutExpired:
        return []
    except Exception:
        return []

def get_records_dns_complete(domain):
    """Gets all the records DNS from the domain using commands from the system"""
    print_colored(f"\n{'='*60}", Colors.CYAN)
    print_colored(f"🌐 ANALYSIS DNS COMPLETE: {domain}", Colors.BOLD + Colors.WHITE)
    print_colored(f"{'='*60}", Colors.CYAN)
    
    records = {}
    
    # types of records DNS a verify
    types_records = {
        'A': 'IPv4',
        'AAAA': 'IPv6', 
        'MX': 'Mail Exchange',
        'NS': 'Name Servers',
        'TXT': 'Text Records',
        'CNAME': 'Canonical Name',
        'SOA': 'Start of Authority'
    }
    
    for type, description in types_records.items():
        print_colored(f"[*] Resolving {type} ({description})...", Colors.BLUE)
        records[type] = resolve_dns_record_command(domain, type)
        
        if records[type]:
            print_colored(f"[+] {type}: {', '.join(records[type])}", Colors.GREEN)
        else:
            print_colored(f"[-] {type}: Not found", Colors.YELLOW)
    
    return records

def reverse_dns_lookup(ip):
    """Performs reverse DNS lookup for a IP"""
    try:
        result = subprocess.run(['nslookup', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
        
        if result.returncode == 0 and result.stdout.strip():
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if 'name = ' in line and not line.startswith('Server:'):
                    # Extract the name from the reverse DNS
                    name = line.split('name = ')[1].strip().rstrip('.')
                    return name
        
        return None
        
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None

def generate_list_subdomains_complete():
    """Generates a list complete of subdomains for test"""
    
    # List basic of subdomains common
    subdomains_basic = [
        'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'ns1', 'ns2', 'dns1', 'dns2',
        'admin', 'cpanel', 'webmail', 'blog', 'dev', 'test', 'staging', 'api',
        'cdn', 'static', 'media', 'images', 'files', 'download', 'upload',
        'support', 'help', 'docs', 'wiki', 'forum', 'community', 'shop', 'store',
        'secure', 'ssl', 'vpn', 'remote', 'ssh', 'telnet', 'monitor', 'status',
        'backup', 'db', 'database', 'sql', 'mysql', 'postgres', 'redis', 'cache'
    ]
    
    # Subdomains specific to energy companies
    energy_specific = [
        'energy', 'power', 'electric', 'gas', 'oil', 'renewable', 'solar', 'wind', 
        'hydro', 'nuclear', 'thermal', 'grid', 'distribution', 'transmission', 
        'generation', 'consumption', 'metering', 'billing', 'customer', 'client', 
        'portal', 'dashboard', 'monitoring', 'control', 'automation', 'iot', 'smart', 
        'green', 'clean', 'sustainable', 'efficiency', 'analytics', 'reporting', 
        'compliance', 'regulatory', 'safety', 'maintenance', 'repair', 'emergency', 
        'outage', 'status', 'map', 'location', 'facility', 'plant', 'station', 
        'substation', 'transformer', 'switchgear', 'breaker', 'relay', 'protection',
        'communication', 'telemetry', 'scada', 'hmi', 'plc', 'archive', 'recovery', 
        'disaster', 'security', 'access', 'authentication', 'authorization', 'audit',
        'log', 'event', 'alarm', 'notification', 'alert', 'schedule', 'calendar', 
        'planning', 'forecast', 'prediction', 'optimization', 'performance', 
        'quality', 'reliability', 'app', 'mobile', 'web', 'cloud', 'hosting',
        'infrastructure', 'network', 'connectivity', 'api', 'rest', 'graphql',
        'websocket', 'webhook', 'microservice', 'container', 'kubernetes', 'docker',
        'orchestration', 'deployment', 'ci', 'cd', 'pipeline', 'build', 'deploy',
        'release', 'monitor', 'observe', 'trace', 'metric', 'insight', 'intelligence',
        'machine-learning', 'ai', 'artificial-intelligence', 'data-science', 'big-data',
        'warehouse', 'lake', 'stream', 'batch', 'real-time', 'corp', 'enterprise',
        'business', 'company', 'inc', 'llc', 'ltd', 'group', 'holdings', 'partners',
        'associates', 'solutions', 'services', 'systems', 'technologies', 'digital',
        'online', 'internet', 'collaboration', 'productivity', 'workflow', 'process',
        'automation', 'integration', 'gateway', 'router', 'switch', 'firewall',
        'loadbalancer', 'proxy', 'ids', 'ips', 'backup', 'recovery', 'archive',
        'logs', 'analytics', 'metrics', 'report', 'dashboard', 'insight'
    ]
    
    # Combine all the lists
    all_subdomains = subdomains_basic + energy_specific
    
    # Remove duplicates
    return list(set(all_subdomains))

def _extract_subdomains_from_domain(names, domain):
    """
    Extracts prefixes of subdomain of a list of FQDN that belong to the domain.
    
    Used for crt.sh, CertSpotter and other sources that return names complete.
    Filters wildcards (*.dom), the domain root and normalizes a lowercase.
    
    Args:
        names (list): FQDN (ej: ['www.example.com', '*.example.com', 'api.staging.example.com'])
        domain (str): Domain base (ej: example.com)
    
    Returns:
        set: prefixes unique (ej: {'www', 'api.staging'}). Includes multi-level.
    
    Ejemplo:
        _extract_subdomains_from_domain(['www.example.com', 'mail.example.com'], 'example.com')
        -> {'www', 'mail'}
    """
    result = set()
    domain_lower = domain.lower().rstrip('.')
    for name in names:
        name = name.strip().lower()
        if not name or name == '@':
            continue
        if name.startswith('*.'):
            name = name[2:]
        elif name.startswith('*'):
            continue
        if name == domain_lower:
            continue
        if name.endswith('.' + domain_lower):
            prefix = name[:-len(domain_lower)-1]
            if prefix:
                result.add(prefix)  # Includes multi-level: api.staging.example.com -> api.staging
    return result


# --- Individual OSINT source queries (used by search_subdomains_osint) ---
# Each function takes the lowercased domain and returns a set() of subdomain
# prefixes found by that single source. They run concurrently, so none of
# them may mutate shared state - each works entirely on its own local `found`
# set and its own requests.Session() where needed.

def _osint_crtsh(domain_lower):
    """crt.sh - Certificate Transparency. https://crt.sh/?q=%25.{domain}&output=json"""
    found = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain_lower}&output=json"
        resp = requests.get(url, timeout=10, headers={'User-Agent': 'ReconSurface/2.8'})
        if resp.status_code == 200:
            data = resp.json()
            for cert in data if isinstance(data, list) else []:
                name_value = cert.get('name_value', '')
                if name_value:
                    names = [n.strip() for n in name_value.replace('\r', '\n').split('\n') if n.strip()]
                    found.update(_extract_subdomains_from_domain(names, domain_lower))
    except Exception:
        pass
    return found

def _osint_threatcrowd(domain_lower):
    """ThreatCrowd. https://www.threatcrowd.org/searchApi/v2/domain/report/"""
    found = set()
    try:
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain_lower}"
        resp = requests.get(url, timeout=10, headers={'User-Agent': 'ReconSurface/2.8'})
        if resp.status_code == 200:
            data = resp.json()
            for sub in data.get('subdomains', []) or []:
                sub = sub.strip().lower()
                if sub.endswith('.' + domain_lower):
                    prefix = sub[:-len(domain_lower)-1]
                    if prefix and '.' not in prefix:
                        found.add(prefix)
                    elif prefix:
                        found.add(prefix.split('.')[0])
    except Exception:
        pass
    return found

def _osint_rapiddns(domain_lower):
    """RapidDNS (scraping HTML). https://rapiddns.io/subdomain/{domain}"""
    found = set()
    try:
        url = f"https://rapiddns.io/subdomain/{domain_lower}"
        resp = requests.get(url, timeout=10, headers={'User-Agent': 'ReconSurface/2.8'})
        if resp.status_code == 200:
            pattern = re.compile(r'<td[^>]*>([a-zA-Z0-9][a-zA-Z0-9.-]*\.' + re.escape(domain_lower) + r')</td>', re.I)
            for m in pattern.finditer(resp.text):
                fqdn = m.group(1).strip().lower()
                if fqdn.endswith('.' + domain_lower):
                    prefix = fqdn[:-len(domain_lower)-1]
                    if prefix:
                        found.add(prefix)
            patron2 = re.compile(r'<a[^>]+href="[^"]*"[^>]*>([a-zA-Z0-9][a-zA-Z0-9.-]*\.' + re.escape(domain_lower) + r')</a>', re.I)
            for m in patron2.finditer(resp.text):
                fqdn = m.group(1).strip().lower()
                if fqdn.endswith('.' + domain_lower):
                    prefix = fqdn[:-len(domain_lower)-1]
                    if prefix:
                        found.add(prefix)
    except Exception:
        pass
    return found

def _osint_netcraft(domain_lower):
    """Netcraft (scraping). https://searchdns.netcraft.com/?host={domain}"""
    found = set()
    try:
        url = f"https://searchdns.netcraft.com/?host={domain_lower}"
        resp = requests.get(url, timeout=10, headers={'User-Agent': 'ReconSurface/2.8'})
        if resp.status_code == 200:
            pattern = re.compile(r'([a-zA-Z0-9][a-zA-Z0-9.-]*\.' + re.escape(domain_lower) + r')', re.I)
            for m in pattern.finditer(resp.text):
                fqdn = m.group(1).strip().lower()
                if fqdn.endswith('.' + domain_lower) and fqdn != domain_lower:
                    prefix = fqdn[:-len(domain_lower)-1]
                    if prefix:
                        found.add(prefix.split('.')[0])
    except Exception:
        pass
    return found

def _osint_certspotter(domain_lower):
    """CertSpotter (SSLMate). https://api.certspotter.com/v1/issuances (10 queries/hour)"""
    found = set()
    try:
        url = f"https://api.certspotter.com/v1/issuances?domain={domain_lower}&include_subdomains=true&expand=dns_names"
        resp = requests.get(url, timeout=10, headers={'User-Agent': 'ReconSurface/2.8'})
        if resp.status_code == 200:
            data = resp.json()
            for iss in data if isinstance(data, list) else []:
                for name in iss.get('dns_names', []) or []:
                    found.update(_extract_subdomains_from_domain([name], domain_lower))
    except Exception:
        pass
    return found

def _osint_hackertarget(domain_lower):
    """HackerTarget hostsearch (50 queries/day free). subdomain,ip per line"""
    found = set()
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain_lower}"
        resp = requests.get(url, timeout=10, headers={'User-Agent': 'ReconSurface/2.8'})
        if resp.status_code == 200 and resp.text.strip():
            text = resp.text.strip().lower()
            if 'error' not in text and 'limit' not in text and 'exceeded' not in text:
                for line in resp.text.strip().splitlines():
                    if ',' in line and domain_lower in line.lower():
                        part = line.split(',')[0].strip().lower()
                        if part.endswith('.' + domain_lower) and part != domain_lower:
                            prefix = part[:-len(domain_lower)-1]
                            if prefix:
                                found.add(prefix)
    except Exception:
        pass
    return found

def _osint_threatminer(domain_lower):
    """ThreatMiner (rt=5 = subdomains, 10 queries/min). https://api.threatminer.org/v2/domain.php"""
    found = set()
    try:
        url = f"https://api.threatminer.org/v2/domain.php?q={domain_lower}&rt=5"
        resp = requests.get(url, timeout=10, headers={'User-Agent': 'ReconSurface/2.8'})
        if resp.status_code == 200:
            data = resp.json()
            for sub in data.get('results', []) or []:
                if isinstance(sub, dict):
                    sub = sub.get('domain') or sub.get('host') or sub.get('value') or ''
                sub = str(sub).strip().lower()
                if sub.endswith('.' + domain_lower):
                    prefix = sub[:-len(domain_lower)-1]
                    if prefix:
                        found.add(prefix)
    except Exception:
        pass
    return found

def _osint_thc(domain_lower):
    """THC (ip.thc.org), 249 req at 0.5/sec replenish. https://ip.thc.org/sb/{domain}"""
    found = set()
    try:
        url = f"https://ip.thc.org/sb/{domain_lower}?l=100&nocolor=1"
        resp = requests.get(url, timeout=15, headers={'User-Agent': 'ReconSurface/2.8'})
        if resp.status_code == 200 and resp.text.strip():
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            for line in resp.text.strip().splitlines():
                line = ansi_escape.sub('', line).strip()
                if not line or line.startswith(';;') or line.startswith('Comment:'):
                    continue
                line_lower = line.lower()
                if line_lower.endswith('.' + domain_lower):
                    prefix = line_lower[:-len(domain_lower)-1]
                    if prefix and not prefix.startswith('*'):
                        found.add(prefix)
    except Exception:
        pass
    return found

def _osint_subdomaincenter(domain_lower):
    """SubdomainCenter (3 queries/min). https://api.subdomain.center/"""
    found = set()
    try:
        url = f"https://api.subdomain.center/?domain={domain_lower}"
        resp = requests.get(url, timeout=15, headers={'User-Agent': 'ReconSurface/2.8'})
        if resp.status_code == 200:
            data = resp.json()
            for sub in data if isinstance(data, list) else []:
                sub = str(sub).strip().lower()
                if sub.endswith('.' + domain_lower):
                    prefix = sub[:-len(domain_lower)-1]
                    if prefix and '*' not in prefix:
                        found.add(prefix)
    except Exception:
        pass
    return found

def _osint_dnsdumpster(domain_lower):
    """DNSDumpster (POST + CSRF). https://dnsdumpster.com/"""
    found = set()
    try:
        session = requests.Session()
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Referer': 'https://dnsdumpster.com/'
        }
        get_resp = session.get('https://dnsdumpster.com/', timeout=15, headers=headers)
        if get_resp.status_code == 200:
            csrf_token = None
            m_csrf = re.search(r'name="csrfmiddlewaretoken"\s+value="([^"]+)"', get_resp.text)
            if m_csrf:
                csrf_token = m_csrf.group(1)
            if not csrf_token:
                csrf_token = session.cookies.get('csrftoken')
            if csrf_token:
                post_data = {
                    'csrfmiddlewaretoken': csrf_token,
                    'targetip': domain_lower,
                    'user': 'free'
                }
                post_resp = session.post('https://dnsdumpster.com/', data=post_data, timeout=30, headers=headers)
                if post_resp.status_code == 200:
                    pattern = re.compile(r'([a-zA-Z0-9][a-zA-Z0-9.-]*\.' + re.escape(domain_lower) + r')', re.I)
                    for m in pattern.finditer(post_resp.text):
                        fqdn = m.group(1).strip().lower()
                        if fqdn.endswith('.' + domain_lower) and fqdn != domain_lower:
                            prefix = fqdn[:-len(domain_lower)-1]
                            if prefix and '*' not in prefix:
                                found.add(prefix)
    except Exception:
        pass
    return found

def _osint_duckduckgo(domain_lower):
    """DuckDuckGo site: search (scraping). https://html.duckduckgo.com/html/"""
    found = set()
    try:
        url = f"https://html.duckduckgo.com/html/?q=site:{domain_lower}"
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
        resp = requests.get(url, timeout=15, headers=headers)
        if resp.status_code == 200:
            pattern = re.compile(r'([a-zA-Z0-9][a-zA-Z0-9.-]*\.' + re.escape(domain_lower) + r')', re.I)
            for m in pattern.finditer(resp.text):
                fqdn = m.group(1).strip().lower()
                if fqdn.endswith('.' + domain_lower) and fqdn != domain_lower:
                    prefix = fqdn[:-len(domain_lower)-1]
                    if prefix and '*' not in prefix:
                        found.add(prefix)
    except Exception:
        pass
    return found

def _osint_bing(domain_lower):
    """Bing site: search (scraping). https://www.bing.com/search"""
    found = set()
    try:
        url = f"https://www.bing.com/search?q=site:{domain_lower}&count=50"
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
        resp = requests.get(url, timeout=15, headers=headers)
        if resp.status_code == 200 and 'captcha' not in resp.text.lower():
            pattern = re.compile(r'([a-zA-Z0-9][a-zA-Z0-9.-]*\.' + re.escape(domain_lower) + r')', re.I)
            for m in pattern.finditer(resp.text):
                fqdn = m.group(1).strip().lower()
                if fqdn.endswith('.' + domain_lower) and fqdn != domain_lower:
                    prefix = fqdn[:-len(domain_lower)-1]
                    if prefix and '*' not in prefix:
                        found.add(prefix.split('.')[0])
    except Exception:
        pass
    return found

def _osint_qwant(domain_lower):
    """Qwant site: search (scraping). https://www.qwant.com/"""
    found = set()
    try:
        url = f"https://www.qwant.com/?q=site:{domain_lower}"
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
        resp = requests.get(url, timeout=15, headers=headers)
        if resp.status_code == 200:
            pattern = re.compile(r'([a-zA-Z0-9][a-zA-Z0-9.-]*\.' + re.escape(domain_lower) + r')', re.I)
            for m in pattern.finditer(resp.text):
                fqdn = m.group(1).strip().lower()
                if fqdn.endswith('.' + domain_lower) and fqdn != domain_lower:
                    prefix = fqdn[:-len(domain_lower)-1]
                    if prefix and '*' not in prefix:
                        found.add(prefix)
    except Exception:
        pass
    return found

def _osint_robots_sitemap(domain_lower):
    """robots.txt and sitemap.xml of the target's own site."""
    found = set()
    try:
        for proto in ('https', 'http'):
            try:
                r = requests.get(f"{proto}://{domain_lower}/robots.txt", timeout=5)
                if r.status_code == 200 and 'subdomain' in r.text.lower():
                    for line in r.text.splitlines():
                        if 'disallow' in line.lower() or 'allow' in line.lower():
                            for part in re.split(r'[/\s]+', line):
                                if domain_lower in part.lower() and part.startswith(('http://', 'https://')):
                                    try:
                                        parsed = urlparse(part)
                                        host = parsed.netloc or parsed.path.split('/')[0]
                                        if host.endswith('.' + domain_lower) and host != domain_lower:
                                            prefix = host[:-len(domain_lower)-1].split('.')[0]
                                            if prefix:
                                                found.add(prefix)
                                    except Exception:
                                        pass
                break
            except Exception:
                continue
        try:
            r = requests.get(f"https://{domain_lower}/sitemap.xml", timeout=5)
            if r.status_code == 200:
                for m in re.finditer(r'<loc>([^<]+)</loc>', r.text):
                    url = m.group(1).strip()
                    try:
                        parsed = urlparse(url)
                        host = (parsed.netloc or parsed.path).split(':')[0]
                        if host.endswith('.' + domain_lower) and host != domain_lower:
                            prefix = host[:-len(domain_lower)-1].split('.')[0]
                            if prefix:
                                found.add(prefix)
                    except Exception:
                        pass
        except Exception:
            pass
    except Exception:
        pass
    return found

# Sources queried by search_subdomains_osint(), run concurrently since each
# hits a different site and only once per scan (no per-site rate limit is
# exceeded by parallelizing across *different* sources).
_OSINT_SOURCES = [
    ("crt.sh", _osint_crtsh),
    ("ThreatCrowd", _osint_threatcrowd),
    ("RapidDNS", _osint_rapiddns),
    ("Netcraft", _osint_netcraft),
    ("CertSpotter", _osint_certspotter),
    ("HackerTarget", _osint_hackertarget),
    ("ThreatMiner", _osint_threatminer),
    ("THC (ip.thc.org)", _osint_thc),
    ("SubdomainCenter", _osint_subdomaincenter),
    ("DNSDumpster", _osint_dnsdumpster),
    ("DuckDuckGo", _osint_duckduckgo),
    ("Bing", _osint_bing),
    ("Qwant", _osint_qwant),
    ("robots.txt/sitemap", _osint_robots_sitemap),
]

def search_subdomains_osint(domain):
    """
    Searches subdomains using 14 sources OSINT free (style TheHarvester), in parallel.

    Sources (see _OSINT_SOURCES / the _osint_*() functions for each one's URL
    and rate-limit notes): crt.sh, ThreatCrowd, RapidDNS, Netcraft, CertSpotter,
    HackerTarget, ThreatMiner, THC, SubdomainCenter, DNSDumpster, DuckDuckGo,
    Bing, Qwant, robots.txt/sitemap.

    Args:
        domain (str): Domain to analyze (ej: example.com)

    Returns:
        list: prefixes of subdomain (ej: ['www', 'mail', 'api.staging']).
              Is verify with DNS in detect_subdomains() before being added to the table.

    notes:
        - All 14 sources are queried concurrently (each hits a different site
          exactly once, so no individual source's rate limit is exceeded).
        - Timeout 10-15s per request; errors individual not stop the flow.
        - User-Agent: ReconSurface/2.8 (or a browser UA for scraped search engines).

    See also:
        _extract_subdomains_from_domain(), detect_subdomains()
    """
    domain_lower = domain.lower().strip()
    print_colored(f"[*] Performing OSINT search for {domain}...", Colors.BLUE)

    subdomains_found = set()
    progress_osint_query = {
        'completed': 0,
        'total': len(_OSINT_SOURCES),
        'active': True,
        'start_time': time.time()
    }

    def show_progress_osint_query():
        """Separate thread to show the progress bar while OSINT sources run in parallel"""
        old_settings = _enter_raw_no_echo_mode()

        chars = "|/-\\"
        i = 0
        while progress_osint_query['active']:
            try:
                elapsed = time.time() - progress_osint_query['start_time']
                elapsed_formatted = f"{int(elapsed//3600):02d}:{int((elapsed%3600)//60):02d}:{int(elapsed%60):02d}"
                print(f"\r[*] Querying {progress_osint_query['total']} OSINT sources in parallel... {chars[i % len(chars)]} ({progress_osint_query['completed']}/{progress_osint_query['total']}) - {elapsed_formatted}", end="", flush=True)
                i += 1
                time.sleep(0.1)
            except KeyboardInterrupt:
                break

        _restore_terminal_mode(old_settings)

    progress_thread = threading.Thread(target=show_progress_osint_query, daemon=True)
    progress_thread.start()

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(_OSINT_SOURCES)) as executor:
            futures = {executor.submit(func, domain_lower): name for name, func in _OSINT_SOURCES}
            for future in concurrent.futures.as_completed(futures):
                name = futures[future]
                progress_osint_query['completed'] += 1
                try:
                    found = future.result()
                except Exception:
                    found = set()
                if found:
                    subdomains_found.update(found)
                    print("\r\033[K", end="", flush=True)
                    print_colored(f"    [+] {name}: {len(found)} subdomains found", Colors.GREEN)
    except KeyboardInterrupt:
        progress_osint_query['active'] = False
        progress_thread.join(timeout=0.3)
        _ensure_terminal_sane()
        print("\n[*] OSINT search cancelled by the user")
        try:
            os._exit(0)
        except Exception:
            pass

    progress_osint_query['active'] = False
    progress_thread.join(timeout=0.3)
    _ensure_terminal_sane()
    print("\r\033[K", end="", flush=True)

    return list(subdomains_found)

def detect_subdomains(domain, show_details=True, show_table2=True, show_summary=True, return_map=False):
    """Detects subdomains from the domain using advanced techniques

    Parameters:
    - show_details: controls messages of progress/headers (not affects tables)
    - show_table2: controls if is prints the Table 2 (Reverse DNS)
    - show_summary: controls printing from the summary final
    """
    if show_details:
        print_colored(f"\n{'='*60}", Colors.CYAN)
        print_colored(f"🔍 DETECTION Of SUBDOMAINS: {domain}", Colors.BOLD + Colors.WHITE)
        print_colored(f"{'='*60}", Colors.CYAN)
    
    # Verify that the domain exists before of proceed
    if not verify_domain_exists(domain):
        if show_details:
            print_colored(f"\n❌ The domain {domain} does not exist or does not resolve. Aborting scan.", Colors.RED)
        return []
    
    if show_details:
        print_colored(f"\n✅ Domain verified. Proceeding with the scan...", Colors.GREEN)
    
    # Generate list complete of subdomains
    subdomains_common = generate_list_subdomains_complete()
    
    subdomains_found = []
    ips_unique = set()
    table_subdomains = []  # For store the information of the table
    
    if show_details:
        print_colored(f"[*] Testing {len(subdomains_common)} subdomains with advanced techniques...", Colors.BLUE)
    
    # Technique 1: Brute force with expanded list
    print_colored(f"[*] Technique 1: Brute force with {len(subdomains_common)} subdomains...", Colors.BLUE)
    
    # Use ThreadPoolExecutor for test subdomains in parallel with barra of progress
    
    # Variables shared for the progress
    progress_data = {
        'processed': 0,
        'found': 0,
        'total': len(subdomains_common),
        'active': True,
        'start_time': time.time()
    }
    
    def show_progress():
        """Thread separate for show the barra of progress"""
        # configure terminal for ignore ENTER but allow CONTROL-C
        old_settings = _enter_raw_no_echo_mode()

        chars = "|/-\\"
        i = 0
        while progress_data['active']:
            try:
                elapsed = time.time() - progress_data['start_time']
                elapsed_formatted = f"{int(elapsed//3600):02d}:{int((elapsed%3600)//60):02d}:{int(elapsed%60):02d}"
                percentage = int((progress_data['processed'] / progress_data['total']) * 100)
                print(f"\r[*] Scanning DNS... {chars[i % len(chars)]} {percentage}% ({progress_data['processed']}/{progress_data['total']}) - {progress_data['found']} found - {elapsed_formatted}", end="", flush=True)
                i += 1
                time.sleep(0.1)  # Update each 100ms
            except KeyboardInterrupt:
                # Only allow CONTROL-C, ignore other keys
                break

        # Restore input
        _restore_terminal_mode(old_settings)

    # Start thread of progress
    print_colored(f"[*] Scanning DNS...", Colors.BLUE, end="")
    progress_thread = threading.Thread(target=show_progress, daemon=True)
    progress_thread.start()
    
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
            futures = {executor.submit(verify_dns_existence, f"{sub}.{domain}"): sub for sub in subdomains_common}
            
            for future in concurrent.futures.as_completed(futures):
                subdomain = futures[future]
                progress_data['processed'] += 1
                
                try:
                    result = future.result()
                    if result:
                        progress_data['found'] += 1
                        # Get IP from the subdomain (already resolves CNAMEs automatically)
                        ips = resolve_ips_a_aaaa(f"{subdomain}.{domain}")
                        if ips:
                            subdomains_found.append(subdomain)
                            ips_unique.update(ips)
                            
                            # Filter only IPs valid and store information for the table
                            ips_filtered = filter_only_ips(ips)
                            for ip in ips_filtered:
                                reverse_dns = reverse_dns_lookup(ip)
                                table_subdomains.append({
                                    'subdomain': f"{subdomain}.{domain}",
                                    'ip': ip,
                                    'reverse_dns': reverse_dns if reverse_dns else 'N/A'
                                })
                            
                except Exception:
                    pass
    except KeyboardInterrupt:
        # Stop thread of progress immediately
        progress_data['active'] = False
        progress_thread.join(timeout=0.3)
        _ensure_terminal_sane()
        print("\n[*] Scan DNS cancelled for the user")
        # Clear terminal and exit cleanly
        try:
            os._exit(0)
        except Exception:
            return []
    
    # Stop thread of progress and show result final
    progress_data['active'] = False
    progress_thread.join(timeout=0.3)
    _ensure_terminal_sane()
    
    # Clear completely the line before of show result final
    print("\r\033[K", end="", flush=True)
    
    elapsed = time.time() - progress_data['start_time']
    elapsed_formatted = f"{int(elapsed//3600):02d}:{int((elapsed%3600)//60):02d}:{int(elapsed%60):02d}"
    print_colored(f"[*] DNS completed - {progress_data['found']} subdomains found in {elapsed_formatted}", Colors.BLUE if progress_data['found'] > 0 else Colors.WHITE)
    
    # Technique 2: OSINT search
    if show_details:
        print_colored(f"\n[*] Technique 2: OSINT search...", Colors.BLUE)

    # Barra of progress for OSINT
    print_colored(f"[*] Scanning OSINT...", Colors.BLUE)
    start_time = time.time()

    subdomains_osint = search_subdomains_osint(domain)
    
    elapsed = time.time() - start_time
    elapsed_formatted = f"{int(elapsed//3600):02d}:{int((elapsed%3600)//60):02d}:{int(elapsed%60):02d}"
    print_colored(f"\r[*] OSINT completed - {len(subdomains_osint)} candidates in {elapsed_formatted}", Colors.BLUE if len(subdomains_osint) > 0 else Colors.WHITE)
    
    # Verify and merge subdomains OSINT (crt.sh, ThreatCrowd, RapidDNS, etc.)
    if subdomains_osint:
        candidates_osint = [sub for sub in subdomains_osint if sub not in subdomains_found]

        if candidates_osint:
            # Shared variables for the progress bar
            progress_osint_verify = {
                'processed': 0,
                'found': 0,
                'total': len(candidates_osint),
                'active': True,
                'start_time': time.time()
            }

            def show_progress_osint_verify():
                """Separate thread to show the progress bar of OSINT DNS verification"""
                # configure terminal for ignore ENTER but allow CONTROL-C
                old_settings = _enter_raw_no_echo_mode()

                chars = "|/-\\"
                i = 0
                while progress_osint_verify['active']:
                    try:
                        elapsed = time.time() - progress_osint_verify['start_time']
                        elapsed_formatted = f"{int(elapsed//3600):02d}:{int((elapsed%3600)//60):02d}:{int(elapsed%60):02d}"
                        percentage = int((progress_osint_verify['processed'] / progress_osint_verify['total']) * 100)
                        print(f"\r[*] Verifying OSINT candidates with DNS... {chars[i % len(chars)]} {percentage}% ({progress_osint_verify['processed']}/{progress_osint_verify['total']}) - {progress_osint_verify['found']} found - {elapsed_formatted}", end="", flush=True)
                        i += 1
                        time.sleep(0.1)
                    except KeyboardInterrupt:
                        break

                _restore_terminal_mode(old_settings)

            if show_details:
                print_colored(f"[*] Verifying {len(candidates_osint)} OSINT candidates with DNS...", Colors.BLUE, end="")

            progress_osint_verify_thread = threading.Thread(target=show_progress_osint_verify, daemon=True)
            progress_osint_verify_thread.start()

            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
                    futures = {executor.submit(verify_dns_existence, f"{sub}.{domain}"): sub for sub in candidates_osint}

                    for future in concurrent.futures.as_completed(futures):
                        sub = futures[future]
                        progress_osint_verify['processed'] += 1
                        try:
                            if future.result():
                                progress_osint_verify['found'] += 1
                                ips = resolve_ips_a_aaaa(f"{sub}.{domain}")
                                if ips:
                                    subdomains_found.append(sub)
                                    ips_unique.update(ips)
                                    ips_filtered = filter_only_ips(ips)
                                    for ip in ips_filtered:
                                        reverse_dns = reverse_dns_lookup(ip)
                                        table_subdomains.append({
                                            'subdomain': f"{sub}.{domain}",
                                            'ip': ip,
                                            'reverse_dns': reverse_dns if reverse_dns else 'N/A'
                                        })
                        except Exception:
                            pass
            except KeyboardInterrupt:
                progress_osint_verify['active'] = False
                progress_osint_verify_thread.join(timeout=0.3)
                _ensure_terminal_sane()
                print("\n[*] OSINT verification cancelled by the user")
                try:
                    os._exit(0)
                except Exception:
                    pass

            progress_osint_verify['active'] = False
            progress_osint_verify_thread.join(timeout=0.3)
            _ensure_terminal_sane()

            print("\r\033[K", end="", flush=True)
            elapsed = time.time() - progress_osint_verify['start_time']
            elapsed_formatted = f"{int(elapsed//3600):02d}:{int((elapsed%3600)//60):02d}:{int(elapsed%60):02d}"
            if show_details:
                print_colored(f"[*] OSINT verification completed - {progress_osint_verify['found']} confirmed in {elapsed_formatted}", Colors.BLUE if progress_osint_verify['found'] > 0 else Colors.WHITE)
    
    # Technique 3: Search for additional subdomains based on patterns
    if show_details:
        print_colored(f"\n[*] Technique 3: Searching additional patterns...", Colors.BLUE)
    
    # Search subdomains that could having been missed
    subdomains_additional = [
        'cs-emobility', 'empresas', 'energy', 'messenger', 'quote', 
        'quotev2', 'socket', 'storage', 'test-equote-api', 'webtest'
    ]
    
    # Barra of progress for additional patterns with separate thread
    print_colored(f"[*] Scanning patterns...", Colors.BLUE, end="")
    
    # Variables shared for the progress of patterns
    progress_patrones = {
        'processed': 0,
        'found': 0,
        'total': len(subdomains_additional),
        'active': True,
        'start_time': time.time()
    }
    
    def show_progress_patrones():
        """Thread separate for show the barra of progress of patterns"""
        # configure terminal for ignore ENTER but allow CONTROL-C
        old_settings = _enter_raw_no_echo_mode()

        chars = "|/-\\"
        i = 0
        while progress_patrones['active']:
            try:
                elapsed = time.time() - progress_patrones['start_time']
                elapsed_formatted = f"{int(elapsed//3600):02d}:{int((elapsed%3600)//60):02d}:{int(elapsed%60):02d}"
                percentage = int((progress_patrones['processed'] / progress_patrones['total']) * 100)
                print(f"\r[*] Scanning patterns... {chars[i % len(chars)]} {percentage}% ({progress_patrones['processed']}/{progress_patrones['total']}) - {progress_patrones['found']} found - {elapsed_formatted}", end="", flush=True)
                i += 1
                time.sleep(0.1)  # Update each 100ms
            except KeyboardInterrupt:
                # Only allow CONTROL-C, ignore other keys
                break
        
        # Restore input
        _restore_terminal_mode(old_settings)

    # Start thread of progress for patterns
    progress_patrones_thread = threading.Thread(target=show_progress_patrones, daemon=True)
    progress_patrones_thread.start()
    
    for sub in subdomains_additional:
        progress_patrones['processed'] += 1
        if sub not in subdomains_found:
            try:
                result = verify_dns_existence(f"{sub}.{domain}")
                if result:
                    progress_patrones['found'] += 1
                    ips = resolve_ips_a_aaaa(f"{sub}.{domain}")
                    if ips:
                        subdomains_found.append(sub)
                        ips_unique.update(ips)
                        
                        # Filter only IPs valid and store information for the table
                        ips_filtered = filter_only_ips(ips)
                        for ip in ips_filtered:
                            reverse_dns = reverse_dns_lookup(ip)
                            table_subdomains.append({
                                'subdomain': f"{sub}.{domain}",
                                'ip': ip,
                                'reverse_dns': reverse_dns if reverse_dns else 'N/A'
                            })
            except Exception:
                pass
    
    # Stop thread of progress and show result final
    progress_patrones['active'] = False
    progress_patrones_thread.join(timeout=0.3)
    _ensure_terminal_sane()
    
    # Clear completely the line before of show result final
    print("\r\033[K", end="", flush=True)
    
    elapsed = time.time() - progress_patrones['start_time']
    elapsed_formatted = f"{int(elapsed//3600):02d}:{int((elapsed%3600)//60):02d}:{int(elapsed%60):02d}"
    print_colored(f"[*] Patterns completed - {progress_patrones['found']} subdomains found in {elapsed_formatted}", Colors.BLUE if progress_patrones['found'] > 0 else Colors.WHITE)
    
    # Group subdomains for IPs
    subdomains_per_ip = {}
    for item in table_subdomains:
        subdomain = item['subdomain']
        ip = item['ip']
        if subdomain not in subdomains_per_ip:
            subdomains_per_ip[subdomain] = []
        subdomains_per_ip[subdomain].append(ip)

    # Include domain main in the tables if it resolves
    try:
        ips_main = resolve_ips_a_aaaa(domain)
        if ips_main:
            # Add to the map for Table 1
            if domain not in subdomains_per_ip:
                subdomains_per_ip[domain] = []
            for ip in ips_main:
                if ip not in subdomains_per_ip[domain]:
                    subdomains_per_ip[domain].append(ip)
            # Add inputs for Table 2 (reverse DNS)
            for ip in ips_main:
                reverse_dns = reverse_dns_lookup(ip)
                table_subdomains.append({
                    'subdomain': domain,
                    'ip': ip,
                    'reverse_dns': reverse_dns if reverse_dns else 'N/A'
                })
    except Exception:
        pass
    
    # Calculate widths optimal for the table 1
    def name_displayable(sub):
        return f"{sub} (MAIN)" if sub == domain else sub

    width_subdomain = max(len('SUBDOMAIN'), max(len(name_displayable(sub)) for sub in subdomains_per_ip.keys()))
    # Calculate the width max of IPs
    max_ips_length = 0
    for ips in subdomains_per_ip.values():
        ips_str = ', '.join(list(set(ips)))
        max_ips_length = max(max_ips_length, len(ips_str))
    width_ips = max(len('IPs'), max_ips_length)
    
    # adjust widths min and max
    width_subdomain = max(20, min(width_subdomain + 2, 50))  # Min 20, max 50
    width_ips = max(20, min(width_ips + 2, 60))  # Min 20, max 60
    
    # Calculate width total of the table (2 barras vertical: left and right)
    width_total = width_subdomain + width_ips + 2
    
    # Calculate margin for center table 1
    term_width = get_terminal_width()
    margin_table1 = max(0, (term_width - width_total) // 2)
    pad1 = " " * margin_table1

    # Show results in dos tables separated (centered)
    print(pad1, end="")
    print_colored(f"{'═'*(width_total+1)}", Colors.CYAN)
    # Title of the table 1 with barras blue
    print(pad1, end="")
    print_colored("║", Colors.BLUE, end="")
    print_colored(f"{'📊 TABLE 1: SUBDOMAINS → IPs':^{width_total-2}}", Colors.BOLD + Colors.WHITE, end="")
    print_colored("║", Colors.BLUE)
    print(pad1, end="")
    print_colored(f"{'═'*(width_total+1)}", Colors.CYAN)
    
    # Header of the table 1 with barras blue
    print(pad1, end="")
    print_colored("║", Colors.BLUE, end="")
    print_colored(f"{'SUBDOMAIN':^{width_subdomain}}", Colors.BOLD + Colors.YELLOW, end="")
    print_colored("║", Colors.BLUE, end="")
    print_colored(f"{'IPs':^{width_ips}}", Colors.BOLD + Colors.YELLOW, end="")
    print_colored("║", Colors.BLUE)
    print(pad1, end="")
    print_colored(f"╠{'═'*width_subdomain}╬{'═'*width_ips}╣", Colors.CYAN)
    
    # Show table 1: Subdomains → IPs (place domain main at the start)
    order_subs = list(subdomains_per_ip.keys())
    if domain in order_subs:
        order_subs = [domain] + [s for s in order_subs if s != domain]
    for i, subdomain in enumerate(order_subs):
        ips = subdomains_per_ip[subdomain]
        ips_unique = list(set(ips))  # Remove duplicates
        ips_str = ', '.join(ips_unique)
        
        # Print row with handling of content long (red if is main)
        color_row = Colors.RED if subdomain == domain else Colors.GREEN
        print_row_table_ip(name_displayable(subdomain), ips_str, width_subdomain, width_ips, margin=pad1, color_content=color_row)
        
        # Add separator of line between subdomains (except the last)
        if i < len(subdomains_per_ip) - 1:
            print(pad1, end="")
            print_colored(f"╟{'─'*width_subdomain}╫{'─'*width_ips}╢", Colors.BLUE)
    
    print(pad1, end="")
    print_colored(f"{'═'*(width_total+1)}", Colors.CYAN)
    
    # Table 2: Subdomains → Reverse DNS (dynamic)
    # Group reverse DNS for subdomain
    subdomains_reverse_dns = {}
    for item in table_subdomains:
        subdomain = item['subdomain']
        reverse_dns = item['reverse_dns']
        if subdomain not in subdomains_reverse_dns:
            subdomains_reverse_dns[subdomain] = []
        if reverse_dns not in subdomains_reverse_dns[subdomain]:
            subdomains_reverse_dns[subdomain].append(reverse_dns)

    if show_table2:
        # Calculate widths optimal for the table 2 a start from the content
        width_sub_t2 = max(len('SUBDOMAINS'), max((len(name_displayable(sub)) for sub in subdomains_reverse_dns.keys()), default=0))
        max_reverse_len = 0
        for reverse_list in subdomains_reverse_dns.values():
            reverse_valid = [rdns for rdns in reverse_list if rdns != 'N/A']
            reverse_str = ', '.join(reverse_valid) if reverse_valid else 'N/A'
            if len(reverse_str) > max_reverse_len:
                max_reverse_len = len(reverse_str)
        width_rev_t2 = max(len('REVERSE DNS'), max_reverse_len)

        # Limits min and max
        width_sub_t2 = max(20, min(width_sub_t2 + 2, 50))
        width_rev_t2 = max(20, min(width_rev_t2 + 2, 80))
        width_total_t2 = width_sub_t2 + width_rev_t2 + 2

        # Calculate margin for center table 2
        term_width = get_terminal_width()
        margin_table2 = max(0, (term_width - width_total_t2) // 2)
        pad2 = " " * margin_table2

        # Print header of table 2
        print("\n", end="")
        print(pad2, end="")
        print_colored(f"{'═'*(width_total_t2+1)}", Colors.CYAN)
        print(pad2, end="")
        print_colored("║", Colors.BLUE, end="")
        print_colored(f"{'🌐 TABLE 2: SUBDOMAINS → REVERSE DNS':^{width_total_t2-2}}", Colors.BOLD + Colors.WHITE, end="")
        print_colored("║", Colors.BLUE)
        print(pad2, end="")
        print_colored(f"{'═'*(width_total_t2+1)}", Colors.CYAN)
        print(pad2, end="")
        print_colored("║", Colors.BLUE, end="")
        print_colored(f"{'SUBDOMAINS':^{width_sub_t2}}", Colors.BOLD + Colors.YELLOW, end="")
        print_colored("║", Colors.BLUE, end="")
        print_colored(f"{'REVERSE DNS':^{width_rev_t2}}", Colors.BOLD + Colors.YELLOW, end="")
        print_colored("║", Colors.BLUE)
        print(pad2, end="")
        print_colored(f"╠{'═'*width_sub_t2}╬{'═'*width_rev_t2}╣", Colors.CYAN)
        
        # Show table 2: Subdomains → Reverse DNS grouped (main first)
        order_t2 = list(subdomains_reverse_dns.keys())
        if domain in order_t2:
            order_t2 = [domain] + [s for s in order_t2 if s != domain]
        for i, subdomain in enumerate(order_t2):
            reverse_dns_list = subdomains_reverse_dns[subdomain]
            # Filter 'N/A' and show only reverse DNS valid
            reverse_dns_valid = [rdns for rdns in reverse_dns_list if rdns != 'N/A']
            
            if reverse_dns_valid:
                # If there is multiple reverse DNS, show them separated for commas
                reverse_dns_str = ', '.join(reverse_dns_valid)
                color_row = Colors.RED if subdomain == domain else Colors.GREEN
                print_row_table_professional(name_displayable(subdomain), reverse_dns_str, width_subdomain=width_sub_t2, width_reverse_dns=width_rev_t2, margin=pad2, color_content=color_row)
            else:
                # If not there is reverse DNS valid, show N/A in orange
                color_row = Colors.RED if subdomain == domain else Colors.GREEN
                print_row_table_professional(name_displayable(subdomain), 'N/A', width_subdomain=width_sub_t2, width_reverse_dns=width_rev_t2, margin=pad2, color_content=Colors.ORANGE)
            
            # Add separator of line between subdomains (except the last)
            if i < len(subdomains_reverse_dns) - 1:
                print(pad2, end="")
                print_colored(f"╟{'─'*width_sub_t2}╫{'─'*width_rev_t2}╢", Colors.BLUE)
        
        print(pad2, end="")
        print_colored(f"{'═'*(width_total_t2+1)}", Colors.CYAN)
    
    if show_summary:
        # Summary final
        print_colored(f"\n📈 SUMMARY Of DETECTION:", Colors.BLUE)
        print_colored(f"  • Total subdomains found: {len(subdomains_found)}", Colors.GREEN)
        print_colored(f"  • Total IPs unique: {len(ips_unique)}", Colors.GREEN)
        print_colored(f"  • Total records in table: {len(table_subdomains)}", Colors.GREEN)

    # Ensure that all the threads of progress are stopped
    try:
        if 'progress_data' in locals():
            progress_data['active'] = False
        if 'progress_patrones' in locals():
            progress_patrones['active'] = False
        # Clear any line residual
        print("\r\033[K", end="", flush=True)
    except Exception:
        pass

    # Return map Subdomain(FQDN) -> IPs if is requests, of lo otherwise list simple
    if return_map:
        return subdomains_per_ip
    else:
        return subdomains_found

def verify_domain_exists(domain):
    """Verifies that the domain exists before of proceed with the scan"""
    print_colored(f"\n{'='*60}", Colors.CYAN)
    print_colored(f"🔍 VERIFYING DOMAIN EXISTENCE: {domain}", Colors.BOLD + Colors.WHITE)
    print_colored(f"{'='*60}", Colors.CYAN)
    
    try:
        # Verify basic DNS resolution
        print_colored(f"[*] Verifying DNS resolution...", Colors.BLUE)
        ips = resolve_dns_record_command(domain, 'A')

        if ips:
            print_colored(f"[+] Domain {domain} exists and resolves to {len(ips)} IP(s)", Colors.GREEN)
            for ip in ips:
                if is_ip_valid(ip):
                    print_colored(f"    • {ip}", Colors.GREEN)
            return True
        else:
            print_colored(f"[-] Domain {domain} does not resolve to any IP", Colors.RED)
            return False
            
    except Exception as e:
        print_colored(f"[-] Error verifying domain: {str(e)}", Colors.RED)
        return False

def is_ip_valid(ip):
    """Verifies if a string is a IP valid (IPv4 or IPv6)"""
    try:
        # Verify if it is IPv4 (all parts must be digits, exactly 4 of them)
        if '.' in ip and ip.count('.') == 3:
            parts = ip.split('.')
            if len(parts) == 4 and all(part.isdigit() for part in parts):
                return all(0 <= int(part) <= 255 for part in parts)
        
        # Verify if is IPv6
        if ':' in ip:
            import ipaddress
            ipaddress.ip_address(ip)
            return True
            
        return False
    except Exception:
        return False

def filter_only_ips(records):
    """Filters only the IPs valid of a list of records DNS"""
    return [record for record in records if is_ip_valid(record)]

def resolve_ips_a_aaaa(domain_fqdn):
    """Resuelve and combines IPs IPv4 (A) e IPv6 (AAAA) for a FQDN."""
    ips_a = resolve_dns_record_command(domain_fqdn, 'A') or []
    ips_aaaa = resolve_dns_record_command(domain_fqdn, 'AAAA') or []
    # Merge and remove duplicates
    combined = list({ip for ip in (ips_a + ips_aaaa) if is_ip_valid(ip)})
    return combined

def _kill_nmap_process_group(process, timeout=2.0):
    """
    Terminates an nmap/sudo process started with start_new_session=True.

    Since the process is the leader of its own session, its process group id
    equals its pid. Signaling only process.pid (via process.terminate()/kill())
    reaches sudo but can leave the actual nmap child (spawned by sudo) running
    as an orphan. Signaling the whole process group ensures both die.
    """
    import signal as _signal
    try:
        pgid = os.getpgid(process.pid)
    except Exception:
        pgid = None
    try:
        if pgid is not None:
            os.killpg(pgid, _signal.SIGTERM)
        else:
            process.terminate()
    except Exception:
        pass
    deadline = time.time() + timeout
    while process.poll() is None and time.time() < deadline:
        time.sleep(0.1)
    if process.poll() is None:
        try:
            if pgid is not None:
                os.killpg(pgid, _signal.SIGKILL)
            else:
                process.kill()
        except Exception:
            pass

def run_nmap_stream(target, sudo_password, ports="-p-", out_dir=None):
    """
    Runs nmap with sudo showing barra of progress and returns path from the file XML.

    SYSTEM Of PROGRESS (5 phases):
      Initialization → Scan -sS → Detection -sV → NSE → Completion
      Each phase 0-100%. Parsing nmap output for actual percentages.

    meter Of TIMES:
      - Creates NmapTimingMeter(out_dir) at the start
      - Uses meter.get_time_*() for constants (fallback to defaults)
      - Upon completion: meter.record_measurement(tee_logger.stats)
      - Precision (estimated vs real) is added to stats and written to the log

    WATCHDOG 95%:
      If progress is in 95%+ during 90s (waiting "Completed SYN Stealth Scan"),
      forces a 100% automatically (time_max_en_95_ss).

    CONTROL-C:
      Loop of reading uses process.poll() + sleep(0.1) for allow interruption.

    Args:
        target (str): IP or domain to scan.
        sudo_password (str): Password sudo for run nmap.
        ports (str): Range of ports (for default "-p-").
        out_dir (str, optional): output directory.

    Returns:
        str: Path from the file XML generated.
    """
    # Command nmap with ports selected
    cmd = ['sudo', '-S', '-k', 'nmap', '-Pn', '-sS', '-sV', '-T4', '-vvv', ports, '--max-retries', '2', '--min-rate', '1000', '--min-parallelism', '1000', '--max-parallelism', '1000', '--initial-rtt-timeout', '10s', '--min-rtt-timeout', '10s', '--max-rtt-timeout', '10s', target]
    
    # Add XML output if a directory is provided
    xml_file = None
    if out_dir:
        session_tag = os.path.basename(out_dir)
        base_tag = re.sub(r"_\d{2}-\d{2}-\d{4}_\d{2}:\d{2}$", "", session_tag)
        xml_file = os.path.join(out_dir, f"{base_tag}_nmap_{safe_filename(target)}.xml")
        # Only use -oX for XML, without redirect stdout
        cmd.extend(['-oX', xml_file])
    
    global _nmap_process_current
    try:
        # Create process with PIPE for leer output in time real
        # start_new_session=True: isolates the child for that CONTROL-C arrives to the process Python
        # (without this, sudo/nmap in the same group can consume SIGINT)
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
            start_new_session=True
        )
        _nmap_process_current = process

        # Enviar password of sudo immediately
        if process.stdin is not None:
            try:
                process.stdin.write(sudo_password + "\n")
                process.stdin.flush()
            except Exception:
                pass
            try:
                process.stdin.close()
            except Exception:
                pass

        # Calculate total ports to scan dynamically
        total_ports = 0
        
        # Search the parameter -p in the command
        for arg in cmd:
            if arg.startswith('-p'):
                ports_str = arg[2:]
                
                if ports_str == '-':
                    # Option 5: All the ports
                    total_ports = 65535
                elif ',' in ports_str:
                    # Option 3 or 4: Group of ports or mixed (separated for commas)
                    # Clear spaces and process each part
                    parts = [p.strip() for p in ports_str.split(',') if p.strip()]
                    
                    for part in parts:
                        if '-' in part:
                            # Is a range (ej: 80-443)
                            try:
                                start, fin = map(int, part.split('-'))
                                total_ports += fin - start + 1
                            except ValueError:
                                total_ports += 1
                        else:
                            # Is a port individual (ej: 22)
                            try:
                                int(part)  # Validate that sea a number
                                total_ports += 1
                            except ValueError:
                                total_ports += 1
                elif '-' in ports_str:
                    # Option 2: Range of ports
                    try:
                        start, fin = map(int, ports_str.split('-'))
                        total_ports = fin - start + 1
                    except ValueError:
                        total_ports = 1
                else:
                    # Option 1: Specific port
                    total_ports = 1
                break
        
        # If the -p parameter is not found, use 1 by default
        if total_ports == 0:
            total_ports = 1
        

        # Show barra of progress with thread separate
        print_colored(f"[*] Scanning {target}...", Colors.BLUE, end="")
        
        import select
        
        # Variables shared for the progress of nmap
        start_time = time.time()

        # System of fallback: use measurements previous or values for default
        meter = NmapTimingMeter(out_dir if out_dir else os.getcwd())
        time_per_port = meter.get_time_per_port()
        time_dns_initialization = meter.get_time_dns_initialization()
        time_nse = meter.get_time_nse()
        time_completion = meter.get_time_completion()
        time_per_port_filtered = meter.get_time_per_port_filtered()
        progress_nmap = {
            'ports_scanned': 0,
            'total_ports': total_ports,
            'active': True,
            'start_time': start_time,
            'target': target,
            'phase_initialization': True,           # New phase: Initialization (0-5%)
            'phase_detection': False,               # Phase: Detection -sV (80-97%)
            'phase_nse': False,                     # Phase: Scripts NSE (97-99%)
            'phase_completion': False,            # New phase: Completion (99-100%)
            'phase_scan_completed': False,      # New: indicates that the scan -sS ended
            'ports_open': 0,                 # Counter specific for ports open
            'ports_closed': 0,                 # Counter specific for ports closed
            'ports_filtered': 0,                # Counter specific for ports filtered
            'services_detected': 0,
            'services_total_expected': 0,
            'time_per_port': time_per_port,
            'time_dns_initialization': time_dns_initialization,
            'time_detection_start': None,
            'time_initialization_start': start_time,  # New: Time start initialization
            'time_nse_start': None,             # New: Time start NSE
            'time_completion_start': None,    # New: Time start completion
            'time_last_port': start_time,    # New: Time from the last port processed
            'port_current': 0,                    # New: Port current being scanned
            
            # NEW COUNTERS Of PROGRESS For PHASE (0-100% each a)
            'progress_initialization': 0,          # Progress of initialization (0-100%)
            'progress_scan_ports': 0,         # Progress of scan of ports (0-100%)
            'progress_service_detection': 0,     # Progress of detection of services (0-100%)
            'factor_adjustment_sv': 1.0,               # Factor of adjustment dynamic for time estimated of -sV
            'progress_nse': 0,                     # Progress of scripts NSE (0-100%)
            'progress_completion': 0,            # Progress of completion (0-100%)
            
            # WEIGHTS Of EACH PHASE In The PROGRESS GLOBAL
            'weight_initialization': 5,              # 5% from the progress total
            'weight_scan_ports': 75,            # 75% from the progress total
            'weight_service_detection': 15,        # 15% from the progress total
            'weight_nse': 3,                         # 3% from the progress total
            'weight_completion': 2,                # 2% from the progress total
            
            # FLAG For indicate PROGRESS REAL Of NMAP AVAILABLE
            'progress_real_nmap_available': False,  # indicates if there is progress real of Nmap timing
            'last_timing_real': None,              # Timestamp from the last percentage real received
            'time_max_sin_timing': 10.0,          # Watchdog: seconds max without timing real before of resume calculation internal
            # Progress max observed for -sS (for avoid regressions to the fall back a calculation internal)
            'progress_ss_max': 0.0,
            # Watchdog for progress stuck in 95%: time when arrived a 95% and flag of forced
            'time_arrival_95_ss': None,           # Timestamp when the progress arrived a 95%
            'progress_95_forced': False,           # Flag that indicates if is forced the progress from 95%
            'time_max_en_95_ss': 90.0,            # Seconds max in 95% before of force a 100%
            # Flags and timers for progress real of -sV
            'progress_real_sv_available': False,
            'last_timing_real_sv': None,
            'time_max_sin_timing_sv': 10.0,
            # Flags and timers for progress real of NSE
            'progress_real_nse_available': False,
            'last_timing_real_nse': None,
            
            # Flags for phases NSE and Completion
            'phase_nse': False,                        # indicates if we are in phase NSE
            'phase_completion': False,               # indicates if we are in phase completion
            'nse_started': False,                     # Flag for detect start of NSE
            'nse_completed': False,                   # Flag for detect fin of NSE
            'nse_completed_printed': False,          # Flag for avoid duplicate of printing
            'detection_completed_impresa': False,    # Flag for avoid duplicate of printing of detection
            'detection_started_impresa': False,      # Flag for avoid duplicate from the message initial of -sV
            'preparing_nse_shown': False,         # Flag for show message of preparing NSE
            'time_nse_start': None,                 # Timestamp of start of NSE
            'time_completion_start': None         # Timestamp of start of completion
        }
        
        # Configuration of debug: disable visual and record a file
        try:
            progress_nmap['debug_visible'] = False
            base_dir_log = out_dir if out_dir else os.getcwd()
            progress_nmap['debug_log_path'] = os.path.join(base_dir_log, f"nmap_debug_{safe_filename(target)}.log")
            # Link log of nmap to the TeeLogger (Tarea #25)
            tee_logger = get_tee_logger()
            if tee_logger and progress_nmap['debug_log_path']:
                tee_logger.set_nmap_debug_log(progress_nmap['debug_log_path'])
        except Exception:
            progress_nmap['debug_visible'] = False
            progress_nmap['debug_log_path'] = None

        def _debug_write(msg):
            try:
                if progress_nmap.get('debug_log_path'):
                    with open(progress_nmap['debug_log_path'], 'a', encoding='utf-8') as _fdbg:
                        _fdbg.write(msg + "\n")
            except Exception:
                pass
        
        # Reset flags of control for avoid duplication between scans multiple
        progress_nmap['nse_completed_printed'] = False
        progress_nmap['preparing_nse_shown'] = False
        progress_nmap['detection_started_impresa'] = False
        progress_nmap['factor_adjustment_sv'] = 1.0  # Reset factor of adjustment at the start of each scan
        
        def show_progress_nmap():
            """Thread separate for show the barra of progress of nmap (v2.7 Ultra-Simplified)
            
            Features v2.7:
            - Progress ultra-simplified: only shows (ports scanned/total)
            - Without messages NSE: removed for be very fast
            - No blinking cursor: removed the erratic cursor issue
            - 5 phases of progress: each a 0-100% of its weight
            - Consistency universal: applied a all the options from the menu
            """
            # Disable input during the progress
            old_settings = _enter_raw_no_echo_mode()

            chars = "|/-\\"
            i = 0
            while progress_nmap['active']:
                try:
                    elapsed = time.time() - start_time
                    elapsed_formatted = f"{int(elapsed//3600):02d}:{int((elapsed%3600)//60):02d}:{int(elapsed%60):02d}"
                    
                    # WATCHDOG: if had progress real but stopped of reach for too much time, resume calculation internal
                    if progress_nmap['progress_real_nmap_available'] and not progress_nmap['phase_scan_completed']:
                        if progress_nmap['last_timing_real'] is not None:
                            if (time.time() - progress_nmap['last_timing_real']) > progress_nmap['time_max_sin_timing']:
                                # Save the max reached before of disable the timing real
                                progress_nmap['progress_ss_max'] = max(progress_nmap.get('progress_ss_max', 0.0), progress_nmap['progress_scan_ports'])
                                # Synchronize counters internal with the reference of Nmap
                                progress_nmap['ports_scanned'] = int((progress_nmap['progress_ss_max'] / 100.0) * progress_nmap['total_ports'])
                                progress_nmap['progress_real_nmap_available'] = False
                                # Not force a 95% here - keep the max real observed

                    # WATCHDOG -sV: if had progress real of -sV but stopped of reach, resume calculation internal
                    if progress_nmap['phase_detection'] and progress_nmap.get('progress_real_sv_available'):
                        if progress_nmap.get('last_timing_real_sv') is not None:
                            if (time.time() - progress_nmap['last_timing_real_sv']) > progress_nmap.get('time_max_sin_timing_sv', 10.0):
                                progress_nmap['progress_real_sv_available'] = False
                                # print(f"\n[DEBUG] ⏱️ Watchdog -sV: without timing real for {progress_nmap.get('time_max_sin_timing_sv', 10.0)}s, resuming calculation internal")
                                # Not force a 95% here - keep the max real observed

                    # TIMER For PORTS FILTERED
                    # If not we are in initialization, detection, ni scan completed And not there is progress real of Nmap
                    if (not progress_nmap['phase_initialization'] and 
                        not progress_nmap['phase_detection'] and 
                        not progress_nmap['phase_scan_completed'] and
                        not progress_nmap['progress_real_nmap_available']):
                        
                        time_from_last_port = time.time() - progress_nmap['time_last_port']
                        
                        # If have passed 10 seconds without detect a port, assume lote of ports filtered
                        if time_from_last_port >= time_per_port_filtered:
                            # Nmap scans exactly 1000 ports concurrent
                            ports_concurrentes = 1000
                            
                            # Validate that not we exceed the total of ports and that the scan not haya finished
                            ports_remaining = progress_nmap['total_ports'] - progress_nmap['ports_scanned']
                            if ports_remaining > 0 and not progress_nmap['phase_scan_completed']:
                                # adjust the lote to the number of ports remaining, but leave to the less 35 ports without scan
                                ports_max = max(0, progress_nmap['total_ports'] - 35)
                                ports_a_add = min(ports_concurrentes, max(0, ports_remaining - 35))
                                
                                if ports_a_add > 0:
                                    # Assume that are ports filtered (not detected for nmap)
                                    ports_before = progress_nmap['ports_scanned']
                                    progress_nmap['ports_scanned'] = min(ports_max, progress_nmap['ports_scanned'] + ports_a_add)
                                    ports_actually_added = progress_nmap['ports_scanned'] - ports_before
                                    progress_nmap['ports_filtered'] += ports_actually_added
                                    progress_nmap['time_last_port'] = time.time()  # Reset timer
                                    progress_nmap['port_current'] += ports_actually_added
                    
                    # NEW SYSTEM: Each phase has its own counter of 0-100%
                    # Calculate progress global based in phase current + progress of the phase
                    if progress_nmap['total_ports'] > 0:
                        # Phase 0: Initialization (0-100% of its weight)
                        # note: The initialization is shows in a sola line that is overwrites with \r.
                        # Shows "initializing" until 95%, then is overwrites with "initialization completed" to the 100%
                        # when is detects "Initiating SYN Stealth Scan", and after passes a new line for the scan of ports.
                        if progress_nmap['phase_initialization']:
                            time_initialization_elapsed = time.time() - progress_nmap['time_initialization_start']
                            # limit the phase of initialization a a max of 95% until that starts the SYN
                            time_init_ref = progress_nmap.get('time_dns_initialization', 0.5)
                            progress_calculated_init = (time_initialization_elapsed / time_init_ref) * 100
                            progress_nmap['progress_initialization'] = min(95.0, round(progress_calculated_init, 2))
                            
                            # Show progress of the phase current (is overwrites in the same line with \r)
                            percentage = progress_nmap['progress_initialization']
                            phase_text = " (initializing)"
                        
                        # Phase 1: Scan of ports -sS (0-100% of its weight)
                        # important: exclude NSE and completion for avoid show "scanning ports" during those phases
                        elif progress_nmap['ports_scanned'] <= progress_nmap['total_ports'] and not progress_nmap['phase_detection'] and not progress_nmap['phase_nse'] and not progress_nmap['phase_completion']:
                            if progress_nmap['phase_scan_completed']:
                                # Scan of ports completed - mark as 100% only if not there is progress real of Nmap available
                                if not progress_nmap['progress_real_nmap_available']:
                                    progress_nmap['progress_scan_ports'] = 100
                                
                                # If detection of services has not started yet, start it automatically
                                # IMPROVEMENT implemented (December 2025): activate phase_detection automatically if "Initiating Service scan" is not detected
                                # This solves the issue where some targets do not generate this line
                                # Result: The progress of -sV works correctly in all the domains, even when nmap not generates "Initiating Service scan"
                                if not progress_nmap['phase_detection']:
                                    # activate phase of detection automatically when ends the scan of ports
                                    progress_nmap['phase_detection'] = True
                                    progress_nmap['services_detected'] = 0
                                    progress_nmap['services_total_expected'] = 0
                                    progress_nmap['time_detection_start'] = time.time()
                                    progress_nmap['progress_service_detection'] = 0.0
                                    progress_nmap['progress_real_sv_available'] = False
                                    progress_nmap['last_timing_real_sv'] = None
                                    progress_nmap['factor_adjustment_sv'] = 1.0
                                    # Fix counters for that add up to exactly 65535
                                    progress_nmap['ports_scanned'] = progress_nmap['total_ports']
                                    progress_nmap['ports_filtered'] = progress_nmap['total_ports'] - progress_nmap['ports_open'] - progress_nmap['ports_closed']
                            else:
                                # During the scan of ports - only recalculate if not there is progress real of Nmap available
                                if not progress_nmap['progress_real_nmap_available']:
                                    # Calculate progress internal based in ports scanned current
                                    progress_calculated = round((progress_nmap['ports_scanned'] / progress_nmap['total_ports']) * 100, 2)
                                    
                                    # If all the ports are scanned, force 100%
                                    if progress_nmap['ports_scanned'] >= progress_nmap['total_ports']:
                                        progress_internal_limited = 100.0
                                        progress_nmap['time_arrival_95_ss'] = None  # Reset watchdog
                                        progress_nmap['progress_95_forced'] = False
                                    else:
                                        progress_internal_limited = min(95.0, progress_calculated)
                                        
                                        # WATCHDOG For PROGRESS STUCK In 95% (implemented December 2025)
                                        # Detects when the progress is in 95%+ for more of 90 seconds and forces the advance a 100%
                                        # This solves the issue where progress gets stuck waiting for "Completed SYN Stealth Scan"
                                        # Result: Time average in 95% reduced of 211.4s a 39.8s (improvement from the 81%)
                                        if progress_internal_limited >= 95.0:
                                            # If we just of reach a 95%, record the time
                                            if progress_nmap['time_arrival_95_ss'] is None:
                                                progress_nmap['time_arrival_95_ss'] = time.time()
                                            
                                            # If has passed more from the time max in 95%, force a 100%
                                            time_en_95 = time.time() - progress_nmap['time_arrival_95_ss']
                                            if time_en_95 > progress_nmap['time_max_en_95_ss'] and not progress_nmap['progress_95_forced']:
                                                # Force progress a 100% after of be in 95%+ for more of 90 seconds
                                                progress_internal_limited = 100.0
                                                progress_nmap['progress_95_forced'] = True
                                                progress_nmap['phase_scan_completed'] = True
                                                progress_nmap['ports_scanned'] = progress_nmap['total_ports']
                                                progress_nmap['ports_filtered'] = progress_nmap['total_ports'] - progress_nmap['ports_open'] - progress_nmap['ports_closed']
                                        else:
                                            # If the progress goes down of 95%, reset the watchdog
                                            progress_nmap['time_arrival_95_ss'] = None
                                            progress_nmap['progress_95_forced'] = False
                                    
                                    progress_nmap['progress_scan_ports'] = progress_internal_limited
                                    
                                    # Update the reference max if the progress calculated is greater
                                    if progress_internal_limited > progress_nmap.get('progress_ss_max', 0):
                                        progress_nmap['progress_ss_max'] = progress_internal_limited
                                # If there is progress real available, verify if all the ports are scanned
                                elif progress_nmap['ports_scanned'] >= progress_nmap['total_ports']:
                                    # If all the ports are scanned, force 100% even with progress real
                                    progress_nmap['progress_scan_ports'] = 100.0
                            
                            # Show progress of the phase current
                            percentage = progress_nmap['progress_scan_ports']
                            phase_text = " (scanning ports)"
                        
                        # Phase 2: Detection of services -sV (0-100% of its weight)
                        # IMPROVEMENT implemented (December 2025): Reset automatic and update continues from the progress
                        # Result: 15/15 domains show reset correct (100%). All show update continues.
                        elif progress_nmap['phase_detection'] and progress_nmap['time_detection_start']:
                            # Calculate time elapsed always (necessary for the calculation)
                            time_detection_elapsed = time.time() - progress_nmap['time_detection_start']
                            
                            # CORRECTION: Ensure that the progress is reset when begins -sV
                            # If the progress still is in 100% (from the scan of ports) or is 0% at the start, reset it
                            # This solves the issue where progress stays at 100% with no updates during -sV
                            if time_detection_elapsed < 0.1:
                                # we just of start -sV, ensure that the progress is in 0%
                                progress_nmap['progress_service_detection'] = 0.0
                            
                            # Prioritize progress real reported for nmap for -sV if is available
                            if progress_nmap.get('progress_real_sv_available'):
                                # Use progress real of nmap if is available
                                percentage = progress_nmap['progress_service_detection']
                            else:
                                # Get amount of ports open detected in the phase previous (-sS)
                                ports_open = progress_nmap.get('ports_open', 0)
                                
                                # If not there is ports open, use min of 1 for avoid division for zero
                                if ports_open == 0:
                                    ports_open = 1
                                
                                # Get amount of services detected until now
                                services_detected = progress_nmap.get('services_detected', 0)
                                
                                # LOGIC Of CALCULATION Of PROGRESS -sV (IMPROVED - December 2025):
                                # 1. If services have been detected: use (services_detected / ports_open) * 100
                                # 2. If no services have been detected yet: use elapsed time / estimated time
                                # 3. ALWAYS calculate progress based in time for ensure update continues
                                # 4. Use the max between time and services detected for show the best progress available
                                # Result: The progress is updates continuously during all the phase -sV, even without services detected
                                
                                # Calculate time estimated total
                                time_per_port = progress_nmap['time_per_port']  # 0.98 seconds for port
                                time_total_estimated = ports_open * time_per_port
                                
                                # If the time estimated is very short (less of 10 seconds), use a min more realistic
                                if time_total_estimated < 10.0:
                                    time_total_estimated = max(10.0, time_total_estimated * 2)
                                
                                # If the time elapsed exceeds the estimated, adjust dynamically
                                if time_detection_elapsed > time_total_estimated:
                                    factor_adjustment = progress_nmap.get('factor_adjustment_sv', 1.0)
                                    if time_detection_elapsed > time_total_estimated * 2:
                                        factor_adjustment = max(factor_adjustment, (time_detection_elapsed / time_total_estimated) * 1.1)
                                        progress_nmap['factor_adjustment_sv'] = factor_adjustment
                                    time_total_estimated = time_total_estimated * factor_adjustment
                                
                                # Calculate progress based in time (ALWAYS is calculates for update continues)
                                progress_phase_sv_time = (time_detection_elapsed / time_total_estimated) * 100
                                
                                # If there is services detected, use the max between time and services detected
                                if services_detected > 0:
                                    progress_phase_sv_services = (services_detected / ports_open) * 100
                                    # Use the max for show the best progress available
                                    progress_phase_sv = max(progress_phase_sv_time, progress_phase_sv_services)
                                else:
                                    # If not there is services detected still, use only time
                                    progress_phase_sv = progress_phase_sv_time
                                
                                # limit a 95% max until that Nmap confirms completed
                                progress_calculated = min(95.0, round(progress_phase_sv, 2))
                                
                                # Ensure progress min gradual based in time elapsed
                                if time_detection_elapsed > 0.1:
                                    # Progress min more aggressive: to the less 0.1% for second elapsed
                                    progress_min = min(1.0, (time_detection_elapsed / max(10.0, time_total_estimated)) * 100)
                                    progress_calculated = max(progress_calculated, round(progress_min, 2))
                                
                                # Update progress ALWAYS (this ensures update continues)
                                progress_nmap['progress_service_detection'] = progress_calculated
                                percentage = progress_calculated
                            
                            # Ensure that the percentage is updates gradually based in time
                            # If the progress is 0% but has passed time, show progress min
                            if percentage == 0.0 and time_detection_elapsed > 0.5:
                                time_estimated_min = 10.0
                                progress_min_time = min(1.0, (time_detection_elapsed / time_estimated_min) * 100)
                                percentage = max(0.1, round(progress_min_time, 2))
                                progress_nmap['progress_service_detection'] = percentage
                            
                            # Show text of phase; keep format current without depender of D for progress
                            phase_text = " (detecting services)"
                        
                        # Phase 3: Scripts NSE (0-100% of its weight)
                        elif progress_nmap['phase_nse']:
                            # Use progress real of NSE if is available, otherwise calculate based in time
                            if progress_nmap.get('progress_real_nse_available', False):
                                # Progress real reported for nmap
                                percentage = progress_nmap['progress_nse']
                            else:
                                # If not there is progress real, calculate based in time elapsed
                                if progress_nmap.get('time_nse_start'):
                                    time_nse_elapsed = time.time() - progress_nmap['time_nse_start']
                                    # NSE can take time several minutes in hosts with many ports open
                                    # Use conservative estimate: min 30 seconds, max 20 minutes
                                    time_estimated_nse = max(30.0, min(1200.0, progress_nmap.get('ports_open', 0) * 0.05))
                                    progress_calculated_nse = min(99.0, (time_nse_elapsed / time_estimated_nse) * 100)
                                    percentage = max(progress_nmap.get('progress_nse', 0), round(progress_calculated_nse, 2))
                                    progress_nmap['progress_nse'] = percentage
                                else:
                                    percentage = progress_nmap.get('progress_nse', 0)
                            phase_text = " (running scripts NSE)"
                        
                        # Phase 5: Completion (0-100% of its weight)
                        elif progress_nmap['phase_completion']:
                            # Progress simple: 0% at the start, 100% on completion
                            # Not we need calculation internal already that completion is very fast
                            percentage = progress_nmap['progress_completion']
                            phase_text = " (finishing)"
                        
                        # Phase 5: Completed (100%)
                        elif progress_nmap['ports_scanned'] >= progress_nmap['total_ports']:
                            # mark all the phases as completed
                            progress_nmap['progress_initialization'] = 100
                            progress_nmap['progress_scan_ports'] = 100
                            progress_nmap['progress_service_detection'] = 100
                            progress_nmap['progress_nse'] = 100
                            progress_nmap['progress_completion'] = 100
                            
                            percentage = 100
                            phase_text = " (completed)"
                        
                        else:
                            # During scan normal (fallback) - use same logic that arriba
                            progress_nmap['progress_scan_ports'] = round((progress_nmap['ports_scanned'] / progress_nmap['total_ports']) * 100, 2)
                            percentage = progress_nmap['progress_scan_ports']
                            phase_text = " (scanning ports)"
                        
                        # Show progress according to phase current (progress simplified without counters A:, C:, F:)
                        if progress_nmap['phase_completion']:
                            # Priority 1: Completion (only if is active)
                            counters = "(finishing)"
                            phase_text = ""
                        elif progress_nmap['phase_nse']:
                            # Priority 2: NSE (only if is active)
                            # Show information useful about NSE
                            ports_open = progress_nmap.get('ports_open', 0)
                            if ports_open > 100:
                                # If there is many ports open, NSE can take time
                                counters = f"(running scripts NSE: {ports_open} ports open)"
                            else:
                                counters = "(running scripts NSE)"
                            phase_text = ""
                        elif progress_nmap['phase_detection']:
                            # Priority 3: -sV (only if is active)
                            # Improve message for show progress real of -sV
                            ports_open = progress_nmap.get('ports_open', 0)
                            services_detected = progress_nmap.get('services_detected', 0)
                            
                            # Show information useful about the progress of detection of services
                            if ports_open > 100:
                                # If there is many ports open, show information detailed
                                if services_detected > 0:
                                    counters = f"(detecting services: {services_detected}/{ports_open} ports)"
                                else:
                                    counters = f"(detecting services: {ports_open} ports open)"
                            elif services_detected > 0:
                                # If there is services detected, show them
                                counters = f"(detecting services: {services_detected}/{ports_open} ports)"
                            else:
                                counters = "(detecting services)"
                            phase_text = ""
                        elif progress_nmap['phase_initialization']:
                            # Priority 4: Initialization (only if is active)
                            counters = "(initializing)"
                            phase_text = ""
                        else:
                            # Priority 5: Progress normal of ports (-sS) or status between phases
                            if progress_nmap['phase_scan_completed']:
                                # Scan -sS already ended, show status between phases
                                if progress_nmap['phase_detection'] or progress_nmap['phase_nse'] or progress_nmap['phase_completion']:
                                    # Detection, NSE or completion active, show only progress basic
                                    counters = f"({progress_nmap['ports_scanned']}/{progress_nmap['total_ports']})"
                                    phase_text = ""
                                else:
                                    # Status between phases, not show nothing for avoid confusion
                                    # But Not stop the thread if we are in phase of detection of services
                                    if not progress_nmap.get('phase_detection', False):
                                        # Only stop if Not we are in detection of services
                                        progress_nmap['active'] = False
                                        break
                                    # If we are in detection of services, continue the loop
                            else:
                                # Scan -sS in progress
                                counters = f"({progress_nmap['ports_scanned']}/{progress_nmap['total_ports']})"
                                phase_text = " (scanning ports)"
                        # build message complete
                        message = f"[*] Scanning {progress_nmap['target']}... {chars[i % len(chars)]} {percentage}% {counters}{phase_text} - {elapsed_formatted}"
                        # limit width from the message a 80 characters max for avoid wrap from the terminal
                        if len(message) > 80:
                            # truncate the message keeping information essential
                            target_short = progress_nmap['target'][:15] if len(progress_nmap['target']) > 15 else progress_nmap['target']
                            message = f"[*] {target_short}... {chars[i % len(chars)]} {percentage}% {counters} - {elapsed_formatted}"
                            if len(message) > 80:
                                message = message[:77] + "..."
                        # Use code ANSI for clear until the final of the line (avoids wrap)
                        sys.stdout.write(f"\r\033[K{message}")
                        sys.stdout.flush()
                    else:
                        # If not there is ports detected, show progress basic
                        message = f"[*] Scanning {progress_nmap['target']}... {chars[i % len(chars)]} 0% - {elapsed_formatted}"
                        # limit width from the message
                        if len(message) > 80:
                            target_short = progress_nmap['target'][:15] if len(progress_nmap['target']) > 15 else progress_nmap['target']
                            message = f"[*] {target_short}... {chars[i % len(chars)]} 0% - {elapsed_formatted}"
                            if len(message) > 80:
                                message = message[:77] + "..."
                        # Use code ANSI for clear until the final of the line (avoids wrap)
                        sys.stdout.write(f"\r\033[K{message}")
                        sys.stdout.flush()
                    
                    i += 1
                    # Verify if the thread must stop before of continue
                    if not progress_nmap['active']:
                        break
                    time.sleep(0.1)  # Update each 100ms
                except KeyboardInterrupt:
                    # Only allow CONTROL-C, ignore other keys
                    break
            
            # Restore input
            _restore_terminal_mode(old_settings)

        # Start thread of progress for nmap
        progress_nmap_thread = threading.Thread(target=show_progress_nmap, daemon=True)
        progress_nmap_thread.start()
        
        # IMPROVEMENT v2.0: Leer output in time real and calculate progress (with handling robust of CONTROL-C)
        # The loop main is wrapped in try-except KeyboardInterrupt for allow cancellation
        # in any moment during the reading from the output of nmap
        while process.poll() is None:
            # Leer lines available from the output
            try:
                # Use select for leer without block (only in Unix)
                if hasattr(select, 'select'):
                        ready, _, _ = select.select([process.stdout], [], [], 0.1)
                        if ready:
                            line = process.stdout.readline()
                            if line:
                                # DEBUG: Show all the lines for diagnose
                                if ("Service" in line or "scan" in line.lower() or "Timing" in line or 
                                    "detection" in line.lower() or "Initiating" in line or "Completed" in line or
                                    "Nmap" in line or "NSE" in line):
                                    _debug_write(f"[DEBUG] Line detected: {line.strip()}")
                                    if progress_nmap.get('debug_visible'):
                                        print(f"\n[DEBUG] Line detected: {line.strip()}")
                                
                                # Detect progress in the output verbose - LOGIC IMPROVED
                                # Only detect ports if Not we are in phase of initialization And not there is progress real of Nmap
                                if not progress_nmap['phase_initialization'] and not progress_nmap['progress_real_nmap_available']:
                                    port_detected = False
                                    if "Discovered open port" in line or ("open" in line.lower() and "port" in line.lower()):
                                        # Port open found
                                        if progress_nmap['ports_scanned'] < progress_nmap['total_ports'] and not progress_nmap['phase_scan_completed']:
                                            progress_nmap['ports_scanned'] += 1
                                            progress_nmap['ports_open'] += 1
                                            port_detected = True
                                    elif "closed" in line.lower() and "port" in line.lower():
                                        # Port closed found
                                        if progress_nmap['ports_scanned'] < progress_nmap['total_ports'] and not progress_nmap['phase_scan_completed']:
                                            progress_nmap['ports_scanned'] += 1
                                            progress_nmap['ports_closed'] += 1
                                            port_detected = True
                                    elif "filtered" in line.lower() and "port" in line.lower():
                                        # Port filtered found (detected for nmap, not for timer)
                                        if progress_nmap['ports_scanned'] < progress_nmap['total_ports'] and not progress_nmap['phase_scan_completed']:
                                            progress_nmap['ports_scanned'] += 1
                                            progress_nmap['ports_filtered'] += 1
                                            port_detected = True
                                    
                                    # Reset timer if is detected a port
                                    if port_detected:
                                        progress_nmap['time_last_port'] = time.time()
                                        progress_nmap['port_current'] += 1
                                
                                # Detect progress real from the scan -sS
                                if "SYN Stealth Scan Timing: About" in line and "% done" in line:
                                    # Extract the percentage from the message "SYN Stealth Scan Timing: About 51.09% done; ETC: 20:08 (0:05:05 remaining)"
                                    _debug_write(f"[DEBUG] 🔍 Processing line of timing: {line.strip()}")
                                    if progress_nmap.get('debug_visible'):
                                        print(f"\n[DEBUG] 🔍 Processing line of timing: {line.strip()}")
                                    match = re.search(r"About\s+([\d.]+)%\s+done", line)
                                    if match:
                                        percentage_real = float(match.group(1))
                                        
                                        # important: ALWAYS synchronize ports_scanned with the percentage real of nmap
                                        # This ensures the internal count continues from the point reported by nmap
                                        ports_scanned_synchronized = int((percentage_real / 100.0) * progress_nmap['total_ports'])
                                        progress_nmap['ports_scanned'] = ports_scanned_synchronized
                                        progress_nmap['time_last_port'] = time.time()  # Reset timer for continue from here
                                        
                                        # If the progress real is lower to the shown, update toward down
                                        # If is greater, limit a 95% until that ends the -sS
                                        if percentage_real < progress_nmap.get('progress_scan_ports', 0):
                                            # Progress real lower: use the value real
                                            percentage_shown = percentage_real
                                            _debug_write(f"[DEBUG] 📉 Progress toward down: {progress_nmap.get('progress_scan_ports', 0)}% → {percentage_real}% (synchronized: {ports_scanned_synchronized}/{progress_nmap['total_ports']} ports)")
                                            if progress_nmap.get('debug_visible'):
                                                print(f"\n[DEBUG] 📉 Progress toward down: {progress_nmap.get('progress_scan_ports', 0)}% → {percentage_real}% (synchronized: {ports_scanned_synchronized}/{progress_nmap['total_ports']} ports)")
                                        else:
                                            # Progress real greater: limit a 95% a less that all the ports are scanned
                                            if progress_nmap['ports_scanned'] >= progress_nmap['total_ports']:
                                                percentage_shown = 100.0
                                                progress_nmap['time_arrival_95_ss'] = None  # Reset watchdog
                                                progress_nmap['progress_95_forced'] = False
                                            else:
                                                percentage_shown = min(95.0, percentage_real)
                                                
                                                # WATCHDOG For PROGRESS STUCK In 95% (implemented December 2025)
                                                # Detects when the progress real is in 95%+ for more of 90 seconds and forces the advance a 100%
                                                # This solves the issue where progress gets stuck waiting for "Completed SYN Stealth Scan"
                                                if percentage_shown >= 95.0:
                                                    # If we just of reach a 95%, record the time
                                                    if progress_nmap['time_arrival_95_ss'] is None:
                                                        progress_nmap['time_arrival_95_ss'] = time.time()
                                                    
                                                    # If has passed more from the time max in 95%, force a 100%
                                                    time_en_95 = time.time() - progress_nmap['time_arrival_95_ss']
                                                    if time_en_95 > progress_nmap['time_max_en_95_ss'] and not progress_nmap['progress_95_forced']:
                                                        # Force progress a 100% after of be in 95%+ for more of 90 seconds
                                                        # This ensures progress does not stay stuck indefinitely
                                                        percentage_shown = 100.0
                                                        progress_nmap['progress_95_forced'] = True
                                                        progress_nmap['phase_scan_completed'] = True
                                                        progress_nmap['ports_scanned'] = progress_nmap['total_ports']
                                                        progress_nmap['ports_filtered'] = progress_nmap['total_ports'] - progress_nmap['ports_open'] - progress_nmap['ports_closed']
                                                else:
                                                    # If the progress goes down of 95%, reset the watchdog
                                                    progress_nmap['time_arrival_95_ss'] = None
                                                    progress_nmap['progress_95_forced'] = False
                                            _debug_write(f"[DEBUG] 📊 Progress real -sS: {percentage_real}% (synchronized: {ports_scanned_synchronized}/{progress_nmap['total_ports']} ports, shown: {percentage_shown}%)")
                                        
                                        progress_nmap['progress_scan_ports'] = round(percentage_shown, 2)
                                        # Update max observed with the VALUE REAL, not the limited
                                        progress_nmap['progress_ss_max'] = max(progress_nmap.get('progress_ss_max', 0.0), percentage_real)
                                        # ALWAYS reactivate the progress real when arrives a timing new
                                        progress_nmap['progress_real_nmap_available'] = True
                                        progress_nmap['last_timing_real'] = time.time()
                                        
                                        # If the progress real arrives to the 100% or all the ports are scanned, reset the flag
                                        if percentage_real >= 100.0 or progress_nmap['ports_scanned'] >= progress_nmap['total_ports']:
                                            progress_nmap['progress_real_nmap_available'] = False
                                            progress_nmap['last_timing_real'] = None
                                            progress_nmap['progress_scan_ports'] = 100.0
                                            _debug_write(f"[DEBUG] 📊 Progress real -sS: {percentage_real}% (all the ports scanned, 100%)")
                                            if progress_nmap.get('debug_visible'):
                                                print(f"\n[DEBUG] 📊 Progress real -sS: {percentage_real}% (all the ports scanned, 100%)")
                                        else:
                                            _debug_write(f"[DEBUG] 📊 Progress real -sS: {percentage_real}% (limited a {percentage_shown}%)")
                                            if progress_nmap.get('debug_visible'):
                                                print(f"\n[DEBUG] 📊 Progress real -sS: {percentage_real}% (limited a {percentage_shown}%)")
                                    else:
                                        # Fallback: search any percentage in the line
                                        _debug_write(f"[DEBUG] ⚠️ Regex main failure, trying fallback...")
                                        if progress_nmap.get('debug_visible'):
                                            print(f"\n[DEBUG] ⚠️ Regex main failure, trying fallback...")
                                        match_fallback = re.search(r"(\d+\.?\d*)%", line)
                                        if match_fallback:
                                            percentage_real = float(match_fallback.group(1))
                                            
                                            # important: ALWAYS synchronize ports_scanned with the percentage real of nmap
                                            # This ensures the internal count continues from the point reported by nmap
                                            ports_scanned_synchronized = int((percentage_real / 100.0) * progress_nmap['total_ports'])
                                            progress_nmap['ports_scanned'] = ports_scanned_synchronized
                                            progress_nmap['time_last_port'] = time.time()  # Reset timer for continue from here
                                            
                                            # If the progress real is lower to the shown, update toward down
                                            # If is greater, limit a 95% until that ends the -sS
                                            if percentage_real < progress_nmap.get('progress_scan_ports', 0):
                                                # Progress real lower: use the value real
                                                percentage_shown = percentage_real
                                                _debug_write(f"[DEBUG] 📉 Progress toward down (fallback): {progress_nmap.get('progress_scan_ports', 0)}% → {percentage_real}% (synchronized: {ports_scanned_synchronized}/{progress_nmap['total_ports']} ports)")
                                                if progress_nmap.get('debug_visible'):
                                                    print(f"\n[DEBUG] 📉 Progress toward down (fallback): {progress_nmap.get('progress_scan_ports', 0)}% → {percentage_real}% (synchronized: {ports_scanned_synchronized}/{progress_nmap['total_ports']} ports)")
                                            else:
                                                # Progress real greater: limit a 95% a less that all the ports are scanned
                                                if progress_nmap['ports_scanned'] >= progress_nmap['total_ports']:
                                                    percentage_shown = 100.0
                                                    progress_nmap['time_arrival_95_ss'] = None  # Reset watchdog
                                                    progress_nmap['progress_95_forced'] = False
                                                else:
                                                    percentage_shown = min(95.0, percentage_real)
                                                    
                                                    # WATCHDOG For PROGRESS STUCK In 95% (implemented December 2025)
                                                    # Detects when the progress real (fallback) is in 95%+ for more of 90 seconds and forces the advance a 100%
                                                    # This solves the issue where progress gets stuck waiting for "Completed SYN Stealth Scan"
                                                    if percentage_shown >= 95.0:
                                                        # If we just of reach a 95%, record the time
                                                        if progress_nmap['time_arrival_95_ss'] is None:
                                                            progress_nmap['time_arrival_95_ss'] = time.time()
                                                        
                                                        # If has passed more from the time max in 95%, force a 100%
                                                        time_en_95 = time.time() - progress_nmap['time_arrival_95_ss']
                                                        if time_en_95 > progress_nmap['time_max_en_95_ss'] and not progress_nmap['progress_95_forced']:
                                                            # Force progress a 100% after of be in 95%+ for more of 90 seconds
                                                            percentage_shown = 100.0
                                                            progress_nmap['progress_95_forced'] = True
                                                            progress_nmap['phase_scan_completed'] = True
                                                            progress_nmap['ports_scanned'] = progress_nmap['total_ports']
                                                            progress_nmap['ports_filtered'] = progress_nmap['total_ports'] - progress_nmap['ports_open'] - progress_nmap['ports_closed']
                                                    else:
                                                        # If the progress goes down of 95%, reset the watchdog
                                                        progress_nmap['time_arrival_95_ss'] = None
                                                        progress_nmap['progress_95_forced'] = False
                                                _debug_write(f"[DEBUG] 📊 Progress real -sS (fallback): {percentage_real}% (synchronized: {ports_scanned_synchronized}/{progress_nmap['total_ports']} ports, shown: {percentage_shown}%)")
                                            
                                            progress_nmap['progress_scan_ports'] = round(percentage_shown, 2)
                                            # Update max observed with the VALUE REAL, not the limited
                                            progress_nmap['progress_ss_max'] = max(progress_nmap.get('progress_ss_max', 0.0), percentage_real)
                                            # ALWAYS reactivate the progress real when arrives a timing new
                                            progress_nmap['progress_real_nmap_available'] = True
                                            progress_nmap['last_timing_real'] = time.time()
                                            
                                            # If the progress real arrives to the 100% or all the ports are scanned, reset the flag
                                            if percentage_real >= 100.0 or progress_nmap['ports_scanned'] >= progress_nmap['total_ports']:
                                                progress_nmap['progress_real_nmap_available'] = False
                                                progress_nmap['last_timing_real'] = None
                                                progress_nmap['progress_scan_ports'] = 100.0
                                                _debug_write(f"[DEBUG] 📊 Progress real -sS (fallback): {percentage_real}% (all the ports scanned, 100%)")
                                                if progress_nmap.get('debug_visible'):
                                                    print(f"\n[DEBUG] 📊 Progress real -sS (fallback): {percentage_real}% (all the ports scanned, 100%)")
                                            else:
                                                _debug_write(f"[DEBUG] 📊 Progress real -sS (fallback): {percentage_real}% (limited a {percentage_shown}%)")
                                                if progress_nmap.get('debug_visible'):
                                                    print(f"\n[DEBUG] 📊 Progress real -sS (fallback): {percentage_real}% (limited a {percentage_shown}%)")
                                        else:
                                            _debug_write(f"[DEBUG] ❌ Could not extract percentage from the line")
                                            if progress_nmap.get('debug_visible'):
                                                print(f"\n[DEBUG] ❌ Could not extract percentage from the line")
                                
                                # Only detect the 5 signals specific of Nmap
                                elif "Initiating SYN Stealth Scan" in line:
                                    # Phase of initialization finished - starting scan of ports
                                    # behavior: The initialization is shows in a sola line that is overwrites.
                                    # Primero shows "initializing" until 95%, then is overwrites with "initialization completed" to the 100%
                                    # in the same line, and after passes a a new line for the scan of ports.
                                    progress_nmap['progress_initialization'] = 100  # complete phase current
                                    progress_nmap['phase_initialization'] = False
                                    progress_nmap['progress_scan_ports'] = 0    # Start next phase from 0%
                                    progress_nmap['progress_ss_max'] = 0.0          # Reset from the max at the start -sS
                                    # Save start from the scan of ports for calculate duration
                                    progress_nmap['time_scan_ports_start'] = time.time()
                                    # Update statistics (Tarea #24)
                                    tee_logger = get_tee_logger()
                                    if tee_logger:
                                        time_init = time.time() - progress_nmap['time_initialization_start']
                                        tee_logger.update_stats({'time_initialization': time_init})
                                    # overwrite the line current of initialization with "completed" and then go through a new line
                                    try:
                                        elapsed_init = time.time() - start_time
                                        elapsed_init_formatted = f"{int(elapsed_init//3600):02d}:{int((elapsed_init%3600)//60):02d}:{int(elapsed_init%60):02d}"
                                        # \r overwrites the line current, \n moves to the next line for the port scan
                                        print(f"\r\033[K[*] Scanning {progress_nmap['target']}... ✓ 100% (0/{progress_nmap['total_ports']}) (initialization completed) - {elapsed_init_formatted}\n", end="", flush=True)
                                    except Exception:
                                        pass
                                elif "Initiating Service scan" in line:
                                    # Phase of detection of services started (-sV)
                                    # IMPROVEMENT implemented (December 2025): Reset complete from the progress when begins -sV
                                    # This ensures that the progress is reset correctly and is updates continuously during -sV
                                    # Result: 15/15 domains show reset correct (100%). All show update continues.
                                    progress_nmap['progress_scan_ports'] = 100  # complete phase current
                                    progress_nmap['phase_detection'] = True
                                    progress_nmap['services_detected'] = 0
                                    progress_nmap['services_total_expected'] = 0
                                    progress_nmap['time_detection_start'] = time.time()
                                    progress_nmap['progress_service_detection'] = 0.0  # Start next phase from 0%
                                    progress_nmap['progress_real_sv_available'] = False  # Reset flag of progress real
                                    progress_nmap['last_timing_real_sv'] = None  # Reset timing real
                                    progress_nmap['factor_adjustment_sv'] = 1.0  # Reset factor of adjustment
                                    # Update statistics (Tarea #24)
                                    tee_logger = get_tee_logger()
                                    if tee_logger:
                                        # Calculate time of scan of ports from the start from the SYN
                                        time_ss = time.time() - progress_nmap.get('time_scan_ports_start', start_time)
                                        tee_logger.update_stats({'time_scan_ports': time_ss})
                                    progress_nmap['time_scan_ports_start'] = time.time()  # Save start for calculate duration
                                    if not progress_nmap.get('detection_started_impresa'):
                                        # Not print message initial here - leave that the thread of progress lo handles
                                        # The thread of progress will show the progress from 0% and lo will update gradually
                                        progress_nmap['detection_started_impresa'] = True
                                        # Ensure the progress thread stays active during detection
                                        progress_nmap['active'] = True
                            elif "Scanning" in line and "services on" in line:
                                # Ej: "Scanning 5 services on host..." -> set total expected
                                m = re.search(r"Scanning\s+(\d+)\s+services\s+on", line)
                                if m:
                                    try:
                                        progress_nmap['services_total_expected'] = int(m.group(1))
                                        # print(f"\n[DEBUG] 📦 Total services expected: {progress_nmap['services_total_expected']}")
                                    except Exception:
                                        pass
                            elif progress_nmap['phase_detection'] and ("/tcp" in line or "/udp" in line) and "open" in line.lower():
                                # Detect services during the scan -sV
                                # Pattern: port/tcp open service version
                                # Ejemplo: "80/tcp open http Apache httpd 2.4.41"
                                # Search pattern of port/tcp or port/udp with "open"
                                match_port = re.search(r"(\d+)/(tcp|udp)\s+open", line, re.IGNORECASE)
                                if match_port:
                                    # Verify that the line has information of service (more of 3 words after of "open")
                                    words_after_open = line.lower().split("open")
                                    if len(words_after_open) > 1:
                                        words_service = words_after_open[1].strip().split()
                                        # If there is to the less 1 word after of "open", probably is a service detected
                                        if len(words_service) >= 1 and words_service[0] not in ["filtered", "closed", "unfiltered"]:
                                            # increment counter of services detected
                                            # Only increment if we have not yet reached the total number of open ports
                                            ports_open = progress_nmap.get('ports_open', 0)
                                            if progress_nmap['services_detected'] < ports_open:
                                                progress_nmap['services_detected'] = min(
                                                    progress_nmap['services_detected'] + 1,
                                                    ports_open
                                                )
                                                # print(f"\n[DEBUG] 🔍 Service detected: {line.strip()} (Total: {progress_nmap['services_detected']}/{ports_open})")
                            elif "Service scan Timing: About" in line and "% done" in line:
                                # Progress real of -sV reported for nmap
                                # print(f"\n[DEBUG] 🔍 Processing line of timing -sV: {line.strip()}")
                                match_sv = re.search(r"About\s+([\d.]+)%\s+done", line)
                                if match_sv:
                                    percentage_real_sv = float(match_sv.group(1))
                                    # Save progress of the phase (0-100%); it will be converted to the 80-97% global range in show_progress_nmap
                                    progress_nmap['progress_service_detection'] = min(100.0, round(percentage_real_sv, 2))
                                    progress_nmap['progress_real_sv_available'] = True
                                    progress_nmap['last_timing_real_sv'] = time.time()
                                    if percentage_real_sv >= 100.0:
                                        progress_nmap['progress_real_sv_available'] = False
                                        progress_nmap['last_timing_real_sv'] = None
                                        # print(f"\n[DEBUG] 📊 Progress real -sV: {percentage_real_sv}% (completed)")
                                else:
                                    match_fallback_sv = re.search(r"(\d+\.?\d*)%", line)
                                    if match_fallback_sv:
                                        percentage_real_sv = float(match_fallback_sv.group(1))
                                        # Save progress of the phase (0-100%); it will be converted to the 80-97% global range in show_progress_nmap
                                        progress_nmap['progress_service_detection'] = min(100.0, round(percentage_real_sv, 2))
                                        progress_nmap['progress_real_sv_available'] = True
                                        progress_nmap['last_timing_real_sv'] = time.time()
                                        if percentage_real_sv >= 100.0:
                                            progress_nmap['progress_real_sv_available'] = False
                                            progress_nmap['last_timing_real_sv'] = None
                                            # print(f"\n[DEBUG] 📊 Progress real -sV (fallback): {percentage_real_sv}% (completed)")
                            elif "Completed Service scan" in line and not progress_nmap.get('detection_completed_impresa', False):
                                # Detect completion of -sV and force 100%
                                # print(f"\n[DEBUG] ✅ Detected: Completed Service scan")
                                progress_nmap['progress_service_detection'] = 100
                                progress_nmap['phase_detection'] = False
                                progress_nmap['detection_completed_impresa'] = True
                                # Print line fixed of closing of -sV with 100%
                                try:
                                    elapsed_sv = time.time() - start_time
                                    elapsed_sv_formatted = f"{int(elapsed_sv//3600):02d}:{int((elapsed_sv%3600)//60):02d}:{int(elapsed_sv%60):02d}"
                                    # Clear line current before of print for avoid lines empty
                                    print(f"\r\033[K[*] Scanning {progress_nmap['target']}... ✓ 100% (detection of services completed) - {elapsed_sv_formatted}")
                                except Exception:
                                    pass
                            elif "Completed Service scan" in line and "services on" in line and not progress_nmap.get('detection_completed_impresa', False):
                                # Ej: "Completed Service scan ... (5 services on 1 host)" -> set D and close phase
                                m = re.search(r"\((\d+)\s+services\s+on", line)
                                if m:
                                    try:
                                        progress_nmap['services_detected'] = int(m.group(1))
                                    except Exception:
                                        pass
                                # Force 100% immediate on completion -sV
                                progress_nmap['progress_real_sv_available'] = False
                                progress_nmap['last_timing_real_sv'] = None
                                progress_nmap['progress_service_detection'] = 100
                                progress_nmap['phase_detection'] = False
                                progress_nmap['detection_completed_impresa'] = True
                                # Print line fixed of closing of -sV with 100%
                                try:
                                    elapsed_sv = time.time() - start_time
                                    elapsed_sv_formatted = f"{int(elapsed_sv//3600):02d}:{int((elapsed_sv%3600)//60):02d}:{int(elapsed_sv%60):02d}"
                                    total_sv = (progress_nmap.get('services_total_expected') or progress_nmap['ports_open'])
                                    # Clear line current before of print for avoid lines empty
                                    print(f"\r\033[K[*] Scanning {progress_nmap['target']}... ✓ 100% (detection of services completed) - {elapsed_sv_formatted}")
                                except Exception:
                                    pass
                                # print(f"\n[DEBUG] 🎯 COMPLETED -sV: 100% (detection of services completed)")
                            elif "Initiating NSE" in line:
                                # Phase NSE started
                                # print(f"\n[DEBUG] ✅ Detected: Initiating NSE")
                                
                                # If still we are in phase of detection, complete it first
                                if progress_nmap['phase_detection'] and not progress_nmap.get('detection_completed_impresa', False):
                                    progress_nmap['progress_service_detection'] = 100
                                    progress_nmap['phase_detection'] = False
                                    progress_nmap['detection_completed_impresa'] = True
                                    # Update statistics (Tarea #24)
                                    tee_logger = get_tee_logger()
                                    if tee_logger and progress_nmap.get('time_detection_start'):
                                        time_sv = time.time() - progress_nmap['time_detection_start']
                                        tee_logger.update_stats({'time_service_detection': time_sv})
                                    # Print message of detection completed
                                    try:
                                        elapsed_sv = time.time() - start_time
                                        elapsed_sv_formatted = f"{int(elapsed_sv//3600):02d}:{int((elapsed_sv%3600)//60):02d}:{int(elapsed_sv%60):02d}"
                                        # Clear line current before of print for avoid lines empty
                                        print(f"\r\033[K[*] Scanning {progress_nmap['target']}... ✓ 100% (detection of services completed) - {elapsed_sv_formatted}")
                                    except Exception:
                                        pass
                                
                                # Not show message of "preparing NSE" - is very fast
                                progress_nmap['phase_nse'] = True
                                progress_nmap['nse_started'] = True
                                progress_nmap['progress_nse'] = 0  # Start NSE from 0%
                                progress_nmap['time_nse_start'] = time.time()
                                progress_nmap['progress_real_nse_available'] = False
                                progress_nmap['last_timing_real_nse'] = None
                                # print(f"\n[DEBUG] 🚀 STARTING NSE: 0% (running scripts NSE)")
                            elif "NSE Timing: About" in line and "% done" in line and progress_nmap['phase_nse']:
                                # Progress real of NSE reported for nmap
                                match_nse = re.search(r"About\s+([\d.]+)%\s+done", line)
                                if match_nse:
                                    percentage_real_nse = float(match_nse.group(1))
                                    # Save progress of the phase NSE (0-100%)
                                    progress_nmap['progress_nse'] = min(99.0, round(percentage_real_nse, 2))  # limit a 99% until complete
                                    progress_nmap['progress_real_nse_available'] = True
                                    progress_nmap['last_timing_real_nse'] = time.time()
                                    if percentage_real_nse >= 100.0:
                                        progress_nmap['progress_nse'] = 100.0
                                        progress_nmap['progress_real_nse_available'] = False
                                        progress_nmap['last_timing_real_nse'] = None
                                else:
                                    # Fallback: search any percentage in the line
                                    match_fallback_nse = re.search(r"(\d+\.?\d*)%", line)
                                    if match_fallback_nse:
                                        percentage_real_nse = float(match_fallback_nse.group(1))
                                        progress_nmap['progress_nse'] = min(99.0, round(percentage_real_nse, 2))
                                        progress_nmap['progress_real_nse_available'] = True
                                        progress_nmap['last_timing_real_nse'] = time.time()
                                        if percentage_real_nse >= 100.0:
                                            progress_nmap['progress_nse'] = 100.0
                                            progress_nmap['progress_real_nse_available'] = False
                                            progress_nmap['last_timing_real_nse'] = None
                            elif "Completed NSE" in line and not progress_nmap['nse_completed_printed']:
                                # Phase NSE completed - NSE is very fast, not show message
                                progress_nmap['progress_nse'] = 100
                                progress_nmap['phase_nse'] = False
                                progress_nmap['nse_completed'] = True
                                progress_nmap['nse_completed_printed'] = True  # mark as printed
                                # Stop thread of progress after of NSE completed
                                progress_nmap['active'] = False
                                # Not print message of NSE completed - is very fast
                            elif "Nmap scan report completed" in line:
                                # Phase Completion started
                                # print(f"\n[DEBUG] ✅ Detected: Nmap scan report completed")
                                progress_nmap['phase_completion'] = True
                                progress_nmap['time_completion_start'] = time.time()
                                progress_nmap['progress_completion'] = 0  # Start completion from 0%
                                # print(f"\n[DEBUG] 🏁 STARTING COMPLETION: 0% (generating report final)")
                                # complete immediately (is very fast)
                                progress_nmap['progress_completion'] = 100
                                progress_nmap['phase_completion'] = False
                                # Only print if NSE has not been printed before
                                if not progress_nmap['nse_completed_printed']:
                                    # Print line fixed of closing of completion with 100%
                                    try:
                                        elapsed_final = time.time() - start_time
                                        elapsed_final_formatted = f"{int(elapsed_final//3600):02d}:{int((elapsed_final%3600)//60):02d}:{int(elapsed_final%60):02d}"
                                        # Clear line current before of print for avoid lines empty
                                        print(f"\r\033[K[*] Scanning {progress_nmap['target']}... ✓ 100% (scan completed) - {elapsed_final_formatted}")
                                    except Exception:
                                        pass
                                # print(f"\n[DEBUG] 🎯 COMPLETED COMPLETION: 100% (report generated)")
                            elif "Completed SYN Stealth Scan" in line:
                                # Fin from the scan -sS reported for nmap
                                # print(f"\n[DEBUG] ✅ Detected: Completed SYN Stealth Scan")
                                progress_nmap['phase_scan_completed'] = True
                                # complete progress a 100% and adjust counters
                                progress_nmap['progress_scan_ports'] = 100
                                progress_nmap['progress_ss_max'] = 100.0
                                progress_nmap['ports_scanned'] = progress_nmap['total_ports']
                                progress_nmap['ports_filtered'] = progress_nmap['total_ports'] - progress_nmap['ports_open'] - progress_nmap['ports_closed']
                                # Force update immediate from the display
                                # print(f"\n[DEBUG] 🎯 COMPLETED -sS: 100% ({progress_nmap['ports_scanned']}/{progress_nmap['total_ports']})")
                                # Print line fixed of closing of -sS with 100% and counters of ports
                                try:
                                    elapsed_ss = time.time() - start_time
                                    elapsed_ss_formatted = f"{int(elapsed_ss//3600):02d}:{int((elapsed_ss%3600)//60):02d}:{int(elapsed_ss%60):02d}"
                                    counters_ss = f"({progress_nmap['ports_scanned']}/{progress_nmap['total_ports']})"
                                    # Clear line current before of print for avoid lines empty
                                    print(f"\r\033[K[*] Scanning {progress_nmap['target']}... ✓ 100% {counters_ss} (scan of ports completed) - {elapsed_ss_formatted}")
                                except Exception:
                                    pass
            except KeyboardInterrupt:
                # Kill the process if interrupted during reading, then always
                # propagate the cancellation upward (do not swallow it here).
                _kill_nmap_process_group(process)
                raise

        # wait a that ends the process completely (allowing CONTROL-C)
        # IMPROVEMENT v2.0: Replaced process.wait() for loop with sleep short for allow interruption
        # This ensures that CONTROL-C works correctly during the wait from the process
        try:
            while process.poll() is None:
                time.sleep(0.1)  # Sleep short (0.1s) for allow interruption with CONTROL-C
        except KeyboardInterrupt:
            # Kill the process if interrupted with CONTROL-C, then propagate
            _kill_nmap_process_group(process)
            raise
        
        # Leer any output remaining for count ports additional
        try:
            remaining_output = process.stdout.read()
            # The ports already were counted in the loop main
        except Exception:
            pass

        # Stop thread of progress and show result final
        progress_nmap['active'] = False
        progress_nmap_thread.join(timeout=0.3)
        _ensure_terminal_sane()
        
        # Update statistics final (Tarea #24)
        tee_logger = get_tee_logger()
        if tee_logger:
            # Update time of NSE if was active
            if progress_nmap.get('time_nse_start'):
                time_nse = time.time() - progress_nmap['time_nse_start']
                tee_logger.update_stats({'time_nse': time_nse})
            # Update time of completion if was active
            if progress_nmap.get('time_completion_start'):
                time_final = time.time() - progress_nmap['time_completion_start']
                tee_logger.update_stats({'time_completion': time_final})
            # Update statistics of ports
            tee_logger.update_stats({
                'ports_total': progress_nmap.get('total_ports', 0),
                'ports_open': progress_nmap.get('ports_open', 0),
                'ports_closed': progress_nmap.get('ports_closed', 0),
                'ports_filtered': progress_nmap.get('ports_filtered', 0)
            })
            # System of fallback: record measurements for future runs
            meter.record_measurement(tee_logger.stats)
        
        # Reset from the terminal after of stop the thread
        try:
            print('\033[0m\033[?25h\033[?7h\033[?1l\033[?1000l', end='', flush=True)
        except Exception:
            pass
        
        # IMPROVEMENT v2.0: Small delay interruptible for ensure that the file XML is haya written
        # In place of time.sleep(0.5), use loop with intervalos of 0.1s for allow CONTROL-C
        try:
            for _ in range(5):  # 5 * 0.1 = 0.5 seconds totals
                time.sleep(0.1)  # Each 0.1s allows verify if is pressed CONTROL-C
        except KeyboardInterrupt:
            pass
        
        # Show progress final based in lo achieved
        elapsed_final = time.time() - start_time
        elapsed_formatted_final = f"{int(elapsed_final//3600):02d}:{int((elapsed_final%3600)//60):02d}:{int(elapsed_final%60):02d}"
        
        if progress_nmap['total_ports'] > 0:
            percentage_final = int((progress_nmap['ports_scanned'] / progress_nmap['total_ports']) * 100)
            counters_final = f"({progress_nmap['ports_scanned']}/{progress_nmap['total_ports']})"
            print(f"\r[*] Scanning {target}... ✓ {percentage_final}% {counters_final} - {elapsed_formatted_final}", end="", flush=True)
        else:
            print(f"\r[*] Scanning {target}... ✓ 100% - {elapsed_formatted_final}", end="", flush=True)
        
        # Clear completely the line before of show result final
        print("\r\033[K", end="", flush=True)
        print(f"[*] Scan completed for {target} in {elapsed_formatted_final}")
        
        
        return xml_file  # Return the XML path instead of text output
    except KeyboardInterrupt:
        # Stop thread of progress immediately
        if 'progress_nmap' in locals():
            progress_nmap['active'] = False
        print("\n[*] Scan nmap cancelled for the user")
        # Clear terminal and exit cleanly
        try:
            os._exit(0)
        except Exception:
            return None
    except Exception as e:
        # Stop thread of progress if is active
        if 'progress_nmap' in locals():
            progress_nmap['active'] = False
        return f"ERROR running nmap: {str(e)}"
    finally:
        _nmap_process_current = None

def parse_nmap_xml(xml_file, target_original=None):
    """parses file XML of nmap and returns list of dicts: { 'target', 'port', 'service', 'version', 'status' }
    
    Processes ports with status 'open' and 'closed'. The field 'status' can be 'open', 'closed' or 'N/A' 
    (for records without detection added manually).
    """
    import xml.etree.ElementTree as ET
    
    results = []
    
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        for host in root.findall('host'):
            # Use the original target if provided, otherwise get it from the XML
            hostname = target_original
            
            if not hostname:
                # Get information from the host from XML
                for hostnames in host.findall('hostnames'):
                    for hostname_elem in hostnames.findall('hostname'):
                        if hostname_elem.get('type') == 'PTR':
                            hostname = hostname_elem.get('name')
                            break
                    if hostname:
                        break
                
                # If not there is hostname, use IP
                if not hostname:
                    for address in host.findall('address'):
                        if address.get('addrtype') == 'ipv4':
                            hostname = address.get('addr')
                            break
            
            # Get ports open and closed
            for ports in host.findall('ports'):
                for port in ports.findall('port'):
                    state = port.find('state')
                    if state is not None:
                        status_port = state.get('state', 'unknown')
                        # process only ports open and closed (not filtered)
                        if status_port in ['open', 'closed']:
                            port_id = port.get('portid')
                            protocol = port.get('protocol')
                            
                            # Get service
                            service = 'unknown'
                            version = ''

                            service_elem = port.find('service')
                            if service_elem is not None:
                                service = service_elem.get('name', 'unknown')
                                version = service_elem.get('version', '')
                                if service_elem.get('product'):
                                    version = service_elem.get('product')
                                    if service_elem.get('version'):
                                        version += f" {service_elem.get('version')}"
                            
                            results.append({
                                'target': hostname,
                                'target_original': hostname,
                                'port': port_id,
                                'service': service,
                                'version': version,
                                'status': status_port  # 'open' or 'closed'
                            })
        
        # Sort for target and port
        results.sort(key=lambda x: (x['target_original'], int(x['port'])))
        
        # mark target only in the first row of each host
        target_previous = None
        for result in results:
            if result['target_original'] != target_previous:
                target_previous = result['target_original']
            else:
                result['target'] = ""
        
        return results
        
    except Exception as e:
        print_colored(f"[!] Error parsing XML: {str(e)}", Colors.RED)
        return []

def run_scan_ports(subdomains_per_ip, sudo_password, ports="-p-", out_dir=None):
    """Runs nmap sequentially for each FQDN showing live progress and accumulating results.

    If out_dir is provided, saves the raw Nmap output for the target for diagnostics.
    """
    results = []
    targets = list(subdomains_per_ip.keys())
    for target in targets:
        print_colored(f"\n[*] Starting scan of ports for: {target}", Colors.BLUE)
        xml_file = run_nmap_stream(target, sudo_password, ports, out_dir)
        
        # parse from XML if is available
        if xml_file and os.path.exists(xml_file):
            parsed = parse_nmap_xml(xml_file, target)
        else:
            # Detailed diagnostic of the issue
            if not xml_file:
                print_colored(f"[!] No XML file was generated for {target} (xml_file is None)", Colors.RED)
            elif not os.path.exists(xml_file):
                print_colored(f"[!] File XML not found: {xml_file}", Colors.RED)
            else:
                print_colored(f"[!] Could not get the XML file for {target}", Colors.RED)
            parsed = []
        # Diagnostic: report of amount of ports detected for each target
        try:
            count_obj = sum(1 for r in parsed if r.get('target_original') == target)
        except Exception:
            count_obj = len(parsed)
        if count_obj > 0:
            print_colored(f"[+] Open ports detected for {target}: {count_obj}", Colors.GREEN)
        else:
            print_colored(f"[-] No open ports detected for {target}", Colors.YELLOW)
            # Add a row of 'without detection' for that appears in the table
            results.append({
                'target': target,
                'target_original': target,
                'port': 'Without DETECTION',
                'service': 'Without DETECTION',
                'version': 'Without DETECTION',
                'status': 'N/A',  # No detection - the status cannot be determined
                'sin_detection': True
            })
        results.extend(parsed)
    return results

def print_table_nmap(results, domain_base=None):
    """Prints the Table 2 with columns: target, port, service, version, status.

    If domain_base is provided, mark that target with (MAIN).
    """
    title = "🌐 TABLE 2: PORT SCAN RESULTS"
    col1 = "TARGET"
    col2 = "PORT"
    col3 = "service"
    col4 = "VERSION"
    col5 = "STATUS"

    # Calculate widths considering the possible marks (MAIN)
    def target_displayable_para_width(obj):
        if domain_base and obj == domain_base:
            return f"{obj} (MAIN)"
        return obj

    # Calculate widths
    width1 = max(len(col1), max((len(target_displayable_para_width(r['target'])) for r in results), default=0))
    width2 = max(len(col2), max((len(r['port']) for r in results), default=0))
    width3 = max(len(col3), max((len(r['service']) for r in results), default=0))
    width4 = max(len(col4), max((len(r.get('version', '')) for r in results), default=0))
    width5 = max(len(col5), max((len(r.get('status', 'open')) for r in results), default=0))

    width1 = max(22, min(width1 + 2, 60))
    width2 = max(8, min(width2 + 2, 15))
    width3 = max(10, min(width3 + 2, 25))
    width4 = max(15, min(width4 + 2, 40))
    width5 = max(8, min(width5 + 2, 12))
    width_total = width1 + width2 + width3 + width4 + width5 + 4  # 4 separators between 5 columns

    term_width = get_terminal_width()
    margin = max(0, (term_width - width_total) // 2)
    pad = " " * margin

    print("\n", end="")
    print(pad, end=""); print_colored(f"{'═'*(width_total+2)}", Colors.CYAN)
    print(pad, end=""); print_colored("║", Colors.BLUE, end=""); print_colored(f"{title:^{width_total-1}}", Colors.BOLD + Colors.WHITE, end=""); print_colored("║", Colors.BLUE)
    print(pad, end=""); print_colored(f"{'═'*(width_total+2)}", Colors.CYAN)
    print(pad, end=""); print_colored("║", Colors.BLUE, end=""); print_colored(f"{col1:^{width1}}", Colors.BOLD + Colors.YELLOW, end=""); print_colored("║", Colors.BLUE, end=""); print_colored(f"{col2:^{width2}}", Colors.BOLD + Colors.YELLOW, end=""); print_colored("║", Colors.BLUE, end=""); print_colored(f"{col3:^{width3}}", Colors.BOLD + Colors.YELLOW, end=""); print_colored("║", Colors.BLUE, end=""); print_colored(f"{col4:^{width4}}", Colors.BOLD + Colors.YELLOW, end=""); print_colored("║", Colors.BLUE, end=""); print_colored(f"{col5:^{width5}}", Colors.BOLD + Colors.YELLOW, end=""); print_colored("║", Colors.BLUE)
    print(pad, end=""); print_colored(f"╠{'═'*width1}╬{'═'*width2}╬{'═'*width3}╬{'═'*width4}╬{'═'*width5}╣", Colors.CYAN)

    if not results:
        print(pad, end=""); print_colored("║", Colors.BLUE, end=""); print_colored(f"{'Without results':^{width_total-2}}", Colors.WHITE, end=""); print_colored("║", Colors.BLUE)
    else:
        # Sort for target original and port, placing the main first if is specific
        def sort_key(r):
            port = r['port']
            # Handle "Without DETECTION" as port 0 for sorting
            try:
                port_num = int(port) if port != 'Without DETECTION' else 0
            except (ValueError, TypeError):
                port_num = 0
            return port_num
        
        if domain_base:
            # Group for target original and sort ports inside of each group
            results_sorted = sorted(results, key=lambda r: (0 if r['target_original'] == domain_base else 1, r['target_original'], sort_key(r)))
        else:
            results_sorted = sorted(results, key=lambda r: (r['target_original'], sort_key(r)))
        for i, r in enumerate(results_sorted):
            obj = r['target']
            if domain_base and obj == domain_base:
                obj = f"{obj} (MAIN)"
                color_subdomain = Colors.RED
            else:
                color_subdomain = Colors.GREEN
            # determine if is row of 'without detection'
            es_sin = r.get('sin_detection', False)
            color_other_columns = Colors.GREEN
            version_txt = r.get('version', '')
            status_txt = r.get('status', 'open')
            if es_sin:
                color_subdomain = Colors.ORANGE
                color_other_columns = Colors.ORANGE
                port_txt = "Without DETECTION"
                service_txt = "Without DETECTION"
                version_txt = "Without DETECTION"
                status_txt = "N/A"
            else:
                port_txt = r['port']
                service_txt = r['service']
            
            # Color for status: green if open, orange if closed
            color_status = Colors.GREEN if status_txt == 'open' else Colors.ORANGE
            
            print(pad, end=""); print_colored("║", Colors.BLUE, end=""); print_colored(f"{obj:^{width1}}", color_subdomain, end=""); print_colored("║", Colors.BLUE, end=""); print_colored(f"{port_txt:^{width2}}", color_other_columns, end=""); print_colored("║", Colors.BLUE, end=""); print_colored(f"{service_txt:^{width3}}", color_other_columns, end=""); print_colored("║", Colors.BLUE, end=""); print_colored(f"{version_txt:^{width4}}", color_other_columns, end=""); print_colored("║", Colors.BLUE, end=""); print_colored(f"{status_txt:^{width5}}", color_status, end=""); print_colored("║", Colors.BLUE)
            if i < len(results_sorted) - 1:
                # Verify if the next row has target empty for create effect of cells merged
                next_row = results_sorted[i + 1]
                if next_row['target'] == "":
                    # Line separator that not crosses the first column (cell merged)
                    print(pad, end=""); print_colored(f"║{' '*width1}╟{'─'*width2}╫{'─'*width3}╫{'─'*width4}╫{'─'*width5}╢", Colors.BLUE)
                else:
                    # Line separator normal
                    print(pad, end=""); print_colored(f"╟{'─'*width1}╫{'─'*width2}╫{'─'*width3}╫{'─'*width4}╫{'─'*width5}╢", Colors.BLUE)

    print(pad, end=""); print_colored(f"{'═'*(width_total+2)}", Colors.CYAN)

def format_long_text(text, width_max):
    """formats text long for that is adjustment inside from the width specified"""
    if len(text) <= width_max:
        return text
    
    # If the text is very long, split it in multiple lines
    words = text.split(', ')
    lines = []
    line_current = ""
    
    for word in words:
        # Calculate the space necessary for is word
        if line_current:
            space_necessary = len(line_current) + 2 + len(word)  # 2 for ", "
        else:
            space_necessary = len(word)
        
        if space_necessary <= width_max:
            if line_current:
                line_current += ", " + word
            else:
                line_current = word
        else:
            if line_current:
                lines.append(line_current)
            line_current = word
    
    if line_current:
        lines.append(line_current)
    
    return lines

def print_row_table_ip(subdomain, ips_str, width_subdomain=40, width_ips=40, margin="", color_content=None):
    """Prints a row of the table of IPs with handling of content long"""
    if color_content is None:
        color_content = Colors.GREEN
    # format the IPs if are very long
    if len(ips_str) <= width_ips:
        # A sola line
        print(margin, end="")
        print_colored("║", Colors.BLUE, end="")
        print_colored(f"{subdomain:^{width_subdomain}}", color_content, end="")
        print_colored("║", Colors.BLUE, end="")
        print_colored(f"{ips_str:^{width_ips}}", color_content, end="")
        print_colored("║", Colors.BLUE)
    else:
        # split in multiple lines
        words = ips_str.split(', ')
        lines = []
        line_current = ""
        
        for word in words:
            if line_current:
                space_necessary = len(line_current) + 2 + len(word)
            else:
                space_necessary = len(word)
            
            if space_necessary <= width_ips:
                if line_current:
                    line_current += ", " + word
                else:
                    line_current = word
            else:
                if line_current:
                    lines.append(line_current)
                line_current = word
        
        if line_current:
            lines.append(line_current)
        
        # Print multiple lines
        for j, line in enumerate(lines):
            if j == 0:
                # first line with the subdomain
                print(margin, end="")
                print_colored("║", Colors.BLUE, end="")
                print_colored(f"{subdomain:^{width_subdomain}}", color_content, end="")
                print_colored("║", Colors.BLUE, end="")
                print_colored(f"{line:^{width_ips}}", color_content, end="")
                print_colored("║", Colors.BLUE)
            else:
                # Lines additional with spaces for keep alignment
                print(margin, end="")
                print_colored("║", Colors.BLUE, end="")
                print_colored(f"{'':^{width_subdomain}}", color_content, end="")
                print_colored("║", Colors.BLUE, end="")
                print_colored(f"{line:^{width_ips}}", color_content, end="")
                print_colored("║", Colors.BLUE)

def print_row_table_professional(subdomain, reverse_dns, width_subdomain=40, width_reverse_dns=40, margin="", color_content=None):
    """Prints a row of the table professional with handling of text long"""
    if color_content is None:
        color_content = Colors.GREEN
    # format the reverse DNS if is very long
    if reverse_dns == 'N/A':
        # Print row with barras blue, subdomain in color normal and N/A in orange
        print(margin, end="")
        print_colored("║", Colors.BLUE, end="")
        print_colored(f"{subdomain:^{width_subdomain}}", color_content, end="")
        print_colored("║", Colors.BLUE, end="")
        print_colored(f"{reverse_dns:^{width_reverse_dns}}", Colors.ORANGE, end="")
        print_colored("║", Colors.BLUE)
    else:
        lines_reverse_dns = format_long_text(reverse_dns, width_reverse_dns)
        
        # Verify if is a list or a string
        if isinstance(lines_reverse_dns, str):
            # It is a simple string (not split)
            # Print row with barras blue and content green
            print(margin, end="")
            print_colored("║", Colors.BLUE, end="")
            print_colored(f"{subdomain:^{width_subdomain}}", color_content, end="")
            print_colored("║", Colors.BLUE, end="")
            print_colored(f"{lines_reverse_dns:^{width_reverse_dns}}", color_content, end="")
            print_colored("║", Colors.BLUE)
        elif len(lines_reverse_dns) == 1:
            # A sola line
            line = lines_reverse_dns[0]
            
            # Print row with barras blue and content green
            print(margin, end="")
            print_colored("║", Colors.BLUE, end="")
            print_colored(f"{subdomain:^{width_subdomain}}", color_content, end="")
            print_colored("║", Colors.BLUE, end="")
            print_colored(f"{line:^{width_reverse_dns}}", color_content, end="")
            print_colored("║", Colors.BLUE)
        else:
            # Multiple lines
            for i, line in enumerate(lines_reverse_dns):
                if i == 0:
                    # first line with the subdomain
                    print(margin, end="")
                    print_colored("║", Colors.BLUE, end="")
                    print_colored(f"{subdomain:^{width_subdomain}}", color_content, end="")
                    print_colored("║", Colors.BLUE, end="")
                    print_colored(f"{line:^{width_reverse_dns}}", color_content, end="")
                    print_colored("║", Colors.BLUE)
                else:
                    # Lines additional with spaces for keep alignment
                    print(margin, end="")
                    print_colored("║", Colors.BLUE, end="")
                    print_colored(f"{'':^{width_subdomain}}", color_content, end="")
                    print_colored("║", Colors.BLUE, end="")
                    print_colored(f"{line:^{width_reverse_dns}}", color_content, end="")
                    print_colored("║", Colors.BLUE)

def analyze_domain(domain):
    """Complete function to analyze a domain like DNSDumpster.com

    In addition to showing the Option 1 tables on screen, it exports:
    - table1_subdomains_ips.csv/json
    - table2_reverse_dns.csv/json
    """
    print_colored(f"\n{'='*60}", Colors.CYAN)
    print_colored(f"🔍 ANALYZING DOMAIN: {domain}", Colors.BOLD + Colors.WHITE)
    print_colored(f"{'='*60}", Colors.CYAN)
    
    # Verify dependencies
    if not verify_dependencies():
        print_colored("[-] Cannot continue the verifications without the dependencies", Colors.RED)
        return False
    
    # Verify that the domain exists BEFORE doing any test
    print_colored(f"\n[*] Verifying existence from the domain {domain}...", Colors.BLUE)
    if not verify_dns_existence(domain):
        print_colored(f"\n❌ ERROR: Domain {domain} not found", Colors.RED)
        print_colored(f"💡 Try again with a valid domain", Colors.YELLOW)
        return False
    
    print_colored(f"✅ Domain {domain} verified and exists", Colors.GREEN)
    print_colored(f"🚀 Starting analysis complete...", Colors.BLUE)
    
    # 1. Resolution DNS complete
    records_dns = get_records_dns_complete(domain)
    
    # prepare output folder for exporting tables (same as Option 2)
    out_dir = create_output_directory(domain)
    print_colored(f"\n[+] Output folder: {out_dir}", Colors.GREEN)

    # 2. Detection of subdomains: show tables and return map for export
    subdomains_per_ip = detect_subdomains(
        domain,
        show_table2=True,
        show_summary=False,
        return_map=True
    )

    # export Table 1: Subdomains → IPs
    session_tag = os.path.basename(out_dir)
    # prefix of files: only domain (without date/hour)
    base_tag = re.sub(r"_\d{2}-\d{2}-\d{4}_\d{2}:\d{2}$", "", session_tag)
    rows_t1 = []
    for sub, ips in subdomains_per_ip.items():
        ips_unique = ", ".join(sorted(set(ips)))
        rows_t1.append({"subdomain": sub, "ips": ips_unique})
    save_csv(os.path.join(out_dir, f"{base_tag}_table1_subdomains_ips.csv"), ["subdomain", "ips"], rows_t1)
    save_json(os.path.join(out_dir, f"{base_tag}_table1_subdomains_ips.json"), rows_t1)

    # export Table 2 (Option 1): Reverse DNS for subdomain
    # Deduplicate IPs first: many subdomains share the same IP, and each
    # reverse_dns_lookup() can take up to 5s (nslookup timeout) when there is
    # no PTR record, so resolving every (subdomain, ip) pair one at a time
    # sequentially could take minutes with no visible feedback.
    unique_ips = sorted({ip for ips in subdomains_per_ip.values() for ip in set(ips)})
    rdns_by_ip = {}

    if unique_ips:
        progress_rdns = {
            'processed': 0,
            'total': len(unique_ips),
            'active': True,
            'start_time': time.time()
        }

        def show_progress_rdns():
            """Separate thread to show the progress bar of reverse DNS lookups"""
            old_settings = _enter_raw_no_echo_mode()

            chars = "|/-\\"
            i = 0
            while progress_rdns['active']:
                try:
                    elapsed = time.time() - progress_rdns['start_time']
                    elapsed_formatted = f"{int(elapsed//3600):02d}:{int((elapsed%3600)//60):02d}:{int(elapsed%60):02d}"
                    percentage = int((progress_rdns['processed'] / progress_rdns['total']) * 100)
                    print(f"\r[*] Resolving reverse DNS... {chars[i % len(chars)]} {percentage}% ({progress_rdns['processed']}/{progress_rdns['total']}) - {elapsed_formatted}", end="", flush=True)
                    i += 1
                    time.sleep(0.1)
                except KeyboardInterrupt:
                    break

            _restore_terminal_mode(old_settings)

        print_colored(f"[*] Resolving reverse DNS for {len(unique_ips)} unique IP(s)...", Colors.BLUE, end="")
        progress_rdns_thread = threading.Thread(target=show_progress_rdns, daemon=True)
        progress_rdns_thread.start()

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
                futures = {executor.submit(reverse_dns_lookup, ip): ip for ip in unique_ips}
                for future in concurrent.futures.as_completed(futures):
                    ip = futures[future]
                    progress_rdns['processed'] += 1
                    try:
                        rdns_by_ip[ip] = future.result() or 'N/A'
                    except Exception:
                        rdns_by_ip[ip] = 'N/A'
        except KeyboardInterrupt:
            progress_rdns['active'] = False
            progress_rdns_thread.join(timeout=0.3)
            _ensure_terminal_sane()
            print("\n[*] Reverse DNS resolution cancelled by the user")
            try:
                os._exit(0)
            except Exception:
                pass

        progress_rdns['active'] = False
        progress_rdns_thread.join(timeout=0.3)
        _ensure_terminal_sane()

        print("\r\033[K", end="", flush=True)
        elapsed = time.time() - progress_rdns['start_time']
        elapsed_formatted = f"{int(elapsed//3600):02d}:{int((elapsed%3600)//60):02d}:{int(elapsed%60):02d}"
        resolved_count = sum(1 for v in rdns_by_ip.values() if v and v != 'N/A')
        print_colored(f"[*] Reverse DNS completed - {resolved_count}/{len(unique_ips)} resolved in {elapsed_formatted}", Colors.BLUE if resolved_count > 0 else Colors.WHITE)

    subdomains_reverse_dns = {}
    for sub, ips in subdomains_per_ip.items():
        for ip in set(ips):
            rdns = rdns_by_ip.get(ip, 'N/A')
            if sub not in subdomains_reverse_dns:
                subdomains_reverse_dns[sub] = []
            if rdns not in subdomains_reverse_dns[sub]:
                subdomains_reverse_dns[sub].append(rdns)

    rows_t2_rev = []
    for sub, rdns_list in subdomains_reverse_dns.items():
        rdns_join = ", ".join([r for r in rdns_list if r] or ['N/A'])
        rows_t2_rev.append({"subdomain": sub, "reverse_dns": rdns_join})
    save_csv(os.path.join(out_dir, f"{base_tag}_table2_reverse_dns.csv"), ["subdomain", "reverse_dns"], rows_t2_rev)
    save_json(os.path.join(out_dir, f"{base_tag}_table2_reverse_dns.json"), rows_t2_rev)

    # --- Folder Consolidated (same layout as Options 2 and 3) ---
    _build_consolidated_folder(out_dir)

    # Create consolidated Excel (reads from Consolidated, writes there)
    try:
        excel_path = create_excel_consolidated(out_dir)
        if excel_path:
            print_colored(f"[+] Consolidated Excel created: {excel_path}", Colors.GREEN)
        else:
            print_colored(f"[-] Could not create the consolidated Excel", Colors.YELLOW)
    except Exception as e:
        print_colored(f"[-] Error creating the consolidated Excel: {str(e)}", Colors.YELLOW)
    
    # 3. Information WHOIS removed
    
    # Summary final
    print_colored(f"\n{'='*60}", Colors.CYAN)
    print_colored(f"📊 SUMMARY From the ANALYSIS: {domain}", Colors.BOLD + Colors.WHITE)
    print_colored(f"{'='*60}", Colors.CYAN)
    
    total_records = sum(len(records) for records in records_dns.values())
    print_colored(f"[+] Total records DNS found: {total_records}", Colors.GREEN)
    print_colored(f"[+] Total subdomains detected: {len(subdomains_per_ip)}", Colors.GREEN)
    print_colored(f"[+] Analysis completed successfully", Colors.GREEN)
    
    # pause controlled for the user
    print(f"{RGB_YELLOW}{'═' * 54}")
    try:
        _ensure_terminal_sane()
        input(f"\n{RGB_BLUE}[*] {Colors.WHITE}Press ENTER for return to the menu main...")
    except KeyboardInterrupt:
        pass
    
    # Reset from the terminal after of the pause
    reset_terminal_complete()
    
    return True

def analyze_domain_with_ports(domain, force_all_ports=False):
    """Option 2: Analyze domain with detection of subdomains (OSINT) and scan of ports.
    
    Is function performs a analysis complete that includes:
    1. Verification of dependencies and existence DNS
    2. Detection of subdomains via techniques OSINT (Table 1: Subdomains -> IPs)
    3. Scan of ports with nmap (Table 2: Results of scan)
    4. Export of results in CSV, JSON, XML and Excel
    
    Args:
        domain (str): Domain to analyze (ej: "example.com")
        force_all_ports (bool): If is True, salta the submenu of selection of ports
                                     and uses directly scan complete (-p-). For default False.
    
    Returns:
        True: Analysis completed successfully.
        "domain_error": Domain does not exist or does not resolve via DNS (the menu increments attempts).
        "abort": Sudo failure, user cancelled, or dependencies missing (returns to the menu without increment).
    
    notes:
        - If force_all_ports=False, shows a submenu interactive for select
          the type of scan of ports (specific, range, group, mixed or complete).
        - exports Table 1 (subdomains -> IPs) and Table 2 (results nmap).
        - CONTROL-C during sudo: returns to the menu without show "Domain wrong".
    """
    # Verify dependencies
    if not verify_dependencies():
        print_colored("[-] Cannot continue the verifications without the dependencies", Colors.RED)
        return "abort"

    # Verify that the domain exists BEFORE doing any test
    print_colored(f"\n[*] Verifying existence from the domain {domain}...", Colors.BLUE)
    if not verify_dns_existence(domain):
        print_colored(f"\n❌ ERROR: Domain {domain} not found", Colors.RED)
        print_colored(f"💡 Try again with a valid domain", Colors.YELLOW)
        return "domain_error"

    print_colored(f"✅ Domain {domain} verified and exists", Colors.GREEN)

    # Detect subdomains and show Table 1 (Subdomains -> IPs)
    print_colored(f"\n[*] Detecting subdomains of {domain}...", Colors.BLUE)
    subdomains_per_ip = detect_subdomains(domain, show_table2=False, return_map=True)

    # Selection of ports: equal that in the option 2 from the submenu of ports
    if force_all_ports:
        ports_scan = "-p-"
        print_colored(f"\n[*] Using full scan (all ports) (-p-)", Colors.BLUE)
    else:
        ports_scan = select_ports_interactive()
        if not ports_scan:
            return "abort"  # User cancelled, not a domain error
    
    # From here: logic common of scan of ports + export (includes OSINT of subdomains)
    result = run_flow_scan_ports(domain, subdomains_per_ip, ports_scan)
    return result if result else "abort"  # sudo/cancel = abort, not domain_error


def run_flow_scan_ports(domain, subdomains_per_ip, ports_scan="-p-"):
    """Runs all the flow common of scan of ports (sudo, nmap, export and display).
    
    Is function centralizes the logic common of scan of ports that is used both for
    the option 2 (with OSINT) as for the option 3 (without OSINT). handles:
    1. Request and verification of credentials sudo (3 attempts)
    2. Execution from the scan nmap with progress in time real
    3. Export of results (CSV, JSON, XML, Excel)
    4. Display of the Table 2 with results
    
    Args:
        domain (str): Main domain being analyzed (used to mark it in the table)
        subdomains_per_ip (dict): Dictionary with structure {subdomain: [ip1, ip2, ...]}
                                   Can contain multiple subdomains (option 2) or only
                                   a unique domain (option 3).
        ports_scan (str): String of ports for nmap (ej: "-p80", "-p80-443", "-p-")
                               For default "-p-" (all the ports).
    
    Returns:
        True: Scan completed successfully.
        False: Sudo failure, user cancelled (CONTROL-C), or password incorrect after 3 attempts.
    
    notes:
        - CONTROL-C during getpass: restores terminal, returns to the menu (not exits from the program).
        - The delays of wait are interruptible (intervalos of 0.1s).
        - exports Table 2 (results nmap) but Not Table 1 (that is exports before of call is function).
    """
    # request password of sudo with 3 attempts (CONTROL-C during getpass: returns to the menu)
    sudo_password = None
    attempts_remaining = 3
    
    while attempts_remaining > 0:
        try:
            print_colored(f"\n[*] please enter the sudo password. Attempt {4 - attempts_remaining} of 3", Colors.BLUE)
            # CONTROL-C during getpass: use handler for default for that KeyboardInterrupt is propagate
            # (the handler custom intercepta SIGINT and exits; here we want return to the menu)
            import signal
            _handler_previo = signal.signal(signal.SIGINT, signal.SIG_DFL)
            try:
                sudo_password = getpass.getpass(prompt=f"{RGB_BLUE}[sudo] {Colors.WHITE}Password: ")
            except KeyboardInterrupt:
                # Restore terminal (getpass leaves in raw mode) and handler before of return
                try:
                    subprocess.run(['stty', 'sane'], check=False, capture_output=True, timeout=1)
                except Exception:
                    pass
                try:
                    print('\033[0m\033[?25h', end='', flush=True)
                except Exception:
                    pass
                signal.signal(signal.SIGINT, _handler_previo)
                print_colored(f"\n[*] Input cancelled. Returning to the menu...", Colors.YELLOW)
                return False
            finally:
                signal.signal(signal.SIGINT, _handler_previo)
        except Exception:
            sudo_password = ''
        
        # Verify password sudo
        print_colored(f"[*] Verifying credentials...", Colors.BLUE)
        try:
            # Use subprocess.run with input for best handling of input
            result = subprocess.run(
                ['sudo', '-S', '-k', 'whoami'],
                input=sudo_password + "\n",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0 and 'root' in result.stdout.strip():
                print_colored(f"[+] credentials of sudo verified correctly", Colors.GREEN)
                
                # Show messages of confirmation after of verify sudo
                print_colored(f"\n[*] Starting scan of ports...", Colors.BLUE)
                print_colored(f"[*] you can press CONTROL-C for cancel", Colors.YELLOW)
                
                try:
                    # IMPROVEMENT v2.0: Sleep interruptible - split in small intervalos for allow CONTROL-C
                    # In place of time.sleep(3), use loop with intervalos of 0.1s
                    for _ in range(30):  # 30 * 0.1 = 3 seconds totals
                        time.sleep(0.1)  # Each 0.1s allows verify if is pressed CONTROL-C
                except KeyboardInterrupt:
                    print_colored(f"\n[*] Scan cancelled for the user", Colors.RED)
                    return False
                
                break  # Exit from the loop if is correct
            else:
                attempts_remaining -= 1
                if attempts_remaining > 0:
                    print_colored(f"[-] Password incorrect. Attempts remaining: {attempts_remaining}", Colors.RED)
                else:
                    print_colored(f"[-] Password incorrect. Ran out of attempts.", Colors.RED)
                    print_colored(f"❌ Cannot continue without administrative privileges", Colors.RED)
                    try:
                        # IMPROVEMENT v2.0: Sleep interruptible - split in small intervalos for allow CONTROL-C
                        for _ in range(30):  # 30 * 0.1 = 3 seconds totals
                            time.sleep(0.1)  # Each 0.1s allows verify if is pressed CONTROL-C
                    except KeyboardInterrupt:
                        pass
                    return False
                
        except Exception as e:
            attempts_remaining -= 1
            if attempts_remaining > 0:
                print_colored(f"[-] Error verifying sudo: {str(e)}. Attempts remaining: {attempts_remaining}", Colors.RED)
            else:
                print_colored(f"[-] Error verifying sudo: {str(e)}", Colors.RED)
                print_colored(f"❌ Cannot continue without administrative privileges", Colors.RED)
                try:
                    # Sleep interruptible: split in small intervalos
                    for _ in range(30):  # 30 * 0.1 = 3 seconds
                        time.sleep(0.1)
                except KeyboardInterrupt:
                    pass
                return False

    # prepare output folder before the scan to save raw data
    out_dir = create_output_directory(domain)
    print_colored(f"\n[+] Output folder: {out_dir}", Colors.GREEN)

    # Run scan of ports with nmap and live progress (saving raw)
    results_nmap = run_scan_ports(subdomains_per_ip, sudo_password, ports_scan, out_dir)

    # out_dir already was created arriba
    session_tag = os.path.basename(out_dir)
    base_tag = re.sub(r"_\d{2}-\d{2}-\d{4}_\d{2}:\d{2}$", "", session_tag)

    # export results of nmap a CSV and JSON (including status: open/closed)
    headers_t2 = ["target", "port", "service", "version", "status"]
    save_csv(os.path.join(out_dir, f"{base_tag}_table2_nmap_results.csv"), headers_t2, results_nmap)
    save_json(os.path.join(out_dir, f"{base_tag}_table2_nmap_results.json"), results_nmap)

    # --- Folder Consolidated ---
    # Content: CSV, JSON, *_consolidated.xml, *_consolidated.xlsx
    # Excluded: reconsurface_nmap_mediciones.json (calibration, not result)
    consolidated_xml = None
    try:
        consolidated_xml = consolidate_xml_session(out_dir)
    except Exception:
        consolidated_xml = None

    # Consolidated XML is already generated directly in Consolidated
    _build_consolidated_folder(out_dir)

    # Create consolidated Excel (reads from Consolidated, writes there)
    try:
        excel_path = create_excel_consolidated(out_dir)
        if excel_path:
            print_colored(f"[+] Consolidated Excel created: {excel_path}", Colors.GREEN)
        else:
            print_colored(f"[-] Could not create the consolidated Excel", Colors.YELLOW)
    except Exception as e:
        print_colored(f"[-] Error creating the consolidated Excel: {str(e)}", Colors.YELLOW)

    # Show Table 2 with results of nmap (marking the domain main)
    print_table_nmap(results_nmap, domain_base=domain)
    
    # write summary statistical before of return to the menu (if the logger is active)
    global _tee_logger
    if _tee_logger:
        try:
            # Force write from the summary without close the logger
            _tee_logger._write_summary()
        except Exception:
            pass
    
    # pause controlled for the user
    print(f"{RGB_YELLOW}{'═' * 54}")
    try:
        _ensure_terminal_sane()
        input(f"\n{RGB_BLUE}[*] {Colors.WHITE}Press ENTER for return to the menu main...")
    except KeyboardInterrupt:
        pass
    
    # Reset from the terminal after of the pause
    reset_terminal_complete()
    
    return True


def select_ports_interactive():
    """Submenu interactive for select the ports to scan.
    
    Shows a menu with 5 options of scan of ports and allows to the user
    select the type of scan desired. Valid all the inputs from the user
    and handles correctly CONTROL-C in any moment.
    
    Options available:
        1. Specific port (ej: 80)
        2. Range of ports (ej: 80-443)
        3. Group of ports (ej: 80,443,22,21)
        4. Scan mixed (ej: 80-443,22,21)
        5. Scan complete (all the ports: -p-)
    
    Returns:
        str: String of ports for nmap (ej. "-p80", "-p80-443", "-p80,443,22", "-p-")
        bool: False if the user cancels with CONTROL-C or if there is a error.
    
    notes:
        - All the validations include verification of ranges valid (1-65535).
        - handles CONTROL-C correctly in any moment from the process.
        - The inputs from the user are validated before of be accepted.
    """
    print_colored(f"\n{'='*60}", Colors.CYAN)
    print_colored(f"🔍 OPTIONS Of SCAN Of PORTS", Colors.BOLD + Colors.WHITE)
    print_colored(f"{'='*60}", Colors.CYAN)
    
    terminal_width = get_terminal_width()
    menu_width = 52
    margin = (terminal_width - menu_width) // 2
    
    print(f"\n{RGB_GREEN}{' ' * margin}╔{'═' * menu_width}╗{RESET_COLOR}")
    print(f"{RGB_GREEN}{' ' * margin}║{RGB_BLUE}{'PORTS TO SCAN':^52}{RGB_GREEN}║{RESET_COLOR}")
    print(f"{RGB_GREEN}{' ' * margin}╠{'═' * menu_width}╣{RESET_COLOR}")
    print(f"{RGB_GREEN}{' ' * margin}║ {RGB_YELLOW}[1]{RGB_BLUE} 🎯 {Colors.WHITE}{pad_menu_line('Scan specific port', menu_width - 8)}{RGB_GREEN}║{RESET_COLOR}")
    print(f"{RGB_GREEN}{' ' * margin}║ {RGB_YELLOW}[2]{RGB_BLUE} 📊 {Colors.WHITE}{pad_menu_line('Scan a range of ports', menu_width - 8)}{RGB_GREEN}║{RESET_COLOR}")
    print(f"{RGB_GREEN}{' ' * margin}║ {RGB_YELLOW}[3]{RGB_BLUE} 🔢 {Colors.WHITE}{pad_menu_line('Scan a group of ports', menu_width - 8)}{RGB_GREEN}║{RESET_COLOR}")
    print(f"{RGB_GREEN}{' ' * margin}║ {RGB_YELLOW}[4]{RGB_BLUE} 🔀 {Colors.WHITE}{pad_menu_line('Mixed scan (range + group)', menu_width - 8)}{RGB_GREEN}║{RESET_COLOR}")
    print(f"{RGB_GREEN}{' ' * margin}║ {RGB_YELLOW}[5]{RGB_BLUE} 🌐 {Colors.WHITE}{pad_menu_line('Full scan (all ports)', menu_width - 8)}{RGB_GREEN}║{RESET_COLOR}")
    print(f"{RGB_GREEN}{' ' * margin}╚{'═' * menu_width}╝{RESET_COLOR}")
    
    while True:
        try:
            option_ports = input(f"\n{RGB_BLUE}[?] {Colors.WHITE}Select an option {RGB_YELLOW}(1-5){Colors.WHITE}: ").strip()
            
            if option_ports == "1":
                # Specific port
                while True:
                    try:
                        port = input(f"\n{RGB_BLUE}[?] {Colors.WHITE}Enter the port to scan (1-65535): ").strip()
                        port_int = int(port)
                        if 1 <= port_int <= 65535:
                            return f"-p{port_int}"
                        else:
                            print_colored(f"[-] Port must be between 1 and 65535", Colors.RED)
                    except ValueError:
                        print_colored(f"[-] Enter a valid number", Colors.RED)
            
            elif option_ports == "2":
                # Range of ports
                print_colored(f"\n[*] Enter a range of ports (example: 80-443)", Colors.BLUE)
                
                while True:
                    try:
                        range_input = input(f"\n{RGB_BLUE}[?] {Colors.WHITE}Range of ports: ").strip()
                        
                        if not range_input:
                            print_colored(f"[-] Cannot be empty", Colors.RED)
                            continue
                        
                        # Validate format of range (only numbers and hyphen)
                        if not re.match(r'^\d+-\d+$', range_input):
                            print_colored(f"[-] Invalid format. Use: 80-443", Colors.RED)
                            continue
                        
                        try:
                            start, fin = range_input.split('-')
                            start_int = int(start)
                            fin_int = int(fin)
                            
                            if start_int > 65535:
                                print_colored(f"[-] Port initial {start_int} exceeds the max (65535)", Colors.RED)
                                continue
                            elif fin_int > 65535:
                                print_colored(f"[-] Port final {fin_int} exceeds the max (65535)", Colors.RED)
                                continue
                            elif start_int < 1:
                                print_colored(f"[-] Port initial {start_int} must be greater than 0", Colors.RED)
                                continue
                            elif fin_int < 1:
                                print_colored(f"[-] Port final {fin_int} must be greater than 0", Colors.RED)
                                continue
                            elif start_int > fin_int:
                                print_colored(f"[-] Port initial {start_int} cannot be greater than the final {fin_int}", Colors.RED)
                                continue
                            
                            return f"-p{range_input}"
                            
                        except ValueError:
                            print_colored(f"[-] Format of invalid range: {range_input}", Colors.RED)
                            
                    except KeyboardInterrupt:
                        print_colored(f"\n[*] Scan cancelled for the user", Colors.RED)
                        return False
            
            elif option_ports == "3":
                # Group of ports (separated for commas)
                print_colored(f"\n[*] Enter ports separated for commas (example: 80,443,22,21)", Colors.BLUE)
                
                while True:
                    try:
                        group_input = input(f"\n{RGB_BLUE}[?] {Colors.WHITE}Group of ports: ").strip()
                        
                        if not group_input:
                            print_colored(f"[-] Cannot be empty", Colors.RED)
                            continue
                        
                        # Validate format basic (only numbers and commas)
                        if not re.match(r'^[\d,\s]+$', group_input):
                            print_colored(f"[-] Only is allow numbers and commas", Colors.RED)
                            continue
                        
                        # Validate ports individual
                        ports_valid = True
                        error_message = ""
                        ports_list = group_input.replace(' ', '').split(',')
                        
                        for port_str in ports_list:
                            try:
                                port_int = int(port_str)
                                if port_int > 65535:
                                    error_message = f"Port {port_int} exceeds the max (65535)"
                                    ports_valid = False
                                    break
                                elif port_int < 1:
                                    error_message = f"Port {port_int} must be greater than 0"
                                    ports_valid = False
                                    break
                                    
                            except ValueError:
                                error_message = f"Invalid port: {port_str}"
                                ports_valid = False
                                break
                        
                        if ports_valid:
                            return f"-p{group_input.replace(' ', '')}"
                        else:
                            print_colored(f"[-] {error_message}", Colors.RED)
                            
                    except KeyboardInterrupt:
                        print_colored(f"\n[*] Scan cancelled for the user", Colors.RED)
                        return False
            
            elif option_ports == "4":
                # Scan mixed (range + group)
                print_colored(f"\n[*] Scan mixed: combines ranges and groups of ports", Colors.BLUE)
                print_colored(f"[*] examples:", Colors.WHITE)
                print_colored(f"  • 80-443,22,21 (range 80-443 + ports 22,21)", Colors.WHITE)
                print_colored(f"  • 80,443,8080-8090,22 (ports 80,443 + range 8080-8090 + port 22)", Colors.WHITE)
                print_colored(f"  • 1-1000,8080,8443,9000-9010 (range 1-1000 + ports 8080,8443 + range 9000-9010)", Colors.WHITE)
                
                while True:
                    try:
                        mixed_input = input(f"\n{RGB_BLUE}[?] {Colors.WHITE}Ports mixed: ").strip()
                        
                        if not mixed_input:
                            print_colored(f"[-] Cannot be empty", Colors.RED)
                            continue
                        
                        # Validate format basic (numbers, commas, hyphens)
                        if not re.match(r'^[\d,\-\s]+$', mixed_input):
                            print_colored(f"[-] Only is allow numbers, commas and hyphens", Colors.RED)
                            continue
                        
                        # Validate ports individual and ranges
                        ports_valid = True
                        error_message = ""
                        parts = mixed_input.replace(' ', '').split(',')
                        
                        for part in parts:
                            if '-' in part:
                                # Is a range
                                try:
                                    start, fin = part.split('-')
                                    start_int = int(start)
                                    fin_int = int(fin)
                                    
                                    if start_int > 65535:
                                        error_message = f"Port initial {start_int} exceeds the max (65535)"
                                        ports_valid = False
                                        break
                                    elif fin_int > 65535:
                                        error_message = f"Port final {fin_int} exceeds the max (65535)"
                                        ports_valid = False
                                        break
                                    elif start_int < 1:
                                        error_message = f"Port initial {start_int} must be greater than 0"
                                        ports_valid = False
                                        break
                                    elif fin_int < 1:
                                        error_message = f"Port final {fin_int} must be greater than 0"
                                        ports_valid = False
                                        break
                                    elif start_int > fin_int:
                                        error_message = f"Port initial {start_int} cannot be greater than the final {fin_int}"
                                        ports_valid = False
                                        break
                                        
                                except ValueError:
                                    error_message = f"Format of invalid range: {part}"
                                    ports_valid = False
                                    break
                            else:
                                # Is a port individual
                                try:
                                    port_int = int(part)
                                    if port_int > 65535:
                                        error_message = f"Port {port_int} exceeds the max (65535)"
                                        ports_valid = False
                                        break
                                    elif port_int < 1:
                                        error_message = f"Port {port_int} must be greater than 0"
                                        ports_valid = False
                                        break
                                        
                                except ValueError:
                                    error_message = f"Invalid port: {part}"
                                    ports_valid = False
                                    break
                        
                        if ports_valid:
                            return f"-p{mixed_input.replace(' ', '')}"
                        else:
                            print_colored(f"[-] {error_message}", Colors.RED)
                            
                    except KeyboardInterrupt:
                        print_colored(f"\n[*] Scan cancelled for the user", Colors.RED)
                        return False
            
            elif option_ports == "5":
                # All the ports
                return "-p-"
            
            else:
                print_colored(f"[-] Option not valid. Select 1, 2, 3, 4 or 5", Colors.RED)
                
        except KeyboardInterrupt:
            print_colored(f"\n[*] Scan cancelled for the user", Colors.RED)
            return False


def analyze_url_site_with_ports(domain):
    """Option 3: Analyze URL/Site with scan of ports (without OSINT of subdomains).
    
    Is function is designed for scan ports of a unique domain or URL without
    perform detection of subdomains. Is useful when is wants analyze quickly
    a specific site without go through for all the process of OSINT.
    
    flow of execution:
        1. Verifies dependencies and existence DNS from the domain/URL
        2. Normalizes the input (extracts host of complete URLs if is necessary)
        3. Shows submenu interactive for select type of scan of ports
        4. Runs the scan nmap only about the domain normalized
        5. exports Table 2 (results nmap) in CSV, JSON, XML and Excel
        6. Shows table visual with results
    
    Args:
        domain (str): Domain or URL to analyze. Can be:
                      - Domain simple: "example.com"
                      - complete URL: "https://example.com/path" (is extracts the host)
    
    Returns:
        True: Analysis completed successfully.
        "domain_error": Domain/URL does not exist or does not resolve via DNS (the menu increments attempts).
        "abort": Sudo failure, user cancelled, or dependencies missing (returns to the menu without increment).
    
    notes:
        - Not performs detection of subdomains (not generates Table 1).
        - Allows select the type of scan of ports (equal that option 2).
        - CONTROL-C during sudo: returns to the menu without show "Domain/URL wrong".
        - exports only Table 2 (results of scan of ports).
    """
    # Verify dependencies
    if not verify_dependencies():
        print_colored("[-] Cannot continue the verifications without the dependencies", Colors.RED)
        return "abort"

    # Verify that the domain exists BEFORE from the scan
    print_colored(f"\n[*] Verifying existence from the domain/URL {domain}...", Colors.BLUE)
    if not verify_dns_existence(domain):
        print_colored(f"\n❌ ERROR: Domain {domain} not found", Colors.RED)
        print_colored(f"💡 Try again with a domain/valid URL", Colors.YELLOW)
        return "domain_error"

    print_colored(f"✅ Domain/URL {domain} verified and exists", Colors.GREEN)

    # Map min: a unique target
    subdomains_per_ip = {domain: [domain]}

    # Submenu of selection of ports (equal that the option 2)
    ports_scan = select_ports_interactive()
    if not ports_scan:
        return "abort"  # User cancelled, not a domain error

    # reuse the flow common of scan of ports
    result = run_flow_scan_ports(domain, subdomains_per_ip, ports_scan)
    return result if result else "abort"  # sudo/cancel = abort, not domain_error

def clear_screen():
    """Clears the screen of way cross-platform and resets the terminal"""
    
    # Clear screen
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # Reset complete and aggressive from the terminal
    try:
        # Flush all the buffers
        sys.stdout.flush()
        sys.stderr.flush()
        
        # Reset complete of escape sequences
        print('\033[0m\033[?25h\033[?7h\033[?1l\033[?1000l', end='', flush=True)
        
        # Restore configuration from the terminal
        if hasattr(sys.stdin, 'fileno'):
            fd = sys.stdin.fileno()
            try:
                import termios
                # Save configuration current
                old_settings = termios.tcgetattr(fd)
                # Discard any buffered keystrokes before restoring
                termios.tcflush(fd, termios.TCIFLUSH)
                # Restore configuration original
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            except Exception:
                pass
        
        # Force reset additional
        print('\033c', end='', flush=True)
        
    except Exception:
        # Fallback: reset basic
        print('\033[0m', end='', flush=True)

def reset_terminal_complete():
    """Reset complete and aggressive from the terminal for fix input invisible"""
    
    try:
        # 1. Flush all the buffers
        sys.stdout.flush()
        sys.stderr.flush()
        
        # 2. Reset of escape sequences
        print('\033[0m\033[?25h\033[?7h\033[?1l\033[?1000l', end='', flush=True)
        
        # 3. Reset from the terminal using stty
        try:
            subprocess.run(['stty', 'sane'], check=False, capture_output=True)
        except Exception:
            pass
        
        # 4. Restore configuration from the terminal
        if hasattr(sys.stdin, 'fileno'):
            fd = sys.stdin.fileno()
            try:
                import termios
                # Get configuration for default
                default_settings = termios.tcgetattr(fd)
                # Discard any buffered keystrokes before restoring
                termios.tcflush(fd, termios.TCIFLUSH)
                # Restore configuration for default
                termios.tcsetattr(fd, termios.TCSADRAIN, default_settings)
            except Exception:
                pass
        
        # 5. Reset additional with escape sequences
        print('\033c', end='', flush=True)
        
        # 6. Force new line and reset final
        print('\n\033[0m', end='', flush=True)
        
    except Exception:
        # Fallback: reset basic
        try:
            print('\033[0m\033[?25h', end='', flush=True)
        except Exception:
            pass

def menu():
    """Main application menu.
    
    Handles return values from analyze_*_with_ports:
    - True: success, clear screen and continue
    - "domain_error": invalid domain/URL, increment attempts
    - "abort": sudo failure or user cancelled, return to the menu without incrementing
    """
    while True:
        # Show ASCII art
        show_ascii_art()
        
        # Menu of options centered dynamically
        terminal_width = get_terminal_width()
        menu_width = 52
        margin = (terminal_width - menu_width) // 2
        
        print(f"\n{RGB_GREEN}{' ' * margin}╔{'═' * menu_width}╗{RESET_COLOR}")
        print(f"{RGB_GREEN}{' ' * margin}║{RGB_BLUE}{'RECONSURFACE - ATTACK SURFACE EXPLORATION':^52}{RGB_GREEN}║{RESET_COLOR}")
        print(f"{RGB_GREEN}{' ' * margin}║{Colors.WHITE}{'Version 2.8':^52}{RGB_GREEN}║{RESET_COLOR}")
        print(f"{RGB_GREEN}{' ' * margin}╠{'═' * menu_width}╣{RESET_COLOR}")
        print(f"{RGB_GREEN}{' ' * margin}║ {RGB_YELLOW}[1]{RGB_BLUE} 🔍 {Colors.WHITE}{pad_menu_line('Analyze domain', menu_width - 8)}{RGB_GREEN}║{RESET_COLOR}")
        print(f"{RGB_GREEN}{' ' * margin}║ {RGB_YELLOW}[2]{RGB_BLUE} 🔍 {Colors.WHITE}{pad_menu_line('Analyze domain with ports', menu_width - 8)}{RGB_GREEN}║{RESET_COLOR}")
        print(f"{RGB_GREEN}{' ' * margin}║ {RGB_YELLOW}[3]{RGB_BLUE} 🔍 {Colors.WHITE}{pad_menu_line('Analyze URL/Site with ports', menu_width - 8)}{RGB_GREEN}║{RESET_COLOR}")
        print(f"{RGB_GREEN}{' ' * margin}║ {RGB_YELLOW}[Q]{RGB_BLUE} ❌ {Colors.WHITE}{pad_menu_line('Exit', menu_width - 8)}{RGB_GREEN}║{RESET_COLOR}")
        print(f"{RGB_GREEN}{' ' * margin}╚{'═' * menu_width}╝{RESET_COLOR}")
        
        import signal
        _handler_previo = signal.signal(signal.SIGINT, signal.SIG_DFL)
        try:
            option = input(f"\n{RGB_BLUE}[?] {Colors.WHITE}Select an option {RGB_YELLOW}(1-3 or Q){Colors.WHITE}: ").strip()
        except KeyboardInterrupt:
            signal.signal(signal.SIGINT, _handler_previo)
            print_colored(f"\n[*] Input cancelled. Returning to the menu...", Colors.BLUE)
            clear_screen()
            continue
        finally:
            signal.signal(signal.SIGINT, _handler_previo)
        
        if option == "1":
            attempts = 0
            max_attempts = 3
            
            while attempts < max_attempts:
                _handler_previo = signal.signal(signal.SIGINT, signal.SIG_DFL)
                try:
                    domain = input(f"\n{RGB_BLUE}[?] {Colors.WHITE}Enter the domain to analyze: ").strip()
                except KeyboardInterrupt:
                    signal.signal(signal.SIGINT, _handler_previo)
                    print_colored(f"\n[*] Input cancelled. Returning to the menu...", Colors.BLUE)
                    clear_screen()
                    break
                finally:
                    signal.signal(signal.SIGINT, _handler_previo)
                if domain:
                    result = analyze_domain(domain)
                    if result:
                        # If result is True, ENTER was already requested inside the function
                        clear_screen()
                        break
                    else:
                        # Domain not found, increment attempts
                        attempts += 1
                        if attempts < max_attempts:
                            print_colored(f"\n❌ Domain wrong, try again ({attempts}/{max_attempts})", Colors.RED)
                        else:
                            print_colored(f"\n❌ Domain wrong, ran out of attempts ({max_attempts}/{max_attempts})", Colors.RED)
                            print_colored(f"\n[*] Returning to the menu main...", Colors.BLUE)
                            clear_screen()
                            break
                else:
                    print_colored(f"\n{RGB_RED}[!] Please enter a valid domain.", Colors.RED)
                    print_colored(f"\n[*] Try of again...", Colors.BLUE)
                    clear_screen()
                
        elif option == "2":
            attempts = 0
            max_attempts = 3
            
            while attempts < max_attempts:
                _handler_previo = signal.signal(signal.SIGINT, signal.SIG_DFL)
                try:
                    domain = input(f"\n{RGB_BLUE}[?] {Colors.WHITE}Enter the domain to analyze with ports: ").strip()
                except KeyboardInterrupt:
                    signal.signal(signal.SIGINT, _handler_previo)
                    print_colored(f"\n[*] Input cancelled. Returning to the menu...", Colors.BLUE)
                    clear_screen()
                    break
                finally:
                    signal.signal(signal.SIGINT, _handler_previo)
                if domain:
                    result = analyze_domain_with_ports(domain)
                    if result is True:
                        # If result is True, ENTER was already requested inside the function
                        clear_screen()
                        break
                    elif result == "domain_error":
                        # Domain not found, increment attempts
                        attempts += 1
                        if attempts < max_attempts:
                            print_colored(f"\n❌ Domain wrong, try again ({attempts}/{max_attempts})", Colors.RED)
                        else:
                            print_colored(f"\n❌ Domain wrong, ran out of attempts ({max_attempts}/{max_attempts})", Colors.RED)
                            print_colored(f"\n[*] Returning to the menu main...", Colors.BLUE)
                            clear_screen()
                            break
                    else:
                        # abort: sudo failure, user cancelled, etc. - not a domain error
                        print_colored(f"\n[*] Returning to the menu main...", Colors.BLUE)
                        try:
                            _ensure_terminal_sane()
                            input(f"\n{RGB_BLUE}[*] {Colors.WHITE}Press ENTER for continue...")
                        except KeyboardInterrupt:
                            pass
                        clear_screen()
                        break
                else:
                    print_colored(f"\n{RGB_RED}[!] Please enter a valid domain.", Colors.RED)
                    print_colored(f"\n[*] Try of again...", Colors.BLUE)
                    clear_screen()
        
        elif option == "3":
            attempts = 0
            max_attempts = 3
            
            while attempts < max_attempts:
                _handler_previo = signal.signal(signal.SIGINT, signal.SIG_DFL)
                try:
                    user_input = input(f"\n{RGB_BLUE}[?] {Colors.WHITE}Enter the URL or site to analyze with ports: ").strip()
                except KeyboardInterrupt:
                    signal.signal(signal.SIGINT, _handler_previo)
                    print_colored(f"\n[*] Input cancelled. Returning to the menu...", Colors.BLUE)
                    clear_screen()
                    break
                finally:
                    signal.signal(signal.SIGINT, _handler_previo)
                if user_input:
                    # Normalize input: if comes as URL, extract host; if comes as domain, use as is
                    target = user_input.strip()
                    try:
                        if "://" in target:
                            parsed = urlparse(target)
                            host = parsed.netloc or parsed.path
                            target_normalized = (host or "").split("/")[0].split(":")[0]
                        else:
                            target_normalized = target.split("/")[0].split(":")[0]
                    except Exception:
                        target_normalized = target
                    
                    if not target_normalized:
                        print_colored(f"\n{RGB_RED}[!] Could not interpret the URL/site provided.", Colors.RED)
                        attempts += 1
                        if attempts < max_attempts:
                            print_colored(f"\n❌ Try again ({attempts}/{max_attempts})", Colors.RED)
                            clear_screen()
                            continue
                        else:
                            print_colored(f"\n❌ Ran out of attempts ({max_attempts}/{max_attempts})", Colors.RED)
                            print_colored(f"\n[*] Returning to the menu main...", Colors.BLUE)
                            clear_screen()
                            break
                    
                    result = analyze_url_site_with_ports(target_normalized)
                    if result is True:
                        # If result is True, ENTER was already requested inside the function
                        clear_screen()
                        break
                    elif result == "domain_error":
                        # Domain/URL not found, increment attempts
                        attempts += 1
                        if attempts < max_attempts:
                            print_colored(f"\n❌ Domain/URL wrong, try again ({attempts}/{max_attempts})", Colors.RED)
                        else:
                            print_colored(f"\n❌ Domain/URL wrong, ran out of attempts ({max_attempts}/{max_attempts})", Colors.RED)
                            print_colored(f"\n[*] Returning to the menu main...", Colors.BLUE)
                            clear_screen()
                            break
                    else:
                        # abort: sudo failure, user cancelled, etc. - not a domain error
                        print_colored(f"\n[*] Returning to the menu main...", Colors.BLUE)
                        try:
                            _ensure_terminal_sane()
                            input(f"\n{RGB_BLUE}[*] {Colors.WHITE}Press ENTER for continue...")
                        except KeyboardInterrupt:
                            pass
                        clear_screen()
                        break
                else:
                    print_colored(f"\n{RGB_RED}[!] Please enter a valid URL or site.", Colors.RED)
                    print_colored(f"\n[*] Try of again...", Colors.BLUE)
                    clear_screen()
                    
        elif option.upper() == "Q":
            # Exit fast: restore terminal and exit without process logger
            global _tee_logger
            # Restore stdout/stderr immediately
            try:
                if _tee_logger:
                    sys.stdout = _tee_logger.original_stdout
                    sys.stderr = _tee_logger.original_stderr
            except Exception:
                pass
            # Reset from the terminal
            try:
                print('\033[0m\033[?25h', end='', flush=True)
                sys.stdout.flush()
                sys.stderr.flush()
                # try stty sane
                subprocess.run(['stty', 'sane'], check=False, capture_output=True, timeout=1)
            except Exception:
                pass
            print(f"\n{RGB_BLUE}[*] {Colors.WHITE}Thanks for use ReconSurface")
            print(f"{RGB_YELLOW}{'═' * 54}")
            sys.stdout.flush()
            sys.stderr.flush()
            # close logger of way fast (without summary)
            if _tee_logger and _tee_logger.log_file:
                try:
                    _tee_logger.log_file.close()
                except Exception:
                    pass
            # Exit directly
            os._exit(0)
            
        else:
            print_colored(f"\n{RGB_RED}[!] Invalid option. Please select 1-3 or Q.", Colors.RED)
            print(f"{RGB_YELLOW}{'═' * 54}")
            _ensure_terminal_sane()
            input(f"\n{RGB_BLUE}[*] {Colors.WHITE}Press ENTER for continue...")
            clear_screen()

def main():
    """Function main from the program"""
    import signal
    global _tee_logger
    
    # Initialize system of logging complete
    try:
        # Create logger with name automatic based in timestamp
        _tee_logger = TeeLogger()
        _tee_logger.start()
        log_path = _tee_logger.get_log_path()
        # Show informational message (only once at startup)
        print_colored(f"\n[INFO] 📝 capturing all the execution in: {log_path}", Colors.CYAN)
        print_colored(f"[INFO] All the updates of progress is save with timestamps\n", Colors.CYAN)
    except Exception as e:
        # If the logger fails, continue without it but notify
        print_colored(f"\n[WARNING] Could not initialize the logging system: {e}", Colors.YELLOW)
        print_colored(f"[WARNING] Continuando without captures of logs...\n", Colors.YELLOW)
        _tee_logger = None
    
    def signal_handler(signum, frame):
        """handles CONTROL-C (SIGINT). Restores the terminal before exiting to avoid it being blocked.
        note: During getpass (sudo), SIG_DFL is used temporarily so that KeyboardInterrupt
        allows returning to the menu instead of exiting."""
        if signum == signal.SIGINT:  # Only CONTROL-C
            # End process nmap if is in execution (start_new_session lo isolates, there is that kill it explicitly)
            global _nmap_process_current
            if _nmap_process_current is not None:
                _kill_nmap_process_group(_nmap_process_current)
                _nmap_process_current = None
            # CRITICAL: Restore the terminal before exiting (getpass leaves the terminal in raw mode)
            try:
                subprocess.run(['stty', 'sane'], check=False, capture_output=True, timeout=1)
            except Exception:
                pass
            try:
                print('\033[0m\033[?25h', end='', flush=True)
            except Exception:
                pass
            # Stop the logger before exiting
            if _tee_logger:
                try:
                    _tee_logger.stop()
                except Exception:
                    pass
            print(f"\n\n{RGB_BLUE}[*] {Colors.WHITE}program interrupted for the user")
            print(f"{RGB_YELLOW}{'═' * 54}")
            try:
                os._exit(0)
            except Exception:
                sys.exit(0)
        # Ignore CONTROL-Z (SIGTSTP)
        elif signum == signal.SIGTSTP:
            pass
    
    # configure handlers of signals
    signal.signal(signal.SIGINT, signal_handler)   # CONTROL-C
    signal.signal(signal.SIGTSTP, signal_handler)  # CONTROL-Z (ignore)
    
    try:
        menu()
    except KeyboardInterrupt:
        # Only runs if not handled in signal_handler
        if _tee_logger:
            try:
                _tee_logger.stop()
            except Exception:
                pass
        print(f"\n\n{RGB_BLUE}[*] {Colors.WHITE}program interrupted for the user")
        print(f"{RGB_YELLOW}{'═' * 54}")
        # Reset complete from the terminal
        reset_terminal_complete()
        try:
            os._exit(0)
        except Exception:
            sys.exit(0)
    except Exception as e:
        if _tee_logger:
            try:
                _tee_logger.stop()
            except Exception:
                pass
        print_colored(f"\n{RGB_RED}[!] Error unexpected: {str(e)}", Colors.RED)
        # Reset complete from the terminal
        reset_terminal_complete()
        sys.exit(1)
    finally:
        # Stop the logger before exiting
        global _exit_with_q
        if _tee_logger:
            try:
                _tee_logger.stop()
            except Exception:
                pass
        # Terminal reset: soft if exited with Q, complete in other cases
        try:
            if _exit_with_q:
                # Reset soft for not interfere with normal exit
                print('\033[0m\033[?25h', end='', flush=True)
            else:
                # Reset complete guaranteed from the terminal
                print('\033[0m\033[?25h\033[?7h\033[?1l\033[?1000l\033c', end='', flush=True)
        except Exception:
            print('\033[0m', end='', flush=True)

if __name__ == "__main__":
    main()