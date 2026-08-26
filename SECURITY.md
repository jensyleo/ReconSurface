# Security Policy

## Overview

ReconSurface is an attack-surface reconnaissance tool for domains and hosts (DNS analysis, subdomain discovery via brute force and 14 free OSINT sources, WHOIS, SSL certificate checks, HTTP header inspection, and optional Nmap port scanning). It is a local CLI tool intended for use only against domains and hosts you own or are explicitly authorized to test.

## Threat Model

ReconSurface runs as a local Python process under the invoking user's privileges. Assumptions:

- **No inbound network exposure**: the tool only makes outbound queries (DNS, WHOIS, HTTP, OSINT APIs) and optionally spawns Nmap; it does not listen on any port.
- **Untrusted target, trusted operator**: the domain/host being scanned is untrusted input from the operator's perspective, but the operator running the tool is trusted.
- **Third-party response data is untrusted**: DNS records, WHOIS/RDAP fields, HTTP headers, and OSINT source responses can contain attacker-influenced text (e.g., a subdomain or WHOIS field crafted to look like a shell command or formula).

## Security Practices

### Nmap Invocation

Nmap is invoked via `subprocess` with an argument list, not a shell string, so target hosts/ports cannot break out into additional shell commands.

### Export Files (CSV / JSON / XML / Excel)

Scan results (subdomains, WHOIS fields, HTTP headers) are written to CSV, JSON, XML, and Excel exports. Because these fields originate from third-party/attacker-influenced sources, values are treated as text/data, not executed — if you open exports in a spreadsheet application, disable automatic formula evaluation for untrusted cells as a general precaution.

### Responsible Use

- Only run ReconSurface against assets you own or have written authorization to assess.
- Unauthorized scanning of third-party infrastructure may violate computer-crime laws in your jurisdiction (e.g., the CFAA in the US) and the acceptable-use policies of the OSINT sources it queries.
- Nmap port scanning can trigger intrusion-detection alerts on networks you do not control — use only within an authorized scope.

## Scope and Limitations

### What is NOT protected

- **Malicious OSINT source responses**: a compromised or malicious third-party OSINT source could return crafted data; ReconSurface does not independently verify source authenticity.
- **Nmap engine vulnerabilities**: security of the scan itself is delegated to the installed Nmap binary.
- **DoS resistance**: the tool is not hardened against adversarial responses designed to exhaust memory or time (e.g., extremely large DNS/WHOIS payloads).

## Reporting a Vulnerability

If you discover a security vulnerability in ReconSurface itself (e.g., unsafe handling of scan output, command injection in the Nmap invocation, insecure export file handling), please report it responsibly by emailing **jensyleo@live.com** instead of opening a public issue. Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive an acknowledgment and the issue will be investigated and addressed promptly.

## Supported Versions

Only the latest released version (currently v2.8) is actively supported with security fixes.
