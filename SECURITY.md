# Security Policy

## Overview

ReconSurface is an attack-surface reconnaissance tool for domains and hosts (DNS analysis, subdomain discovery, WHOIS, SSL certificate checks, HTTP header inspection, and optional Nmap port scanning). It is intended for use only against domains and hosts you own or are explicitly authorized to test.

## Responsible Use

- Only run ReconSurface against assets you own or have written authorization to assess.
- Unauthorized scanning of third-party infrastructure may violate computer-crime laws in your jurisdiction (e.g., CFAA in the US) and the acceptable-use policies of the OSINT sources it queries.
- Nmap port scanning in particular can trigger intrusion-detection alerts on networks you do not control — use only within an authorized scope.

## Reporting a Vulnerability

If you discover a security vulnerability in ReconSurface itself (e.g., unsafe handling of scan output, command injection in the Nmap invocation, insecure export file handling), please report it responsibly by sending details to **jensyleo@live.com** instead of using the public issue tracker. Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

Reports will be reviewed and addressed promptly.

## Supported Versions

Only the latest released version is actively supported with security fixes.
