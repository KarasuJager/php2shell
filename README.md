# php2shell

**PHP2Shell Vulnerability Assessment Tool** — CVE-2026-109618 / CVE-2026-109619

Assessment-only fingerprinting tool for the PHP2Shell pre-authentication RCE vulnerability chain. Detects vulnerable PHP versions, server configuration, and attack surface exposure. Generates bug bounty-ready reports.

> **This tool does NOT exploit or trigger the vulnerability.** It performs passive/semi-passive checks via standard HTTP requests.

## What it does

1. **PHP version fingerprinting** — Extracts version from `X-Powered-By`, `Server` headers, and response body
2. **Handler detection** — Identifies mod_php (highest risk) vs PHP-FPM vs LiteSpeed
3. **OS detection** — Extracts distribution info from Server header
4. **session.upload_progress check** — Tests if the attack surface feature is enabled (standard POST, not an exploit trigger)
5. **Version analysis** — Matches against the full affected version matrix
6. **Report generation** — Markdown reports with CVSS, evidence, remediation, and references

## Affected versions

| Branch | Vulnerable | Fixed in |
|--------|-----------|----------|
| PHP 8.5 | < 8.5.12 | 8.5.12 |
| PHP 8.4 | < 8.4.27 | 8.4.27 |
| PHP 8.3 | < 8.3.36 | 8.3.36 |
| PHP 8.2 | < 8.2.35 | 8.2.35 |
| PHP 8.1 | ALL | None (EOL) |
| PHP 8.0 | ALL | None (EOL) |
| PHP 7.x | ALL | None (EOL) |
| PHP 5.x | ALL | None (EOL) |

## Usage

```bash
# Single target
python3 php2shell_assess.py -u https://target.com

# With report generation
python3 php2shell_assess.py -u https://target.com --report

# Batch scan from file
python3 php2shell_assess.py -f targets.txt -o reports/

# Manual version (when expose_php=Off)
python3 php2shell_assess.py -u target.com --version 8.4.26

# JSON output
python3 php2shell_assess.py -u https://target.com --json

# Skip upload_progress check
python3 php2shell_assess.py -u https://target.com --no-upload-check
```

## Requirements

- Python 3.6+
- No external dependencies (stdlib only)

## Responsible disclosure

This tool is intended for authorized security testing only (bug bounty programs, penetration tests with written authorization). All HTTP traffic includes researcher identification headers.

## References

- [CVE-2026-109618](https://nvd.nist.gov/vuln/detail/CVE-2026-109618) — OOM Hash Table Corruption (UAF)
- [CVE-2026-109619](https://nvd.nist.gov/vuln/detail/CVE-2026-109619) — Stale Global State (UAF)
- Patches released October 21, 2026

## Author

[@KarasuJager](https://github.com/KarasuJager)
