#!/usr/bin/env python3
"""
php2shell_assess.py — PHP2Shell Vulnerability Assessment Tool
CVE-2026-109618 & CVE-2026-109619

Assessment-only: fingerprints PHP version, detects server configuration,
checks attack surface features, and generates bug bounty reports.
Does NOT trigger, exploit, or demonstrate the vulnerability.

Usage:
  python3 php2shell_assess.py -u https://target.com
  python3 php2shell_assess.py -u https://target.com --report
  python3 php2shell_assess.py -f targets.txt -o reports/
  python3 php2shell_assess.py -u target.com --version 8.4.26

Researcher: Manuel_Miguel (Bugcrowd)
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import socket
import ssl
import sys
import time
import urllib.parse

# ─── Version Matrix (patched Oct 21 2026) ─────────────────────────
FIXED = {
    "8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12,
}
EOL = {
    "5.0","5.1","5.2","5.3","5.4","5.5","5.6",
    "7.0","7.1","7.2","7.3","7.4",
    "8.0","8.1",
}

HANDLE   = "Manuel_Miguel"
UA       = f"{HANDLE}-BugBounty-Assessment/1.0"
CVES     = "CVE-2026-109618 / CVE-2026-109619"
CVSS     = "9.2"
CVSS_VEC = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


# ═══════════════════════════════════════════════════════════════════
#  HTTP helpers
# ═══════════════════════════════════════════════════════════════════
def _connect(host: str, port: int, scheme: str, timeout: float = 10):
    s = socket.create_connection((host, port), timeout=timeout)
    if scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=host)
    return s


def http_req(url: str, method="GET", extra_headers=None, body=None, timeout=10):
    u = urllib.parse.urlsplit(url if "://" in url else "https://" + url)
    host = u.hostname or ""
    port = u.port or (443 if u.scheme == "https" else 80)
    path = (u.path or "/") + (f"?{u.query}" if u.query else "")

    hdrs = (f"{method} {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {UA}\r\n"
            f"X-Bug-Bounty: {HANDLE}\r\n"
            f"Connection: close\r\n")
    if extra_headers:
        for k, v in extra_headers.items():
            hdrs += f"{k}: {v}\r\n"
    if body:
        hdrs += f"Content-Length: {len(body)}\r\n"
    hdrs += "\r\n"

    raw = hdrs.encode()
    if body:
        raw += body if isinstance(body, bytes) else body.encode()

    s = _connect(host, port, u.scheme or "https", timeout)
    s.sendall(raw)
    data = b""
    try:
        while len(data) < 131072:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    except (socket.timeout, OSError):
        pass
    s.close()

    head, _, resp_body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status = 0
    m = re.search(rb"\d{3}", lines[0] if lines else b"")
    if m:
        status = int(m.group())
    headers = {}
    for ln in lines[1:]:
        if b":" in ln:
            k, _, v = ln.partition(b":")
            headers.setdefault(k.decode("latin-1").strip().lower(),
                               v.decode("latin-1").strip())
    return status, headers, resp_body


# ═══════════════════════════════════════════════════════════════════
#  Fingerprinting
# ═══════════════════════════════════════════════════════════════════
def fingerprint_version(url: str):
    """PHP version from headers/body.  Returns (version|None, server, x-powered-by)."""
    try:
        _, hdrs, body = http_req(url)
    except Exception as exc:
        return None, "", "", str(exc)

    server  = hdrs.get("server", "")
    powered = hdrs.get("x-powered-by", "")
    version = None
    source  = ""

    m = re.search(r"PHP/(\d+\.\d+\.\d+)", powered)
    if m:
        version, source = m.group(1), "X-Powered-By header"
    if not version:
        m = re.search(rb"PHP/(\d+\.\d+\.\d+)", body)
        if m:
            version, source = m.group(1).decode(), "response body"

    return version, server, powered, source


def detect_handler(server: str):
    s = server.lower()
    if "apache" in s:
        return "mod_php (probable)", "HIGHEST — attack runs before app code"
    if "nginx" in s:
        return "PHP-FPM (probable)", "HIGH — different UAF path"
    if "litespeed" in s:
        return "LiteSpeed SAPI", "HIGH"
    return "unknown", "UNDETERMINED"


def detect_distro(server: str):
    s = server.lower()
    for name in ("debian","ubuntu","fedora","centos","red hat",
                 "alpine","amazon","suse","arch"):
        if name in s:
            return name.title()
    for codename in ("bookworm","bullseye","buster","trixie","stretch"):
        if codename in s:
            return f"Debian ({codename})"
    return None


def check_upload_progress(url: str):
    """Non-invasive check: does a normal multipart POST get a PHPSESSID cookie?

    session.upload_progress is a documented PHP feature (default=On since 5.4).
    This sends a tiny standard form — no OOM, no corruption, no exploit trigger.
    """
    boundary = "----Assess7e3a9b"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"assess\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="f"; filename="t.txt"\r\n'
        f"Content-Type: text/plain\r\n\r\nassess\r\n"
        f"--{boundary}--\r\n"
    ).encode()

    try:
        code, hdrs, _ = http_req(url, method="POST", extra_headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Cookie": f"PHPSESSID=assess_{HANDLE.lower()}",
        }, body=body)
    except Exception as exc:
        return None, str(exc)

    has = "PHPSESSID" in hdrs.get("set-cookie", "")
    return has, f"HTTP {code}, Set-Cookie: {'PHPSESSID present' if has else 'no PHPSESSID'}"


# ═══════════════════════════════════════════════════════════════════
#  Version analysis
# ═══════════════════════════════════════════════════════════════════
def analyze_version(ver: str):
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", ver or "")
    if not m:
        return {"status": "UNKNOWN", "detail": "Cannot parse version"}

    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    branch = f"{major}.{minor}"

    r = {"version": ver, "branch": branch}

    if branch in EOL:
        r.update(status="VULNERABLE_EOL",
                 detail=f"PHP {branch} is End-of-Life — NO FIX EXISTS",
                 severity="CRITICAL",
                 fix="Upgrade to PHP 8.2.35+, 8.3.36+, 8.4.27+, or 8.5.12+")
        return r

    fixed_patch = FIXED.get(branch)
    if fixed_patch is not None:
        if patch < fixed_patch:
            r.update(status="VULNERABLE",
                     detail=f"PHP {ver} < {branch}.{fixed_patch}",
                     fixed_in=f"{branch}.{fixed_patch}",
                     severity="CRITICAL",
                     fix=f"Upgrade to PHP {branch}.{fixed_patch}+")
        else:
            r.update(status="PATCHED",
                     detail=f"PHP {ver} >= {branch}.{fixed_patch}",
                     severity="NONE", fix="N/A")
        return r

    r.update(status="UNKNOWN", detail=f"Branch {branch} outside known matrix")
    return r


# ═══════════════════════════════════════════════════════════════════
#  Report
# ═══════════════════════════════════════════════════════════════════
REPORT_TPL = """# Vulnerability Report — PHP2Shell ({cves})

| Field | Value |
|-------|-------|
| **Target** | {target} |
| **Date** | {date} |
| **Researcher** | {handle} (Bugcrowd) |
| **Priority** | {priority} |
| **CVSSv4** | {cvss} |

---

## Summary

The target runs **PHP {version}** — {verdict} to {cves}, a **pre-authentication Remote Code Execution** vulnerability chain.{eol_warning}

## Evidence

| Check | Result |
|-------|--------|
| PHP Version | `{version}` ({version_source}) |
| Server | `{server}` |
| PHP Handler | {handler} — risk: {handler_risk} |
| OS | {distro} |
| session.upload_progress | {upload_progress} |

### Raw Headers
```
Server: {server}
X-Powered-By: {powered_by}
```

## Vulnerability Details

### CVE-2026-109618 — OOM Hash Table Corruption (UAF)
- **Type:** Use-After-Free (CWE-416)
- **Vector:** Crafted multipart HTTP request triggers OOM in session upload-progress handler
- **Prerequisite:** `session.upload_progress.enabled = On` (default since PHP 5.4)
- **Authentication:** None required
- **Impact:** Memory corruption leading to arbitrary code execution

### CVE-2026-109619 — Stale Global State (UAF)
- **Type:** Use-After-Free (CWE-416)
- **Vector:** Interrupted multipart parse leaves dangling pointers in module globals
- **Prerequisite:** Same as above
- **Authentication:** None required
- **Impact:** Subsequent requests reuse freed memory → code execution

### Combined Chain
The two CVEs together enable **unauthenticated pre-auth RCE over HTTP**. On mod_php configurations, the attack succeeds **before any application code executes** — every PHP file on the server is an entry point. Public PoC exploits exist and have been independently verified.

### Affected Versions

| Branch | Status | Fix |
|--------|--------|-----|
| PHP 8.5 < 8.5.12 | VULNERABLE | 8.5.12 |
| PHP 8.4 < 8.4.27 | VULNERABLE | 8.4.27 |
| PHP 8.3 < 8.3.36 | VULNERABLE | 8.3.36 |
| PHP 8.2 < 8.2.35 | VULNERABLE | 8.2.35 |
| PHP 8.1 (all) | VULNERABLE | None (EOL) |
| PHP 8.0 (all) | VULNERABLE | None (EOL) |
| PHP 7.x (all) | VULNERABLE | None (EOL) |
| PHP 5.x (all) | VULNERABLE | None (EOL) |

## Impact

An unauthenticated remote attacker can execute arbitrary operating-system commands on the server. No credentials, no specific endpoint, and no user interaction are required. The `session.upload_progress` feature is enabled by default in all PHP installations since 5.4.

Attack surface scale (public data): approximately 4.38 million PHP services on ~1.89 million hosts are exposed on the internet, with ~883,000 running versions that will never receive a fix.

## Remediation

{fix}

**Immediate mitigations if upgrade is not possible:**
1. Disable `session.upload_progress` in `php.ini`:
   ```ini
   session.upload_progress.enabled = Off
   ```
2. Switch from mod_php to PHP-FPM (reduces risk, but still vulnerable via different path)
3. Deploy WAF rules to detect multipart requests with excessive empty-filename fields
4. Monitor for `zend_mm_heap corrupted` messages in error logs

## References

- PHP Security Advisories: CVE-2026-109618, CVE-2026-109619
- Wiz Research: PHP2Shell pre-auth RCE chain discovery (August 2026)
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-109618
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-109619
- Elastic Security Labs: PHP2Shell detection guidance
- watchTowr Intelligence: PHP2Shell FAQ
- CVSS v4.0 Vector: {cvss_vec}

---
*Assessment performed during authorized bug bounty testing. Researcher: {handle}*
"""


def make_report(target: str, f: dict, out_dir: str | None = None) -> str:
    va = f.get("version_analysis", {})
    status = va.get("status", "UNKNOWN")
    is_vuln = "VULNERABLE" in status

    priority = "P1 — Critical" if is_vuln else ("None" if status == "PATCHED" else "P3 — Undetermined")
    eol = ("\n\n> **⚠ WARNING:** This PHP branch is End-of-Life. "
           "No security patch will ever be released. "
           "The ONLY remediation is a full PHP version upgrade."
           if status == "VULNERABLE_EOL" else "")

    text = REPORT_TPL.format(
        cves=CVES, target=target,
        date=datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        handle=HANDLE, priority=priority, cvss=CVSS,
        version=f.get("version", "not detected"),
        verdict="**vulnerable**" if is_vuln else "not confirmed vulnerable",
        eol_warning=eol,
        version_source=f.get("version_source", "N/A"),
        server=f.get("server", "N/A"),
        handler=f.get("handler", "unknown"),
        handler_risk=f.get("handler_risk", "unknown"),
        distro=f.get("distro") or "not detected",
        upload_progress=f.get("upload_progress", "not checked"),
        powered_by=f.get("powered_by") or "(hidden)",
        fix=va.get("fix", "Upgrade PHP to a patched version."),
        cvss_vec=CVSS_VEC,
    )

    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        safe = re.sub(r"[^\w.-]", "_", target)[:80]
        ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(out_dir, f"php2shell_{safe}_{ts}.md")
        with open(path, "w") as fh:
            fh.write(text)
        return path
    return text


# ═══════════════════════════════════════════════════════════════════
#  Assessment driver
# ═══════════════════════════════════════════════════════════════════
def assess(url: str, check_upload=True, manual_version=None, quiet=False) -> dict:
    f: dict = {"target": url, "ts": datetime.datetime.utcnow().isoformat()}

    if not quiet:
        print(f"\n{'='*62}")
        print(f"  PHP2Shell Assessment  |  {url}")
        print(f"  {HANDLE}  |  {CVES}")
        print(f"{'='*62}\n")

    # 1 — Version
    if not quiet:
        print("[1/4] Fingerprinting PHP version …")
    ver, server, powered, source = fingerprint_version(url)
    if manual_version and not ver:
        ver, source = manual_version, "manually specified (--version)"
    f.update(version=ver, server=server, powered_by=powered, version_source=source)
    if not quiet:
        print(f"      Version : {ver or '(not detected)'}  [{source}]")
        print(f"      Server  : {server or '(empty)'}")

    # 2 — Handler / OS
    if not quiet:
        print("[2/4] Detecting handler & OS …")
    handler, risk = detect_handler(server)
    distro = detect_distro(server)
    f.update(handler=handler, handler_risk=risk, distro=distro)
    if not quiet:
        print(f"      Handler : {handler}  →  risk {risk}")
        if distro:
            print(f"      OS      : {distro}")

    # 3 — upload_progress
    if check_upload:
        if not quiet:
            print("[3/4] Checking session.upload_progress …")
        has, detail = check_upload_progress(url)
        if has is True:
            f["upload_progress"] = f"ENABLED ({detail})"
        elif has is False:
            f["upload_progress"] = f"not confirmed ({detail})"
        else:
            f["upload_progress"] = f"check failed ({detail})"
        if not quiet:
            print(f"      Result  : {f['upload_progress']}")
    else:
        f["upload_progress"] = "skipped"
        if not quiet:
            print("[3/4] session.upload_progress — skipped (--no-upload-check)")

    # 4 — Verdict
    if not quiet:
        print("[4/4] Analysing version …")
    va = analyze_version(ver) if ver else {"status": "UNKNOWN", "detail": "version not detected"}
    f["version_analysis"] = va
    status = va.get("status", "UNKNOWN")

    if not quiet:
        print()
        if "VULNERABLE" in status:
            print(f"  ╔══════════════════════════════════════════════════╗")
            print(f"  ║  ⚠  VULNERABLE — {va['detail']:<32} ║")
            print(f"  ║  Severity: CRITICAL  |  CVSSv4: {CVSS:<15}  ║")
            if status == "VULNERABLE_EOL":
                print(f"  ║  ⛔ EOL branch — NO PATCH WILL EVER EXIST       ║")
            print(f"  ╚══════════════════════════════════════════════════╝")
        elif status == "PATCHED":
            print(f"  ✅  PATCHED — {va['detail']}")
        else:
            print(f"  ❓  INCONCLUSIVE — {va.get('detail','')}")
        print()

    return f


# ═══════════════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════════════
def main() -> int:
    ap = argparse.ArgumentParser(
        description=f"PHP2Shell Assessment Tool — {CVES}",
        epilog=f"Assessment only. Does NOT trigger/exploit the vulnerability.\nResearcher: {HANDLE}",
        formatter_class=argparse.RawDescriptionHelpFormatter)

    ap.add_argument("-u", "--url", help="single target URL")
    ap.add_argument("-f", "--file", help="file with one URL per line")
    ap.add_argument("-o", "--output", default="reports", help="report output dir (default: reports/)")
    ap.add_argument("--report", action="store_true", help="generate Markdown report per target")
    ap.add_argument("--json", action="store_true", help="print JSON findings to stdout")
    ap.add_argument("--version", help="assume this PHP version when headers hide it (e.g. 8.4.26)")
    ap.add_argument("--no-upload-check", action="store_true", help="skip session.upload_progress probe")
    ap.add_argument("--delay", type=float, default=1.0, help="seconds between targets (default 1)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if not args.url and not args.file:
        ap.error("-u URL or -f FILE required")

    targets = []
    if args.url:
        targets.append(args.url)
    if args.file:
        with open(args.file) as fh:
            targets += [l.strip() for l in fh if l.strip() and not l.startswith("#")]

    results = []
    vuln = 0

    for i, t in enumerate(targets):
        if i > 0:
            time.sleep(args.delay)
        if not t.startswith("http"):
            t = "https://" + t

        f = assess(t, check_upload=not args.no_upload_check,
                   manual_version=args.version, quiet=args.quiet)

        st = f.get("version_analysis", {}).get("status", "")
        if "VULNERABLE" in st:
            vuln += 1
        if args.report:
            path = make_report(t, f, args.output)
            if not args.quiet:
                print(f"  📄 Report → {path}\n")
        results.append(f)

    if args.json:
        print(json.dumps(results, indent=2, default=str))

    if len(targets) > 1 and not args.quiet:
        print(f"{'='*62}")
        print(f"  DONE — {len(targets)} targets scanned, {vuln} vulnerable")
        print(f"{'='*62}")

    return 0 if vuln == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
