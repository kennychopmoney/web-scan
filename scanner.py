#!/usr/bin/env python3
"""Low-impact HTTP scanner for learning and authorized testing.

This tool is intentionally narrow. It performs only a few passive/active-but-low-impact
checks against a target URL: headers, security-header presence, robots.txt discovery,
and a fixed list of harmless paths. It does not brute-force credentials, attempt login,
probe for authentication bypasses, or upload or delete files.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import urljoin, urlsplit

import requests

DEFAULT_ALLOWLIST = {
    ("http", "127.0.0.1", 8080),
    ("http", "localhost", 8080),
}

SAFE_PATHS = [
    "/",
    "/robots.txt",
    "/favicon.ico",
    "/public/",
    "/docs/",
    "/examples/",
]

SECURITY_HEADERS = [
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "content-security-policy",
    "referrer-policy",
    "permissions-policy",
]

REQUEST_LIMIT = 20
TIMEOUT_SECONDS = 5
REQUEST_DELAY_SECONDS = 0.5


def parse_target(target: str) -> Any:
    if not target or not target.strip():
        raise ValueError("A target URL is required.")

    parsed = urlsplit(target.strip())
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid URL: {target!r}. Use a full URL such as http://127.0.0.1:8080/.")
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"Unsupported URL scheme {parsed.scheme!r}. Only http and https are allowed.")
    return parsed


def is_default_allowed(target_url: str) -> bool:
    parsed = parse_target(target_url)
    host = parsed.hostname or ""
    port = parsed.port or (80 if parsed.scheme == "http" else 443)
    return (parsed.scheme, host, port) in DEFAULT_ALLOWLIST


def ensure_authorization(target_url: str, authorized: bool) -> None:
    if authorized:
        return
    if not is_default_allowed(target_url):
        raise PermissionError(
            "Target is outside the default localhost-only safety boundary. Re-run with --authorized "
            "only if you have explicit permission to scan this target."
        )


def build_probe_url(base_url: str, path: str) -> str:
    normalized = base_url.rstrip("/") + "/"
    return urljoin(normalized, path.lstrip("/"))


def make_finding(
    check: str,
    method: str,
    url: str,
    status_code: int,
    severity: str,
    description: str,
    evidence: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "check": check,
        "method": method,
        "url": url,
        "status_code": status_code,
        "severity": severity,
        "finding": description,
        "evidence": evidence,
        "manual_verification_required": True,
        "result": "possible finding requiring manual verification",
    }


def request_and_log(session: requests.Session, method: str, url: str, timeout: int, delay: float) -> requests.Response:
    print(f"REQUEST {method} {url}")
    if delay > 0:
        time.sleep(delay)
    response = session.request(method=method, url=url, timeout=timeout, allow_redirects=False)
    print(f"RESPONSE {method} {url} -> {response.status_code}")
    return response


def scan_headers(
    response: requests.Response,
    url: str,
    method: str,
    findings: List[Dict[str, Any]],
) -> None:
    headers = {name.lower(): value for name, value in response.headers.items()}
    present = [name for name in SECURITY_HEADERS if name in headers]
    missing = [name for name in SECURITY_HEADERS if name not in headers]

    if missing:
        findings.append(
            make_finding(
                "security_headers",
                method,
                url,
                response.status_code,
                "medium",
                "Missing common security headers. This is a possible configuration issue that requires manual verification.",
                {
                    "headers_seen": sorted(headers.keys()),
                    "missing_headers": missing,
                    "observed_headers": present,
                },
            )
        )

    if "server" in headers:
        findings.append(
            make_finding(
                "server_version_disclosure",
                method,
                url,
                response.status_code,
                "low",
                "Server version information is exposed in the response headers. This is a disclosure issue requiring manual verification.",
                {"server_header": headers["server"]},
            )
        )


def check_redirects(response: requests.Response, url: str, findings: List[Dict[str, Any]], authorized: bool) -> None:
    if response.status_code not in {301, 302, 303, 307, 308}:
        return

    location = response.headers.get("Location")
    if not location:
        return

    try:
        redirect_target = urljoin(url, location)
    except Exception:
        redirect_target = location

    parsed = urlsplit(redirect_target)
    redirect_host = parsed.hostname or ""
    redirect_scheme = parsed.scheme or ""
    redirect_port = parsed.port or (80 if redirect_scheme == "http" else 443 if redirect_scheme == "https" else 0)

    if authorized:
        if redirect_host:
            findings.append(
                make_finding(
                    "redirect_outside_target",
                    "GET",
                    url,
                    response.status_code,
                    "low",
                    "The target redirects to another destination. The scanner did not follow the redirect because the project forbids automatic redirects.",
                    {"Location": location, "redirect_target": redirect_target, "authorized_scan": True},
                )
            )
        return

    if redirect_host and (redirect_scheme, redirect_host, redirect_port) not in DEFAULT_ALLOWLIST:
        findings.append(
            make_finding(
                "redirect_outside_allowlist",
                "GET",
                url,
                response.status_code,
                "medium",
                "Redirect target is outside the localhost-only allowlist and was not requested. This is possible information disclosure or navigation outside the safe boundary.",
                {"Location": location, "redirect_target": redirect_target, "allowlist": list(DEFAULT_ALLOWLIST)},
            )
        )


def perform_robots_check(session: requests.Session, base_url: str, timeout: int, delay: float, findings: List[Dict[str, Any]]) -> None:
    robots_url = build_probe_url(base_url, "/robots.txt")
    response = request_and_log(session, "GET", robots_url, timeout, delay)
    if response.status_code == 200:
        noisey = response.text.strip()
        if noisey:
            findings.append(
                make_finding(
                    "robots_disclosure",
                    "GET",
                    robots_url,
                    response.status_code,
                    "low",
                    "robots.txt is available and reveals path information. This should be treated as metadata disclosure and manually reviewed.",
                    {"content_preview": noisey[:200]},
                )
            )
        else:
            findings.append(
                make_finding(
                    "robots_missing",
                    "GET",
                    robots_url,
                    response.status_code,
                    "info",
                    "The target does not expose a robots.txt file. No issue is reported; this is informational only.",
                    {"content_length": len(response.text)},
                )
            )


def perform_harmless_probe(session: requests.Session, base_url: str, path: str, timeout: int, delay: float, findings: List[Dict[str, Any]], authorized: bool) -> None:
    probe_url = build_probe_url(base_url, path)
    response = request_and_log(session, "GET", probe_url, timeout, delay)
    scan_headers(response, probe_url, "GET", findings)
    check_redirects(response, probe_url, findings, authorized)

    if response.status_code == 404:
        findings.append(
            make_finding(
                "path_not_found",
                "GET",
                probe_url,
                response.status_code,
                "info",
                "The path did not respond, which is expected for some harmless probe paths. This is informational only.",
                {"path": path, "status_code": response.status_code},
            )
        )


def run_scan(target_url: str, authorized: bool, output_dir: str = "reports", request_limit: int = REQUEST_LIMIT, timeout: int = TIMEOUT_SECONDS, delay: float = REQUEST_DELAY_SECONDS) -> Dict[str, Any]:
    ensure_authorization(target_url, authorized)

    parsed = parse_target(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    session = requests.Session()
    session.headers.update({"User-Agent": "webscan-learning/1.0 (+educational-only)"})

    findings: List[Dict[str, Any]] = []
    checks_performed: List[Dict[str, Any]] = []
    request_count = 0

    for path in SAFE_PATHS:
        if request_count >= request_limit:
            break
        probe_url = build_probe_url(base_url, path)
        response = request_and_log(session, "GET", probe_url, timeout, delay)
        request_count += 1
        checks_performed.append({"method": "GET", "url": probe_url, "status_code": response.status_code})
        scan_headers(response, probe_url, "GET", findings)
        check_redirects(response, probe_url, findings, authorized)

        if path == "/robots.txt":
            if response.status_code == 200:
                content = response.text.strip()
                if content:
                    findings.append(
                        make_finding(
                            "robots_disclosure",
                            "GET",
                            probe_url,
                            response.status_code,
                            "low",
                            "robots.txt is available and exposes path hints. This is metadata disclosure requiring manual validation.",
                            {"content_preview": content[:200]},
                        )
                    )

    if request_count < request_limit and "/robots.txt" not in SAFE_PATHS:
        pass

    report: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": target_url,
        "authorized": authorized,
        "default_allowlist": ["http://127.0.0.1:8080", "http://localhost:8080"],
        "checks_performed": checks_performed,
        "request_limit": request_limit,
        "timeout_seconds": timeout,
        "delay_seconds": delay,
        "findings": findings,
        "limitations": [
            "This tool does not perform brute force, credential attacks, file upload actions, exploit testing, or destructive requests.",
            "It only uses GET and POST requests, with a fixed probe list and request budget.",
            "Redirects are not automatically followed.",
            "Results are possible findings that require manual verification and cannot be treated as confirmed vulnerabilities.",
        ],
        "remediation": [
            "Review responses and verify whether the headers, robots.txt, and path behavior are intentional for the target application.",
            "Remove or limit directory listing and version disclosure when they are not required.",
            "Add missing security headers and confirm that robots.txt does not reveal sensitive paths.",
            "Use a change management process before exposing any additional service or host to active scanning.",
        ],
    }

    reports_dir = Path(output_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    json_path = reports_dir / f"{timestamp}-{safe_filename(target_url)}.json"
    markdown_path = reports_dir / f"{timestamp}-{safe_filename(target_url)}.md"

    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    markdown_path.write_text(render_markdown_report(report), encoding="utf-8")

    print(f"Saved JSON report: {json_path}")
    print(f"Saved Markdown report: {markdown_path}")
    return report


def run_port_check(
    address: str,
    port: int,
    authorized: bool,
    output_dir: str = "reports",
    timeout: int = TIMEOUT_SECONDS,
) -> Dict[str, Any]:
    if not authorized:
        raise PermissionError("A TCP port check requires --authorized and explicit permission for the target.")
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")
    if timeout <= 0:
        raise ValueError("Timeout must be greater than zero.")

    try:
        parsed_address = ipaddress.ip_address(address)
    except ValueError as exc:
        raise ValueError("Port checks accept one IP address only; hostnames and network ranges are not accepted.") from exc

    normalized_address = str(parsed_address)
    display_address = f"[{normalized_address}]" if parsed_address.version == 6 else normalized_address
    target = f"tcp://{display_address}:{port}"

    print(f"REQUEST TCP CONNECT {target}")
    try:
        with socket.create_connection((normalized_address, port), timeout=timeout):
            status = "open"
            evidence = {"ip_address": normalized_address, "port": port, "connection_accepted": True}
    except ConnectionRefusedError:
        status = "closed"
        evidence = {"ip_address": normalized_address, "port": port, "connection_accepted": False}
    except (socket.timeout, TimeoutError):
        status = "timed_out"
        evidence = {"ip_address": normalized_address, "port": port, "connection_accepted": False}
    except OSError as exc:
        status = "unreachable_or_filtered"
        evidence = {
            "ip_address": normalized_address,
            "port": port,
            "connection_accepted": False,
            "error": str(exc),
        }
    print(f"RESPONSE TCP CONNECT {target} -> {status}")

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    report: Dict[str, Any] = {
        "timestamp": timestamp,
        "target": target,
        "authorized": True,
        "default_allowlist": ["http://127.0.0.1:8080", "http://localhost:8080"],
        "checks_performed": [
            {
                "method": "TCP CONNECT",
                "url": target,
                "status": status,
                "evidence": evidence,
            }
        ],
        "request_limit": 1,
        "timeout_seconds": timeout,
        "delay_seconds": 0,
        "findings": [],
        "observations": [
            {
                "check": "tcp_port_reachability",
                "severity": "info",
                "status": status,
                "finding": (
                    "A TCP connection was accepted. An open port is not itself a vulnerability; "
                    "confirm that this service is expected to be reachable."
                    if status == "open"
                    else "No TCP connection was established. This result alone cannot distinguish a closed port from filtering or routing issues."
                ),
                "evidence": evidence,
            }
        ],
        "limitations": [
            "This check attempts exactly one TCP connection to one explicit IP address and port.",
            "It does not scan port ranges, discover services, send application data, or perform vulnerability checks.",
            "A timeout or connection error does not prove that a port is closed.",
            "This is an informational reachability observation, not a confirmed vulnerability.",
        ],
        "remediation": [
            "Verify that any reachable service is expected and restricted to intended networks.",
            "Use firewall rules to limit access to services that do not need to be publicly reachable.",
        ],
    }

    reports_dir = Path(output_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    file_timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    file_address = normalized_address.replace(".", "-").replace(":", "-")
    report_stem = f"{file_timestamp}-{file_address}-{port}"
    json_path = reports_dir / f"{report_stem}.json"
    markdown_path = reports_dir / f"{report_stem}.md"

    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    markdown_path.write_text(render_markdown_report(report), encoding="utf-8")
    print(f"Saved JSON report: {json_path}")
    print(f"Saved Markdown report: {markdown_path}")
    return report


def safe_filename(target_url: str) -> str:
    parsed = parse_target(target_url)
    host = parsed.hostname or "target"
    port = parsed.port or (80 if parsed.scheme == "http" else 443)
    return f"{host}-{port}".replace(".", "-").replace(":", "-")


def render_markdown_report(report: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("# Web Scanner Report")
    lines.append("")
    lines.append(f"- Timestamp: {report['timestamp']}")
    lines.append(f"- Target: {report['target']}")
    lines.append(f"- Authorized: {report['authorized']}")
    lines.append(f"- Request limit: {report['request_limit']}")
    lines.append(f"- Timeout: {report['timeout_seconds']}s")
    lines.append(f"- Delay between requests: {report['delay_seconds']}s")
    lines.append("")
    lines.append("## Checks performed")
    for item in report["checks_performed"]:
        status = item.get("status", item.get("status_code"))
        lines.append(f"- {item['method']} {item['url']} -> {status}")
    lines.append("")
    if report.get("observations"):
        lines.append("## Observations")
        for item in report["observations"]:
            lines.append(f"- [{item['severity'].upper()}] {item['check']}: {item['finding']}")
            lines.append(f"  - Status: {item['status']}")
            lines.append(f"  - Evidence: {json.dumps(item['evidence'], sort_keys=True)}")
        lines.append("")
    lines.append("## Possible findings")
    if not report["findings"]:
        lines.append("- No possible findings were detected after the allowed low-impact checks.")
    else:
        for item in report["findings"]:
            lines.append(f"- [{item['severity'].upper()}] {item['check']}: {item['finding']}")
            lines.append(f"  - URL: {item['url']}")
            lines.append(f"  - Status: {item['status_code']}")
            lines.append(f"  - Evidence: {json.dumps(item['evidence'], sort_keys=True)}")
    lines.append("")
    lines.append("## Limitations")
    for item in report["limitations"]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Remediation suggestions")
    for item in report["remediation"]:
        lines.append(f"- {item}")
    return "\n".join(lines) + "\n"


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Low-impact HTTP scanner for authorized testing only.")
    parser.add_argument("target", nargs="?", help="Target URL to scan, such as http://127.0.0.1:8080/")
    parser.add_argument("--check-port", metavar="IP", help="Check one TCP port on one IP address (requires --port and --authorized).")
    parser.add_argument("--port", type=int, help="Single TCP port to check with --check-port.")
    parser.add_argument("--authorized", action="store_true", help="Explicitly confirm you are authorized to scan this target.")
    parser.add_argument("--output-dir", default="reports", help="Directory for JSON and Markdown reports (default: reports)")
    parser.add_argument("--limit", type=int, default=REQUEST_LIMIT, help=f"Maximum number of requests to send (default: {REQUEST_LIMIT})")
    parser.add_argument("--timeout", type=int, default=TIMEOUT_SECONDS, help=f"Per-request timeout in seconds (default: {TIMEOUT_SECONDS})")
    parser.add_argument("--delay", type=float, default=REQUEST_DELAY_SECONDS, help=f"Delay between requests in seconds (default: {REQUEST_DELAY_SECONDS})")
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.check_port:
        if args.target:
            parser.error("Do not provide a URL when using --check-port.")
        if args.port is None:
            parser.error("--port is required when using --check-port.")
    else:
        if args.target is None:
            parser.error("Provide a target URL or use --check-port with --port.")
        if args.port is not None:
            parser.error("--port can only be used with --check-port.")

    try:
        if args.check_port:
            report = run_port_check(
                args.check_port,
                args.port,
                authorized=args.authorized,
                output_dir=args.output_dir,
                timeout=args.timeout,
            )
        else:
            report = run_scan(
                args.target,
                authorized=args.authorized,
                output_dir=args.output_dir,
                request_limit=args.limit,
                timeout=args.timeout,
                delay=args.delay,
            )
    except (PermissionError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except requests.RequestException as exc:
        print(f"ERROR: Network request failed: {exc}", file=sys.stderr)
        return 1

    if "observations" in report:
        print(f"TCP port check result: {report['observations'][0]['status']}")
        return 0

    print("Summary: possible findings requiring manual verification")
    if report["findings"]:
        print(f"Number of possible findings: {len(report['findings'])}")
    else:
        print("No possible findings were detected in the allowed checks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
