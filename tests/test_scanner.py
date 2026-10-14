import json
from pathlib import Path
from unittest.mock import patch

from scanner import run_scan


class DummyResponse:
    def __init__(self, status_code, headers=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self.reason = "OK" if status_code < 400 else "ERROR"


def fake_request(self, method, url, timeout=None, allow_redirects=False):
    local_responses = {
        "http://127.0.0.1:8080/": DummyResponse(200, {"Server": "Apache/2.4.58", "Content-Type": "text/html"}, "welcome"),
        "http://127.0.0.1:8080/robots.txt": DummyResponse(200, {"Server": "Apache/2.4.58"}, "User-agent: *\nDisallow: /private/"),
        "http://127.0.0.1:8080/favicon.ico": DummyResponse(404, {"Server": "Apache/2.4.58"}, ""),
        "http://127.0.0.1:8080/public/": DummyResponse(200, {"Server": "Apache/2.4.58"}, "public page"),
        "http://127.0.0.1:8080/docs/": DummyResponse(200, {"Server": "Apache/2.4.58"}, "docs"),
        "http://127.0.0.1:8080/examples/": DummyResponse(301, {"Location": "http://evil.example/redirect"}, "redirect"),
    }
    if url in local_responses:
        return local_responses[url]

    if url.startswith("https://example.com:8443/"):
        path = url.replace("https://example.com:8443", "") or "/"
        if path == "/":
            return DummyResponse(200, {"Server": "nginx/1.25.0", "Content-Type": "text/html"}, "example")
        if path == "/robots.txt":
            return DummyResponse(200, {"Server": "nginx/1.25.0"}, "User-agent: *\nDisallow: /admin")
        if path == "/favicon.ico":
            return DummyResponse(404, {"Server": "nginx/1.25.0"}, "")
        if path in {"/public/", "/docs/", "/examples/"}:
            return DummyResponse(200, {"Server": "nginx/1.25.0"}, "example page")
        return DummyResponse(404, {"Server": "nginx/1.25.0"}, "")

    raise KeyError(url)


def test_default_allowlist_allows_localhost(tmp_path):
    with patch("scanner.requests.Session.request", new=fake_request):
        report = run_scan("http://127.0.0.1:8080/", authorized=False, output_dir=str(tmp_path), request_limit=6, delay=0)
    assert report["target"] == "http://127.0.0.1:8080/"
    assert report["findings"]


def test_authorized_mode_allows_other_targets(tmp_path):
    with patch("scanner.requests.Session.request", new=fake_request):
        report = run_scan("https://example.com:8443/", authorized=True, output_dir=str(tmp_path), request_limit=6, delay=0)
    assert report["authorized"] is True
    assert report["target"] == "https://example.com:8443/"


def test_redirect_outside_allowlist_is_reported_without_following(tmp_path):
    with patch("scanner.requests.Session.request", new=fake_request):
        report = run_scan("http://127.0.0.1:8080/", authorized=False, output_dir=str(tmp_path), request_limit=6, delay=0)
    redirect_finding = next((item for item in report["findings"] if item["check"] == "redirect_outside_allowlist"), None)
    assert redirect_finding is not None
    assert redirect_finding["manual_verification_required"] is True


def test_markdown_report_includes_sections(tmp_path):
    with patch("scanner.requests.Session.request", new=fake_request):
        report = run_scan("http://127.0.0.1:8080/", authorized=False, output_dir=str(tmp_path), request_limit=6, delay=0)
    report_dir = Path(tmp_path)
    markdown_file = next(report_dir.glob("*.md"))
    contents = markdown_file.read_text(encoding="utf-8")
    assert "# Web Scanner Report" in contents
    assert "## Possible findings" in contents
    assert "## Limitations" in contents
    assert "## Remediation suggestions" in contents
    assert "manual verification" in json.dumps(report).lower()
