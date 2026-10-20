# WebScan Lab and Authorized Scanner

This project creates a safe Apache lab and a low-impact HTTP scanner for learning and authorized testing. It intentionally avoids brute force, credential attacks, exploitation, destructive requests, and file uploads.

## Safety boundary and authorization

The scanner behaves like this:

- Without `--authorized`, it permits only `http://127.0.0.1` and `http://localhost` on port 8080.
- With `--authorized`, it can scan other hosts, ports, and URL schemes, including URLs with credentials and redirect destinations outside the localhost boundary.
- It never follows redirects automatically.
- It logs every request before sending it.
- It only sends GET and POST requests, and it uses a small, fixed list of harmless probe targets.
- It labels findings as `possible findings requiring manual verification`, not confirmed vulnerabilities.
- Its optional TCP reachability mode checks exactly one IP address and one port per run. It requires `--authorized`, accepts IP literals only, and does not scan ranges or identify services.

This reduces accidental exposure while still teaching how to inspect HTTP headers, security headers, robots.txt, and redirect behavior.

## Project structure

```text
web-scan/
├── README.md
├── docker-compose.yml
├── requirements.txt
├── scanner.py
├── apache-lab/
│   ├── httpd.conf
│   └── www/
│       ├── index.html
│       ├── robots.txt
│       ├── public/
│       │   └── index.html
│       ├── docs/
│       │   └── index.html
│       └── examples/
│           ├── index.html
│           ├── sample.txt
│           └── notes.txt
├── reports/
└── tests/
    └── test_scanner.py
```

## Kali Linux installation/setup

```bash
sudo apt update
sudo apt install -y apache2 python3 python3-pip python3-venv docker.io docker-compose-plugin nmap nikto
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If you want to use the Docker Apache lab instead of a local Apache service, Docker Desktop is not required on Kali; the Docker engine is enough.

## Start the Apache lab on localhost:8080

### Option A: Docker (recommended)

```bash
docker compose up -d
```

This binds the lab to `127.0.0.1:8080` only.

### Option B: System Apache on Kali

```bash
sudo cp apache-lab/httpd.conf /etc/apache2/sites-available/webscan.conf
sudo mkdir -p /var/www/webscan-lab
sudo cp -r apache-lab/www/* /var/www/webscan-lab/
sudo a2dissite 000-default.conf 2>/dev/null || true
sudo a2ensite webscan.conf 2>/dev/null || true
sudo apache2ctl configtest
sudo systemctl restart apache2
```

The lab is intentionally bound to `127.0.0.1:8080` and uses a harmless homepage plus a directory-listing example.

## Local lab behavior

- Homepage: `http://127.0.0.1:8080/`
- robots.txt: `http://127.0.0.1:8080/robots.txt`
- Directory listing example: `http://127.0.0.1:8080/examples/`
- Public page: `http://127.0.0.1:8080/public/`
- Docs page: `http://127.0.0.1:8080/docs/`

The directory listing and Apache version disclosure are deliberately exposed for learning; they are safe, local-only, and contain no secrets.

## Run the scanner

```bash
source .venv/bin/activate
python3 scanner.py http://127.0.0.1:8080/ --authorized
```

For a non-authorized local-only target, this is also allowed:

```bash
python3 scanner.py http://127.0.0.1:8080/
```

For other targets, pass the explicit flag:

```bash
python3 scanner.py https://example.com --authorized
```

The tool saves JSON and Markdown reports in the `reports/` directory.

### Check one TCP port on one IP

Only use this for a system you own or are explicitly authorized to test. The check attempts a single TCP connection; it does not scan other ports, identify the service, or send application data.

```bash
python3 scanner.py --check-port 192.0.2.10 --port 443 --authorized
```

IPv6 is supported as an IP literal:

```bash
python3 scanner.py --check-port 2001:db8::10 --port 443 --authorized
```

This mode requires both `--check-port IP` and `--port PORT`. It rejects hostnames and network ranges. It writes JSON and Markdown reports like the HTTP scan.

## Inspect reports

```bash
ls -lt reports
sed -n '1,200p' reports/*.json
sed -n '1,200p' reports/*.md
```

## Run the unit tests

```bash
source .venv/bin/activate
pytest -q
```

The tests use mocked HTTP responses and never connect to a network host.

## Optional Nmap and Nikto examples (reference only)

These commands are examples for review and use on targets you are explicitly authorized to test. Do not run them against arbitrary systems without permission.

```bash
nmap -sV -Pn 127.0.0.1 -p 8080
nmap -sV -Pn 192.168.1.0/24
nikto -h http://127.0.0.1:8080
nikto -h https://example.com
```

## Stop and clean up the lab

### Docker cleanup

```bash
docker compose down --volumes
```

### System Apache cleanup

```bash
sudo a2dissite webscan.conf 2>/dev/null || true
sudo rm -f /etc/apache2/sites-available/webscan.conf
sudo systemctl restart apache2
sudo rm -rf /var/www/webscan-lab
```

## Notes

- The scanner does not perform brute force, credential testing, login bypasses, file upload testing, or destructive requests.
- The lab content is intentionally dummy-only.
- All findings are reported as possible issues requiring manual verification.
- The project is designed for authorized learning and controlled demonstrations, not production security testing.
