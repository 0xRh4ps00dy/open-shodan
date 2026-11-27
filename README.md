<p align="center">
  <img src="assets/banner.jpg" alt="Shodan-like Network Scanner Banner" width="100%">
</p>

<h1 align="center">Shodan-like Network & SSL/HTTP Scanner</h1>

<p align="center">
  Asynchronous cloud IP range scanner, SSL/HTTP banner grabber, and Flask + MongoDB search dashboard.
</p>

---

## Overview

This project automates large-scale asset discovery across major cloud providers. It combines `masscan` for fast port discovery, an asynchronous Python scanner (`aiohttp` + `pyOpenSSL`) for HTTP/HTTPS and SSL certificate inspection, and a Flask + MongoDB web interface to query and filter indexed hosts.

## Features

- **Cloud IP Range Extractor** (`ip-ranges/cidr_extractor.sh`): Fetches and merges public CIDR blocks from AWS, GCP, Azure, Cloudflare, DigitalOcean, Fastly, Linode, and Oracle Cloud into `ips.txt`.
- **Asynchronous Scanner** (`scanner.py`):
  - Runs `masscan` against target CIDRs on common web/service ports (`80`, `443`, `8000-8088`, `8443`, `9200`, `10250`, etc.).
  - Extracts SSL/TLS certificate `Common Name` (CN) metadata.
  - Performs concurrent HTTP/HTTPS requests (both by IP and resolved domain) to capture page titles, response headers, redirects, and body snippets.
  - Sends results to the Flask API and optionally notifies via Discord webhook (`DISCORD_WEBHOOK_URL` environment variable).
- **Web Dashboard & API** (`server/server.py`):
  - Stores scan results in MongoDB (`scannerdb.sslchecker`).
  - Provides endpoints to search by title (`/bytitle`), domain (`/bydomain`), IP (`/byip`), and port (`/byport`).

## Project Structure

```text
.
├── assets/
│   └── banner.jpg              # Project header image
├── ip-ranges/
│   ├── cidr_extractor.sh       # Cloud CIDR range fetcher
│   └── *.txt                   # Provider CIDR lists
├── server/
│   ├── server.py               # Flask + MongoDB backend
│   ├── static/                 # CSS & static assets
│   └── templates/
│       └── index.html          # Web UI
├── ips.txt                     # Combined target CIDRs
├── requirements.txt            # Python dependencies
└── scanner.py                  # Masscan + async HTTP/SSL scanner
```

## Setup & Usage

### 1. Prerequisites

- Python 3.10+
- MongoDB running locally on `mongodb://localhost:27017/`
- `masscan` installed and available in `PATH`
- `jq` and `curl` (for `ip-ranges/cidr_extractor.sh`)

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Update Cloud IP Ranges (Optional)

```bash
bash ip-ranges/cidr_extractor.sh
```

### 4. Start the Web Server

```bash
python server/server.py
```

### 5. Run the Scanner

```bash
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..." # Optional
python scanner.py
```

## Legal Disclaimer & Liability Notice

> [!CAUTION]
> **For Educational and Authorized Security Research Only.**
>
> This software is provided **"AS IS"**, without warranty of any kind, express or implied. The author assumes **no liability or responsibility** for any misuse, unauthorized access, service disruption, data loss, or legal consequences resulting from the use or misuse of this tool.
>
> By using this project, you agree that you are solely responsible for your actions and that you will **only** scan networks, IP ranges, and systems that you own or for which you have **explicit, written authorization**. Unauthorized port scanning or probing of third-party infrastructure may violate local, national, or international laws.
