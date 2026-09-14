# DNS Pinger

A lightweight daemon that continuously monitors dynamic DNS records and synchronizes them with your Hostinger VPS firewall rules.

If your home or office IP changes frequently, DNS Pinger resolves your domains and updates your Hostinger VPS firewall group automatically so you never get locked out.

---

## Features

* **Dynamic DNS Tracking**: Resolves domain records (`A` and `AAAA`) at configurable intervals.
* **On-the-Fly Config Reloading**: Edit your firewall rules in `config/firewall-config.yaml` anytime; the container re-evaluates the config file dynamically on each check without requiring a container restart or recreation.
* **Drift & Change Detection**: Compares desired rules against active rules in Hostinger, only making API calls when DNS records or configuration rules actually change.
* **DNS Outage Safeguard**: If DNS resolution temporarily fails or returns no records, the update cycle is aborted to prevent wiping out active firewall rules.
* **Graceful Shutdown**: Listens for `SIGTERM` and `SIGINT` signals to terminate immediately and cleanly.
* **Structured Logging**: Formatted timestamps and log levels (`INFO`, `DEBUG`, `WARNING`, `ERROR`).

---

## Quickstart

### 1. Configure Environment

Copy the example environment file and fill in your values:

```bash
cp .env.example .env
```

Edit `.env` with your details:
* `APIKEY`: Your Hostinger API token (with VPS management permissions).
* `DOMAINS`: Comma-separated list of domains to track (e.g. `home.example.com`).
* `FIREWALL_NAME`: The name of the firewall group in Hostinger (e.g. `MyFirewallGroup`).

### 2. Configure Firewall Rules

Copy the example firewall configuration:

```bash
cp config/firewall-config.yaml.example config/firewall-config.yaml
```

Edit `config/firewall-config.yaml` to specify the rules for your firewall group. Use `source_detail: "{{ dns_record }}"` on rules where you want your resolved dynamic IP addresses inserted:

```yaml
---
name: Example
rules:
  - action: accept
    protocol: SSH
    port: "22"
    source: any
    source_detail: any

  - action: accept
    protocol: HTTPS
    port: "443"
    source: custom
    source_detail: "{{ dns_record }}"
```

### 3. Run with Docker Compose

Start the container in the background:

```bash
docker compose up -d
```

Check the logs:

```bash
docker compose logs -f
```

---

## Configuration Reference

All settings can be configured via environment variables in `.env` or `docker-compose.yaml`:

| Variable | Required | Default | Description |
| :--- | :---: | :--- | :--- |
| `APIKEY` | **Yes** | — | Hostinger API Access Token. |
| `DOMAINS` | **Yes** | — | Comma-separated domains to monitor (e.g. `home.example.com,vpn.example.com`). |
| `RECORD_TYPES` | No | `A` | DNS record types to resolve (`A`, `AAAA`, or `A,AAAA`). |
| `FIREWALL_NAME` | No | *(first found)* | Name of the firewall group in Hostinger VPS panel. |
| `INTERVAL` | No | `300` | Seconds to wait between DNS and firewall checks. |
| `LOG_LEVEL` | No | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`). |
| `CONFIG_PATH` | No | `./config/firewall-config.yaml` | Path to the firewall rules YAML configuration file. |
| `PRETTY_JSON` | No | `false` | When `true`, logs raw Hostinger API responses at `DEBUG` level. |

---

## Local Development

If you prefer running without Docker:

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install pinned dependencies
pip install -r requirements.txt

# Run the script
python dnspython-pinger.py
```
