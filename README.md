# network-scanner
License: MIT

A simple Nmap scanner which scans a local subnet and merges discovered device data (using MAC address as primary key) into a Google Sheet inventory.

Useful to run as a scheduled systemd service for keeping track of MAC addresses, IP leases, and vendor information on a home network.

## Quickstart (`uv`)

Install dependencies with [`uv`](https://docs.astral.sh/uv/):
```bash
uv sync
```

Run tests:
```bash
uv run pytest
```

Run in dry-run mode (scans network, reads sheet, prints diff, but does not modify sheet):
```bash
uv run python network-scanner.py --config config.ini --dry-run
```

Run live synchronization:
```bash
uv run python network-scanner.py --config config.ini
```

## Enable Sudoless Nmap

By default `nmap` needs raw network capabilities to capture MAC addresses on Layer 2.

Sudoless nmap capability on Linux can be enabled with:
```bash
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap
```

## Systemd User Service Configuration

Deploying via systemd user units:

```ini
$ cat ~/.config/systemd/user/network-scanner.service
[Unit]
Description=Timed network scanner
Wants=network-scanner.timer

[Service]
Type=oneshot
WorkingDirectory=/home/kintel/code/network-scanner
ExecStart=/home/kintel/.local/bin/uv run python network-scanner.py --config config.ini

[Install]
WantedBy=default.target
```

```ini
$ cat ~/.config/systemd/user/network-scanner.timer 
[Unit]
Description=Timed network scan
Requires=network-scanner.service

[Timer]
Unit=network-scanner.service
OnBootSec=60
OnUnitInactiveSec=3600

[Install]
WantedBy=timers.target
```

**Useful systemd commands:**
```bash
systemctl --user daemon-reload
systemctl --user enable network-scanner.timer
systemctl --user start network-scanner.service
journalctl -S today --user-unit network-scanner.service

# Lingering ensures user services stay active across logouts
sudo loginctl enable-linger kintel

systemctl --user status network-scanner.timer
systemctl --user status network-scanner.service
systemctl --user list-timers --all
```

