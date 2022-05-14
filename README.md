# network-scanner
License: MIT

A simple nmap scanner which scans a subnet and merges data, using the MAC address as key, about the devices found into a Google sheet.

Useful to run as a cron job for keeping track of MAC addresses and IP addresses of a home network.

**Usage:**
```
pipenv install
pipenv run python network-scanner.py --config config.ini
```

## Enable sudoless nmap

By default `nmap` needs to be run as root to be able to scan for MAC addresses.

Sudoless nmap can be enabled with:
```
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap
```

## systemd config

Deploying this using systemd user units can be done with a timer plus a oneshot service.
The usage of pipenv here isn't too elegant, but it does the job for now.

```
$ cat ~/.config/systemd/user/network-scanner.service
[Unit]
Description=Logs system statistics to the systemd journal
Wants=network-scanner.timer

[Service]
Type=oneshot
WorkingDirectory=/home/kintel/code/network-scanner
ExecStart=/usr/bin/pipenv run python network-scanner.py --config config.ini

[Install]
WantedBy=default.target
```

```
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

**Useful cmd-lines:**
```
systemctl --user enable network-scanner.service
systemctl --user enable network-scanner.timer
journalctl -S today --user-unit network-scanner.service

# Lingering is important for user services as otherwise, 
# the systemd user service is only active while a login session exists.
sudo loginctl enable-linger kintel

systemctl --user status network-scanner.timer
systemctl --user status network-scanner.service
systemctl --user list-timers --all
```
