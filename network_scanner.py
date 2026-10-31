"""
Network Scanner & Google Sheets Synchronizer

Scans a local subnet using Nmap and synchronizes discovered hosts and MAC
addresses with an inventory tracking spreadsheet in Google Sheets.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading
from datetime import datetime
from typing import Any

import configargparse
from googleapiclient.discovery import build
from libnmap.parser import NmapParser, NmapParserException
from libnmap.process import NmapProcess

from enrichment import (
    PRIVATE_MAC_VENDOR,
    _build_mdns_query,
    _decode_dns_name,
    clean_hostname,
    clean_mdns_hostname,
    enrich_host_from_names,
    infer_from_hostname,
    is_randomized_mac,
    is_unset,
    lookup_oui_vendor,
    resolve_dns_and_mdns,
    resolve_dns_name,
    resolve_vendor,
)

logger = logging.getLogger("network_scanner")

SHEET_HEADERS = ["mac", "ip", "dns_name", "mdns_name", "name", "type", "vendor", "timestamp"]

__all__ = [
    "PRIVATE_MAC_VENDOR",
    "SHEET_HEADERS",
    "_build_mdns_query",
    "_decode_dns_name",
    "build_arg_parser",
    "build_network",
    "clean_hostname",
    "clean_mdns_hostname",
    "enrich_host_from_names",
    "infer_from_hostname",
    "is_randomized_mac",
    "is_unset",
    "lookup_oui_vendor",
    "main",
    "merge_network_data",
    "read_sheet",
    "resolve_dns_and_mdns",
    "resolve_dns_name",
    "resolve_vendor",
    "run_once",
    "scan",
    "write_sheet",
]



def build_arg_parser() -> configargparse.ArgParser:
    """Build the CLI argument and config file parser."""
    parser = configargparse.ArgParser(
        default_config_files=["config.ini"],
        description="Nmap subnet scanner and Google Sheets synchronization tool",
    )
    parser.add_argument("--config", is_config_file=True, help="Path to config.ini file")
    parser.add_argument("--spreadsheet", type=str, required=True, help="Google Sheets spreadsheet ID")
    parser.add_argument("--credentials", type=str, required=True, help="Google API service account credentials JSON file")
    parser.add_argument("--network", type=str, required=True, help="Network subnet to scan (CIDR notation, e.g. 192.168.2.0/24)")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Simulate execution: scan network, calculate diff against Google Sheets, but do not write changes",
    )
    parser.add_argument(
        "--mock-scan",
        type=str,
        default=None,
        help="Path to an Nmap XML output file to parse instead of executing a live Nmap process",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Set the logging level (default: INFO)",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=0,
        help="Run continuously, repeating scan every N seconds (0 = run once and exit)",
    )
    return parser


def scan(target: str, mock_file: str | None = None, options: str = "--privileged -sn") -> Any | None:
    """
    Execute an Nmap ping scan or parse a mock XML file.
    Returns parsed NmapReport object, or None on failure.
    """
    if mock_file:
        logger.info(f"Loading mock Nmap scan from file: {mock_file}")
        try:
            with open(mock_file, "r", encoding="utf-8") as f:
                content = f.read()
            return NmapParser.parse(content)
        except (OSError, NmapParserException) as e:
            logger.error(f"Failed to read or parse mock scan file: {e}")
            return None

    logger.info(f"Initiating live Nmap scan on target: {target} (options: '{options}')")
    nm = NmapProcess(target, options=options)
    rc = nm.run()
    if rc != 0:
        logger.error(f"Nmap scan failed with return code {rc}: {nm.stderr}")
        return None

    try:
        return NmapParser.parse(nm.stdout)
    except NmapParserException as e:
        logger.error(f"Exception raised while parsing Nmap output: {e.msg}")
        return None


def build_network(nmap_report: Any | None, resolve_names: bool = False) -> dict[str, dict[str, Any]]:
    """Extract up hosts with MAC addresses from NmapReport."""
    if nmap_report is None:
        return {}

    logger.info(f"Started Nmap {nmap_report.version} at {nmap_report.started}")
    network: dict[str, dict[str, Any]] = {}
    nmap_hostnames: dict[str, list[str]] = {}

    for host in nmap_report.hosts:
        if host.status == "up" and host.mac:
            mac = host.mac.upper()
            network[mac] = {
                "ip": host.address,
                "dns_name": "",
                "mdns_name": "",
                "timestamp": datetime.fromtimestamp(nmap_report.started).isoformat(sep=" "),
            }
            if host.vendor:
                network[mac]["vendor"] = host.vendor
            if getattr(host, "hostnames", None):
                nmap_hostnames[host.address] = [str(h) for h in host.hostnames if h]

    if resolve_names and network:
        active_ips = [info["ip"] for info in network.values() if info.get("ip")]
        dns_map, mdns_map, raw_by_ip = resolve_dns_and_mdns(active_ips, nmap_hostnames=nmap_hostnames)
        for mac, info in network.items():
            ip = info.get("ip", "")
            if ip in dns_map:
                info["dns_name"] = dns_map[ip]
            if ip in mdns_map:
                info["mdns_name"] = mdns_map[ip]
            enrich_host_from_names(info, raw_by_ip.get(ip))
            resolved_v = resolve_vendor(mac, info.get("vendor"))
            if not is_unset(resolved_v):
                info["vendor"] = resolved_v
    else:
        for info in network.values():
            ip = info.get("ip", "")
            if ip in nmap_hostnames:
                enrich_host_from_names(info, nmap_hostnames[ip])

    logger.info(nmap_report.summary)
    logger.info(f"Discovered {len(network)} active hosts with MAC addresses.")
    return network


def read_sheet(service: Any, sheet_id: str) -> dict[str, dict[str, Any]]:
    """Read existing device mapping from the 'Network' tab in Google Sheets (supports 6- or 8-column header)."""
    logger.info(f"Fetching existing devices from sheet: {sheet_id}")
    result = (
        service.spreadsheets()
        .values()
        .get(spreadsheetId=sheet_id, range="Network")
        .execute()
    )
    rows = result.get("values", [])
    if not rows:
        logger.warning("No rows returned from sheet; initializing empty network inventory.")
        return {}

    header = [col.strip().lower() for col in rows[0]]
    col_idx = {name: idx for idx, name in enumerate(header)}

    def _cell(row: list[str], col_name: str, fallback_idx: int | None, default: Any) -> Any:
        idx = col_idx.get(col_name, fallback_idx)
        if idx is not None and idx < len(row) and row[idx] != "":
            return row[idx]
        return default

    is_legacy_6col = "dns_name" not in col_idx and "mdns_name" not in col_idx
    network: dict[str, dict[str, Any]] = {}
    for row in rows[1:]:
        if not row or not row[0]:
            continue
        mac = row[0].strip().upper()
        if is_legacy_6col:
            network[mac] = {
                "ip": _cell(row, "ip", 1, ""),
                "dns_name": "",
                "mdns_name": "",
                "name": _cell(row, "name", 2, "Unknown"),
                "type": _cell(row, "type", 3, "Unknown"),
                "vendor": _cell(row, "vendor", 4, "Unknown"),
                "timestamp": _cell(row, "timestamp", 5, None),
            }
        else:
            network[mac] = {
                "ip": _cell(row, "ip", 1, ""),
                "dns_name": _cell(row, "dns_name", 2, ""),
                "mdns_name": _cell(row, "mdns_name", 3, ""),
                "name": _cell(row, "name", 4, "Unknown"),
                "type": _cell(row, "type", 5, "Unknown"),
                "vendor": _cell(row, "vendor", 6, "Unknown"),
                "timestamp": _cell(row, "timestamp", 7, None),
            }

    logger.info(f"Loaded {len(network)} existing device records from sheet.")
    return network


def merge_network_data(
    existing_network: dict[str, dict[str, Any]],
    scan_network: dict[str, dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], list[str], list[str]]:
    """
    Merge newly scanned devices into existing network inventory.
    Preserves manual user tags ('name', 'type') from existing_network.
    Updates live reachability ('ip', 'dns_name', 'mdns_name', 'timestamp') and 'vendor'.
    Returns:
      (merged_network, new_macs_list, updated_macs_list)
    """
    merged: dict[str, dict[str, Any]] = {}
    for mac, details in existing_network.items():
        rec = dict(details)
        existing_ip = rec.get("ip", "")
        raw_dns = rec.get("dns_name", "")
        cleaned_dns_label = clean_hostname(raw_dns, ip=existing_ip)
        rec["dns_name"] = f"{cleaned_dns_label}.home" if cleaned_dns_label else ""
        rec["mdns_name"] = clean_mdns_hostname(rec.get("mdns_name", ""), ip=existing_ip)
        if is_unset(rec.get("vendor")):
            rec["vendor"] = resolve_vendor(mac, rec.get("vendor"))
        merged[mac] = rec

    new_devices: list[str] = []
    updated_devices: list[str] = []

    for mac, device in scan_network.items():
        scanned_vendor = resolve_vendor(mac, device.get("vendor"))
        if mac in merged:
            merged[mac]["ip"] = device["ip"]
            merged[mac]["timestamp"] = device["timestamp"]
            if device.get("dns_name"):
                merged[mac]["dns_name"] = device["dns_name"]
            if device.get("mdns_name"):
                merged[mac]["mdns_name"] = device["mdns_name"]
            if is_unset(merged[mac].get("name")) and not is_unset(device.get("name")):
                merged[mac]["name"] = device["name"]
            if is_unset(merged[mac].get("type")) and not is_unset(device.get("type")):
                merged[mac]["type"] = device["type"]
            if not is_unset(scanned_vendor) and (
                is_unset(merged[mac].get("vendor"))
                or merged[mac].get("vendor") == PRIVATE_MAC_VENDOR
                or scanned_vendor != PRIVATE_MAC_VENDOR
            ):
                merged[mac]["vendor"] = scanned_vendor
            updated_devices.append(mac)
        else:
            logger.info(f"New device found: {mac} (IP: {device.get('ip')}, Vendor: {scanned_vendor})")
            merged[mac] = {
                "ip": device["ip"],
                "dns_name": device.get("dns_name", ""),
                "mdns_name": device.get("mdns_name", ""),
                "name": device.get("name") if not is_unset(device.get("name")) else "Unknown",
                "type": device.get("type") if not is_unset(device.get("type")) else "Unknown",
                "vendor": scanned_vendor,
                "timestamp": device["timestamp"],
            }
            new_devices.append(mac)

    return merged, new_devices, updated_devices


def write_sheet(
    service: Any,
    sheet_id: str,
    network: dict[str, dict[str, Any]],
    dry_run: bool = False,
) -> int:
    """
    Write updated inventory values to the 'Network' tab in Google Sheets.
    If dry_run is True, logs the planned change without issuing the update call.
    Returns updated cell count (or planned cell count if dry_run).
    """
    values = [list(SHEET_HEADERS)]
    for mac, device in network.items():
        values.append([
            mac,
            device.get("ip", ""),
            device.get("dns_name", ""),
            device.get("mdns_name", ""),
            device.get("name", "Unknown"),
            device.get("type", "Unknown"),
            device.get("vendor", "Unknown"),
            device.get("timestamp", ""),
        ])

    total_cells = len(values) * len(SHEET_HEADERS)
    if dry_run:
        logger.info(f"[DRY-RUN] Simulating write: would update {len(values)} rows ({total_cells} cells) in sheet {sheet_id}.")
        return total_cells

    logger.info(f"Writing {len(values)} rows to Google Sheets...")
    result = (
        service.spreadsheets()
        .values()
        .update(
            spreadsheetId=sheet_id,
            range="Network",
            valueInputOption="USER_ENTERED",
            body={"values": values},
        )
        .execute()
    )
    updated_cells = result.get("updatedCells", 0)
    logger.info(f"Successfully updated {updated_cells} cells.")
    return updated_cells


def run_once(args: Any) -> int:
    """Execute a single scan and sheet synchronization pass."""
    parsed_scan = scan(args.network, mock_file=args.mock_scan)
    new_network = build_network(parsed_scan, resolve_names=(args.mock_scan is None))

    if not new_network:
        logger.warning("No network hosts with MAC addresses found. Was this executed with appropriate permissions?")
        return 1

    try:
        service = build("sheets", "v4", cache_discovery=False)
        existing_network = read_sheet(service, args.spreadsheet)
        merged_network, new_macs, updated_macs = merge_network_data(existing_network, new_network)
        logger.info(f"Diff summary: {len(new_macs)} new devices, {len(updated_macs)} updated active hosts.")
        write_sheet(service, args.spreadsheet, merged_network, dry_run=args.dry_run)
    except Exception as e:  # noqa: BLE001
        logger.error(f"Google Sheets synchronization failed: {e}")
        return 1

    return 0


def main(argv: list[str] | None = None, stop_event: threading.Event | None = None) -> int:
    """Main CLI entrypoint."""
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    if args.dry_run:
        logger.info("=== DRY-RUN MODE ACTIVE: No changes will be written to Google Sheets ===")

    credentials_path = args.credentials
    if not os.path.isabs(credentials_path) and not os.path.exists(credentials_path) and args.config:
        config_dir = os.path.dirname(os.path.abspath(args.config))
        candidate = os.path.join(config_dir, credentials_path)
        if os.path.exists(candidate):
            credentials_path = candidate

    if not os.path.exists(credentials_path):
        logger.error(f"Credentials file not found: {credentials_path}")
        return 1

    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = credentials_path

    if args.interval <= 0:
        return run_once(args)

    event = stop_event or threading.Event()

    def _handle_signal(signum: int, _frame: Any) -> None:
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        event.set()

    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGINT, _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)

    logger.info(f"Starting continuous daemon mode (interval: {args.interval}s)")
    while not event.is_set():
        run_once(args)
        if event.is_set():
            break
        logger.info(f"Sleeping {args.interval} seconds until next scan...")
        event.wait(args.interval)

    logger.info("Daemon stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

