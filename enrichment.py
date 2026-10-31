"""
Device Hostname Normalization, Unicast DNS (.home), mDNS (.local), and
Hostname-Based Type/Vendor Inference for network-scanner.
"""

from __future__ import annotations

import json
import logging
import os
import re
import socket
import struct
import time
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from typing import Any

logger = logging.getLogger("network_scanner")

MDNS_SERVICE_TYPES = (
    "_googlecast._tcp.local",
    "_hap._tcp.local",
    "_airplay._tcp.local",
    "_raop._tcp.local",
    "_ipp._tcp.local",
    "_printer._tcp.local",
    "_home-assistant._tcp.local",
    "_device-info._tcp.local",
)

PRIVATE_MAC_VENDOR = "Private / Randomized MAC"

# Built-in OUI overrides for modern / virtual prefixes so offline unit tests and
# environments without /app/manuf still resolve known homelab hardware accurately.
KNOWN_OUI_OVERRIDES: dict[str, str] = {
    "0241A2": "Home Assistant",
    "2010B1": "Amazon Technologies Inc.",
    "308398": "Espressif Inc.",
    "30C599": "ASUSTek COMPUTER INC.",
    "30C9AB": "Cloud Network Technology Singapore PTE.",
    "38182B": "Espressif Inc.",
    "409151": "Espressif Inc.",
    "4C0F3E": "Intel Corporate",
    "707DA1": "Sagemcom Broadband SAS",
    "788DAF": "Sagemcom Broadband SAS",
    "943CC6": "Espressif Inc.",
    "BC2411": "Proxmox Server Solutions GmbH",
    "BC351E": "Tuya Smart Inc.",
    "BCFCE7": "ASUSTek COMPUTER INC.",
    "CCBABD": "TP-Link Systems Inc.",
    "D0CF13": "Espressif Inc.",
    "D0EF76": "Espressif Inc.",
    "E831CD": "Espressif Inc.",
}

_OUI_CACHE: dict[str, str] | None = None
_OUI_PATHS = (
    "/app/manuf",
    "/usr/share/nmap/nmap-mac-prefixes",
    "/opt/homebrew/share/nmap/nmap-mac-prefixes",
    "/usr/local/share/nmap/nmap-mac-prefixes",
)

# Placeholders that should never be used as a device's descriptive 'name'
# or as a deterministic '.home' script-reachability hostname.
GENERIC_HOSTNAMES = {
    "unknown",
    "localhost",
    "mynetwork",
    "wlan0",
    "eth0",
    "android",
    "iphone",
    "ipad",
    "macbookpro",
    "macbookair",
    "mac",
}

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_MAC_DASH_RE = re.compile(r"^[0-9a-f]{2}(?:[-:][0-9a-f]{2}){5}$", re.IGNORECASE)
_MAC_HEX_RE = re.compile(r"^[0-9a-f]{12}$", re.IGNORECASE)
_UUID_RE = re.compile(
    r"^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{32})$",
    re.IGNORECASE,
)
_ANDROID_HEX_RE = re.compile(r"^android_[0-9a-f]{16,}$", re.IGNORECASE)
_GENERIC_NUMBERED_RE = re.compile(r"^(?:iphone|ipad|macbookpro|macbookair|mac|android)-\d+$", re.IGNORECASE)


def is_unset(value: str | None) -> bool:
    """Return True if a sheet field is empty, None, or 'Unknown'."""
    return value is None or str(value).strip() in ("", "Unknown")


def _normalize_oui_prefix(mac_or_prefix: str) -> str:
    """Extract uppercase 6-hex-character (24-bit) OUI prefix from a MAC string."""
    hex_only = re.sub(r"[^0-9A-Fa-f]", "", mac_or_prefix).upper()
    return hex_only[:6] if len(hex_only) >= 6 else ""


def load_oui_database(extra_paths: tuple[str, ...] = ()) -> dict[str, str]:
    """
    Load 24-bit OUI prefix -> vendor mapping from Nmap and Wireshark manuf files,
    layered with KNOWN_OUI_OVERRIDES.
    """
    global _OUI_CACHE
    if _OUI_CACHE is not None and not extra_paths:
        return _OUI_CACHE

    db: dict[str, str] = {}
    for path in (*_OUI_PATHS, *extra_paths):
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "\t" in line:
                        # Wireshark manuf format: AA:BB:CC\tShortName\tFull Vendor Name
                        parts = [p.strip() for p in line.split("\t") if p.strip()]
                        if len(parts) >= 2 and "/" not in parts[0]:
                            prefix = _normalize_oui_prefix(parts[0])
                            if len(prefix) == 6:
                                db[prefix] = parts[-1]
                    else:
                        # Nmap nmap-mac-prefixes format: AABBCC Vendor Name
                        parts = line.split(None, 1)
                        if len(parts) == 2 and len(parts[0]) == 6:
                            prefix = _normalize_oui_prefix(parts[0])
                            if len(prefix) == 6 and prefix not in db:
                                db[prefix] = parts[1].strip()
        except OSError as exc:
            logger.debug(f"Could not read OUI file {path}: {exc}")

    db.update(KNOWN_OUI_OVERRIDES)
    if not extra_paths:
        _OUI_CACHE = db
    return db


def lookup_oui_vendor(mac: str) -> str:
    """Look up a MAC address's 24-bit OUI in the modern OUI database."""
    prefix = _normalize_oui_prefix(mac)
    if len(prefix) != 6:
        return ""
    return load_oui_database().get(prefix, "")


def is_randomized_mac(mac: str) -> bool:
    """
    Return True if `mac` has the IEEE locally administered bit set (byte0 & 0x02 != 0)
    AND does not match a known registered OUI (such as HAOS 02:41:A2).
    """
    prefix = _normalize_oui_prefix(mac)
    if len(prefix) < 2:
        return False
    if lookup_oui_vendor(mac):
        return False
    try:
        first_byte = int(prefix[:2], 16)
        return bool(first_byte & 0x02)
    except ValueError:
        return False


def resolve_vendor(mac: str, existing_or_nmap_vendor: str | None = None) -> str:
    """
    Resolve the vendor for `mac`:
      1. Preserve existing/Nmap vendor if already known (and not 'Private / Randomized MAC').
      2. Query the modern OUI database (Wireshark manuf + Nmap prefixes + overrides).
      3. If locally administered bit is set, return 'Private / Randomized MAC'.
      4. Otherwise return 'Unknown'.
    """
    if (
        existing_or_nmap_vendor
        and not is_unset(existing_or_nmap_vendor)
        and existing_or_nmap_vendor != PRIVATE_MAC_VENDOR
    ):
        return existing_or_nmap_vendor

    oui_vendor = lookup_oui_vendor(mac)
    if oui_vendor:
        return oui_vendor

    if is_randomized_mac(mac):
        return PRIVATE_MAC_VENDOR

    return "Unknown"


def strip_domain_suffix(raw_hostname: str) -> str:
    """Strip trailing dots and known local domain suffixes (.home, .local, .lan, .home.arpa)."""
    host = raw_hostname.strip().rstrip(".")
    for suffix in (".home.arpa", ".local", ".home", ".lan"):
        if host.lower().endswith(suffix):
            host = host[: -len(suffix)]
            break
    return host.strip(".")


def clean_hostname(raw_hostname: str | None, ip: str = "") -> str:
    """
    Normalize a raw hostname for use as a descriptive device 'name'.
    Returns '' if the hostname is noise, an IP/MAC literal, UUID, or a generic placeholder.
    """
    if not raw_hostname:
        return ""
    raw = raw_hostname.strip().rstrip(".")
    if not raw or raw.lower().endswith(".in-addr.arpa"):
        return ""

    base = strip_domain_suffix(raw)
    if not base:
        return ""

    lower = base.lower()
    if base == ip or _IPV4_RE.match(base):
        return ""
    if _MAC_DASH_RE.match(base) or _MAC_HEX_RE.match(base):
        return ""
    if _UUID_RE.match(base) or _ANDROID_HEX_RE.match(base):
        return ""
    if lower in GENERIC_HOSTNAMES or _GENERIC_NUMBERED_RE.match(lower):
        return ""

    return base


def clean_mdns_hostname(raw_mdns: str | None, ip: str = "") -> str:
    """
    Validate and normalize an mDNS (.local) hostname for script reachability.
    Filters out ephemeral UUIDs and Android_<hex>.local names.
    """
    if not raw_mdns:
        return ""
    cleaned = clean_hostname(raw_mdns, ip=ip)
    if not cleaned:
        return ""
    return f"{cleaned}.local"


def infer_from_hostname(raw_hostname: str | None) -> dict[str, str]:
    """
    Infer 'type' and/or 'vendor' from known hostname patterns (including generic
    Apple/Android hostnames that clean_hostname() filters out as descriptive names).
    """
    if not raw_hostname:
        return {}
    base = strip_domain_suffix(raw_hostname)
    if not base:
        return {}
    lower = base.lower()

    if re.match(r"^esp32c5[-_]", lower):
        return {"type": "ESP32-C5 Dev Board", "vendor": "Espressif"}
    if re.match(r"^esp32[-_]", lower) or re.match(r"^esp[-_]", lower):
        return {"type": "ESP32 / IoT Dev Board", "vendor": "Espressif"}
    if re.match(r"^esp8266[-_]", lower):
        return {"type": "ESP8266 / IoT Dev Board", "vendor": "Espressif"}
    if re.match(r"^brw[0-9a-f]{12}$", lower):
        return {"type": "Printer", "vendor": "Brother"}
    if re.match(r"^yoto[-_]", lower) or lower == "yoto":
        return {"type": "Yoto Player", "vendor": "Yoto"}
    if lower == "kp400":
        return {"type": "TP-Link KP400", "vendor": "TP-Link"}
    if re.match(r"^ps4[-_]", lower) or lower == "ps4":
        return {"type": "PS4", "vendor": "Sony Interactive Entertainment"}
    if re.match(r"^rt-be58u", lower) or lower == "asus":
        return {"vendor": "ASUS"}
    if lower.startswith("nest-thermostat"):
        return {"type": "Nest Thermostat", "vendor": "Google"}
    if lower.startswith("nest-wifi"):
        return {"type": "Google Nest Point", "vendor": "Google"}
    if lower.startswith("nest-hello"):
        return {"type": "Nest Hello", "vendor": "Nest Labs"}
    if lower.startswith("chromecast"):
        return {"type": "Chromecast", "vendor": "Google"}
    if lower.startswith("ultimaker"):
        return {"type": "Ultimaker", "vendor": "Ultimaker"}
    if lower.startswith("amazon-"):
        return {"type": "Amazon Echo", "vendor": "Amazon Technologies Inc."}
    if lower.startswith(("iphone", "jphone")):
        return {"type": "iPhone", "vendor": "Apple"}
    if lower.startswith("ipad"):
        return {"type": "iPad", "vendor": "Apple"}
    if "macbook-pro" in lower or lower.startswith("macbookpro"):
        return {"type": "MacBook Pro", "vendor": "Apple"}
    if "macbook-air" in lower or lower.startswith("macbookair"):
        return {"type": "MacBook Air", "vendor": "Apple"}
    if lower.startswith("android"):
        return {"type": "Android Device"}

    return {}


def resolve_dns_name(ip: str, nmap_hostnames: list[str] | None = None) -> tuple[str, list[str]]:
    """
    Resolve and forward-verify a script-reachable '<label>.home' DNS name for `ip`.
    Returns (verified_dns_name, all_raw_hostnames_seen).
    """
    raw_candidates: list[str] = list(nmap_hostnames or [])
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        if host and host not in raw_candidates:
            raw_candidates.append(host)
    except OSError:
        pass

    for raw in raw_candidates:
        label = clean_hostname(raw, ip=ip)
        if not label or "." in label:
            continue
        candidate = f"{label}.home"
        try:
            if socket.gethostbyname(candidate) == ip:
                return candidate, raw_candidates
        except OSError:
            continue

    return "", raw_candidates


def _build_mdns_query(qname_str: str, qtype: int, txid: int = 0) -> bytes:
    """Build a raw DNS/mDNS query packet."""
    header = struct.pack("!HHHHHH", txid, 0x0000, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode("utf-8") for p in qname_str.strip(".").split(".")) + b"\x00"
    return header + qname + struct.pack("!HH", qtype, 0x0001)


def _decode_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a potentially compressed DNS name from packet bytes."""
    labels: list[str] = []
    jumped = False
    orig_offset = offset
    seen: set[int] = set()
    while offset < len(data) and offset not in seen:
        seen.add(offset)
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            if not jumped:
                orig_offset = offset + 2
                jumped = True
            offset = ((length & 0x3F) << 8) | data[offset + 1]
            continue
        offset += 1
        labels.append(data[offset : offset + length].decode("utf-8", errors="replace"))
        offset += length
    return ".".join(labels), (orig_offset if jumped else offset)


def resolve_dns_and_mdns(
    ips: list[str],
    nmap_hostnames: dict[str, list[str]] | None = None,
    mdns_timeout: float = 1.5,
) -> tuple[dict[str, str], dict[str, str], dict[str, list[str]]]:
    """
    Resolve verified .home (unicast DNS) and .local (mDNS) hostnames for active IPs.
    Returns (dns_names_by_ip, mdns_names_by_ip, raw_hostnames_by_ip).
    """
    dns_names: dict[str, str] = {}
    raw_by_ip: dict[str, list[str]] = {}
    candidate_labels: dict[str, str] = {}

    for ip in ips:
        verified_dns, raws = resolve_dns_name(ip, (nmap_hostnames or {}).get(ip))
        if raws:
            raw_by_ip[ip] = raws
        if verified_dns:
            dns_names[ip] = verified_dns
            candidate_labels[ip] = strip_domain_suffix(verified_dns)

    mdns_names: dict[str, str] = {}
    if not ips or mdns_timeout <= 0:
        return dns_names, mdns_names, raw_by_ip

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass
        try:
            sock.bind(("", 5353))
            mreq = struct.pack("4s4s", socket.inet_aton("224.0.0.251"), socket.inet_aton("0.0.0.0"))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except OSError:
            sock.bind(("", 0))
        sock.settimeout(0.1)

        ip_set = set(ips)
        for idx, ip in enumerate(ips):
            rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
            try:
                sock.sendto(_build_mdns_query(rev, 12, idx + 1), ("224.0.0.251", 5353))
                if ip in candidate_labels:
                    sock.sendto(_build_mdns_query(f"{candidate_labels[ip]}.local", 1, idx + 2000), ("224.0.0.251", 5353))
            except OSError:
                pass

        deadline = time.monotonic() + mdns_timeout
        while time.monotonic() < deadline:
            try:
                data, _ = sock.recvfrom(4096)
                if len(data) < 12:
                    continue
                _, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
                if (flags & 0x8000) == 0:
                    continue
                offset = 12
                for _ in range(qdcount):
                    _, offset = _decode_dns_name(data, offset)
                    offset += 4
                for _ in range(ancount + nscount + arcount):
                    if offset >= len(data):
                        break
                    rr_name, offset = _decode_dns_name(data, offset)
                    if offset + 10 > len(data):
                        break
                    rtype, _, _, rdlen = struct.unpack("!HHIH", data[offset : offset + 10])
                    offset += 10
                    if rtype == 12 and rr_name.endswith(".in-addr.arpa"):
                        target, _ = _decode_dns_name(data, offset)
                        parts = rr_name[: -len(".in-addr.arpa")].split(".")
                        if len(parts) == 4:
                            ip_str = ".".join(reversed(parts))
                            if ip_str in ip_set:
                                raw_by_ip.setdefault(ip_str, []).append(target.rstrip("."))
                                cleaned_mdns = clean_mdns_hostname(target, ip=ip_str)
                                if cleaned_mdns:
                                    mdns_names[ip_str] = cleaned_mdns
                    elif rtype == 1 and rdlen == 4 and rr_name.lower().endswith(".local"):
                        ip_str = socket.inet_ntoa(data[offset : offset + 4])
                        if ip_str in ip_set:
                            raw_by_ip.setdefault(ip_str, []).append(rr_name.rstrip("."))
                            if ip_str not in mdns_names:
                                cleaned_mdns = clean_mdns_hostname(rr_name, ip=ip_str)
                                if cleaned_mdns:
                                    mdns_names[ip_str] = cleaned_mdns
                    offset += rdlen
            except TimeoutError:
                continue
            except (OSError, struct.error) as exc:
                logger.debug(f"Ignoring malformed mDNS packet: {exc}")
                continue
    finally:
        sock.close()

    return dns_names, mdns_names, raw_by_ip


def enrich_host_from_names(
    info: dict[str, str],
    raw_hostnames: list[str] | None = None,
) -> None:
    """
    Populate 'name', 'type', and 'vendor' on an active host record using its
    resolved dns_name, mdns_name, and raw Nmap/PTR hostnames (when unset).
    """
    ip = info.get("ip", "")
    candidates: list[str] = []
    if info.get("dns_name"):
        candidates.append(info["dns_name"])
    if info.get("mdns_name"):
        candidates.append(info["mdns_name"])
    if raw_hostnames:
        for raw in raw_hostnames:
            if raw and raw not in candidates:
                candidates.append(raw)

    if is_unset(info.get("name")):
        for cand in candidates:
            cleaned = clean_hostname(cand, ip=ip)
            if cleaned:
                info["name"] = cleaned
                break

    for cand in candidates:
        inferred = infer_from_hostname(cand)
        if inferred.get("type") and is_unset(info.get("type")):
            info["type"] = inferred["type"]
        if inferred.get("vendor") and is_unset(info.get("vendor")):
            info["vendor"] = inferred["vendor"]


def _parse_mdns_txt(rdata: bytes) -> dict[str, str]:
    """Parse DNS TXT record rdata (length-prefixed key=value strings) into a dict."""
    props: dict[str, str] = {}
    idx = 0
    while idx < len(rdata):
        length = rdata[idx]
        idx += 1
        if length == 0 or idx + length > len(rdata):
            break
        entry = rdata[idx : idx + length].decode("utf-8", errors="replace")
        idx += length
        if "=" in entry:
            k, v = entry.split("=", 1)
            props[k.strip()] = v.strip()
    return props


def extract_mdns_service_metadata(rr_name: str, txt: dict[str, str]) -> dict[str, str]:
    """Extract friendly name, model/type, and vendor from an mDNS service TXT record."""
    meta: dict[str, str] = {}
    lower_name = rr_name.lower()

    if "_googlecast._tcp" in lower_name:
        if txt.get("fn"):
            meta["name"] = txt["fn"]
        if txt.get("md"):
            meta["type"] = txt["md"]
    elif "_ipp._tcp" in lower_name or "_printer._tcp" in lower_name:
        model = txt.get("ty") or txt.get("usb_MDL") or txt.get("product", "").strip("()")
        if model:
            meta["type"] = model
        if txt.get("usb_MFG"):
            meta["vendor"] = txt["usb_MFG"]
    elif "_airplay._tcp" in lower_name or "_raop._tcp" in lower_name or "_hap._tcp" in lower_name:
        model = txt.get("model") or txt.get("am") or txt.get("md")
        if model:
            meta["type"] = model
        if txt.get("manufacturer"):
            meta["vendor"] = txt["manufacturer"]
    elif "_home-assistant._tcp" in lower_name:
        meta["type"] = "Home Assistant HAOS"
        meta["vendor"] = "Home Assistant"
    elif "_device-info._tcp" in lower_name and txt.get("model"):
        meta["type"] = txt["model"]

    return meta


def parse_upnp_xml(xml_text: str) -> dict[str, str]:
    """Parse UPnP root device XML description for friendlyName, modelName, and manufacturer."""
    meta: dict[str, str] = {}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return meta

    for elem in root.iter():
        tag = elem.tag.split("}", 1)[-1] if "}" in elem.tag else elem.tag
        val = (elem.text or "").strip()
        if not val:
            continue
        if tag == "friendlyName" and "name" not in meta:
            meta["name"] = val
        elif tag == "modelName" and "type" not in meta:
            meta["type"] = val
        elif tag == "manufacturer" and "vendor" not in meta:
            meta["vendor"] = val
    return meta


def _fetch_upnp_location(url: str, timeout: float = 1.5) -> dict[str, str]:
    """Fetch and parse a single SSDP LOCATION XML URL with a strict timeout."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "network-scanner/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            xml_bytes = resp.read(65536)
        return parse_upnp_xml(xml_bytes.decode("utf-8", errors="replace"))
    except Exception:  # noqa: BLE001
        return {}


def discover_ssdp_services(active_ips: list[str], timeout: float = 1.5) -> dict[str, dict[str, str]]:
    """
    Send an SSDP M-SEARCH multicast probe (239.255.255.250:1900) and fetch UPnP XML
    device descriptors in parallel for active hosts.
    """
    if not active_ips or timeout <= 0:
        return {}

    ip_set = set(active_ips)
    locations_by_ip: dict[str, str] = {}
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode("ascii")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.settimeout(0.15)
        try:
            sock.sendto(msg, ("239.255.255.250", 1900))
        except OSError:
            return {}

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, (src_ip, _) = sock.recvfrom(4096)
                if src_ip not in ip_set or src_ip in locations_by_ip:
                    continue
                text = data.decode("utf-8", errors="replace")
                for line in text.splitlines():
                    if line.lower().startswith("location:"):
                        loc = line.split(":", 1)[1].strip()
                        if loc.startswith(("http://", "https://")):
                            locations_by_ip[src_ip] = loc
                            break
            except TimeoutError:
                continue
            except OSError:
                break
    finally:
        sock.close()

    if not locations_by_ip:
        return {}

    results: dict[str, dict[str, str]] = {}
    with ThreadPoolExecutor(max_workers=min(8, len(locations_by_ip))) as pool:
        futures = {ip: pool.submit(_fetch_upnp_location, url, 1.5) for ip, url in locations_by_ip.items()}
        for ip, fut in futures.items():
            meta = fut.result()
            if meta:
                results[ip] = meta
    return results


def discover_mdns_services(active_ips: list[str], timeout: float = 1.5) -> dict[str, dict[str, str]]:
    """
    Query common mDNS service types (224.0.0.251:5353) and extract service TXT
    metadata (friendly name, model, vendor) keyed by source IPv4 address.
    """
    if not active_ips or timeout <= 0:
        return {}

    ip_set = set(active_ips)
    results: dict[str, dict[str, str]] = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass
        try:
            sock.bind(("", 5353))
            mreq = struct.pack("4s4s", socket.inet_aton("224.0.0.251"), socket.inet_aton("0.0.0.0"))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except OSError:
            sock.bind(("", 0))
        sock.settimeout(0.1)

        for idx, svc in enumerate(MDNS_SERVICE_TYPES):
            try:
                sock.sendto(_build_mdns_query(svc, 12, 5000 + idx), ("224.0.0.251", 5353))
            except OSError:
                pass

        queried_instances: set[str] = set()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, (src_ip, _) = sock.recvfrom(4096)
                if len(data) < 12 or src_ip not in ip_set:
                    continue
                _, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
                if (flags & 0x8000) == 0:
                    continue
                offset = 12
                for _ in range(qdcount):
                    _, offset = _decode_dns_name(data, offset)
                    offset += 4
                for _ in range(ancount + nscount + arcount):
                    if offset >= len(data):
                        break
                    rr_name, offset = _decode_dns_name(data, offset)
                    if offset + 10 > len(data):
                        break
                    rtype, _, _, rdlen = struct.unpack("!HHIH", data[offset : offset + 10])
                    offset += 10
                    if rtype == 12 and any(rr_name.lower().startswith(s) for s in MDNS_SERVICE_TYPES):
                        inst, _ = _decode_dns_name(data, offset)
                        if inst and inst not in queried_instances:
                            queried_instances.add(inst)
                            try:
                                sock.sendto(_build_mdns_query(inst, 16, 6000), ("224.0.0.251", 5353))
                            except OSError:
                                pass
                    elif rtype == 16 and offset + rdlen <= len(data):
                        txt = _parse_mdns_txt(data[offset : offset + rdlen])
                        meta = extract_mdns_service_metadata(rr_name, txt)
                        if meta:
                            cur = results.setdefault(src_ip, {})
                            for k, v in meta.items():
                                if v and not cur.get(k):
                                    cur[k] = v
                    offset += rdlen
            except TimeoutError:
                continue
            except (OSError, struct.error):
                continue
    finally:
        sock.close()

    return results


def kasa_xor_encrypt(plaintext: str) -> bytes:
    """Encrypt a JSON string with TP-Link Kasa's autokey XOR cipher (key=171)."""
    key = 171
    out = bytearray()
    for b in plaintext.encode("utf-8"):
        key ^= b
        out.append(key)
    return bytes(out)


def kasa_xor_decrypt(ciphertext: bytes) -> str:
    """Decrypt TP-Link Kasa autokey XOR ciphertext (key=171) into a JSON string."""
    key = 171
    out = bytearray()
    for b in ciphertext:
        out.append(key ^ b)
        key = b
    return out.decode("utf-8", errors="replace")


def probe_kasa_sysinfo(ip: str, timeout: float = 0.6) -> dict[str, str]:
    """Query UDP port 9999 on `ip` for TP-Link Kasa system get_sysinfo JSON."""
    payload = kasa_xor_encrypt('{"system":{"get_sysinfo":{}}}')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(payload, (ip, 9999))
            resp, _ = sock.recvfrom(4096)
            data = json.loads(kasa_xor_decrypt(resp))
            sysinfo = data.get("system", {}).get("get_sysinfo", {})
            meta: dict[str, str] = {}
            if sysinfo.get("alias"):
                meta["name"] = str(sysinfo["alias"])
            if sysinfo.get("model"):
                meta["type"] = str(sysinfo["model"])
            if meta:
                meta["vendor"] = "TP-Link Systems Inc."
            return meta
        except Exception:  # noqa: BLE001
            return {}


def probe_tuya_port(ip: str, timeout: float = 0.35) -> bool:
    """Return True if Tuya local TCP port 6668 is open on `ip`."""
    try:
        with socket.create_connection((ip, 6668), timeout=timeout):
            return True
    except OSError:
        return False


def enrich_active_network_protocols(network: dict[str, dict[str, Any]]) -> None:
    """
    Run bounded mDNS service discovery, SSDP/UPnP discovery, and Kasa/Tuya IoT
    probes across active hosts in `network`.
    """
    active_ips = [info["ip"] for info in network.values() if info.get("ip")]
    if not active_ips:
        return

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_mdns = pool.submit(discover_mdns_services, active_ips, 1.5)
        fut_ssdp = pool.submit(discover_ssdp_services, active_ips, 1.5)
        mdns_svc_map = fut_mdns.result()
        ssdp_map = fut_ssdp.result()

    for info in network.values():
        ip = info.get("ip", "")
        for svc_map in (mdns_svc_map, ssdp_map):
            meta = svc_map.get(ip, {})
            if meta.get("name") and is_unset(info.get("name")):
                info["name"] = meta["name"]
            if meta.get("type") and is_unset(info.get("type")):
                info["type"] = meta["type"]
            if meta.get("vendor") and (
                is_unset(info.get("vendor")) or info.get("vendor") == PRIVATE_MAC_VENDOR
            ):
                info["vendor"] = meta["vendor"]

        # Step 4: IoT local protocol probes for hosts still missing name or type
        if is_unset(info.get("name")) or is_unset(info.get("type")):
            kasa_meta = probe_kasa_sysinfo(ip, timeout=0.4)
            if kasa_meta:
                if kasa_meta.get("name") and is_unset(info.get("name")):
                    info["name"] = kasa_meta["name"]
                if kasa_meta.get("type") and is_unset(info.get("type")):
                    info["type"] = kasa_meta["type"]
                if kasa_meta.get("vendor") and is_unset(info.get("vendor")):
                    info["vendor"] = kasa_meta["vendor"]
            elif is_unset(info.get("type")) and (
                info.get("vendor") == "Tuya Smart Inc." or probe_tuya_port(ip, timeout=0.25)
            ):
                info["type"] = "Tuya Smart Device"


def backfill_network_data(
    network: dict[str, dict[str, Any]],
    active_ips: set[str] | None = None,
    enable_reverse_dns: bool = True,
) -> tuple[int, int, int]:
    """
    Backfill missing/Unknown name, type, and vendor across all historical rows in `network`.
    Returns (names_enriched, types_enriched, vendors_enriched).
    """
    names_enriched = 0
    types_enriched = 0
    vendors_enriched = 0
    active_ip_set = active_ips or set()

    for mac, rec in network.items():
        ip = rec.get("ip", "")
        ts = str(rec.get("timestamp") or "")

        # 1. Resolve OUI / randomized MAC vendor for historical Unknown rows
        if is_unset(rec.get("vendor")):
            resolved_v = resolve_vendor(mac, rec.get("vendor"))
            if not is_unset(resolved_v):
                rec["vendor"] = resolved_v
                vendors_enriched += 1

        # 2. For recent 2026 rows whose IP isn't currently leased to another active device,
        #    check if reverse DNS (.home) resolves a valid hostname
        if (
            enable_reverse_dns
            and ip.startswith("192.168.2.")
            and ts.startswith("2026")
            and ip not in active_ip_set
            and (is_unset(rec.get("name")) or not rec.get("dns_name"))
        ):
            verified_dns, raws = resolve_dns_name(ip)
            if verified_dns and not rec.get("dns_name"):
                rec["dns_name"] = verified_dns
            before_name = rec.get("name")
            before_type = rec.get("type")
            before_vendor = rec.get("vendor")
            enrich_host_from_names(rec, raws)
            if is_unset(before_name) and not is_unset(rec.get("name")):
                names_enriched += 1
            if is_unset(before_type) and not is_unset(rec.get("type")):
                types_enriched += 1
            if is_unset(before_vendor) and not is_unset(rec.get("vendor")):
                vendors_enriched += 1

        # 3. Infer type/vendor from existing name, dns_name, mdns_name, or vendor
        before_name = rec.get("name")
        before_type = rec.get("type")
        before_vendor = rec.get("vendor")
        enrich_host_from_names(rec, [rec.get("name", "")])
        if is_unset(rec.get("type")) and rec.get("vendor") == "Tuya Smart Inc.":
            rec["type"] = "Tuya Smart Device"
        if is_unset(before_name) and not is_unset(rec.get("name")):
            names_enriched += 1
        if is_unset(before_type) and not is_unset(rec.get("type")):
            types_enriched += 1
        if (is_unset(before_vendor) or before_vendor == PRIVATE_MAC_VENDOR) and (
            not is_unset(rec.get("vendor")) and rec.get("vendor") != before_vendor
        ):
            vendors_enriched += 1

    return names_enriched, types_enriched, vendors_enriched






