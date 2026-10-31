"""
Device Hostname Normalization, Unicast DNS (.home), mDNS (.local), and
Hostname-Based Type/Vendor Inference for network-scanner.
"""

from __future__ import annotations

import logging
import re
import socket
import struct
import time

logger = logging.getLogger("network_scanner")

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



