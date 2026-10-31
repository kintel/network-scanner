import struct
from pathlib import Path
from unittest.mock import patch

from network_scanner import (
    _build_mdns_query,
    _decode_dns_name,
    build_network,
    resolve_dns_and_mdns,
    scan,
)

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "sample_scan.xml"


def test_scan_mock_file():
    report = scan("10.20.30.0/24", mock_file=str(FIXTURE_PATH))
    assert report is not None
    assert len(report.hosts) == 3
    assert report.hosts_up == 2


def test_build_network():
    report = scan("10.20.30.0/24", mock_file=str(FIXTURE_PATH))
    network = build_network(report)

    assert len(network) == 2
    assert "00:0D:B9:18:E6:CD" in network
    assert network["00:0D:B9:18:E6:CD"]["ip"] == "10.20.30.1"
    assert network["00:0D:B9:18:E6:CD"]["dns_name"] == ""
    assert network["00:0D:B9:18:E6:CD"]["mdns_name"] == ""
    assert network["00:0D:B9:18:E6:CD"]["vendor"] == "PC Engines GmbH"
    assert "timestamp" in network["00:0D:B9:18:E6:CD"]

    assert "00:24:1D:76:BF:25" in network
    assert network["00:24:1D:76:BF:25"]["ip"] == "10.20.30.3"
    assert "vendor" not in network["00:24:1D:76:BF:25"]


def test_build_network_empty():
    assert build_network(None) == {}


def test_mdns_query_and_decode():
    pkt = _build_mdns_query("esp-tester-5g.local", 1, txid=42)
    name, offset = _decode_dns_name(pkt, 12)
    assert name == "esp-tester-5g.local"
    qtype, qclass = struct.unpack("!HH", pkt[offset : offset + 4])
    assert qtype == 1
    assert qclass == 1


def test_resolve_dns_and_mdns_forward_verified():
    with (
        patch("enrichment.socket.gethostbyaddr", return_value=("esp-tester-5g.home", [], ["192.168.2.107"])),
        patch("enrichment.socket.gethostbyname", return_value="192.168.2.107"),
    ):
        dns_map, mdns_map, raw_map = resolve_dns_and_mdns(["192.168.2.107"], mdns_timeout=0)
        assert dns_map == {"192.168.2.107": "esp-tester-5g.home"}
        assert mdns_map == {}
        assert raw_map == {"192.168.2.107": ["esp-tester-5g.home"]}


