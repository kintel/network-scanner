from pathlib import Path

from network_scanner import build_network, scan

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
    assert network["00:0D:B9:18:E6:CD"]["vendor"] == "PC Engines GmbH"
    assert "timestamp" in network["00:0D:B9:18:E6:CD"]

    assert "00:24:1D:76:BF:25" in network
    assert network["00:24:1D:76:BF:25"]["ip"] == "10.20.30.3"
    assert "vendor" not in network["00:24:1D:76:BF:25"]


def test_build_network_empty():
    assert build_network(None) == {}
