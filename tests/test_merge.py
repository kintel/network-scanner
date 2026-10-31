from network_scanner import merge_network_data


def test_merge_new_devices():
    existing = {}
    scanned = {
        "AA:BB:CC:DD:EE:01": {
            "ip": "192.168.2.50",
            "timestamp": "2026-10-25 04:00:00",
            "vendor": "Acme Corp",
        }
    }
    merged, new_devs, updated_devs = merge_network_data(existing, scanned)

    assert len(merged) == 1
    assert "AA:BB:CC:DD:EE:01" in new_devs
    assert len(updated_devs) == 0

    record = merged["AA:BB:CC:DD:EE:01"]
    assert record["ip"] == "192.168.2.50"
    assert record["dns_name"] == ""
    assert record["mdns_name"] == ""
    assert record["name"] == "Unknown"
    assert record["type"] == "Unknown"
    assert record["vendor"] == "Acme Corp"
    assert record["timestamp"] == "2026-10-25 04:00:00"


def test_merge_preserves_custom_annotations():
    existing = {
        "AA:BB:CC:DD:EE:01": {
            "ip": "192.168.2.50",
            "dns_name": "old-cam.home",
            "mdns_name": "old-cam.local",
            "name": "Living Room Camera",
            "type": "Security",
            "vendor": "Acme Old",
            "timestamp": "2026-10-24 12:00:00",
        }
    }
    scanned = {
        "AA:BB:CC:DD:EE:01": {
            "ip": "192.168.2.55",  # DHCP lease changed
            "dns_name": "new-cam.home",
            "mdns_name": "",  # mDNS temporarily not seen; preserve previous
            "timestamp": "2026-10-25 04:00:00",
            "vendor": "Acme Corp",
        }
    }
    merged, new_devs, updated_devs = merge_network_data(existing, scanned)

    assert len(new_devs) == 0
    assert "AA:BB:CC:DD:EE:01" in updated_devs

    record = merged["AA:BB:CC:DD:EE:01"]
    assert record["ip"] == "192.168.2.55"
    assert record["dns_name"] == "new-cam.home"  # updated live
    assert record["mdns_name"] == "old-cam.local"  # preserved when empty
    assert record["name"] == "Living Room Camera"  # preserved
    assert record["type"] == "Security"  # preserved
    assert record["vendor"] == "Acme Corp"  # updated
    assert record["timestamp"] == "2026-10-25 04:00:00"  # updated

