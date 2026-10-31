from unittest.mock import patch

from enrichment import (
    PRIVATE_MAC_VENDOR,
    clean_hostname,
    clean_mdns_hostname,
    enrich_host_from_names,
    infer_from_hostname,
    is_randomized_mac,
    is_unset,
    load_oui_database,
    lookup_oui_vendor,
    resolve_dns_name,
    resolve_vendor,
)
from network_scanner import merge_network_data


def test_is_unset():
    assert is_unset(None)
    assert is_unset("")
    assert is_unset("  ")
    assert is_unset("Unknown")
    assert not is_unset("Ecobee Thermostat")


def test_clean_hostname_filters_noise_and_keeps_valid_names():
    # Rejects IP literals, MAC strings, UUIDs, Android hex, and generic placeholders
    assert clean_hostname("192.168.2.86", ip="192.168.2.86") == ""
    assert clean_hostname("bc-fc-e7-22-be-28.local") == ""
    assert clean_hostname("bcfce722be28.home") == ""
    assert clean_hostname("4ad82b8614274f4f999b754bca5b6a31.local") == ""
    assert clean_hostname("3a0c420a-eb0f-bb95-9dea-d10c7e9ea5d6.local") == ""
    assert clean_hostname("Android_5d5a9b41cd6f44248a0c1dfee08c43b0.local") == ""
    assert clean_hostname("mynetwork.home") == ""
    assert clean_hostname("wlan0.home") == ""
    assert clean_hostname("iPhone.home") == ""
    assert clean_hostname("iPad-2.local") == ""
    assert clean_hostname("MacBookPro.home") == ""

    # Keeps meaningful hostnames and strips local domain suffixes
    assert clean_hostname("esp-tester-5g.home") == "esp-tester-5g"
    assert clean_hostname("ESP-Memory-Shiftr-Halls.home.") == "ESP-Memory-Shiftr-Halls"
    assert clean_hostname("KP400.home") == "KP400"
    assert clean_hostname("ratatosk.local") == "ratatosk"
    assert clean_hostname("Janes-MacBook-Pro.local") == "Janes-MacBook-Pro"
    assert clean_hostname("BRW30C9ABE8DD02.local") == "BRW30C9ABE8DD02"


def test_clean_mdns_hostname():
    assert clean_mdns_hostname("Android_5d5a9b41cd6f44248a0c1dfee08c43b0.local") == ""
    assert clean_mdns_hostname("ratatosk.local.") == "ratatosk.local"


def test_infer_from_hostname():
    assert infer_from_hostname("esp32c5-E8DC50.home") == {
        "type": "ESP32-C5 Dev Board",
        "vendor": "Espressif",
    }
    assert infer_from_hostname("esp-tester.home") == {
        "type": "ESP32 / IoT Dev Board",
        "vendor": "Espressif",
    }
    assert infer_from_hostname("ESP-Memory-Shiftr-Halls") == {
        "type": "ESP32 / IoT Dev Board",
        "vendor": "Espressif",
    }
    assert infer_from_hostname("BRW30C9ABE8DD02.local") == {
        "type": "Printer",
        "vendor": "Brother",
    }
    assert infer_from_hostname("yoto-mini.home") == {
        "type": "Yoto Player",
        "vendor": "Yoto",
    }
    assert infer_from_hostname("KP400.home") == {
        "type": "TP-Link KP400",
        "vendor": "TP-Link",
    }
    assert infer_from_hostname("Janes-MacBook-Pro.local") == {
        "type": "MacBook Pro",
        "vendor": "Apple",
    }
    assert infer_from_hostname("iPad-2.local") == {
        "type": "iPad",
        "vendor": "Apple",
    }


def test_resolve_dns_name_rejects_generic_and_verifies_forward():
    with (
        patch("enrichment.socket.gethostbyaddr", return_value=("wlan0.home", [], ["192.168.2.193"])),
        patch("enrichment.socket.gethostbyname", return_value="192.168.2.193"),
    ):
        dns_name, raws = resolve_dns_name("192.168.2.193")
        assert dns_name == ""
        assert raws == ["wlan0.home"]

    with (
        patch("enrichment.socket.gethostbyaddr", return_value=("KP400", [], ["192.168.2.86"])),
        patch("enrichment.socket.gethostbyname", return_value="192.168.2.86"),
    ):
        dns_name, raws = resolve_dns_name("192.168.2.86")
        assert dns_name == "KP400.home"


def test_enrich_and_merge_upgrades_unknown_without_overwriting_human():
    info = {
        "ip": "192.168.2.86",
        "dns_name": "KP400.home",
        "mdns_name": "",
        "timestamp": "2026-10-31 18:00:00",
    }
    enrich_host_from_names(info)
    assert info["name"] == "KP400"
    assert info["type"] == "TP-Link KP400"
    assert info["vendor"] == "TP-Link"

    # Existing row with Unknown name/type/vendor gets upgraded
    existing_unknown = {
        "CC:BA:BD:BE:D1:72": {
            "ip": "192.168.2.86",
            "dns_name": "",
            "mdns_name": "",
            "name": "Unknown",
            "type": "Unknown",
            "vendor": "Unknown",
            "timestamp": "2026-10-30 12:00:00",
        }
    }
    merged, _, _ = merge_network_data(existing_unknown, {"CC:BA:BD:BE:D1:72": info})
    assert merged["CC:BA:BD:BE:D1:72"]["name"] == "KP400"
    assert merged["CC:BA:BD:BE:D1:72"]["type"] == "TP-Link KP400"
    assert merged["CC:BA:BD:BE:D1:72"]["vendor"] == "TP-Link"

    # Existing row with human-assigned name/type is NEVER overwritten
    existing_human = {
        "CC:BA:BD:BE:D1:72": {
            "ip": "192.168.2.86",
            "dns_name": "",
            "mdns_name": "",
            "name": "Dual outdoor smart plug",
            "type": "Outdoor Plug",
            "vendor": "TP-Link",
            "timestamp": "2026-10-30 12:00:00",
        }
    }
    merged_human, _, _ = merge_network_data(existing_human, {"CC:BA:BD:BE:D1:72": info})
    assert merged_human["CC:BA:BD:BE:D1:72"]["name"] == "Dual outdoor smart plug"
    assert merged_human["CC:BA:BD:BE:D1:72"]["type"] == "Outdoor Plug"
    assert merged_human["CC:BA:BD:BE:D1:72"]["dns_name"] == "KP400.home"


def test_randomized_mac_and_oui_resolution(tmp_path):
    # Locally administered randomized MACs (second least-significant bit of first byte is 1)
    assert is_randomized_mac("12:6A:B3:AE:97:83")
    assert is_randomized_mac("EA:36:CC:3B:0E:52")
    assert is_randomized_mac("CE:ED:66:91:9F:69")
    assert resolve_vendor("12:6A:B3:AE:97:83") == PRIVATE_MAC_VENDOR

    # Known virtual OUI with local bit set (HAOS 02:41:A2) is NOT treated as randomized
    assert not is_randomized_mac("02:41:A2:D2:6D:4B")
    assert resolve_vendor("02:41:A2:D2:6D:4B") == "Home Assistant"

    # Known modern hardware OUIs (ESP32-C5, Proxmox, Tuya, ASUS, TP-Link)
    assert not is_randomized_mac("D0:CF:13:E8:DC:50")
    assert resolve_vendor("D0:CF:13:E8:DC:50") == "Espressif Inc."
    assert resolve_vendor("BC:24:11:29:CC:65") == "Proxmox Server Solutions GmbH"
    assert resolve_vendor("BC:35:1E:DD:E7:6B") == "Tuya Smart Inc."
    assert resolve_vendor("CC:BA:BD:BE:D1:72") == "TP-Link Systems Inc."

    # Custom Wireshark manuf and Nmap prefix file parsing
    manuf_file = tmp_path / "manuf"
    manuf_file.write_text("# Comment\n00:11:22\tTestShort\tTest Full Vendor\nAA:BB:CC/28\tSkipBlock\tSkip\n")
    nmap_file = tmp_path / "nmap-mac-prefixes"
    nmap_file.write_text("001133 Nmap Format Vendor\n")
    db = load_oui_database(extra_paths=(str(manuf_file), str(nmap_file)))
    assert db["001122"] == "Test Full Vendor"
    assert db["001133"] == "Nmap Format Vendor"
    assert lookup_oui_vendor("D0:CF:13:E8:DC:50") == "Espressif Inc."

