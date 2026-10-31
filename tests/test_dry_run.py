from unittest.mock import MagicMock

from network_scanner import read_sheet, write_sheet


def test_write_sheet_dry_run():
    mock_service = MagicMock()
    network = {
        "AA:BB:CC:DD:EE:01": {
            "ip": "192.168.2.50",
            "dns_name": "test-device.home",
            "mdns_name": "test-device.local",
            "name": "Test Device",
            "type": "Sensor",
            "vendor": "Acme",
            "timestamp": "2026-10-25 04:00:00",
        }
    }

    # dry_run = True should NOT execute an update API call
    cells = write_sheet(mock_service, "test-sheet-id", network, dry_run=True)
    assert cells == 16  # 2 rows (header + 1 device) * 8 columns = 16 cells
    mock_service.spreadsheets().values().update.assert_not_called()


def test_write_sheet_live():
    mock_service = MagicMock()
    mock_update = mock_service.spreadsheets().values().update.return_value
    mock_update.execute.return_value = {"updatedCells": 16}

    network = {
        "AA:BB:CC:DD:EE:01": {
            "ip": "192.168.2.50",
            "dns_name": "test-device.home",
            "mdns_name": "test-device.local",
            "name": "Test Device",
            "type": "Sensor",
            "vendor": "Acme",
            "timestamp": "2026-10-25 04:00:00",
        }
    }

    cells = write_sheet(mock_service, "test-sheet-id", network, dry_run=False)
    assert cells == 16
    mock_service.spreadsheets().values().update.assert_called_once()


def test_read_sheet_supports_legacy_6col_and_8col():
    mock_service = MagicMock()
    mock_get = mock_service.spreadsheets().values().get.return_value

    # Legacy 6-column format
    mock_get.execute.return_value = {
        "values": [
            ["mac", "ip", "name", "type", "vendor", "timestamp"],
            ["aa:bb:cc:dd:ee:01", "192.168.2.12", "Ecobee", "Thermostat", "ecobee", "2026-10-30"],
        ]
    }
    net6 = read_sheet(mock_service, "sheet-id")
    assert net6["AA:BB:CC:DD:EE:01"]["dns_name"] == ""
    assert net6["AA:BB:CC:DD:EE:01"]["mdns_name"] == ""
    assert net6["AA:BB:CC:DD:EE:01"]["name"] == "Ecobee"

    # Upgraded 8-column format
    mock_get.execute.return_value = {
        "values": [
            ["mac", "ip", "dns_name", "mdns_name", "name", "type", "vendor", "timestamp"],
            ["aa:bb:cc:dd:ee:01", "192.168.2.12", "Main-Floor.home", "ecobee-ares.local", "Ecobee", "Thermostat", "ecobee", "2026-10-30"],
        ]
    }
    net8 = read_sheet(mock_service, "sheet-id")
    assert net8["AA:BB:CC:DD:EE:01"]["dns_name"] == "Main-Floor.home"
    assert net8["AA:BB:CC:DD:EE:01"]["mdns_name"] == "ecobee-ares.local"
    assert net8["AA:BB:CC:DD:EE:01"]["name"] == "Ecobee"

