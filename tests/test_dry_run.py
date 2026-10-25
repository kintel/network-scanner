from unittest.mock import MagicMock

from network_scanner import write_sheet


def test_write_sheet_dry_run():
    mock_service = MagicMock()
    network = {
        "AA:BB:CC:DD:EE:01": {
            "ip": "192.168.2.50",
            "name": "Test Device",
            "type": "Sensor",
            "vendor": "Acme",
            "timestamp": "2026-10-25 04:00:00",
        }
    }

    # dry_run = True should NOT execute an update API call
    cells = write_sheet(mock_service, "test-sheet-id", network, dry_run=True)
    assert cells == 12  # 2 rows (header + 1 device) * 6 columns = 12 cells
    mock_service.spreadsheets().values().update.assert_not_called()


def test_write_sheet_live():
    mock_service = MagicMock()
    mock_update = mock_service.spreadsheets().values().update.return_value
    mock_update.execute.return_value = {"updatedCells": 12}

    network = {
        "AA:BB:CC:DD:EE:01": {
            "ip": "192.168.2.50",
            "name": "Test Device",
            "type": "Sensor",
            "vendor": "Acme",
            "timestamp": "2026-10-25 04:00:00",
        }
    }

    cells = write_sheet(mock_service, "test-sheet-id", network, dry_run=False)
    assert cells == 12
    mock_service.spreadsheets().values().update.assert_called_once()
