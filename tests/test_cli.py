from pathlib import Path
from unittest.mock import MagicMock, patch

from network_scanner import main

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "sample_scan.xml"


def test_main_dry_run_with_mock_scan(tmp_path):
    creds_file = tmp_path / "credentials.json"
    creds_file.write_text('{"type": "service_account"}')

    mock_service = MagicMock()
    mock_get = mock_service.spreadsheets().values().get.return_value
    mock_get.execute.return_value = {
        "values": [
            ["mac", "ip", "name", "type", "vendor", "timestamp"],
            ["00:0D:B9:18:E6:CD", "10.20.30.1", "Old Gateway", "Router", "PC Engines", "2026-01-01"],
        ]
    }

    with patch("network_scanner.build", return_value=mock_service):
        rc = main([
            "--network", "10.20.30.0/24",
            "--spreadsheet", "test-spreadsheet-id",
            "--credentials", str(creds_file),
            "--mock-scan", str(FIXTURE_PATH),
            "--dry-run",
        ])

    assert rc == 0
    # Assert values().update() was NOT called in dry-run mode
    mock_service.spreadsheets().values().update.assert_not_called()
