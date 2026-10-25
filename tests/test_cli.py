import threading
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


def test_main_resolves_relative_credentials_from_config_dir(tmp_path):
    config_dir = tmp_path / "config_dir"
    config_dir.mkdir()
    creds_file = config_dir / "credentials.json"
    creds_file.write_text('{"type": "service_account"}')
    config_file = config_dir / "config.ini"
    config_file.write_text(
        "network = 10.20.30.0/24\n"
        "spreadsheet = test-spreadsheet-id\n"
        "credentials = credentials.json\n"
    )

    mock_service = MagicMock()
    mock_get = mock_service.spreadsheets().values().get.return_value
    mock_get.execute.return_value = {
        "values": [
            ["mac", "ip", "name", "type", "vendor", "timestamp"],
        ]
    }

    with patch("network_scanner.build", return_value=mock_service):
        rc = main([
            "--config", str(config_file),
            "--mock-scan", str(FIXTURE_PATH),
            "--dry-run",
        ])

    assert rc == 0
    mock_service.spreadsheets().values().update.assert_not_called()


def test_main_interval_daemon_mode_stops_cleanly(tmp_path):
    creds_file = tmp_path / "credentials.json"
    creds_file.write_text('{"type": "service_account"}')

    mock_service = MagicMock()
    mock_get = mock_service.spreadsheets().values().get.return_value
    mock_get.execute.return_value = {
        "values": [
            ["mac", "ip", "name", "type", "vendor", "timestamp"],
        ]
    }

    stop_event = threading.Event()

    def stop_after_first_wait(_timeout):
        stop_event.set()
        return True

    with (
        patch("network_scanner.build", return_value=mock_service),
        patch.object(stop_event, "wait", side_effect=stop_after_first_wait) as mock_wait,
    ):
        rc = main(
            [
                "--network", "10.20.30.0/24",
                "--spreadsheet", "test-spreadsheet-id",
                "--credentials", str(creds_file),
                "--mock-scan", str(FIXTURE_PATH),
                "--dry-run",
                "--interval", "3600",
            ],
            stop_event=stop_event,
        )

    assert rc == 0
    mock_wait.assert_called_once_with(3600)


