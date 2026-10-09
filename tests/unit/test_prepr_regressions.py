"""Pre-PR regressions with mocked network clients and child processes only."""
import importlib.util
import io
from pathlib import Path
import threading
from contextlib import contextmanager
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def review_web(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTOPWN_DATA_DIR", str(tmp_path))
    path = Path(__file__).parents[2] / "modules" / "web_ui.py"
    spec = importlib.util.spec_from_file_location("prepr_web", path)
    wu = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(wu)
    wu._load_settings()
    wu._settings["webhook"] = {"enabled": True, "url": "https://example.invalid/notify", "on_complete": True}
    monkeypatch.setattr("requests.sessions.Session.request", lambda *a, **k: pytest.fail("Real HTTP is blocked"))
    return wu


@pytest.mark.parametrize("channel", ["webhook", "email"])
def test_offline_mode_cannot_be_enabled_during_notification_preparation(review_web, monkeypatch, channel):
    wu = review_web
    job = wu.ScanJob("notification", "192.0.2.1", {"vulnerability_source": "online"})
    job.mark_done()
    preparing = threading.Event()
    release = threading.Event()
    sent = []
    def hosts_list():
        preparing.set()
        assert release.wait(3)
        return []
    monkeypatch.setattr(job, "hosts_list", hosts_list)
    wu._settings["email"] = {"enabled": True, "smtp_host": "example.invalid", "to_addr": "test@example.invalid", "on_complete": True}
    monkeypatch.setattr(wu._requests, "post", lambda *a, **k: sent.append(wu._offline_enabled()) or MagicMock())
    @contextmanager
    def smtp(cfg):
        server = MagicMock()
        server.sendmail.side_effect = lambda *a: sent.append(wu._offline_enabled())
        yield server
    monkeypatch.setattr(wu, "_smtp_connection", smtp)
    sender = threading.Thread(target=getattr(wu, "_send_" + channel), args=(job,))
    sender.start()
    assert preparing.wait(3)
    try:
        app = wu._build_app(wu._STATIC_DIR)
        app.config["TESTING"] = True
        response = app.test_client().put("/api/settings", json={"offline_mode": True})
        assert response.status_code == 409
        assert not wu._offline_enabled()
    finally:
        release.set()
        sender.join(3)
    assert not sender.is_alive()
    assert sent == [False]
    assert wu._notification_operations == 0
    assert app.test_client().put("/api/settings", json={"offline_mode": True}).status_code == 200


@pytest.mark.parametrize("channel", ["webhook", "email"])
def test_manual_notification_routes_reserve_the_offline_transition(review_web, monkeypatch, channel):
    wu = review_web
    wu._settings["email"] = {"enabled": True, "smtp_host": "example.invalid", "to_addr": "test@example.invalid"}
    entered = threading.Event()
    release = threading.Event()
    modes = []
    def post(*args, **kwargs):
        entered.set()
        assert release.wait(3)
        modes.append(wu._offline_enabled())
        return MagicMock(status_code=200)
    @contextmanager
    def smtp(cfg):
        entered.set()
        assert release.wait(3)
        modes.append(wu._offline_enabled())
        yield MagicMock()
    monkeypatch.setattr(wu._requests, "post", post)
    monkeypatch.setattr(wu, "_smtp_connection", smtp)
    app = wu._build_app(wu._STATIC_DIR)
    app.config["TESTING"] = True
    responses = []
    sender = threading.Thread(target=lambda: responses.append(app.test_client().post("/api/settings/test_" + channel).status_code))
    sender.start()
    assert entered.wait(3)
    try:
        assert app.test_client().put("/api/settings", json={"offline_mode": True}).status_code == 409
    finally:
        release.set()
        sender.join(3)
    assert responses == [200] and modes == [False] and wu._notification_operations == 0


def test_notification_operation_releases_its_reservation_on_failure(review_web):
    wu = review_web
    with pytest.raises(RuntimeError):
        with wu._notification_operation() as allowed:
            assert allowed and wu._notification_operations == 1
            raise RuntimeError("delivery failed")
    assert wu._notification_operations == 0


def test_cli_offline_ports_only_does_not_require_a_cve_database(tmp_path, monkeypatch):
    import autopwn
    from rich.console import Console
    monkeypatch.setenv("AUTOPWN_DATA_DIR", str(tmp_path))
    monkeypatch.setattr("sys.argv", ["autopwn.py", "--offline", "--vuln-db", str(tmp_path / "missing.sqlite3"),
                                    "--skip-discovery", "-t", "192.0.2.1", "--no-color"])
    monkeypatch.setattr(autopwn, "Console", lambda **kw: Console(file=io.StringIO(), **kw))
    monkeypatch.setattr(autopwn, "check_nmap", MagicMock())
    monkeypatch.setattr(autopwn, "UserConfirmation", lambda args: (True, False, False))
    nm = MagicMock()
    nm.all_hosts.return_value = ["192.0.2.1"]
    scan = MagicMock(return_value=nm)
    monkeypatch.setattr(autopwn, "PortScan", scan)
    monkeypatch.setattr(autopwn, "AnalyseScanResults", lambda *a: [])
    monkeypatch.setattr(autopwn, "SaveOutput", MagicMock())
    monkeypatch.setattr(autopwn, "SearchSploits", lambda *a, **k: pytest.fail("Unexpected CVE lookup"))
    autopwn.main()
    scan.assert_called_once()


def test_lazy_offline_lookup_still_fails_explicitly_if_cve_data_is_requested(tmp_path):
    from modules.nist_search import VulnerabilityLookup
    from modules.vulnerability_db import DatabaseUnavailable
    lookup = VulnerabilityLookup("offline", tmp_path / "missing.sqlite3", lazy=True)
    assert lookup.local is None
    try:
        with pytest.raises(DatabaseUnavailable):
            lookup.search("OpenSSH 8.2p1", MagicMock())
    finally:
        lookup.close()
