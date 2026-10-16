# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Runtime credentials can live in owner-managed files apart from configuration."""

from unittest.mock import MagicMock, patch

import pytest

from modules import utils, web_ui
from modules.credential_files import (
    NIST_API_KEY,
    SMTP_PASSWORD,
    WEBHOOK_URL,
    CredentialFileError,
    credential_from_environment,
    read_credential_file,
)


def test_credential_file_strips_only_the_line_ending(tmp_path):
    path = tmp_path / "secret"
    path.write_bytes(b" key with spaces \r\n")
    assert read_credential_file(path) == " key with spaces "


@pytest.mark.parametrize("content", [b"", b"\n", b"LEAKMARK\nSECOND\n", b"\xffLEAKMARK", b"LEAKMARK" * 600])
def test_invalid_credential_files_are_rejected_without_echoing_content(tmp_path, content):
    path = tmp_path / "secret"
    path.write_bytes(content)
    with pytest.raises(CredentialFileError) as error:
        read_credential_file(path)
    assert "LEAKMARK" not in str(error.value)


def test_directory_and_missing_files_are_rejected(tmp_path):
    for path in (tmp_path, tmp_path / "absent"):
        with pytest.raises(CredentialFileError):
            read_credential_file(path)


def test_environment_reference_is_optional_and_reread_on_rotation(tmp_path, monkeypatch):
    monkeypatch.delenv(NIST_API_KEY, raising=False)
    assert credential_from_environment(NIST_API_KEY) is None
    path = tmp_path / "nist"
    path.write_text("first\n")
    monkeypatch.setenv(NIST_API_KEY, str(path))
    assert credential_from_environment(NIST_API_KEY) == "first"
    path.write_text("second\n")  # replaced without restarting or editing configuration
    assert credential_from_environment(NIST_API_KEY) == "second"


def _args(**values):
    args = MagicMock()
    args.api = None
    args.report = "email"
    for name in ("report_email", "report_email_password", "report_email_to", "report_email_from",
                 "report_email_server", "report_email_server_port", "report_webhook"):
        setattr(args, name, None)
    for name, value in values.items():
        setattr(args, name, value)
    return args


def test_cli_prefers_explicit_value_then_file_then_legacy_source(tmp_path, monkeypatch):
    log = MagicMock()
    secret = tmp_path / "nist"
    secret.write_text("from-file\n")
    monkeypatch.setenv(NIST_API_KEY, str(secret))
    assert utils.InitArgsAPI(_args(api="explicit"), log) == "explicit"
    assert utils.InitArgsAPI(_args(), log) == "from-file"
    monkeypatch.setenv(NIST_API_KEY, str(tmp_path / "missing"))
    with patch.object(utils, "read_file_any_encoding", return_value="legacy"):
        assert utils.InitArgsAPI(_args(), log) == "legacy"
    assert any("Credential file" in call.args[1] for call in log.logger.call_args_list)


def test_cli_report_secrets_use_files_instead_of_prompts(tmp_path, monkeypatch):
    password = tmp_path / "smtp"
    password.write_text("smtp-secret\n")
    monkeypatch.setenv(SMTP_PASSWORD, str(password))
    hook = tmp_path / "hook"
    hook.write_text("https://hooks.example.test/x\n")
    monkeypatch.setenv(WEBHOOK_URL, str(hook))
    with patch("builtins.input", side_effect=AssertionError("prompted")):
        method, webhook = utils.InitReport(_args(report="webhook"), MagicMock())
        assert webhook == "https://hooks.example.test/x"
        with patch.object(utils, "ReportMail") as mail:
            utils.InitReport(_args(report="email", report_email="a@b.test", report_email_to="c@d.test",
                                   report_email_from="a@b.test", report_email_server="smtp.test",
                                   report_email_server_port=587), MagicMock())
    assert "smtp-secret" in str(mail.call_args)


def test_dashboard_file_credentials_override_settings_and_are_never_persisted(tmp_path, monkeypatch):
    for name, text in ((NIST_API_KEY, "nist-file"), (SMTP_PASSWORD, "smtp-file"), (WEBHOOK_URL, "https://hooks.example.test/f")):
        path = tmp_path / name
        path.write_text(text + "\n")
        monkeypatch.setenv(name, str(path))
    stored = {"nist_api_key": "stored", "email": {"password": "stored", "username": "u"}, "webhook": {"url": "stored", "enabled": True}}
    with patch.dict(web_ui._settings, stored, clear=True):
        assert web_ui._get_setting("nist_api_key") == "nist-file"
        assert web_ui._get_setting("email", "password") == "smtp-file"
        assert web_ui._get_setting("email") == {"password": "smtp-file", "username": "u"}
        assert web_ui._get_setting("webhook")["url"] == "https://hooks.example.test/f"
        assert web_ui._settings["email"]["password"] == "stored"  # the persisted copy is untouched


def test_dashboard_falls_back_to_settings_when_a_credential_file_is_unusable(tmp_path, monkeypatch):
    monkeypatch.setenv(SMTP_PASSWORD, str(tmp_path / "missing"))
    with patch.dict(web_ui._settings, {"email": {"password": "stored"}}, clear=True):
        assert web_ui._get_setting("email", "password") == "stored"


def test_dashboard_and_cli_default_to_loopback_and_certificate_verification(monkeypatch):
    monkeypatch.delenv("AUTOPWN_WEB_HOST", raising=False)
    with patch("sys.argv", ["autopwn.py"]):
        args = utils.cli()
    assert args.web_host == "127.0.0.1"
    assert args.insecure_tls is False
    with patch("sys.argv", ["autopwn.py", "--insecure-tls", "--web-host", "0.0.0.0"]):
        args = utils.cli()
    assert args.insecure_tls is True and args.web_host == "0.0.0.0"
