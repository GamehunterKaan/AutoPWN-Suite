# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
import ipaddress
import ssl
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, call, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from modules.web.tls import _context, _handshake, check_tls, inspect_certificate


@pytest.fixture
def certificate_der():
    def make(*, names=("example.com",), expired=False, future=False):
        now = datetime.now(timezone.utc)
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
        builder = x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(1)
        builder = builder.not_valid_before(now + timedelta(days=1) if future else now - timedelta(days=30))
        builder = builder.not_valid_after(now - timedelta(days=1) if expired else now + timedelta(days=30))
        if names is not None:
            builder = builder.add_extension(x509.SubjectAlternativeName([
                x509.IPAddress(name) if isinstance(name, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else x509.DNSName(name)
                for name in names]), critical=False)
        return builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
    return make


@pytest.mark.unit
@pytest.mark.parametrize("options,url,expected", [
    ({}, "https://example.com/", []),
    ({"expired": True}, "https://example.com/", ["expired"]),
    ({"future": True}, "https://example.com/", ["not valid before"]),
    ({"names": ("other.example",)}, "https://example.com/", ["No certificate"]),
    ({"names": ("*.example.com",)}, "https://app.example.com/", []),
    ({"names": ("*.example.com",)}, "https://nested.app.example.com/", ["No certificate"]),
    ({"names": (ipaddress.ip_address("192.0.2.1"),)}, "https://192.0.2.1/", []),
    ({"names": None}, "https://example.com/", ["No certificate"]),
])
def test_certificate_dates_and_san_matching(certificate_der, options, url, expected):
    results = inspect_certificate(url, certificate_der(**options))
    assert len(results) == len(expected)
    assert all(any(marker in item["evidence"] for item in results) for marker in expected)


@pytest.mark.unit
def test_obsolete_tls_requires_actual_exact_version_handshake(certificate_der):
    der = certificate_der()
    with patch("modules.web.tls._handshake", side_effect=[(der, "TLSv1.3"), (der, "TLSv1"), (der, "TLSv1.1")]) as handshake:
        results = check_tls("https://example.com:8443/", MagicMock(), MagicMock())
    assert [item["type"] for item in results] == ["TLS_PROTOCOL", "TLS_PROTOCOL"]
    assert handshake.call_count == 3
    assert all(call.args[2] == 8443 for call in handshake.call_args_list)
    contexts = [call.args[0] for call in handshake.call_args_list]
    assert contexts[0].verify_mode == ssl.CERT_REQUIRED
    assert contexts[1].minimum_version == contexts[1].maximum_version == ssl.TLSVersion.TLSv1
    assert contexts[2].minimum_version == contexts[2].maximum_version == ssl.TLSVersion.TLSv1_1


@pytest.mark.parametrize("verify", [True, False])
def test_non_legacy_tls_contexts_keep_modern_protocol_defaults(verify):
    context = _context(verify=verify)
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert context.verify_mode == (ssl.CERT_REQUIRED if verify else ssl.CERT_NONE)


def test_tls_handshake_reads_metadata_without_application_data():
    context = MagicMock()
    secure = context.wrap_socket.return_value.__enter__.return_value
    secure.getpeercert.return_value = b"certificate"
    secure.version.return_value = "TLSv1"
    with patch("modules.web.tls.socket.create_connection") as connect:
        assert _handshake(context, "example.com", 8443) == (b"certificate", "TLSv1")
    assert secure.method_calls == [call.getpeercert(binary_form=True), call.version()]
    connect.return_value.__exit__.assert_called_once()
    context.wrap_socket.return_value.__exit__.assert_called_once()


@pytest.mark.unit
def test_trust_failure_does_not_skip_expiry_or_hostname_checks(certificate_der):
    error = ssl.SSLCertVerificationError(1, "untrusted")
    error.verify_code = 18
    der = certificate_der(expired=True, names=("other.example",))
    with patch("modules.web.tls._handshake", side_effect=[error, (der, "TLSv1.3"), ssl.SSLError(1, "rejected"), ssl.SSLError(1, "rejected")]):
        results = check_tls("https://example.com/", MagicMock(), MagicMock())
    assert [item["type"] for item in results] == ["TLS_TRUST", "TLS_CERTIFICATE", "TLS_CERTIFICATE"]
    assert "private CA" in results[0]["evidence"]


@pytest.mark.unit
def test_unavailable_protocols_are_reported_as_unverified(certificate_der):
    log = MagicMock()
    with patch("modules.web.tls._handshake", return_value=(certificate_der(), "TLSv1.3")) as handshake, patch("modules.web.tls.ssl.HAS_TLSv1", False), patch("modules.web.tls.ssl.HAS_TLSv1_1", False):
        assert check_tls("https://example.com/", log, MagicMock()) == []
    handshake.assert_called_once()
    assert log.logger.call_count == 2
    assert all("not checked" in call.args[1] for call in log.logger.call_args_list)


@pytest.mark.unit
def test_plain_http_does_not_make_tls_connections():
    with patch("modules.web.tls._handshake") as handshake:
        assert check_tls("http://example.com/", MagicMock(), MagicMock()) == []
    handshake.assert_not_called()
