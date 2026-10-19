# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Inspect certificates and positively verify obsolete TLS support."""

import ipaddress
import socket
import ssl
import warnings
from datetime import datetime, timezone
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from autopwn_suite.text import printable
from autopwn_suite.web.findings import emit, finding
from autopwn_suite.web.runtime import ACTIVE


def _context(version=None, *, verify=True):
    if verify:
        return ssl.create_default_context()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if version is not None:
        # Relax only this diagnostic client, not the application HTTPS policy.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            context.minimum_version = version
            context.maximum_version = version
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    return context


def _handshake(context, hostname, port):
    current = ACTIVE.get()
    if current:
        current.before()
    with socket.create_connection((hostname, port), timeout=current.options["timeout"] if current else 10) as connection:
        # Legacy contexts intentionally test whether the target accepts TLS 1.0/1.1.
        # Only handshake/certificate metadata is exchanged: no HTTP, credentials or application data.
        with context.wrap_socket(connection, server_hostname=hostname) as secure:
            return secure.getpeercert(binary_form=True), secure.version()


def _dns_match(pattern, hostname):
    pattern, hostname = pattern.lower().rstrip("."), hostname.lower().rstrip(".")
    if "*" not in pattern:
        return pattern == hostname
    labels, host_labels = pattern.split("."), hostname.split(".")
    return len(labels) >= 3 and labels[0] == "*" and len(labels) == len(host_labels) and labels[1:] == host_labels[1:]


def _certificate_matches(certificate, hostname):
    try:
        names = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return False
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        hostname = hostname.encode("idna").decode("ascii")
        return any(_dns_match(name, hostname) for name in names.get_values_for_type(x509.DNSName))
    return address in names.get_values_for_type(x509.IPAddress)


def inspect_certificate(url, der, *, now=None):
    certificate = x509.load_der_x509_certificate(der)
    hostname = urlsplit(url).hostname
    now = now or datetime.now(timezone.utc)
    results = []
    # The names are the target's own text, and rfc4514_string() escapes only its special characters.
    certificate_data = {"subject": printable(certificate.subject.rfc4514_string()), "issuer": printable(certificate.issuer.rfc4514_string()),
                        "not_before": certificate.not_valid_before_utc.isoformat(), "not_after": certificate.not_valid_after_utc.isoformat(),
                        "fingerprint_sha256": certificate.fingerprint(hashes.SHA256()).hex(), "serial_number": str(certificate.serial_number)}
    reproduction = {"strategy": "tls", "target": url, "requests": [], "certificate": certificate_data}
    if now > certificate.not_valid_after_utc:
        results.append(finding("TLS_CERTIFICATE", url, f"Certificate expired at {certificate.not_valid_after_utc.isoformat()}", severity="medium", confidence="observation", reproduction=reproduction))
    if now < certificate.not_valid_before_utc:
        results.append(finding("TLS_CERTIFICATE", url, f"Certificate is not valid before {certificate.not_valid_before_utc.isoformat()}",
                               severity="medium", confidence="observation", reproduction=reproduction))
    if not _certificate_matches(certificate, hostname):
        results.append(finding("TLS_CERTIFICATE", url, "No certificate subject alternative name matches the target hostname/IP",
                               severity="medium", confidence="observation", reproduction=reproduction))
    return results


def check_tls(url, log, console):
    parts = urlsplit(url)
    if parts.scheme != "https":
        return []
    hostname = parts.hostname.encode("idna").decode("ascii")
    port = parts.port or 443
    results, der = [], None
    try:
        der, _ = _handshake(_context(), hostname, port)
    except ssl.SSLCertVerificationError as exc:
        results.append(finding("TLS_TRUST", url, f"Certificate validation failed against the local trust store (code {exc.verify_code}); private CA trust may be required", confidence="advisory"))
    except OSError:
        log.logger("warning", f"Verified TLS handshake incomplete on {url}.")
    if der is None:
        try:
            der, _ = _handshake(_context(verify=False), hostname, port)
        except OSError:
            log.logger("warning", f"Certificate inspection incomplete on {url}.")
    if der:
        try:
            results.extend(inspect_certificate(url, der))
        except (ValueError, x509.DuplicateExtension, x509.UnsupportedGeneralNameType):
            log.logger("warning", f"Unable to parse certificate details on {url}.")
    for version, label, supported in ((ssl.TLSVersion.TLSv1, "TLSv1", ssl.HAS_TLSv1),
                                      (ssl.TLSVersion.TLSv1_1, "TLSv1.1", ssl.HAS_TLSv1_1)):
        if not supported:
            log.logger("warning", f"{label} probe unavailable in this TLS runtime; support was not checked.")
            continue
        try:
            legacy_der, negotiated = _handshake(_context(version, verify=False), hostname, port)
        except ssl.SSLError as exc:
            if getattr(exc, "reason", None) in ("NO_CIPHERS_AVAILABLE", "NO_PROTOCOLS_AVAILABLE", "LEGACY_SIGALG_DISALLOWED_OR_UNSUPPORTED"):
                log.logger("warning", f"{label} probe limited by the local TLS runtime; support was not verified.")
            # A rejected handshake is not a positive finding or a complete cipher audit.
            continue
        except (OSError, ValueError):
            log.logger("warning", f"{label} probe incomplete on {url}.")
            continue
        if negotiated == label:
            results.append(finding("TLS_PROTOCOL", url, f"Server negotiated obsolete {label} in an exact-version handshake", severity="medium", confidence="observation"))
            if der is None and legacy_der:
                der = legacy_der
                try:
                    results.extend(inspect_certificate(url, der))
                except (ValueError, x509.DuplicateExtension, x509.UnsupportedGeneralNameType):
                    log.logger("warning", f"Unable to parse legacy endpoint certificate on {url}.")
    for result in results:
        emit(console, result)
    return results
