# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Coverage-guided fuzzing of the Nmap XML parser, which reads target-influenced output, and of the reading of the
service CPEs it returns."""
import sys

import atheris

with atheris.instrument_imports():
    from autopwn_suite.cpe_match import is_system, service_products
    from autopwn_suite.nmap_backend import parse_nmap_xml


def TestOneInput(data):
    text = atheris.FuzzedDataProvider(data).ConsumeUnicodeNoSurrogates(len(data))
    try:
        result = parse_nmap_xml(text)
    except RuntimeError:
        return  # the documented rejection of a malformed document; anything else is a finding
    # Each service's CPEs and product name choose the CVEs that apply to it (autopwn_suite.searchvuln).
    for host in result["scan"].values():
        for protocol in ("ip", "tcp", "udp", "sctp"):
            for service in host.get(protocol, {}).values():
                service_products(service.get("cpes", ()), service["product"])
                is_system(service.get("cpes", ()), service["product"])


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
