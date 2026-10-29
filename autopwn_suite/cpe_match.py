# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Which product versions an NVD record marks vulnerable, from its CPE applicability statements."""
import re

_CPE_SEPARATOR = re.compile(r"(?<!\\):")
_RANGE = ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding")
# NVD's CPE product names that differ from the name a description and GenerateKeyword use.
_PRODUCT_ALIASES = {"internet_information_server": "iis", "internet_information_services": "iis", "mysql_server": "mysql"}


def _words(text):
    return frozenset(re.findall(r"[a-z0-9]+", text.casefold()))


def find_affected(record) -> tuple:
    """The vulnerable CPE matches of an NVD record as (vendor, product, version, update, start including,
    start excluding, end including, end excluding); empty when NVD has not analyzed the record."""
    found = []
    try:
        for configuration in record["cve"].get("configurations") or ():
            for node in configuration.get("nodes") or ():
                for match in node.get("cpeMatch") or ():
                    criteria = match.get("criteria")
                    if match.get("vulnerable") is not True or not isinstance(criteria, str):
                        continue
                    parts = _CPE_SEPARATOR.split(criteria)
                    if len(parts) < 7:
                        continue
                    bounds = tuple(match.get(name) if isinstance(match.get(name), str) else None for name in _RANGE)
                    found.append((parts[3], parts[4], parts[5], parts[6]) + bounds)
    except (KeyError, TypeError, AttributeError):
        pass
    return tuple(found)


def _key(version):
    # Bounded runs: int() refuses numbers of more than 4300 digits, and a copied database controls these texts.
    return [(1, int(part)) if part.isdigit() else (0, part)
            for part in re.findall(r"[0-9]{1,18}|[a-z]+", version.casefold())]


def _covers(entry, version):
    _vendor, _product, cpe_version, update, start_in, start_ex, end_in, end_ex = entry
    if cpe_version == "-":
        return False
    if cpe_version != "*":
        if update in ("*", "-", ""):
            if cpe_version.casefold() == version:
                return True
            # 1.3.3 with any update covers 1.3.3c.
            return update == "*" and cpe_version.casefold() == re.match(r"[0-9.]*", version).group()
        return (cpe_version + update).casefold() == version
    ours = _key(version)
    if update not in ("*", "-", ""):  # openssh:*:p2 up to 7.2 is up to 7.2p2
        start_in, start_ex, end_in, end_ex = (bound and bound + update for bound in (start_in, start_ex, end_in, end_ex))
    return not ((start_in and ours < _key(start_in)) or (start_ex and ours <= _key(start_ex))
                or (end_in and ours > _key(end_in)) or (end_ex and ours >= _key(end_ex)))


def affects(affected, name, version):
    """Whether the CPE matches for the product called `name` cover `version`: None when none names it.

    A CPE names the product when its product words, plus any of its vendor words, are the words of `name`
    (apache:http_server is "Apache HTTP Server", openbsd:openssh is "OpenSSH"; apache:tomcat is neither)."""
    words = _words(name)
    version = version.casefold()
    named = False
    for entry in affected:
        vendor, product = entry[0], _PRODUCT_ALIASES.get(entry[1], entry[1])
        product_words = _words(product)
        if not product_words <= words or not words <= product_words | _words(vendor):
            continue
        named = True
        if _covers(entry, version):
            return True
    return False if named else None
