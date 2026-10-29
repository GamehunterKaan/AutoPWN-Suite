# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Which product versions an NVD record marks vulnerable, from its CPE applicability statements."""
import re

_CPE_SEPARATOR = re.compile(r"(?<!\\):")
_RANGE = ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding")
# NVD's CPE product names that differ from the name a description and GenerateKeyword use.
_PRODUCT_ALIASES = {"internet_information_server": "iis", "internet_information_services": "iis", "mysql_server": "mysql"}
# Words NVD adds to a product's own name: f5:nginx_open_source is nginx, bea:weblogic_server is WebLogic.
_GENERIC_WORDS = frozenset({"application", "daemon", "ftp", "http", "imap", "mail", "open", "server", "service",
                            "services", "source", "web"})
# Libraries and plugins named like the network service Nmap fingerprints (the Mongoose web server is cesanta's).
_OTHER_PRODUCTS = frozenset({("docmosis", "tornado"), ("mongodb", "node.js"), ("mongoosejs", "mongoose"),
                             ("php", "memcached")})
# These words mark a release before the one they follow (2.0rc1 < 2.0), in this order; other letters follow it
# (1.3.3c > 1.3.3), and these name the release itself (4.0.0.Final is 4.0.0).
_PRE_RELEASE = {"dev": 0, "snapshot": 0, "alpha": 1, "beta": 2, "m": 3, "milestone": 3, "pre": 4, "preview": 4, "rc": 5}
_FINAL = frozenset({"final", "ga", "release"})


def _words(text):
    return frozenset(re.findall(r"[a-z0-9]+", text.casefold()))


def find_affected(record) -> tuple:
    """The vulnerable CPE matches of an NVD record as (part, vendor, product, version, update, start including,
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
                    found.append((parts[2], parts[3], parts[4], parts[5], parts[6]) + bounds)
    except (KeyError, TypeError, AttributeError):
        pass
    return tuple(found)


def _parts(version):
    # Bounded runs: int() refuses numbers of more than 4300 digits, and a copied database controls these texts.
    return re.findall(r"[0-9]{1,18}|[a-z]+", version.casefold())


def _release(parts):
    """The leading numbers of a version: 2.4.52 of 2.4.52, 7.9 of 7.9p1."""
    numbers = []
    for part in parts:
        if not part.isdigit():
            break
        numbers.append(int(part))
    return numbers


def _key(version):
    """Sort key of a version: numbers compare numerically, the release's trailing zeros do not count (2.4 is
    2.4.0), pre-releases sort below it and other suffixes above it, and a marker ends every key."""
    parts = _parts(version)
    numbers = _release(parts)
    key = [(2, number) for number in numbers]
    while key and key[-1] == (2, 0):
        key.pop()
    for index in range(len(numbers), len(parts)):
        part = parts[index]
        if part.isdigit():
            key.append((2, int(part)))
        elif part in _PRE_RELEASE and (part != "m" or index + 1 < len(parts) and parts[index + 1].isdigit()):
            key.append((-1, _PRE_RELEASE[part]))  # 9.0.0-M1 is a milestone; OpenSSL's 1.0.0m is not
        elif part not in _FINAL:
            key.append((1, part))
    return key + [(0, "")]


def _numbers(version):
    """The dotted numbers a version starts with: 7.9 of 7.9p1."""
    return re.match(r"[0-9.]*", version).group()


def _join(version, update):
    """A CPE version with its update: 7.2p2, but 10.6.0.1 rather than 10.6.01 for update 1."""
    return version + "." + update if update[:1].isdigit() else version + update


def _undecided(version, bound, upper):
    """Whether a bound falls inside the releases our version may be: is Apache's "2.4" below 2.4.52 or not? An
    upper bound of 2.4.0 or 2.4 leaves out the later 2.4.x; a lower one of 2.4.0 does not."""
    ours, theirs = _release(_parts(version)), _release(_parts(bound))
    if theirs[:len(ours)] != ours:
        return False
    return len(theirs) >= len(ours) if upper else len(theirs) > len(ours) and any(theirs[len(ours):])


def _pre_release_of(version, bound):
    """Whether `version` is a pre-release of the release `bound` names: NVD starts "9.0.0-M1 to 9.0.30" at 9.0.0."""
    return (any(rank == -1 for rank, _part in _key(version)) and all(rank != -1 for rank, _part in _key(bound))
            and _key(_numbers(version)) == _key(bound))


def _covers(entry, version, shortened, portable):
    _part, _vendor, product, cpe_version, update, start_in, start_ex, end_in, end_ex = entry
    if cpe_version == "-":
        return False
    ours = _key(version)
    if cpe_version != "*":
        if shortened:
            return False  # Apache's "2.4" may be any 2.4.x, not the one release listed (2.4.0, or NVD's "2.4")
        if update not in ("*", "-", ""):
            return _key(_join(cpe_version, update)) == ours
        if _key(cpe_version) == ours:
            return True
        # 1.3.3 with any update covers 1.3.3c, and 9.2 (old records' 9.2.0) its 9.2.0rc1 or 2.6 its 2.6.0b1, but 9.6
        # (BIND's 9.6-ESV) does not cover the patch level 9.6.0-P1.
        prefix = _numbers(version)
        return (update == "*" and _key(cpe_version) == _key(prefix)
                and (len(_release(_parts(cpe_version))) == len(_release(_parts(prefix)))
                     or not re.fullmatch(r"p[0-9]+", version[len(prefix):], re.IGNORECASE)))
    if update not in ("*", "-", ""):  # openssh:*:p2 up to 7.2 is up to 7.2p2
        start_in, start_ex, end_in, end_ex = (bound and _join(bound, update)
                                              for bound in (start_in, start_ex, end_in, end_ex))
    elif (product == "openssh" and end_in and _key(re.sub(r"p[0-9]+$", "", version)) == _key(end_in)
          and (portable is None or portable > _key(end_in))):
        # Portable 7.9p1 is release 7.9, which "up to 7.9" includes, unless the record lists portable releases
        # itself and none after 7.9 (CVE-2024-6387 lists 8.5p1 and stops at 9.8, which 9.8p1 fixed).
        end_in = None
    for bound, upper, holds in ((start_in, False, lambda key: ours >= key or _pre_release_of(version, start_in)),
                                (start_ex, False, lambda key: ours > key),
                                (end_in, True, lambda key: ours <= key), (end_ex, True, lambda key: ours < key)):
        if bound and (shortened and _undecided(version, bound, upper) or not holds(_key(bound))):
            return False
    return True


def _names(entry, words):
    """Whether a CPE names the application called by `words`: its product words, less the generic ones, plus
    any of its vendor words (apache:http_server is "Apache HTTP Server", openbsd:openssh is "OpenSSH")."""
    part, vendor, product = entry[0], entry[1], _PRODUCT_ALIASES.get(entry[2], entry[2])
    if part != "a" or (vendor, entry[2]) in _OTHER_PRODUCTS:  # An operating system is not its own ftpd.
        return False
    product_words = _words(product)
    return (product_words - _GENERIC_WORDS or product_words) <= words <= product_words | _words(vendor)


def cut_short(records, name, version):
    """Whether `version` has fewer release numbers than the product's releases almost always have, judged by
    the versions NVD gives for it in `records` (the affected matches of each search result): Apache's "2.4"
    is some 2.4.x, while Exim's 4.92 is a release of its own (4.92.1 fixed it). A version with a suffix
    (8.5beta2, 7.9p1) names its release."""
    words, length = _words(name), len(_release(_parts(version)))
    if len(_parts(version)) > length:
        return False
    lengths = [len(_release(_parts(text))) for affected in records for entry in affected if _names(entry, words)
               for text in (entry[3],) + entry[5:] if text and text[0].isdigit()]
    return sum(found <= length for found in lengths) < 0.15 * len(lengths)


def reaches(version, fixed):
    """Whether `version` is the release `fixed` names or a later build of it: 4.4p1 reaches 4.4, 9.11.5P4
    9.11.5P2, 1.3.3d 1.3.3c and 1.1.21 1.1.21rc1, but 2.4.52 does not reach 2.4, nor 9.12.0 9.11.5P4, nor a beta
    (2.23b1) or a vendor's own build (8.0hp1) its release, nor 10.7.0 a series named with fewer numbers (10.7)."""
    build, fixed_build = version[len(_numbers(version)):].lower(), fixed[len(_numbers(fixed)):].lower()
    return (_key(_numbers(version)) == _key(_numbers(fixed)) and _key(version) >= _key(fixed)
            and len(_release(_parts(fixed))) >= len(_release(_parts(version))) and (
        re.fullmatch(r"(?:p[0-9]+|[a-z])?", build) is not None or build.rstrip("0123456789") == fixed_build.rstrip("0123456789")))


def affects(affected, name, version, shortened=False):
    """Whether the CPE matches for the application called `name` cover `version`.

    None when they say nothing about versions: there are no matches (NVD has not analyzed the record) or the
    product's only matches are unbounded ("every version", mostly in old records, which would otherwise apply
    to every release ever made). False when the matches name only other products. A `shortened` version is
    any release that starts with it, so a bound or release with more numbers does not cover it."""
    if not affected:
        return None
    words = _words(name)
    # The last portable OpenSSH release (8.5p1) the record lists itself, if any.
    portable = max((_key(entry[3]) for entry in affected if entry[2] == "openssh" and re.fullmatch(r"p[0-9]+", entry[4])),
                   default=None)
    bounded = unbounded = False
    for entry in affected:
        if not _names(entry, words):
            continue
        if entry[3] == "*" and not any(entry[5:]):
            unbounded = True
            continue
        bounded = True
        if _covers(entry, version, shortened, portable):
            return True
    return None if unbounded and not bounded else False
