#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Refresh the digest-pinned base image and Debian snapshot date in the Dockerfile.

Policy: the Dockerfile pins ``BASE_IMAGE`` as ``<tag>@sha256:<index digest>`` and
``DEBIAN_SNAPSHOT`` as a snapshot.debian.org timestamp that is on or after the
base image's creation time. Run this script (and review the diff) whenever base
image or Debian security updates should be picked up; builds never float.

The digest is the multi-architecture image index digest from Docker Hub, and the
script refuses to write it unless the index lists linux/amd64 and linux/arm64.

Usage:
    python scripts/update_base_image.py                 # same tag, new digest + today's snapshot
    python scripts/update_base_image.py --tag python:3.13-slim-trixie
    python scripts/update_base_image.py --dry-run
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
import urllib.request
from pathlib import Path

DOCKERFILE = Path(__file__).resolve().parents[1] / "Dockerfile"
BASE_RE = re.compile(r"^ARG BASE_IMAGE=(?P<tag>[^@\s]+)(?:@(?P<digest>sha256:[0-9a-f]{64}))?$", re.M)
SNAPSHOT_RE = re.compile(r"^ARG DEBIAN_SNAPSHOT=(?P<value>\d{8}T\d{6}Z)$", re.M)
INDEX_TYPES = ",".join(
    (
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    )
)
REQUIRED_PLATFORMS = {("linux", "amd64"), ("linux", "arm64")}


def _get(url: str, headers: dict[str, str]):
    request = urllib.request.Request(url, headers=headers)
    return urllib.request.urlopen(request, timeout=60)  # noqa: S310 - fixed https URLs


def resolve_digest(tag: str) -> str:
    """Return the verified multi-arch index digest for a Docker Hub library tag."""
    repository, _, version = tag.partition(":")
    if not version or "/" in repository:
        raise SystemExit(f"Expected a Docker Hub official image tag like python:3.13-slim, got {tag!r}")
    token_url = (
        "https://auth.docker.io/token?service=registry.docker.io"
        f"&scope=repository:library/{repository}:pull"
    )
    with _get(token_url, {}) as response:
        token = json.load(response)["token"]
    headers = {"Authorization": f"Bearer {token}", "Accept": INDEX_TYPES}
    url = f"https://registry-1.docker.io/v2/library/{repository}/manifests/{version}"
    with _get(url, headers) as response:
        digest = response.headers["Docker-Content-Digest"]
        index = json.load(response)
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest or ""):
        raise SystemExit(f"Registry returned an unexpected digest: {digest!r}")
    platforms = {
        (m["platform"]["os"], m["platform"]["architecture"])
        for m in index.get("manifests", [])
        if "platform" in m
    }
    missing = REQUIRED_PLATFORMS - platforms
    if missing:
        raise SystemExit(f"{tag} index lacks required platforms: {sorted(missing)}")
    return digest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tag", help="image tag to pin (default: the tag already in the Dockerfile)")
    parser.add_argument(
        "--snapshot",
        help="DEBIAN_SNAPSHOT value such as 20261015T000000Z (default: start of today, UTC)",
    )
    parser.add_argument("--dockerfile", type=Path, default=DOCKERFILE)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    text = args.dockerfile.read_text(encoding="utf-8")
    base = BASE_RE.search(text)
    snapshot = SNAPSHOT_RE.search(text)
    if not base or not snapshot:
        raise SystemExit("Dockerfile lacks the expected ARG BASE_IMAGE / ARG DEBIAN_SNAPSHOT lines")

    tag = args.tag or base.group("tag")
    digest = resolve_digest(tag)
    stamp = args.snapshot or dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT000000Z")
    if not re.fullmatch(r"\d{8}T\d{6}Z", stamp):
        raise SystemExit("--snapshot must look like 20261015T000000Z")

    text = BASE_RE.sub(lambda _m: f"ARG BASE_IMAGE={tag}@{digest}", text, count=1)
    text = SNAPSHOT_RE.sub(lambda _m: f"ARG DEBIAN_SNAPSHOT={stamp}", text, count=1)
    print(f"BASE_IMAGE={tag}@{digest}\nDEBIAN_SNAPSHOT={stamp}")
    if not args.dry_run:
        args.dockerfile.write_bytes(text.encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
