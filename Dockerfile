# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
# Repeatable build policy (see docs/BUILDING.md):
#  * The base image is pinned by tag AND multi-arch index digest. Refresh both
#    together with: python scripts/update_base_image.py
#  * Debian packages come from a dated snapshot.debian.org archive, so the same
#    DEBIAN_SNAPSHOT yields the same nmap and dependency versions.
#  * Python dependencies are installed from requirements-locked.txt, which is
#    generated from poetry.lock and carries artifact hashes (--require-hashes).
#  * Pass --build-arg SOURCE_DATE_EPOCH=<unix time> together with BuildKit's
#    rewrite-timestamp output option to make layer timestamps deterministic.
ARG BASE_IMAGE=python:3.13-slim-trixie@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f
FROM ${BASE_IMAGE}

# Must be on or after the creation date of the pinned base image.
ARG DEBIAN_SNAPSHOT=20261015T000000Z
ARG DEBIAN_CODENAME=trixie
ARG DEBIAN_FRONTEND=noninteractive
# Intentionally has no default: BuildKit uses it for rewrite-timestamp, and an
# unset value is simply absent from the build environment.
ARG SOURCE_DATE_EPOCH

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN set -eux; \
    keyring=/usr/share/keyrings/debian-archive-keyring.gpg; \
    test -s "$keyring"; \
    { \
      printf 'Types: deb\n'; \
      printf 'URIs: http://snapshot.debian.org/archive/debian/%s\n' "${DEBIAN_SNAPSHOT}"; \
      printf 'Suites: %s %s-updates\n' "${DEBIAN_CODENAME}" "${DEBIAN_CODENAME}"; \
      printf 'Components: main\n'; \
      printf 'Signed-By: %s\n\n' "$keyring"; \
      printf 'Types: deb\n'; \
      printf 'URIs: http://snapshot.debian.org/archive/debian-security/%s\n' "${DEBIAN_SNAPSHOT}"; \
      printf 'Suites: %s-security\n' "${DEBIAN_CODENAME}"; \
      printf 'Components: main\n'; \
      printf 'Signed-By: %s\n' "$keyring"; \
    } > /etc/apt/sources.list.d/debian.sources; \
    rm -f /etc/apt/sources.list; \
    printf 'Acquire::Check-Valid-Until "false";\nAcquire::Retries "5";\n' > /etc/apt/apt.conf.d/99snapshot; \
    apt-get -y update; \
    apt-get -y install --no-install-recommends nmap; \
    apt-get -y clean; \
    rm -rf /var/lib/apt/lists/* /var/log/apt/* /var/log/dpkg.log /var/log/alternatives.log \
           /var/cache/ldconfig/aux-cache

# Hash-checked, wheel-only, no bytecode compilation (pyc files embed install
# time and would make the layer differ between builds).
COPY requirements-locked.txt .
RUN pip install --no-compile --require-hashes --only-binary=:all: -r requirements-locked.txt

COPY . .

# Inside a container the dashboard must listen on the container interface so that
# a published port can reach it. Publish it to loopback only (-p 127.0.0.1:8080:8080)
# or override this with AUTOPWN_WEB_HOST=127.0.0.1 when using host networking.
ENV AUTOPWN_WEB_HOST=0.0.0.0
ENV AUTOPWN_WEB_PORT=8080

EXPOSE ${AUTOPWN_WEB_PORT}

ENTRYPOINT ["python", "autopwn.py"]
CMD ["--web"]
