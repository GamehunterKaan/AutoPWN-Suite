# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
# Pinned by digest; refresh it deliberately (gcr.io/oss-fuzz-base/base-builder-python:v1).
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:21f6fab17ace4dc76e1c56de91ee95d3d03da021df94b41056ba036f6c6f55e9
COPY . $SRC/autopwn-suite
WORKDIR $SRC/autopwn-suite
COPY .clusterfuzzlite/build.sh $SRC/
