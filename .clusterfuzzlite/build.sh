#!/bin/bash -eu
# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
# Builds the Atheris fuzzers in scripts/fuzz/ for ClusterFuzzLite ($SRC is the checkout, $OUT receives the fuzzers).

# The same hash-verified runtime dependencies as the container image. Like the container image, the fuzzers use the
# package from the checkout (no pip install of an unhashed directory), so PyInstaller finds it on the import path.
pip3 install --require-hashes --no-deps -r requirements-locked.txt
export PYTHONPATH="$PWD${PYTHONPATH:+:$PYTHONPATH}"

# The PyInstaller builds run in parallel. compile_python_fuzzer empties $SRC/pyfuzzworkdir before each build, so
# every build gets its own $SRC for that work directory; its other outputs are named after the fuzzer.
builds=()
for fuzzer in scripts/fuzz/fuzz_*.py; do
  SRC="$(mktemp -d)" compile_python_fuzzer "$fuzzer" &
  builds+=("$!")
  name="$(basename "$fuzzer" .py)"
  # A seed corpus of valid inputs lets the fuzzer start from inputs that pass the first checks.
  if [ -d "scripts/fuzz/seeds/$name" ]; then
    zip -jq "$OUT/${name}_seed_corpus.zip" scripts/fuzz/seeds/"$name"/*
  fi
done
# `wait PID` returns that build's exit status, so a failed build fails the script (-e).
for build in "${builds[@]}"; do
  wait "$build"
done
