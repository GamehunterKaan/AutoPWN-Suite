#!/bin/bash -eu
# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
# Builds the Atheris fuzzers in fuzz/ for ClusterFuzzLite ($SRC is the checkout, $OUT receives the fuzzers).

# The same hash-verified runtime dependencies as the container image, then the package itself.
pip3 install --require-hashes --no-deps -r requirements-locked.txt
pip3 install --no-deps .

for fuzzer in fuzz/fuzz_*.py; do
  compile_python_fuzzer "$fuzzer"
  name="$(basename "$fuzzer" .py)"
  # A seed corpus of valid inputs lets the fuzzer start from inputs that pass the first checks.
  if [ -d "fuzz/seeds/$name" ]; then
    zip -jq "$OUT/${name}_seed_corpus.zip" fuzz/seeds/"$name"/*
  fi
done
