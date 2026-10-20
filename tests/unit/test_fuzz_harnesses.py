# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""The ClusterFuzzLite harnesses in scripts/fuzz/ must keep importing, accept their seeds and never fail on junk."""
import importlib.util
import random
import sys
import types
from contextlib import contextmanager
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
HARNESSES = sorted((ROOT / "scripts" / "fuzz").glob("fuzz_*.py"))


class FuzzedDataProvider:
    """The small part of atheris.FuzzedDataProvider the harnesses use."""

    def __init__(self, data):
        self.data, self.position = data, 0

    def ConsumeUnicodeNoSurrogates(self, count):
        chunk = self.data[self.position:self.position + count]
        self.position += len(chunk)
        return chunk.decode("utf-8", "ignore")

    def ConsumeIntInRange(self, low, high):
        byte = self.data[self.position] if self.position < len(self.data) else 0
        self.position += 1
        return low + byte % (high - low + 1)


@pytest.fixture
def harness(monkeypatch):
    """Load a harness with atheris replaced by a stub, so the normal suite needs no fuzzing engine."""
    stub = types.ModuleType("atheris")
    stub.instrument_imports = contextmanager(lambda: (yield))
    stub.FuzzedDataProvider = FuzzedDataProvider
    stub.Setup = stub.Fuzz = lambda *args, **kwargs: None
    monkeypatch.setitem(sys.modules, "atheris", stub)

    def load(path):
        spec = importlib.util.spec_from_file_location(path.stem, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    return load


def test_every_harness_has_a_seed_directory_with_a_valid_seed():
    assert len(HARNESSES) >= 3
    for path in HARNESSES:
        seeds = [seed for seed in (ROOT / "scripts" / "fuzz" / "seeds" / path.stem).glob("*") if seed.is_file()]
        assert seeds, f"{path.name} needs a seed corpus in scripts/fuzz/seeds/{path.stem}/"


@pytest.mark.parametrize("path", HARNESSES, ids=lambda path: path.name)
def test_harness_accepts_its_seeds_and_survives_junk(harness, path):
    module = harness(path)
    assert callable(module.TestOneInput) and callable(module.main)
    for seed in (ROOT / "scripts" / "fuzz" / "seeds" / path.stem).glob("*"):
        module.TestOneInput(seed.read_bytes())
    rng = random.Random(20261018)
    for _ in range(300):
        module.TestOneInput(bytes(rng.randrange(256) for _ in range(rng.randrange(0, 200))))


@pytest.mark.parametrize("nested", [b"[" * 200000, b"[" * 4096, b'{"a":' * 3000], ids=["lists-200000", "lists-4096", "objects-3000"])
def test_the_options_harness_survives_json_nested_deeper_than_python_allows(harness, nested):
    # json.loads raises RecursionError (not ValueError) beyond about a thousand levels on Python 3.10 and 3.11,
    # and beyond a much larger depth on newer versions; the fuzzer must not report that as a finding.
    harness(ROOT / "scripts" / "fuzz" / "fuzz_web_options.py").TestOneInput(nested)


def test_the_nmap_seed_is_a_document_the_parser_accepts(harness):
    from autopwn_suite.nmap_backend import parse_nmap_xml

    assert parse_nmap_xml((ROOT / "scripts/fuzz/seeds/fuzz_nmap_xml/valid.xml").read_text(encoding="utf-8"))


def test_the_options_seed_passes_the_schema(harness):
    import json

    from autopwn_suite.web.options import normalize_options

    assert normalize_options(json.loads((ROOT / "scripts/fuzz/seeds/fuzz_web_options/valid.json").read_text(encoding="utf-8")))["verify_tls"] is True


def test_the_update_harness_drives_each_check_with_real_input(harness):
    module = harness(ROOT / "scripts" / "fuzz" / "fuzz_update_checker.py")
    # The first byte picks the check: 0 repository, 1 branch or tag name, 2 GitHub's release response.
    module.TestOneInput(b"\x00GamehunterKaan/AutoPWN-Suite")
    module.TestOneInput(b"\x00../etc")  # refused through the documented error
    module.TestOneInput(b"\x01release/2.7")
    module.TestOneInput(b"\x01--upload-pack=x")
    module.TestOneInput(b'\x02{"tag_name": "v9.9.9", "html_url": "https://example.test/r"}')
    module.TestOneInput(b'\x02["not", "an", "object"]')
    module.TestOneInput(b'\x02{"tag_name": 7}')
    module.TestOneInput(b'\x02{"tag_name": "' + b"9" * 5000 + b'"}')  # int() refuses 4300 digits or more


def test_the_workflow_and_build_script_cover_the_harnesses():
    build = (ROOT / ".clusterfuzzlite/build.sh").read_text(encoding="utf-8")
    assert "scripts/fuzz/fuzz_*.py" in build and "compile_python_fuzzer" in build and "--require-hashes" in build
    workflow = (ROOT / ".github/workflows/cflite_pr.yml").read_text(encoding="utf-8")
    assert "build_fuzzers@" in workflow and "run_fuzzers@" in workflow and "mode: code-change" in workflow


def test_fuzz_files_are_kept_out_of_the_product_image_but_not_out_of_the_fuzzing_image():
    product = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    assert "scripts/fuzz" in product and ".clusterfuzzlite" in product
    # ClusterFuzzLite builds with the repository's .dockerignore unless a Dockerfile-specific one exists,
    # and would then lose .clusterfuzzlite/build.sh from its build context.
    own = (ROOT / ".clusterfuzzlite/Dockerfile.dockerignore").read_text(encoding="utf-8").splitlines()
    assert "scripts/fuzz" not in own and ".clusterfuzzlite" not in own
