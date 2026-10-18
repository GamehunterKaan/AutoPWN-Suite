# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""The standalone binaries are built from a hash-pinned interpreter, twice, and must come out identical."""
import hashlib
import importlib.util
import io
import re
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("build_binary", ROOT / "scripts" / "build_binary.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

WORKFLOW = (ROOT / ".github" / "workflows" / "build-binary.yml").read_text(encoding="utf-8")


def make_archive(directory, name="interpreter.tar.gz", member="python/bin/python3"):
    archive = directory / name
    with tarfile.open(archive, "w:gz") as tar:
        data = b"#!/bin/sh\n"
        info = tarfile.TarInfo(member)
        info.size, info.mode = len(data), 0o755
        tar.addfile(info, io.BytesIO(data))
    return archive


def pins_for(archive, sha256=None, target="linux-amd64"):
    return {"url": builder.DOWNLOAD_PREFIX + "1/", "archives": {target: {"file": archive.name, "sha256": sha256 or builder.sha256_of(archive)}}}


def test_pins_cover_every_binary_target_with_a_verifiable_archive():
    pins = builder.load_pins()
    targets = set(re.findall(r"^\s+- target: (\S+)$", WORKFLOW, re.MULTILINE))
    assert set(pins["archives"]) == targets == {"linux-amd64", "linux-arm64", "windows-amd64", "macos-arm64"}
    assert pins["url"].startswith(builder.DOWNLOAD_PREFIX) and pins["url"].endswith(f"/{pins['release']}/")
    for target, entry in pins["archives"].items():
        assert entry["file"].startswith(f"cpython-{pins['python']}+{pins['release']}-"), target
        assert entry["file"].endswith("-install_only_stripped.tar.gz"), target
        assert re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]), target
    assert len({entry["sha256"] for entry in pins["archives"].values()}) == 4


def test_interpreter_is_unpacked_only_after_its_hash_matches(tmp_path):
    archive = make_archive(tmp_path)
    python = builder.fetch_python(pins_for(archive), "linux-amd64", tmp_path)
    assert python == tmp_path / "python" / "python" / "bin" / "python3" and python.read_bytes() == b"#!/bin/sh\n"


def test_tampered_interpreter_archive_is_refused_without_unpacking(tmp_path):
    archive = make_archive(tmp_path)
    with pytest.raises(SystemExit, match="expected " + "0" * 64):
        builder.fetch_python(pins_for(archive, sha256="0" * 64), "linux-amd64", tmp_path)
    assert not (tmp_path / "python").exists()


def test_archive_members_cannot_leave_the_destination(tmp_path):
    for name, kind, link in [("../escape", tarfile.REGTYPE, ""), ("/absolute", tarfile.REGTYPE, ""), ("python/link", tarfile.SYMTYPE, "../../outside"),
                             ("python/hard", tarfile.LNKTYPE, "../outside"), ("python/device", tarfile.CHRTYPE, "")]:
        archive = tmp_path / "bad.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            info = tarfile.TarInfo(name)
            info.type, info.linkname = kind, link
            tar.addfile(info)
        with pytest.raises(SystemExit, match="refusing archive member"):
            builder.fetch_python(pins_for(archive), "linux-amd64", tmp_path)
        assert not (tmp_path / "python" / "python" / "escape").exists() and not (tmp_path / "escape").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="creating symbolic links needs a privilege on Windows")
def test_interpreter_archive_keeps_its_relative_links(tmp_path):
    archive = tmp_path / "links.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        real = tarfile.TarInfo("python/bin/python3.13")
        real.size = 1
        tar.addfile(real, io.BytesIO(b"x"))
        link = tarfile.TarInfo("python/bin/python3")
        link.type, link.linkname = tarfile.SYMTYPE, "python3.13"
        tar.addfile(link)
    python = builder.fetch_python(pins_for(archive), "linux-amd64", tmp_path)
    assert python.is_symlink() and python.read_bytes() == b"x"


def test_download_is_limited_to_the_pinned_release_host(tmp_path):
    pins = pins_for(make_archive(tmp_path))
    pins["url"] = "https://example.com/python/"
    with pytest.raises(SystemExit, match="refusing to download"):
        builder.fetch_python(pins, "linux-amd64", tmp_path)


def test_windows_interpreter_is_the_exe_in_the_archive_root(tmp_path):
    archive = make_archive(tmp_path, member="python/python.exe")
    python = builder.fetch_python(pins_for(archive, target="windows-amd64"), "windows-amd64", tmp_path)
    assert python.name == "python.exe" and python.is_file()


@pytest.fixture
def fake_pyinstaller(monkeypatch, tmp_path):
    """run_pyinstaller stand-in that writes whatever bytes the test queues, one build at a time."""
    outputs = []

    def run(python, work, target, epoch):
        built = work / "dist" / "autopwn-suite"
        built.parent.mkdir(parents=True, exist_ok=True)
        built.write_bytes(outputs.pop(0))
        return built

    monkeypatch.setattr(builder, "run_pyinstaller", run)
    return outputs


def test_repeat_build_passes_when_both_builds_are_identical(fake_pyinstaller, tmp_path):
    fake_pyinstaller += [b"same", b"same"]
    built = builder.build(None, tmp_path, "linux-amd64", 1, repeat=True)
    assert built.read_bytes() == b"same" and fake_pyinstaller == []


def test_repeat_build_fails_when_the_second_build_differs(fake_pyinstaller, tmp_path):
    fake_pyinstaller += [b"one", b"two"]
    with pytest.raises(SystemExit, match=hashlib.sha256(b"one").hexdigest() + " then " + hashlib.sha256(b"two").hexdigest()):
        builder.build(None, tmp_path, "linux-amd64", 1, repeat=True)


def test_without_repeat_the_binary_is_built_once(fake_pyinstaller, tmp_path):
    fake_pyinstaller += [b"only"]
    assert builder.build(None, tmp_path, "linux-amd64", 1, repeat=False).read_bytes() == b"only"


def test_source_date_epoch_is_required(monkeypatch, tmp_path):
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    with pytest.raises(SystemExit):
        builder.main(["--target", "linux-amd64", "--work-dir", str(tmp_path), "--output", str(tmp_path / "out")])


def test_workflow_builds_through_the_script_with_the_commit_time():
    assert "scripts/build_binary.py" in WORKFLOW and "--repeat" in WORKFLOW
    assert "source-date-epoch" in WORKFLOW and "SOURCE_DATE_EPOCH" in WORKFLOW
