"""Release artifacts must bind reviewed tagged source, bytes and image digest."""

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import zipfile

import pytest


spec = importlib.util.spec_from_file_location(
    "release_assets", Path(__file__).resolve().parents[2] / "scripts/release_assets.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


def command(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


@pytest.fixture
def source_repo(tmp_path):
    repo = tmp_path / "source"
    repo.mkdir()
    command(repo, "init", "-b", "main")
    command(repo, "config", "user.name", "Release Test")
    command(repo, "config", "user.email", "release@example.test")
    (repo / "pyproject.toml").write_text('[tool.poetry]\nversion = "2.6.0"\n')
    (repo / "autopwn.py").write_text('__version__ = "2.6.0"\n')
    (repo / "source.txt").write_text("reviewed source")
    command(repo, "add", ".")
    command(repo, "-c", "commit.gpgsign=false", "commit", "-m", "Reviewed source")
    command(repo, "tag", "v2.6.0")
    command(repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    return repo


def test_archives_use_tag_and_manifest_binds_every_asset(source_repo, tmp_path):
    (source_repo / "source.txt").write_text("dirty unreviewed source")
    (source_repo / "secret.txt").write_text("must not enter archive")
    notes = tmp_path / "CHANGELOG.md"
    notes.write_text("## [2.6.0]\n### Functional changes\nChanges.\n### Security changes\nSecurity.\n")
    output = tmp_path / "assets"
    commit = release.prepare(source_repo, "v2.6.0", output, notes)
    with zipfile.ZipFile(output / "autopwn-suite-v2.6.0.zip") as archive:
        assert archive.read("autopwn-suite-v2.6.0/source.txt") == b"reviewed source"
        assert not any(name.endswith("secret.txt") for name in archive.namelist())
    digest = "sha256:" + "a" * 64
    manifest = release.write_manifest(source_repo, "v2.6.0", output,
                                      "docker.io/gamehunterkaan/autopwn-suite", digest)
    assert manifest["source_commit"] == commit
    assert manifest["container"]["digest"] == digest
    assert len(manifest["assets"]) == 3
    for asset in manifest["assets"]:
        assert asset["sha256"] == hashlib.sha256((output / asset["name"]).read_bytes()).hexdigest()
    assert json.loads((output / "release-manifest.json").read_text()) == manifest


@pytest.mark.parametrize("tag", ["../v2.6.0", "v2.6.0\nattack", "--help", "v02.6.0", "v2.6.0;id"])
def test_untrusted_tag_is_rejected_before_git(source_repo, tag):
    with pytest.raises(ValueError, match="version tag"):
        release.release_commit(source_repo, tag)


def test_version_mismatch_and_unreviewed_source_are_rejected(source_repo):
    command(source_repo, "tag", "v2.6.1")
    with pytest.raises(ValueError, match="package version"):
        release.release_commit(source_repo, "v2.6.1")
    (source_repo / "source.txt").write_text("not reviewed")
    command(source_repo, "add", ".")
    command(source_repo, "-c", "commit.gpgsign=false", "commit", "-m", "Not on reviewed ref")
    command(source_repo, "tag", "v2.7.0")
    with pytest.raises(subprocess.CalledProcessError):
        release.release_commit(source_repo, "v2.7.0")


def test_notes_must_describe_functional_and_security_changes():
    with pytest.raises(ValueError, match="functional and security"):
        release.release_notes("## [2.6.0]\nJust a commit link.\n", "v2.6.0")
    with pytest.raises(ValueError, match="descriptive"):
        release.release_notes("## [2.6.0]\n### Functional changes\nSomething.\n### Security changes\n", "v2.6.0")


def test_runtime_version_must_match(source_repo):
    (source_repo / "autopwn.py").write_text('__version__ = "2.5.0"\n')
    command(source_repo, "add", ".")
    command(source_repo, "-c", "commit.gpgsign=false", "commit", "-m", "Mismatched runtime")
    command(source_repo, "tag", "-f", "v2.6.0")
    command(source_repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    with pytest.raises(ValueError, match="runtime version"):
        release.release_commit(source_repo, "v2.6.0")


@pytest.mark.parametrize("image,digest", [
    ("evil.example/autopwn-suite", "sha256:" + "a" * 64),
    ("docker.io/gamehunterkaan/autopwn-suite", "sha256:bad"),
])
def test_manifest_rejects_invalid_registry_or_digest(source_repo, tmp_path, image, digest):
    with pytest.raises(ValueError, match="official Docker Hub"):
        release.write_manifest(source_repo, "v2.6.0", tmp_path, image, digest)
