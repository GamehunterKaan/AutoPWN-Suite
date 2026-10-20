# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Release artifacts must bind reviewed tagged source, bytes and image digest."""

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

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
    (repo / "autopwn_suite").mkdir()
    (repo / "autopwn_suite" / "__init__.py").write_text('__version__ = "2.6.0"\n')
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
    for arch in ("amd64", "arm64"):
        (output / f"autopwn-suite-v2.6.0-linux-{arch}.cdx.json").write_text(json.dumps({
            "bomFormat": "CycloneDX", "components": [{"name": "nmap"}, {"name": "requests"}],
        }))
    manifest = release.write_manifest(source_repo, "v2.6.0", output,
                                      "docker.io/gamehunterkaan/autopwn-suite", digest)
    assert manifest["source_commit"] == commit
    assert manifest["container"]["digest"] == digest
    assert len(manifest["assets"]) == 3
    assert len(manifest["supporting_archive"]["files"]) == 4
    assert {p.name for p in output.iterdir()} == {
        "autopwn-suite-v2.6.0.tar.gz", "autopwn-suite-v2.6.0.zip",
        "autopwn-suite-v2.6.0-security.zip", "release-manifest.json",
    }
    assert_supporting_hashes(output, manifest)
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
    (source_repo / "autopwn_suite" / "__init__.py").write_text('__version__ = "2.5.0"\n')
    command(source_repo, "add", ".")
    command(source_repo, "-c", "commit.gpgsign=false", "commit", "-m", "Mismatched runtime")
    command(source_repo, "tag", "-f", "v2.6.0")
    command(source_repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    with pytest.raises(ValueError, match="runtime version"):
        release.release_commit(source_repo, "v2.6.0")


def test_release_before_the_package_layout_keeps_its_version_in_autopwn_py(source_repo):
    """Backfilling signatures for old tags still finds the runtime version."""
    shutil.rmtree(source_repo / "autopwn_suite")
    (source_repo / "autopwn.py").write_text('__version__ = "2.6.0"\n')
    command(source_repo, "add", "-A")
    command(source_repo, "-c", "commit.gpgsign=false", "commit", "-m", "Legacy layout")
    command(source_repo, "tag", "-f", "v2.6.0")
    command(source_repo, "update-ref", "refs/remotes/origin/main", "HEAD")
    assert release.release_commit(source_repo, "v2.6.0") == command(source_repo, "rev-parse", "HEAD")


@pytest.mark.parametrize("image,digest", [
    ("evil.example/autopwn-suite", "sha256:" + "a" * 64),
    ("docker.io/gamehunterkaan/autopwn-suite", "sha256:bad"),
])
def test_manifest_rejects_invalid_registry_or_digest(source_repo, tmp_path, image, digest):
    with pytest.raises(ValueError, match="official Docker Hub"):
        release.write_manifest(source_repo, "v2.6.0", tmp_path, image, digest)


@pytest.fixture
def backfill_assets(source_repo, tmp_path):
    notes = tmp_path / "notes.md"
    notes.write_text("## [2.6.0]\n### Functional changes\nChanges.\n### Security changes\nSecurity.\n")
    output = tmp_path / "assets"
    commit = release.prepare(source_repo, "v2.6.0", output, notes)
    index = {"manifests": [{"platform": {"os": "linux", "architecture": arch},
                            "digest": "sha256:" + char * 64}
                           for arch, char in [("amd64", "a"), ("arm64", "b")]]}
    data = json.dumps(index).encode()
    (output / "autopwn-suite-v2.6.0-image-index.json").write_bytes(data)
    for arch in ("amd64", "arm64"):
        prefix = f"autopwn-suite-v2.6.0-linux-{arch}"
        (output / f"{prefix}.cdx.json").write_text(json.dumps({
            "bomFormat": "CycloneDX", "components": [{"name": "nmap"}, {"name": "requests"}],
        }))
        (output / f"{prefix}-sca.json").write_text(json.dumps({"results": [{"packages": [{
            "package": {"name": "example", "version": "1"},
            "vulnerabilities": [{"id": "SYNTHETIC-TEST-1"}],
        }]}]}))
        (output / f"{prefix}-policy.json").write_text(json.dumps({
            "version": "2.6.0", "packages": 1, "violations": ["Synthetic test finding"],
        }))
        (tmp_path / f"config-{arch}.json").write_text(json.dumps([{
            "Os": "linux", "Architecture": arch,
            "RepoDigests": ["gamehunterkaan/autopwn-suite@" + release.platform_digest(index, arch)],
            "Config": {"Labels": {"org.opencontainers.image.revision": commit,
                                   "org.opencontainers.image.version": "2.6.0"}},
        }]))
    return output, "sha256:" + hashlib.sha256(data).hexdigest()


def record_both(source_repo, output, tmp_path):
    for arch in ("amd64", "arm64"):
        release.backfill_record(source_repo, "v2.6.0", output, arch, tmp_path / f"config-{arch}.json")


def test_backfill_binds_original_images_and_keeps_findings(source_repo, tmp_path, backfill_assets):
    output, digest = backfill_assets
    record_both(source_repo, output, tmp_path)
    with pytest.raises(ValueError, match="Unexpected"):
        release.write_manifest(source_repo, "v2.6.0", output, release.OFFICIAL_IMAGE, digest)
    manifest = release.write_manifest(source_repo, "v2.6.0", output, release.OFFICIAL_IMAGE, digest, backfill=True)
    assert len(manifest["assets"]) == 3
    assert len(manifest["supporting_archive"]["files"]) == 11
    assert_supporting_hashes(output, manifest)
    assert manifest["publication"]["security_clearance"] is False
    assert manifest["publication"]["rebuilt"] is False
    assert all(r["policy_violations"] == ["Synthetic test finding"] for r in manifest["publication"]["platforms"])
    for asset in manifest["assets"]:
        assert asset["sha256"] == hashlib.sha256((output / asset["name"]).read_bytes()).hexdigest()


def assert_supporting_hashes(output, manifest):
    metadata = manifest["supporting_archive"]
    with zipfile.ZipFile(output / metadata["name"]) as archive:
        assert set(archive.namelist()) == {asset["name"] for asset in metadata["files"]}
        for asset in metadata["files"]:
            assert hashlib.sha256(archive.read(asset["name"])).hexdigest() == asset["sha256"]
            assert not (output / asset["name"]).exists()


def test_supporting_zip_is_stable_and_preserves_source_bytes(tmp_path):
    archives = []
    for index, order in enumerate([["notes.md", "report.json"], ["report.json", "notes.md"]]):
        output = tmp_path / str(index)
        output.mkdir()
        data = {"autopwn-suite-v2.6.0.zip": b"source zip",
                "autopwn-suite-v2.6.0.tar.gz": b"source tar",
                "notes.md": b"Release notes\n", "report.json": b'{"findings":["example"]}\n'}
        assets = []
        for name in ["autopwn-suite-v2.6.0.zip", "autopwn-suite-v2.6.0.tar.gz", *order]:
            (output / name).write_bytes(data[name])
            assets.append({"name": name, "sha256": hashlib.sha256(data[name]).hexdigest()})
        published, supporting = release.bundle_supporting(output, "v2.6.0", assets)
        assert len(published) == 3
        assert_supporting_hashes(output, {"supporting_archive": supporting})
        assert (output / "autopwn-suite-v2.6.0.zip").read_bytes() == data["autopwn-suite-v2.6.0.zip"]
        assert (output / "autopwn-suite-v2.6.0.tar.gz").read_bytes() == data["autopwn-suite-v2.6.0.tar.gz"]
        archives.append((output / supporting["name"]).read_bytes())
    assert archives[0] == archives[1]


@pytest.mark.parametrize("field,value", [("Architecture", "arm64"), ("RepoDigests", []), ("Config", {"Labels": {}})])
def test_backfill_rejects_wrong_platform_digest_or_revision(source_repo, tmp_path, backfill_assets, field, value):
    output, _ = backfill_assets
    config_path = tmp_path / "config-amd64.json"
    config = json.loads(config_path.read_text())
    config[0][field] = value
    config_path.write_text(json.dumps(config))
    with pytest.raises(ValueError, match="does not match"):
        release.backfill_record(source_repo, "v2.6.0", output, "amd64", config_path)


def test_backfill_does_not_treat_failed_scan_as_success(source_repo, tmp_path, backfill_assets):
    output, _ = backfill_assets
    (output / "autopwn-suite-v2.6.0-linux-amd64-sca.json").write_text('{"results":[]}')
    with pytest.raises(ValueError, match="complete current scan"):
        release.backfill_record(source_repo, "v2.6.0", output, "amd64", tmp_path / "config-amd64.json")


def test_backfill_rejects_tampered_index_or_clearance(source_repo, tmp_path, backfill_assets):
    output, digest = backfill_assets
    record_both(source_repo, output, tmp_path)
    with pytest.raises(ValueError, match="index digest mismatch"):
        release.write_manifest(source_repo, "v2.6.0", output, release.OFFICIAL_IMAGE, "sha256:" + "c" * 64, backfill=True)
    path = output / "autopwn-suite-v2.6.0-linux-amd64-backfill.json"
    record = json.loads(path.read_text())
    record["security_clearance"] = True
    path.write_text(json.dumps(record))
    with pytest.raises(ValueError, match="does not bind"):
        release.write_manifest(source_repo, "v2.6.0", output, release.OFFICIAL_IMAGE, digest, backfill=True)


def test_backfill_rejects_ambiguous_or_invalid_platform():
    entry = {"platform": {"os": "linux", "architecture": "amd64"}, "digest": "sha256:" + "a" * 64}
    with pytest.raises(ValueError, match="exactly one"):
        release.platform_digest({"manifests": [entry, entry]}, "amd64")
    entry["digest"] = "invalid"
    with pytest.raises(ValueError, match="exactly one"):
        release.platform_digest({"manifests": [entry]}, "amd64")


@pytest.fixture
def binary_assets(source_repo, tmp_path):
    """Release staging directory as the sign job sees it: sources, image SBOMs, binaries and their SBOM."""
    notes = tmp_path / "notes.md"
    notes.write_text("## [2.6.0]\n### Functional changes\nChanges.\n### Security changes\nSecurity.\n")
    output = tmp_path / "assets"
    release.prepare(source_repo, "v2.6.0", output, notes)
    for arch in ("amd64", "arm64"):
        (output / f"autopwn-suite-v2.6.0-linux-{arch}.cdx.json").write_text(json.dumps({
            "bomFormat": "CycloneDX", "components": [{"name": "nmap"}, {"name": "requests"}],
        }))
    for name in release.binary_names("v2.6.0"):
        (output / name).write_bytes(b"binary " + name.encode())
    for name in release.binary_sbom_names("v2.6.0"):
        (output / name).write_text(json.dumps({
            "bomFormat": "CycloneDX", "components": [{"name": "requests"}, {"name": "Flask"}, {"name": "cpython"}],
        }))
    return output


IMAGE = "docker.io/gamehunterkaan/autopwn-suite"
DIGEST = "sha256:" + "a" * 64


def test_manifest_binds_binaries_checksums_and_their_sbom(source_repo, binary_assets):
    output = binary_assets
    binaries = release.binary_names("v2.6.0")
    manifest = release.write_manifest(source_repo, "v2.6.0", output, IMAGE, DIGEST, binaries=True)

    published = [asset["name"] for asset in manifest["assets"]]
    assert published == ["autopwn-suite-v2.6.0.tar.gz", "autopwn-suite-v2.6.0.zip", *binaries, "SHA256SUMS",
                         "autopwn-suite-v2.6.0-security.zip"]
    assert {p.name for p in output.iterdir()} == {*published, "release-manifest.json"}
    for asset in manifest["assets"]:
        assert asset["sha256"] == hashlib.sha256((output / asset["name"]).read_bytes()).hexdigest()
    # The binaries stay separate downloads; only their SBOM joins the supporting archive.
    supporting = {asset["name"] for asset in manifest["supporting_archive"]["files"]}
    assert set(release.binary_sbom_names("v2.6.0")) <= supporting
    assert not supporting.intersection({*binaries, "SHA256SUMS"})
    # SHA256SUMS is what `sha256sum -c` reads, sorted, one line per binary.
    lines = (output / "SHA256SUMS").read_text().splitlines()
    assert [line.split("  ", 1)[1] for line in lines] == sorted(binaries)
    for line in lines:
        digest, name = line.split("  ", 1)
        assert digest == hashlib.sha256((output / name).read_bytes()).hexdigest()


def test_manifest_without_the_flag_rejects_binaries_in_staging(source_repo, binary_assets):
    with pytest.raises(ValueError, match="Unexpected"):
        release.write_manifest(source_repo, "v2.6.0", binary_assets, IMAGE, DIGEST)


@pytest.mark.parametrize("missing", ["autopwn-suite-v2.6.0-windows-amd64.exe", "autopwn-suite-v2.6.0-binary-macos-arm64.cdx.json"])
def test_a_missing_binary_or_binaries_sbom_stops_the_release(source_repo, binary_assets, missing):
    (binary_assets / missing).unlink()
    with pytest.raises(ValueError, match="missing"):
        release.write_manifest(source_repo, "v2.6.0", binary_assets, IMAGE, DIGEST, binaries=True)


def test_an_empty_binary_stops_the_release(source_repo, binary_assets):
    (binary_assets / "autopwn-suite-v2.6.0-linux-amd64").write_bytes(b"")
    with pytest.raises(ValueError, match="missing"):
        release.write_manifest(source_repo, "v2.6.0", binary_assets, IMAGE, DIGEST, binaries=True)


@pytest.mark.parametrize("document", [
    {"bomFormat": "SPDX", "components": [{"name": "requests"}, {"name": "flask"}, {"name": "cpython"}]},
    {"bomFormat": "CycloneDX", "components": []},
    {"bomFormat": "CycloneDX", "components": [{"name": "requests"}, {"name": "cpython"}]},
    {"bomFormat": "CycloneDX", "components": [{"name": "requests"}, {"name": "flask"}]},
])
def test_binary_sboms_must_list_the_bundled_dependencies_and_interpreter(source_repo, binary_assets, document):
    (binary_assets / "autopwn-suite-v2.6.0-binary-windows-amd64.cdx.json").write_text(json.dumps(document))
    with pytest.raises(ValueError, match="SBOM"):
        release.write_manifest(source_repo, "v2.6.0", binary_assets, IMAGE, DIGEST, binaries=True)


def test_backfill_never_claims_binaries(source_repo, binary_assets):
    with pytest.raises(ValueError, match="never rebuilds"):
        release.write_manifest(source_repo, "v2.6.0", binary_assets, release.OFFICIAL_IMAGE, DIGEST, backfill=True, binaries=True)


def test_current_version_has_matching_release_notes_and_runtime_version():
    """Catch a version bump without its changelog section at PR time, not in the release run."""
    root = Path(__file__).resolve().parents[2]
    version = release.re.search(r'^version\s*=\s*"([^"]+)"', (root / "pyproject.toml").read_text(encoding="utf-8"), release.re.MULTILINE)[1]
    runtime = release.re.findall(r'^\s*__version__\s*=\s*"([^"]+)"', (root / "autopwn_suite" / "__init__.py").read_text(encoding="utf-8"), release.re.MULTILINE)
    assert runtime == [version], "autopwn_suite.__version__ must equal the pyproject version"
    # Needs a '## [<version>]' section with non-empty Functional and Security notes, as the release workflow does.
    notes = release.release_notes((root / "CHANGELOG.md").read_text(encoding="utf-8"), f"v{version}")
    assert notes.startswith(f"# AutoPWN Suite v{version}")


@pytest.mark.parametrize("tag,version", [
    ("v2.7.0", "2.7.0"), ("v2.8.0-rc.1", "2.8.0rc1"), ("v2.8.0-beta.2", "2.8.0b2"), ("v2.8.0-alpha.10", "2.8.0a10"),
])
def test_pypi_file_names_carry_the_pep_440_version_of_the_tag(tag, version):
    """poetry-core builds autopwn_suite-2.8.0rc1-* for the tag v2.8.0-rc.1; the PyPI workflow must expect that."""
    assert release.pypi_files(tag) == [f"autopwn_suite-{version}-py3-none-any.whl", f"autopwn_suite-{version}.tar.gz"]


@pytest.mark.parametrize("tag", ["v2.8.0-notaversion", "2.7.0", "v2.7.0;id"])
def test_a_tag_pypi_cannot_name_or_that_is_not_a_tag_is_rejected(tag):
    with pytest.raises(ValueError):
        release.pypi_files(tag)


def test_the_build_directory_must_hold_exactly_the_wheel_and_the_sdist(tmp_path):
    for name in release.pypi_files("v2.8.0-rc.1"):
        (tmp_path / name).write_bytes(b"distribution")
    assert release.check_pypi_dist("v2.8.0-rc.1", tmp_path) == release.pypi_files("v2.8.0-rc.1")
    # Another version, a missing sdist or an extra file all stop the release.
    with pytest.raises(ValueError, match="PyPI distribution"):
        release.check_pypi_dist("v2.8.1-rc.1", tmp_path)
    (tmp_path / "autopwn_suite-2.8.0rc1.tar.gz").unlink()
    with pytest.raises(ValueError, match="PyPI distribution"):
        release.check_pypi_dist("v2.8.0-rc.1", tmp_path)
    (tmp_path / "autopwn_suite-2.8.0rc1.tar.gz").write_bytes(b"distribution")
    (tmp_path / "extra.txt").write_bytes(b"unexpected")
    with pytest.raises(ValueError, match="PyPI distribution"):
        release.check_pypi_dist("v2.8.0-rc.1", tmp_path)


def test_the_pypi_workflow_checks_file_names_with_the_normalising_helper(tmp_path):
    root = Path(__file__).resolve().parents[2]
    workflow = (root / ".github/workflows/publish-pypi.yml").read_text(encoding="utf-8")
    assert 'python scripts/release_assets.py pypi-dist --tag "$RELEASE_TAG" --output dist' in workflow
    assert "py3-none-any.whl\\nautopwn_suite-%s.tar.gz" not in workflow
    for name in release.pypi_files("v2.8.0-rc.1"):
        (tmp_path / name).write_bytes(b"distribution")
    shown = subprocess.run([sys.executable, str(root / "scripts/release_assets.py"), "pypi-dist", "--tag", "v2.8.0-rc.1",
                            "--output", str(tmp_path)], capture_output=True, text=True, check=True)
    assert shown.stdout.split() == release.pypi_files("v2.8.0-rc.1")


def test_pypi_upload_skips_existing_files_only_when_a_release_run_is_retried():
    """A partial upload is completed by re-running the release run, whose tag ref the pypi environment admits (v* tags)."""
    root = Path(__file__).resolve().parents[2]
    publish = (root / ".github/workflows/publish-pypi.yml").read_text(encoding="utf-8").split("\n  publish:\n", 1)[1]
    assert "skip-existing: ${{ github.run_attempt > 1 }}" in publish
    assert "workflow_dispatch" not in publish
    assert "attestations: true" in publish
    # Nothing is uploaded unless every earlier gate passed, whichever way the run was started.
    assert "needs: [validate, source-security, dynamic-analysis, build]" in publish
    docs = (root / "docs/RELEASING.md").read_text(encoding="utf-8")
    assert "gh run rerun RUN_ID --failed" in docs
    # A dispatch runs from main, which the environment's v* tag rule refuses: it must not be offered as the recovery.
    assert "gh workflow run publish-pypi.yml" not in docs
    assert "deployment rules admit only tags that match `v*`" in docs
    assert "does not require a deployment protection rule" not in docs
    model = (root / "docs/THREAT_MODEL.md").read_text(encoding="utf-8")
    assert "without comparing them" in model and "`pypi` environment admits only `v*` tags" in model


def test_pypi_deployment_link_is_the_version_page_without_the_tag_prefix():
    """PyPI addresses a release as /project/autopwn-suite/2.7.0/; the tag is v2.7.0."""
    workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/publish-pypi.yml").read_text(encoding="utf-8")
    assert "url: https://pypi.org/project/autopwn-suite/${{ needs.validate.outputs.version }}/" in workflow
    assert "version: ${{ steps.release.outputs.version }}" in workflow
    assert "\"$commit\" \"${RELEASE_TAG#v}\" \"$epoch\" >> \"$GITHUB_OUTPUT\"" in workflow
    assert "project/autopwn-suite/${{ github.event.release.tag_name" not in workflow


def test_verification_docs_name_every_signer_identity_the_workflows_can_produce():
    """The certificate identity is GITHUB_WORKFLOW_REF: the tag for a release event, main for a dispatch."""
    root = Path(__file__).resolve().parents[2]
    docker = (root / ".github/workflows/publish-docker.yml").read_text(encoding="utf-8")
    backfill = (root / ".github/workflows/backfill-release-signatures.yml").read_text(encoding="utf-8")
    for workflow in (docker, backfill):
        assert 'identity="https://github.com/$GITHUB_WORKFLOW_REF"' in workflow
    # A recovery dispatch is accepted from main only, so its identity ends in @refs/heads/main.
    assert "workflow_dispatch:" in docker and "github.ref == 'refs/heads/main'" in docker
    docs = (root / "docs/RELEASING.md").read_text(encoding="utf-8")
    for identity in ("publish-docker.yml@refs/tags/vVERSION", "publish-docker.yml@refs/heads/main",
                     "backfill-release-signatures.yml@refs/heads/main"):
        assert identity in docs
    # Only v2.7.0 and later can be dispatched now, so the v2.6.1 recovery is history, not a repeatable procedure.
    assert "v2.6.1 was recovered this way, with the workflow as it was then" in docs


SIGNING_WORKFLOWS = ["publish-docker.yml", "backfill-release-signatures.yml"]
VERIFY_LINE = ('cosign verify --certificate-identity "$identity" '
               '--certificate-oidc-issuer https://token.actions.githubusercontent.com "$IMAGE@$DIGEST"')


def workflow_text(workflow):
    return (Path(__file__).resolve().parents[2] / ".github/workflows" / workflow).read_text(encoding="utf-8")


def image_signature_snippet(workflow):
    """The lines from the one image signing to the next signing command: the sign and its verify loop."""
    text = workflow_text(workflow)
    start = text.index("cosign sign --yes")
    return text[start:text.index("cosign sign-blob", start)]


@pytest.mark.parametrize("workflow", SIGNING_WORKFLOWS)
def test_image_signature_check_is_retried_and_the_signing_is_not(workflow):
    """Docker Hub can list a new referrer late, so cosign v3 exits 10 ("no signatures found") right after a good sign."""
    snippet = image_signature_snippet(workflow)
    assert snippet.count("cosign sign --yes") == 1 and snippet.count("cosign verify ") == 1
    loop_start = snippet.index("for delay in ")
    loop = snippet[loop_start:snippet.index("\n          done\n", loop_start)]
    assert "cosign sign" not in loop and VERIFY_LINE in loop and "break" in loop
    # The signing runs once, ahead of the loop, and a verification that never succeeds still fails the step.
    assert snippet.index("cosign sign --yes") < loop_start
    assert snippet.rstrip().endswith('[ "$verified" = true ]')
    assert 'identity="https://github.com/$GITHUB_WORKFLOW_REF"' in workflow_text(workflow)


@pytest.mark.skipif(sys.platform == "win32" or shutil.which("bash") is None, reason="needs a POSIX bash")
@pytest.mark.parametrize("workflow", SIGNING_WORKFLOWS)
@pytest.mark.parametrize(("failures", "succeeds"), [(2, True), (0, True), (99, False)])
def test_image_signature_loop_retries_a_late_signature_and_still_fails(tmp_path, workflow, failures, succeeds):
    snippet = image_signature_snippet(workflow)
    script = tmp_path / "loop.sh"
    script.write_text(
        "set -euo pipefail\n"
        'sleep() { echo "$1" >> "$LOG_DIR/sleeps"; }\n'
        "calls=0\n"
        'cosign() { echo "$*" >> "$LOG_DIR/cosign"; calls=$((calls + 1)); [ "$calls" -gt "$FAILURES" ]; }\n'
        "identity=https://example.test/workflow IMAGE=docker.io/example/image DIGEST=sha256:00\n"
        + snippet[snippet.index("# Docker Hub can list"):], encoding="utf-8", newline="\n")
    env = {"PATH": "/usr/bin:/bin", "LOG_DIR": str(tmp_path), "FAILURES": str(failures)}
    result = subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True, check=False)
    calls = (tmp_path / "cosign").read_text().splitlines()
    sleeps = [int(n) for n in (tmp_path / "sleeps").read_text().split()]
    assert (result.returncode == 0) is succeeds, result.stderr
    assert all(call.startswith("verify ") and call.endswith("example/image@sha256:00") for call in calls)
    assert len(calls) == (failures + 1 if succeeds else 7)
    assert sleeps == [0, 5, 10, 15, 20, 30, 30][:len(calls)] and sum(sleeps) <= 120


@pytest.mark.parametrize("workflow", ["publish-docker.yml", "publish-pypi.yml"])
def test_dispatch_example_tag_has_the_layout_the_policy_scans(workflow):
    """Tags before v2.7.0 lack packaging/requirements-*.txt, so the dispatch input must not suggest one."""
    text = (Path(__file__).resolve().parents[2] / ".github/workflows" / workflow).read_text(encoding="utf-8")
    example = release.re.search(r"for example v(\d+)\.(\d+)\.(\d+)", text)
    assert example and tuple(map(int, example.groups())) >= (2, 7, 0)


def test_pypi_attestation_example_names_the_pep_440_file_for_a_prerelease():
    docs = (Path(__file__).resolve().parents[2] / "docs/RELEASING.md").read_text(encoding="utf-8").replace("\r\n", "\n")
    assert "pypi:autopwn_suite-VERSION-py3-none-any.whl`;\nVERSION is the PEP 440 form of the version, for example `2.8.0rc1`" in docs
    assert release.pypi_files("v2.8.0-rc.1")[0] == "autopwn_suite-2.8.0rc1-py3-none-any.whl"


def test_old_tag_dispatch_doc_says_where_each_workflow_stops():
    """A release with uploaded assets is refused in the validate job, before the policy scans anything."""
    root = Path(__file__).resolve().parents[2]
    workflows = root / ".github/workflows"
    for name in ("publish-docker.yml", "backfill-release-signatures.yml"):
        assert "jq '.assets | length'" in (workflows / name).read_text(encoding="utf-8")
    assert "jq '.assets | length'" not in (workflows / "publish-pypi.yml").read_text(encoding="utf-8")
    docs = " ".join((root / "docs/RELEASING.md").read_text(encoding="utf-8").split())  # rewrapping must not matter
    assert "in the validate job of `publish-docker.yml` and of the backfill" in docs
    assert "A tag before v2.6.0 fails release validation" in docs
    assert "only `publish-pypi.yml`, which does not look at release assets, carries on to the source security job" in docs
    assert "stops in the source security job" not in docs
