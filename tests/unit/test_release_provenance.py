# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""The release provenance predicate names the exact tag, commit, workflow and run it describes."""
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("release_provenance", ROOT / "scripts" / "release_provenance.py")
provenance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provenance)

COMMIT = "a" * 40
MANIFEST = {"release": "v2.7.0", "source_commit": COMMIT, "assets": []}
ENV = {
    "GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": "GamehunterKaan/AutoPWN-Suite",
    "GITHUB_WORKFLOW_REF": "GamehunterKaan/AutoPWN-Suite/.github/workflows/publish-docker.yml@refs/tags/v2.7.0",
    "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_EVENT_NAME": "release", "RUNNER_ENVIRONMENT": "github-hosted",
}


def test_predicate_binds_tag_commit_workflow_and_run():
    predicate = provenance.build_predicate(MANIFEST, ENV)
    definition, details = predicate["buildDefinition"], predicate["runDetails"]
    assert definition["resolvedDependencies"] == [{
        "uri": "git+https://github.com/GamehunterKaan/AutoPWN-Suite@refs/tags/v2.7.0", "digest": {"gitCommit": COMMIT}}]
    assert definition["externalParameters"]["release"] == "v2.7.0"
    # The builder id is the signer identity consumers verify (the workflow ref cosign puts in the certificate).
    assert details["builder"]["id"] == "https://github.com/" + ENV["GITHUB_WORKFLOW_REF"]
    assert details["metadata"]["invocationId"] == "https://github.com/GamehunterKaan/AutoPWN-Suite/actions/runs/123/attempts/2"


@pytest.mark.parametrize("manifest", [
    {**MANIFEST, "release": "../v2.7.0"},
    {**MANIFEST, "release": "2.7.0"},
    {**MANIFEST, "source_commit": "abc"},
    {**MANIFEST, "source_commit": "A" * 40},
])
def test_untrusted_manifest_fields_are_rejected(manifest):
    with pytest.raises(ValueError, match="version tag"):
        provenance.build_predicate(manifest, ENV)


def test_a_missing_environment_variable_is_an_error():
    with pytest.raises(KeyError):
        provenance.build_predicate(MANIFEST, {k: v for k, v in ENV.items() if k != "GITHUB_RUN_ID"})


def test_command_line_writes_json(tmp_path, monkeypatch):
    for name, value in ENV.items():
        monkeypatch.setenv(name, value)
    manifest = tmp_path / "release-manifest.json"
    manifest.write_text(json.dumps(MANIFEST), encoding="utf-8")
    output = tmp_path / "predicate.json"
    provenance.main(["--manifest", str(manifest), "--output", str(output)])
    assert json.loads(output.read_text(encoding="utf-8"))["runDetails"]["builder"]["id"].endswith("@refs/tags/v2.7.0")
