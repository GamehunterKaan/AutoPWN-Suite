#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""Write the SLSA v1 provenance predicate for a release, to be signed over the release manifest.

Usage: release_provenance.py --manifest release-manifest.json --output predicate.json

The release manifest binds the hash of every release file, so an attestation whose subject is the manifest
covers them all. The predicate describes this repository's release workflow run from the GitHub Actions
environment; the workflow signs it with its own OIDC identity (`cosign attest-blob --type slsaprovenance1`),
which produces the `*.intoto.jsonl` bundle published with the release. It is self-attested provenance
(the builder is the workflow that also signs), not output of an isolated builder.
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

TAG = re.compile(r"v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?")
BUILD_TYPE = "https://github.com/GamehunterKaan/AutoPWN-Suite/blob/main/docs/RELEASING.md#release-provenance"


def build_predicate(manifest, env):
    tag = manifest["release"]
    if not TAG.fullmatch(tag) or not re.fullmatch(r"[0-9a-f]{40}", manifest["source_commit"]):
        raise ValueError("Manifest needs a version tag and a full source commit")
    server, repository = env["GITHUB_SERVER_URL"], env["GITHUB_REPOSITORY"]
    workflow_ref = env["GITHUB_WORKFLOW_REF"]
    run = f"{server}/{repository}/actions/runs/{env['GITHUB_RUN_ID']}/attempts/{env['GITHUB_RUN_ATTEMPT']}"
    return {
        "buildDefinition": {
            "buildType": BUILD_TYPE,
            "externalParameters": {"repository": f"{server}/{repository}", "release": tag, "workflow": workflow_ref},
            "internalParameters": {"event": env["GITHUB_EVENT_NAME"], "runnerEnvironment": env.get("RUNNER_ENVIRONMENT", "")},
            "resolvedDependencies": [{
                "uri": f"git+{server}/{repository}@refs/tags/{tag}",
                "digest": {"gitCommit": manifest["source_commit"]},
            }],
        },
        "runDetails": {
            "builder": {"id": f"{server}/{workflow_ref}"},
            "metadata": {"invocationId": run},
        },
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    predicate = build_predicate(manifest, os.environ)
    args.output.write_text(json.dumps(predicate, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"{args.output}: provenance for {manifest['release']} at {manifest['source_commit']}")


if __name__ == "__main__":
    sys.exit(main())
