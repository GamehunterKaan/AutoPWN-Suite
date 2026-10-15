# Release procedure and verification

## Maintainer procedure

1. Review source, dependencies and known advisories. Update the runtime version
   in `autopwn.py` and package version in `pyproject.toml` consistently.
   Give every release a unique `vMAJOR.MINOR.PATCH` tag (optional prerelease).
2. Add a `## [VERSION] - YYYY-MM-DD` changelog entry with descriptive
   `### Functional changes` and `### Security changes`. Describe security impact
   and link applicable advisories; do not publish uncoordinated exploit details.
   If no security changes were made, say so explicitly rather than inventing one.
3. Merge a reviewed PR only after required status checks pass. Any exceptional
   manual bypass must be explained in that PR. Protect `main`, prevent direct
   pushes/deletion, and require the PR test checks in GitHub branch settings.
4. Create the version tag at reviewed history on `main` and publish the GitHub
   release with its descriptive changelog. The publishing workflow archives the
   exact tagged source, builds the multi-platform image, and signs/verifies both
   the image digest and release manifest using GitHub OIDC and Cosign.
5. Check every publishing/signing/upload step succeeds. Download the uploaded
   artifacts and independently verify signatures/hashes with the procedure below
   before claiming signed distribution. A configured workflow alone is not proof
   that an existing release is signed.

The release job explicitly gets `contents:write` and `id-token:write`; workflow
defaults remain read-only. Docker Hub publishing uses existing repository secrets
`DOCKERHUB_USERNAME`/`DOCKERHUB_TOKEN`. Pin third-party release actions by commit.
Never give PR tests publishing credentials or run unreviewed PR source in this job.

The workflow can also be dispatched **from main** with an existing published
release tag, for example to sign v2.6.0 after this automation has been merged.
It validates tag syntax, source package version and ancestry in `origin/main`.
Historical changelog notes may come from the trusted automation checkout. It
refuses releases with existing uploaded assets and never silently overwrites
them. Resolve partial uploads manually after inspecting the failed run. Only a
release currently identified as GitHub's latest release updates the image's
`latest` tag; historical backfills do not move it to an older release.

## Published artifact format

- `autopwn-suite-vVERSION.tar.gz` and `.zip`: source archives made by `git archive`
  from the validated tag/commit, with a versioned top-level directory.
- `release-notes.md`: descriptive changelog for that version.
- `release-manifest.json`: release tag, source commit, SHA-256 of each of the three
  files above, and the exact Docker Hub image digest.
- `release-manifest.sigstore.json`: Cosign signing certificate/signature and
  transparency-log verification bundle for the manifest.
- The container's exact `sha256:` digest also has a Cosign registry signature.

The manifest and bundle form the signature envelope; they cannot include their
own hashes recursively. Prefer these attached project archives when verifying
downloaded bytes. GitHub's automatically generated Source code ZIP/tar links may
have different archive bytes and are not the files covered by this manifest.
Older releases without these artifacts must be treated as unsigned.

## Consumer verification

Install Cosign 3.x from its official distribution and GitHub CLI. Download the
five release files without executing them. Choose the expected signer identity
from the trusted workflow/ref, not from an untrusted bundle:

```sh
gh release download v2.6.0 --repo GamehunterKaan/AutoPWN-Suite --dir release-files
cd release-files
cosign verify-blob --bundle release-manifest.sigstore.json \
  --certificate-identity 'https://github.com/GamehunterKaan/AutoPWN-Suite/.github/workflows/publish-docker.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  release-manifest.json
```

That exact identity is for a manual backfill from main. For an automatic published
release, use the same workflow path followed by `@refs/tags/vVERSION`. Confirm the
expected repository, workflow, ref and source commit against the release record.
Do not disable identity or issuer checking. Missing signatures are a verification
failure, not a reason to bypass verification.

After signature verification, verify all asset hashes without trusting filenames
outside the download directory:

```python
import hashlib
import json
from pathlib import Path

manifest = json.loads(Path("release-manifest.json").read_text())
for asset in manifest["assets"]:
    name = asset["name"]
    if Path(name).name != name:
        raise ValueError("Invalid manifest filename")
    if hashlib.sha256(Path(name).read_bytes()).hexdigest() != asset["sha256"]:
        raise ValueError(f"Hash mismatch: {name}")
print(manifest["source_commit"], manifest["container"])
```

Verify the printed image **by digest**, using the same expected signing identity:

```sh
cosign verify --certificate-identity 'EXPECTED_WORKFLOW_IDENTITY' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  docker.io/gamehunterkaan/autopwn-suite@sha256:EXACT_MANIFEST_DIGEST
```

The expected identities/issuer and exact manifest digest matter; a mutable tag
alone does not identify signed bytes. See [Sigstore blob signing](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/)
and [container verification](https://docs.sigstore.dev/cosign/verifying/verify/).
