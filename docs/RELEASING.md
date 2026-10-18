# Release procedure and verification

## Maintainer procedure

1. Review source, dependencies and known advisories. Update the runtime version
   in `autopwn_suite/__init__.py` and package version in `pyproject.toml` consistently.
   Give every release a unique `vMAJOR.MINOR.PATCH` tag (optional prerelease).
2. Add a `## [VERSION] - YYYY-MM-DD` changelog entry with descriptive
   `### Functional changes` and `### Security changes`. Describe security impact
   and link applicable advisories; do not publish uncoordinated exploit details.
   If no security changes were made, say so explicitly rather than inventing one.
3. Merge only after the required tests, Security policy, CodeQL checks and
   non-author human approval pass. Protect administrators too; never bypass the
   independent human review. Resolve SCA/SAST violations under
   [Security testing](SECURITY_TESTING.md) and review native dependency license
   obligations. Update [SUPPORT.md](../SUPPORT.md), the
   [threat model](THREAT_MODEL.md) and advisories for relevant changes.
4. Create the version tag at reviewed history on `main` and publish the GitHub
   release with its descriptive changelog. The publishing workflow archives the
   exact tagged source, builds the multi-platform image, and signs/verifies both
   the image digest and release manifest using GitHub OIDC and Cosign.
5. Check every publishing/signing/upload step succeeds. Download the uploaded
   artifacts and independently verify signatures/hashes with the procedure below
   before claiming signed distribution. A configured workflow alone is not proof
   that an existing release is signed.

Read-only jobs validate/archive the release and run source security checks, then
build each architecture without publication secrets. Syft generates a CycloneDX
SBOM from each actual image archive; OSV checks installed OS/Python dependencies
and Python licenses before registry publication. A separate push job has no
GitHub token permissions and only the Docker Hub credentials it needs. Signing
gets `contents:read`, `id-token:write` and registry signature-push access. Upload
alone gets `contents:write` and no OIDC or Docker credentials. Workflow defaults
remain read-only. Third-party actions/tools are pinned. These checks apply to
historical rebuilds too; an old tag does not waive current security policy.

The build/publish workflow validates tag syntax, source package version and
ancestry in `origin/main`. It refuses existing uploaded assets and never silently
overwrites them. Resolve partial uploads manually after inspecting the failed
run. Only GitHub's latest stable release updates the image's `latest` alias.

## Authenticity backfill for an existing release

Use **Backfill release signatures**, dispatched from main, when adding signatures
to an already published release such as v2.6.0:

```sh
gh workflow run backfill-release-signatures.yml --ref main -f tag=v2.6.0 \
  -f image-digest=sha256:7a241cc52d8afda6c63e5a67cceda69cee691e4570aaf674f5dae5c05c8748bb
```

Record the expected original index digest independently before dispatch; the
example above is the verified original v2.6.0 digest. A tag that has moved to a
different digest is rejected rather than silently signed.

This path does **not rebuild or replace application source or Docker images** and
does not change version/latest image tags. It snapshots the existing official
image index and both platform digests, checks their source-revision/version
labels against the reviewed Git tag, and reads image contents without executing
them. Source SCA/SAST checks must still pass. Syft SBOMs and complete current
image SCA/policy reports accompany the signature backfill. Scanner errors or
incomplete reports stop it; completed reports with findings remain visible and
are included in signed hashes rather than suppressed.

The signed manifest explicitly records `purpose: authenticity_backfill`,
`rebuilt: false` and `security_clearance: false`, plus the original platform
digests and findings. Signing establishes the identity/integrity of existing
bytes; it does not declare dependencies safe or findings fixed. Remediate
applicable findings before a new software release or rebuild under
[Security testing](SECURITY_TESTING.md). Adding backfill metadata does not turn
those findings into VEX not-affected declarations.

This is a separately reviewed metadata-only operation. It can run only from
protected main and requires an existing non-draft release without uploaded
assets. It archives the exact original tagged source, uses descriptive trusted
changelog notes, signs the unchanged original image digest and manifest through
GitHub OIDC, and uploads verified assets. It never publishes a new software tag.

## Published artifact format

The next release using this layout publishes **five attached files**:

| File | Contents |
| --- | --- |
| `autopwn-suite-vVERSION.tar.gz` | Exact tagged source, archived by `git archive` under a versioned directory. |
| `autopwn-suite-vVERSION.zip` | The same tagged source in ZIP format. |
| `autopwn-suite-vVERSION-security.zip` | Release notes, both platform SBOMs, VEX index/declarations and any backfill reports. |
| `release-manifest.json` | Release/source identity, hashes of the three archives, hashes of every supporting ZIP member, and exact Docker image digest. |
| `release-manifest.sigstore.json` | Cosign certificate/signature and transparency-log verification bundle for the manifest. |

The security ZIP preserves the original report filenames and bytes at its root:
`release-notes.md`, per-platform `-linux-amd64.cdx.json` / `-linux-arm64.cdx.json`
CycloneDX SBOMs, and a versioned `-vex-index.json` plus any listed OpenVEX files.
The SBOMs include native and Python dependencies. The VEX index can be empty
when no non-exploitability determination has been made. Authenticity backfills
also include the original `-image-index.json` and per-architecture `-sca.json`,
`-policy.json` and `-backfill.json` records. Findings stay available inside this
archive, with the same assessment times and limitations.

The manifest's `assets` array hashes the three downloadable archives. Its
`supporting_archive` object identifies the security ZIP by `name` and lists each
member's `name` and `sha256` in `files`. The ZIP uses fixed timestamps and member
ordering; its completed contents are verified before separate staging copies
are removed. Release notes are read from the ZIP for the GitHub release body.
The container's exact `sha256:` digest also has a Cosign registry signature.

Existing releases, including the already signed v2.6.0 release, retain their
previous separate-file layout. This change does not replace their assets or
invalidate their existing signatures. Both layouts use the same top-level
manifest hash verification below; only bundled layouts add `supporting_archive`.

The manifest and bundle form the signature envelope; they cannot include their
own hashes recursively. Prefer these attached project archives when verifying
downloaded bytes. GitHub's automatically generated Source code ZIP/tar links may
have different archive bytes and are not the files covered by this manifest.
Older releases without these artifacts must be treated as unsigned.

## Consumer verification

Install Cosign 3.x from its official distribution and GitHub CLI. Download the
release files without executing them. Choose the expected signer identity
from the trusted workflow/ref, not from an untrusted bundle:

```sh
gh release download v2.6.0 --repo GamehunterKaan/AutoPWN-Suite --dir release-files
cd release-files
cosign verify-blob --bundle release-manifest.sigstore.json \
  --certificate-identity 'https://github.com/GamehunterKaan/AutoPWN-Suite/.github/workflows/backfill-release-signatures.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  release-manifest.json
```

That exact identity is for an authenticity backfill from main. For an automatic
published release, use `publish-docker.yml@refs/tags/vVERSION` under the same
repository's `.github/workflows/` path instead. Confirm the
expected repository, workflow, ref and source commit against the release record.
Do not disable identity or issuer checking. Missing signatures are a verification
failure, not a reason to bypass verification.

After signature verification, verify all asset hashes without trusting filenames
outside the download directory:

```python
import hashlib
import json
from pathlib import Path
import zipfile

manifest = json.loads(Path("release-manifest.json").read_text())
for asset in manifest["assets"]:
    name = asset["name"]
    if Path(name).name != name:
        raise ValueError("Invalid manifest filename")
    if hashlib.sha256(Path(name).read_bytes()).hexdigest() != asset["sha256"]:
        raise ValueError(f"Hash mismatch: {name}")
if "supporting_archive" in manifest:
    supporting = manifest["supporting_archive"]
    if Path(supporting["name"]).name != supporting["name"]:
        raise ValueError("Invalid supporting archive filename")
    with zipfile.ZipFile(supporting["name"]) as archive:
        expected = {entry["name"] for entry in supporting["files"]}
        if len(archive.namelist()) != len(expected) or set(archive.namelist()) != expected:
            raise ValueError("Unexpected or missing supporting files")
        for entry in supporting["files"]:
            if hashlib.sha256(archive.read(entry["name"])).hexdigest() != entry["sha256"]:
                raise ValueError(f"Supporting hash mismatch: {entry['name']}")
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
