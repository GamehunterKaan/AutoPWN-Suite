"""Archive reviewed tagged source and bind release assets to their digests."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import urllib.request


POLICY_ROOT = Path(__file__).resolve().parents[1] / ".security"


TAG = re.compile(r"v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?")
IMAGE = re.compile(r"docker\.io/[a-z0-9]+(?:[._-][a-z0-9]+)*/autopwn-suite")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
OFFICIAL_IMAGE = "docker.io/gamehunterkaan/autopwn-suite"


def image_index(tag, output):
    """Snapshot an existing public image without rebuilding or changing its tags."""
    if not TAG.fullmatch(tag):
        raise ValueError("Expected a version tag")
    repository = "gamehunterkaan/autopwn-suite"
    with urllib.request.urlopen(
            "https://auth.docker.io/token?service=registry.docker.io&scope=repository:"
            + repository + ":pull", timeout=60) as response:
        token = json.load(response)["token"]
    request = urllib.request.Request(
        f"https://registry-1.docker.io/v2/{repository}/manifests/{tag[1:]}", headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json",
        })
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read()
        digest = response.headers["Docker-Content-Digest"]
    if digest != "sha256:" + hashlib.sha256(data).hexdigest():
        raise ValueError("Registry index digest mismatch")
    index = json.loads(data)
    for arch in ("amd64", "arm64"):
        platform_digest(index, arch)
    (output / f"autopwn-suite-{tag}-image-index.json").write_bytes(data)
    return digest


def platform_digest(index, arch):
    if arch not in ("amd64", "arm64"):
        raise ValueError("Unsupported image architecture")
    matches = [m["digest"] for m in index["manifests"]
               if m.get("platform", {}).get("os") == "linux"
               and m["platform"].get("architecture") == arch]
    if len(matches) != 1 or not DIGEST.fullmatch(matches[0]):
        raise ValueError("Expected exactly one immutable image per architecture")
    return matches[0]


def backfill_record(repo, tag, output, arch, config_path):
    commit = release_commit(repo, tag)
    index_path = output / f"autopwn-suite-{tag}-image-index.json"
    digest = "sha256:" + hashlib.sha256(index_path.read_bytes()).hexdigest()
    child = platform_digest(json.loads(index_path.read_bytes()), arch)
    configurations = json.loads(config_path.read_text(encoding="utf-8"))
    if len(configurations) != 1:
        raise ValueError("Expected one inspected image")
    config = configurations[0]
    labels = config.get("Config", {}).get("Labels", {}) or {}
    if (config.get("Os") != "linux" or config.get("Architecture") != arch
            or labels.get("org.opencontainers.image.revision") != commit
            or labels.get("org.opencontainers.image.version") != tag[1:]
            or not {f"gamehunterkaan/autopwn-suite@{child}", f"{OFFICIAL_IMAGE}@{child}"}.intersection(config.get("RepoDigests", []))):
        raise ValueError("Existing image does not match the tagged source and platform digest")
    prefix = f"autopwn-suite-{tag}-linux-{arch}"
    report = json.loads((output / f"{prefix}-sca.json").read_text(encoding="utf-8"))
    policy = json.loads((output / f"{prefix}-policy.json").read_text(encoding="utf-8"))
    packages = [p for r in report["results"] for p in r["packages"]]
    if (not packages or policy.get("version") != tag[1:] or policy.get("packages") != len(packages)
            or not isinstance(policy.get("violations"), list)
            or not all(isinstance(v, str) for v in policy["violations"])):
        raise ValueError("Backfill requires a complete current scan and policy result")
    record = {"purpose": "authenticity_backfill", "source_commit": commit,
              "image": OFFICIAL_IMAGE, "index_digest": digest,
              "platform": f"linux/{arch}", "platform_digest": child,
              "recorded_at": datetime.now(timezone.utc).isoformat(),
              "policy_violations": policy["violations"],
              "security_clearance": False, "rebuilt": False}
    (output / f"{prefix}-backfill.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return record


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def release_commit(repo, tag, reviewed_ref="refs/remotes/origin/main"):
    if not TAG.fullmatch(tag):
        raise ValueError("Expected a version tag such as v2.6.0 or v2.6.1-rc.1")
    commit = git(repo, "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}")
    subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor",
                    commit, reviewed_ref], check=True)
    source = git(repo, "show", f"{commit}:pyproject.toml")
    version = re.search(r'^version\s*=\s*"([^"]+)"', source, re.MULTILINE)
    if not version or version[1] != tag[1:]:
        raise ValueError("Release tag does not match the source package version")
    runtime = git(repo, "show", f"{commit}:autopwn.py")
    runtime_versions = re.findall(r'^\s*__version__\s*=\s*"([^"]+)"', runtime, re.MULTILINE)
    if runtime_versions != [tag[1:]]:
        raise ValueError("Release tag does not match the runtime version")
    return commit


def release_notes(changelog, tag):
    pattern = rf"^## \[{re.escape(tag[1:])}\][^\n]*\n(.*?)(?=^## |\Z)"
    match = re.search(pattern, changelog, re.MULTILINE | re.DOTALL)
    if not match or not all(heading in match[1] for heading in
                            ("### Functional changes", "### Security changes")):
        raise ValueError("Changelog needs functional and security notes for this version")
    for heading in ("Functional changes", "Security changes"):
        section = re.search(rf"^### {heading}\s*\n(.*?)(?=^### |\Z)",
                            match[1], re.MULTILINE | re.DOTALL)
        if not section or not section[1].strip():
            raise ValueError("Changelog needs descriptive functional and security notes")
    return f"# AutoPWN Suite {tag}\n\n{match[1].strip()}\n"


def prepare(repo, tag, output, changelog, reviewed_ref="refs/remotes/origin/main"):
    commit = release_commit(repo, tag, reviewed_ref)
    notes = release_notes(changelog.read_text(encoding="utf-8"), tag)
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError("Release staging directory must be empty")
    for extension in ("tar.gz", "zip"):
        destination = output / f"autopwn-suite-{tag}.{extension}"
        subprocess.run(["git", "-C", str(repo), "archive", f"--format={extension}",
                        f"--prefix=autopwn-suite-{tag}/", f"--output={destination.resolve()}",
                        commit], check=True)
    (output / "release-notes.md").write_text(notes, encoding="utf-8", newline="\n")
    index = json.loads((POLICY_ROOT / "vex/index.json").read_text(encoding="utf-8"))
    names = []
    for name in index["documents"]:
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]*\.openvex\.json", name):
            raise ValueError("Invalid VEX filename")
        destination = f"autopwn-suite-{tag}-{name}"
        (output / destination).write_bytes((POLICY_ROOT / "vex" / name).read_bytes())
        names.append(destination)
    (output / f"autopwn-suite-{tag}-vex-index.json").write_text(
        json.dumps({"schema_version": 1, "documents": names}, indent=2) + "\n", encoding="utf-8")
    return commit


def write_manifest(repo, tag, output, image, digest, reviewed_ref="refs/remotes/origin/main", *, backfill=False):
    commit = release_commit(repo, tag, reviewed_ref)
    if not IMAGE.fullmatch(image) or not DIGEST.fullmatch(digest):
        raise ValueError("Expected an official Docker Hub image and a SHA-256 digest")
    names = [f"autopwn-suite-{tag}.tar.gz", f"autopwn-suite-{tag}.zip", "release-notes.md"]
    names += [f"autopwn-suite-{tag}-linux-{arch}.cdx.json" for arch in ("amd64", "arm64")]
    vex_index = f"autopwn-suite-{tag}-vex-index.json"
    index = json.loads((output / vex_index).read_text(encoding="utf-8"))
    for name in index["documents"]:
        if not re.fullmatch(rf"autopwn-suite-{re.escape(tag)}-[a-zA-Z0-9][a-zA-Z0-9._-]*\.openvex\.json", name):
            raise ValueError("Invalid versioned VEX filename")
    names += [vex_index, *index["documents"]]
    records = []
    if backfill:
        if image != OFFICIAL_IMAGE:
            raise ValueError("Backfill only supports the existing official image")
        index_name = f"autopwn-suite-{tag}-image-index.json"
        raw_index = (output / index_name).read_bytes()
        if "sha256:" + hashlib.sha256(raw_index).hexdigest() != digest:
            raise ValueError("Backfill image index digest mismatch")
        names.append(index_name)
        for arch in ("amd64", "arm64"):
            prefix = f"autopwn-suite-{tag}-linux-{arch}"
            names += [f"{prefix}-sca.json", f"{prefix}-policy.json", f"{prefix}-backfill.json"]
            record = json.loads((output / f"{prefix}-backfill.json").read_text(encoding="utf-8"))
            policy = json.loads((output / f"{prefix}-policy.json").read_text(encoding="utf-8"))
            if (record.get("purpose") != "authenticity_backfill" or record.get("source_commit") != commit
                    or record.get("image") != image or record.get("index_digest") != digest
                    or record.get("platform") != f"linux/{arch}"
                    or record.get("platform_digest") != platform_digest(json.loads(raw_index), arch)
                    or record.get("security_clearance") is not False or record.get("rebuilt") is not False
                    or record.get("policy_violations") != policy.get("violations")):
                raise ValueError("Backfill record does not bind the assessed original image")
            records.append(record)
    if set(p.name for p in output.iterdir()) != set(names):
        raise ValueError("Unexpected or missing release staging assets")
    for arch in ("amd64", "arm64"):
        sbom = json.loads((output / f"autopwn-suite-{tag}-linux-{arch}.cdx.json").read_text(encoding="utf-8"))
        if sbom.get("bomFormat") != "CycloneDX" or not sbom.get("components"):
            raise ValueError("Every image architecture requires a nonempty CycloneDX SBOM")
        package_names = {component.get("name") for component in sbom["components"]}
        if not {"nmap", "requests"}.issubset(package_names):
            raise ValueError("Image SBOM must include native and Python runtime dependencies")
    assets = []
    for name in names:
        path = output / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Release assets must be regular files")
        assets.append({"name": name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    manifest = {"schema_version": 1, "release": tag, "source_commit": commit,
                "assets": assets, "container": {"image": image, "digest": digest}}
    if backfill:
        manifest["publication"] = {"purpose": "authenticity_backfill", "security_clearance": False,
                                   "rebuilt": False, "platforms": records}
    (output / "release-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "manifest", "image-index", "platform-digest", "backfill-record"))
    parser.add_argument("--tag", required=True)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--changelog", type=Path, default=Path("CHANGELOG.md"))
    parser.add_argument("--image")
    parser.add_argument("--digest")
    parser.add_argument("--arch", choices=("amd64", "arm64"))
    parser.add_argument("--image-config", type=Path)
    parser.add_argument("--backfill", action="store_true")
    args = parser.parse_args()
    if not TAG.fullmatch(args.tag):
        parser.error("Expected a version tag such as v2.6.0")
    if args.mode == "prepare":
        print(prepare(args.repo, args.tag, args.output, args.changelog))
    elif args.mode == "image-index":
        print(image_index(args.tag, args.output))
    elif args.mode == "platform-digest":
        if not args.arch:
            parser.error("platform-digest requires --arch")
        print(platform_digest(json.loads((args.output / f"autopwn-suite-{args.tag}-image-index.json").read_bytes()), args.arch))
    elif args.mode == "backfill-record":
        if not args.arch or not args.image_config:
            parser.error("backfill-record requires --arch and --image-config")
        backfill_record(args.repo, args.tag, args.output, args.arch, args.image_config)
    else:
        if not args.image or not args.digest:
            parser.error("manifest requires --image and --digest")
        write_manifest(args.repo, args.tag, args.output, args.image, args.digest, backfill=args.backfill)


if __name__ == "__main__":
    main()
