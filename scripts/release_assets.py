"""Archive reviewed tagged source and bind release assets to their digests."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


POLICY_ROOT = Path(__file__).resolve().parents[1] / ".security"


TAG = re.compile(r"v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?")
IMAGE = re.compile(r"docker\.io/[a-z0-9]+(?:[._-][a-z0-9]+)*/autopwn-suite")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


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


def write_manifest(repo, tag, output, image, digest, reviewed_ref="refs/remotes/origin/main"):
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
    (output / "release-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "manifest"))
    parser.add_argument("--tag", required=True)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--changelog", type=Path, default=Path("CHANGELOG.md"))
    parser.add_argument("--image")
    parser.add_argument("--digest")
    args = parser.parse_args()
    if args.mode == "prepare":
        print(prepare(args.repo, args.tag, args.output, args.changelog))
    else:
        if not args.image or not args.digest:
            parser.error("manifest requires --image and --digest")
        write_manifest(args.repo, args.tag, args.output, args.image, args.digest)


if __name__ == "__main__":
    main()
