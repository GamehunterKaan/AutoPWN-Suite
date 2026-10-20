# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2026 Kaan Gültekin
"""CodeQL runs as workflows so pull requests from forks are analyzed; check what the required checks rely on.

GitHub's default setup never scans a pull request from a fork, so the required `Analyze (...)` and `CodeQL`
checks could not report on one. codeql.yml analyzes with a read-only token and codeql-upload.yml, from main,
uploads the results. The inline script of the second is run here with GitHub API responses.
"""

import json
import re
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
ANALYZE = (WORKFLOWS / "codeql.yml").read_text(encoding="utf-8")
UPLOAD = (WORKFLOWS / "codeql-upload.yml").read_text(encoding="utf-8")
REQUIRED = {"Analyze (actions)", "Analyze (javascript-typescript)", "Analyze (python)"}
SHA = "a" * 40
MERGE = "c" * 40


def _languages(source):
    return set(re.search(r"language: \[([^\]]*)\]", source).group(1).replace(" ", "").split(","))


def test_the_analysis_jobs_keep_the_names_that_branch_protection_requires():
    assert 'name: Analyze (${{ matrix.language }})' in ANALYZE
    assert {f"Analyze ({language})" for language in _languages(ANALYZE)} == REQUIRED
    assert _languages(UPLOAD) == _languages(ANALYZE)
    assert re.search(r"^name: CodeQL$", ANALYZE, re.MULTILINE)
    assert "workflows: [CodeQL]" in UPLOAD


def test_the_categories_are_the_ones_default_setup_used_and_both_workflows_agree():
    assert "category: /language:${{ matrix.language }}" in ANALYZE
    assert "category: /language:${{ matrix.language }}" in UPLOAD


@pytest.mark.parametrize("source", [ANALYZE, UPLOAD])
def test_actions_are_pinned_and_no_untrusted_input_reaches_a_shell(source):
    uses = re.findall(r"^\s*-?\s*uses: (\S+)", source, re.MULTILINE)
    assert uses and all(re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", item) for item in uses), uses
    assert "pull_request_target" not in source
    assert not [line for line in source.splitlines() if re.match(r"\s*(- )?run:", line) and "${{" in line]


def test_the_analysis_workflow_checks_out_without_credentials_runs_on_every_pull_request_and_builds_nothing():
    assert "persist-credentials: false" in ANALYZE
    assert not re.search(r"^\s+paths(-ignore)?:", ANALYZE, re.MULTILINE)
    assert "build-mode: none" in ANALYZE and "autobuild" not in ANALYZE
    # A pull request run only analyzes; its results reach code scanning through the handler.
    assert "upload: ${{ github.event_name == 'pull_request' && 'never' || 'always' }}" in ANALYZE
    assert ANALYZE.count("if: github.event_name == 'pull_request'") == 2


def test_the_upload_workflow_never_checks_out_or_runs_code_of_the_pull_request():
    assert "actions/checkout" not in UPLOAD
    assert "workflow_run:" in UPLOAD and re.search(r"^permissions:\n  actions: read\n", UPLOAD, re.MULTILINE)
    assert "if: github.event.workflow_run.event == 'pull_request' && github.event.workflow_run.conclusion == 'success'" in UPLOAD
    # The ref and the commit come from the validated script outputs, never from the artifact.
    assert "ref: refs/pull/${{ steps.target.outputs.number }}/merge" in UPLOAD
    assert "sha: ${{ steps.target.outputs.sha }}" in UPLOAD


pytestmark_node = pytest.mark.skipif(shutil.which("node") is None, reason="Node is needed for Actions script tests")


def _script():
    block = UPLOAD.split("          script: |\n", 1)[1]
    lines = []
    for line in block.splitlines():
        if line.strip() and not line.startswith(" " * 12):
            break
        lines.append(line)
    return textwrap.dedent("\n".join(lines))


def _sarif(language="python", **overrides):
    run = {"tool": {"driver": {"name": "CodeQL"}}, "automationDetails": {"id": f"/language:{language}/"}, "results": []}
    return {"version": "2.1.0", "runs": [{**run, **overrides}]}


def _artifact(tmp_path, sarif=None, analysis=None, extra=None):
    directory = tmp_path / "work"
    (directory / "sarif").mkdir(parents=True, exist_ok=True)
    (directory / "sarif" / "analysis.json").write_text(json.dumps({"sha": MERGE} if analysis is None else analysis), encoding="utf-8")
    (directory / "sarif" / "upload.sarif").write_text(json.dumps(_sarif() if sarif is None else sarif), encoding="utf-8")
    for name in extra or []:
        (directory / "sarif" / name).write_text("x", encoding="utf-8")
    return directory


def pull(number=83, **overrides):
    value = {"number": number, "state": "open", "mergeable": True, "merge_commit_sha": MERGE, "base": {"ref": "main"},
             "head": {"sha": SHA, "ref": "topic", "repo": {"full_name": "fork/repo"}}}
    for key, item in overrides.items():
        value[key] = {**value[key], **item} if isinstance(item, dict) else item
    return value


def run_script(tmp_path, *, event="pull_request", prs=None, associated=None, run_pull_requests=None, directory=None, language="python"):
    prs = [pull()] if prs is None else prs
    scenario = {"dir": str(directory or _artifact(tmp_path)), "prs": {str(item["number"]): item for item in prs},
                "associated": associated if associated is not None else [{"number": item["number"]} for item in prs],
                "run": {"event": event, "head_sha": SHA, "head_branch": "topic", "head_repository": {"full_name": "fork/repo"},
                        "pull_requests": run_pull_requests or []},
                "language": language}
    harness = r"""
const result = {outputs: {}, notices: [], sleeps: 0, reads: 0};
const github = {
  rest: {pulls: {get: async ({pull_number}) => {
    result.reads++;
    const data = {...scenario.prs[String(pull_number)]};
    if (scenario.prs[String(pull_number)].computeAfter && result.reads <= scenario.prs[String(pull_number)].computeAfter) data.mergeable = null;
    return {data};
  }}, repos: {listPullRequestsAssociatedWithCommit: () => {}}},
  paginate: async (fn, args) => { result.args = args; return scenario.associated; }
};
const context = {repo: {owner: 'owner', repo: 'repo'}, payload: {workflow_run: scenario.run}};
const core = {setOutput: (key, value) => { result.outputs[key] = value; }, notice: message => result.notices.push(message)};
const sleep = callback => { result.sleeps++; callback(); };
process.chdir(scenario.dir);
process.env.LANGUAGE = scenario.language;
const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
(async () => {
  try { await new AsyncFunction('github', 'context', 'core', 'require', 'setTimeout', script)(github, context, core, require, sleep); }
  catch (error) { result.error = error.message; }
  process.stdout.write(JSON.stringify(result));
})();
"""
    javascript = "const scenario = " + json.dumps(scenario) + ";\nconst script = " + json.dumps(_script()) + ";\n" + harness
    return json.loads(subprocess.run(["node", "-e", javascript], check=True, capture_output=True, text=True).stdout)


@pytestmark_node
def test_a_fork_pull_request_is_resolved_through_the_commit_association_and_gets_its_results_uploaded(tmp_path):
    result = run_script(tmp_path)
    assert not result.get("error")
    assert result["outputs"] == {"upload": "true", "number": "83", "sha": MERGE}
    assert result["args"]["commit_sha"] == SHA


@pytestmark_node
def test_a_same_repository_pull_request_listed_by_the_run_needs_no_lookup(tmp_path):
    result = run_script(tmp_path, run_pull_requests=[{"number": 83}], associated=[])
    assert result["outputs"]["upload"] == "true" and "args" not in result


@pytestmark_node
@pytest.mark.parametrize("override", [
    {"state": "closed"}, {"base": {"ref": "dev"}}, {"head": {"sha": "b" * 40}}, {"head": {"ref": "other"}},
    {"head": {"repo": {"full_name": "someone/else"}}}, {"merge_commit_sha": "d" * 40}, {"merge_commit_sha": None},
])
def test_a_pull_request_that_moved_on_or_does_not_match_gets_nothing(tmp_path, override):
    result = run_script(tmp_path, prs=[pull(**override)])
    assert not result.get("error")
    assert result["outputs"] == {"upload": "false"} and len(result["notices"]) == 1


@pytestmark_node
def test_only_the_pull_request_whose_test_merge_was_analyzed_gets_the_results(tmp_path):
    result = run_script(tmp_path, prs=[pull(84, merge_commit_sha="d" * 40), pull(83)])
    assert result["outputs"]["number"] == "83"
    result = run_script(tmp_path, prs=[pull(84), pull(83)])
    assert "More than one pull request" in result["error"]


@pytestmark_node
def test_it_waits_while_github_computes_the_test_merge(tmp_path):
    result = run_script(tmp_path, prs=[pull(computeAfter=2)])
    assert result["outputs"]["upload"] == "true" and result["sleeps"] == 2


@pytestmark_node
@pytest.mark.parametrize("event", ["push", "schedule", "workflow_dispatch"])
def test_only_a_pull_request_analysis_is_handled(tmp_path, event):
    assert "Expected a pull request analysis" in run_script(tmp_path, event=event)["error"]


@pytestmark_node
@pytest.mark.parametrize("build,message", [
    (lambda path: _artifact(path, extra=["other.txt"]), "Unexpected files"),
    (lambda path: _artifact(path, analysis={"sha": "main"}), "Invalid analysis metadata"),
    (lambda path: _artifact(path, analysis={"sha": 5}), "Invalid analysis metadata"),
    (lambda path: _artifact(path, sarif={"version": "2.0.0", "runs": [{}]}), "not a SARIF 2.1.0 log"),
    (lambda path: _artifact(path, sarif={"version": "2.1.0", "runs": []}), "not a SARIF 2.1.0 log"),
    (lambda path: _artifact(path, sarif=_sarif("javascript-typescript")), "do not belong to this language"),
    (lambda path: _artifact(path, sarif=_sarif(tool={"driver": {"name": "Other"}})), "do not belong to this language"),
    (lambda path: _artifact(path, sarif=_sarif(automationDetails={})), "do not belong to this language"),
])
def test_an_artifact_that_is_not_exactly_this_languages_codeql_result_is_refused(tmp_path, build, message):
    result = run_script(tmp_path, directory=build(tmp_path))
    assert message in result["error"] and "upload" not in result["outputs"]
