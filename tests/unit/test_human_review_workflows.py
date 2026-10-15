"""Exercise the actual inline Actions scripts with GitHub API responses."""

import json
from pathlib import Path
import shutil
import subprocess
import textwrap

import pytest


ROOT = Path(__file__).resolve().parents[2]
SHA = "a" * 40
pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="Node is needed for Actions script tests")


def run_script(workflow, **scenario):
    source = (ROOT / ".github/workflows" / workflow).read_text(encoding="utf-8")
    script = textwrap.dedent(source.split("          script: |\n", 1)[1])
    harness = r"""
const result = {reruns: [], failures: [], queries: [], waits: 0};
let pullReads = 0;
const pr = scenario.pr || {number: 83, state: 'open', base: {ref: 'main'},
  user: {id: 1}, head: {sha: SHA, ref: 'topic'}};
const getPR = async () => {
  pullReads++;
  return {data: scenario.changeHeadAfter && pullReads >= scenario.changeHeadAfter
    ? {...pr, head: {...pr.head, sha: 'b'.repeat(40)}} : pr};
};
const listRuns = () => {};
const listReviews = () => {};
const associated = () => {};
const statuses = [...(scenario.statuses || [])];
const github = {
  rest: {
    pulls: {get: getPR, listReviews},
    repos: {listPullRequestsAssociatedWithCommit: associated},
    actions: {listWorkflowRuns: listRuns,
      getWorkflowRun: async () => ({data: {status: statuses.shift() || 'completed'}}),
      reRunWorkflow: async args => { result.reruns.push(args.run_id); }}
  },
  paginate: async (fn, args) => {
    result.queries.push(args);
    if (fn === listRuns) return scenario.runs || [];
    if (fn === listReviews) return scenario.reviews || [];
    if (fn === associated) return scenario.associated || [];
    throw Error('Unexpected pagination');
  }
};
const context = {repo: {owner: 'owner', repo: 'repo'}, payload: {
  pull_request: {number: 83, head: {sha: SHA}},
  workflow_run: scenario.signal || {event: 'pull_request_review', head_sha: SHA, pull_requests: [{number: 83}]}
}};
const core = {setFailed: message => result.failures.push(message), info: () => {}};
const sleep = callback => { result.waits++; callback(); };
const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
(async () => {
  try { await new AsyncFunction('github', 'context', 'core', 'setTimeout', script)(github, context, core, sleep); }
  catch (error) { result.error = error.message; }
  process.stdout.write(JSON.stringify(result));
})();
"""
    javascript = ("const scenario = " + json.dumps(scenario) + ";\nconst SHA = " + json.dumps(SHA)
                  + ";\nconst script = " + json.dumps(script) + ";\n" + harness)
    process = subprocess.run(["node", "-e", javascript], check=True, capture_output=True, text=True)
    return json.loads(process.stdout)


def review(state="APPROVED", commit=SHA, user_id=2, user_type="User"):
    return {"state": state, "commit_id": commit, "user": {"id": user_id, "type": user_type}}


@pytest.mark.parametrize("reviews,passed", [
    ([review()], True),
    ([], False),
    ([review(user_id=1)], False),
    ([review(user_type="Bot")], False),
    ([review(commit="b" * 40)], False),
    ([review(), review(state="DISMISSED")], False),
    ([review(), review(state="CHANGES_REQUESTED")], False),
    ([review(), review(state="COMMENTED")], True),
])
def test_current_non_author_human_approval_is_required(reviews, passed):
    result = run_script("human-review.yml", reviews=reviews)
    assert not result.get("error")
    assert (not result["failures"]) == passed


def test_old_run_cannot_pass_using_a_new_revision_approval():
    result = run_script("human-review.yml", changeHeadAfter=1, reviews=[review(commit="b" * 40)])
    assert "older PR revision" in result["failures"][0]


def original_run(run_id=10, **overrides):
    return {"id": run_id, "head_sha": SHA, "event": "pull_request", "head_branch": "topic",
            "pull_requests": [{"number": 83}], **overrides}


def test_review_refresh_reruns_all_original_checks_and_filters_unrelated_runs():
    result = run_script("human-review-refresh.yml", runs=[
        original_run(10), original_run(11), original_run(12, event="push"),
        original_run(13, head_sha="b" * 40), original_run(14, head_branch="other"),
        original_run(15, pull_requests=[{"number": 99}]),
    ])
    assert not result.get("error")
    assert result["reruns"] == [10, 11]
    assert result["queries"] == [{"owner": "owner", "repo": "repo", "workflow_id": "human-review.yml",
                                   "event": "pull_request", "head_sha": SHA, "per_page": 100}]


def test_fork_notification_resolves_associated_pr_before_refresh():
    result = run_script("human-review-refresh.yml", signal={
        "event": "pull_request_review", "head_sha": SHA, "pull_requests": [],
    }, associated=[{"number": 83}], runs=[original_run(pull_requests=[])])
    assert not result.get("error")
    assert result["reruns"] == [10]
    assert result["queries"][0]["commit_sha"] == SHA


@pytest.mark.parametrize("state,base,head", [
    ("closed", "main", SHA), ("open", "dev", SHA), ("open", "main", "b" * 40),
])
def test_unrelated_or_stale_review_notifications_cannot_rerun(state, base, head):
    result = run_script("human-review-refresh.yml", pr={
        "state": state, "base": {"ref": base}, "head": {"sha": head, "ref": "topic"},
    }, runs=[original_run()])
    assert not result.get("error")
    assert result["reruns"] == []


def test_refresh_waits_for_original_run_and_rechecks_live_revision():
    result = run_script("human-review-refresh.yml", runs=[original_run()], statuses=["in_progress", "completed"])
    assert not result.get("error")
    assert result["waits"] == 1 and result["reruns"] == [10]
    result = run_script("human-review-refresh.yml", runs=[original_run()], changeHeadAfter=3, statuses=["in_progress"])
    assert not result.get("error")
    assert result["reruns"] == []


def test_missing_original_check_is_reported_instead_of_creating_another():
    result = run_script("human-review-refresh.yml")
    assert "No original approval check" in result["error"]
    assert result["reruns"] == []


def test_review_events_do_not_create_a_second_required_approval_check():
    approval = (ROOT / ".github/workflows/human-review.yml").read_text(encoding="utf-8")
    triggers = approval.split("permissions:", 1)[0]
    assert "pull_request:" in triggers and "pull_request_review:" not in triggers
    notification = (ROOT / ".github/workflows/human-review-events.yml").read_text(encoding="utf-8")
    assert "pull_request_review:" in notification
    assert "Independent human approval" not in notification
