# Regression-test ledger

Supports the OpenSSF `regression_tests_added50` criterion: regression tests must be
added for at least 50% of the bugs fixed in the last six months. This ledger covers
**2026-04-16 to 2026-10-16** and is rebuilt from public history, so anyone can check it.

## Method

1. Take every non-merge commit on `main` in the window (**59**).
2. Select commits whose subject describes fixing a defect (`fix`, `bug`, `vulnerability`,
   `prevent`, `resolve`, `regression`, `correct`, `handle`, `avoid`, `harden`, `escape`).
3. Exclude changes that do not fix product behavior (a YAML typo, a version bump).
4. For each remaining fix, record whether the same commit changed files under `tests/`.

Reproduce with:

```bash
git log origin/main --since=2026-04-16 --no-merges --format='%h %ad %s' --date=short
git show --name-only --format= <commit>
```

**Limits.** Matching on commit subjects can miss a fix described in other words, and a
single commit may fix several defects. The ledger counts commits, not individual defects,
and a test in the same commit is taken as the regression test. There were no bug reports on
the public issue tracker in this window; the most recent bug report (#67) predates it.

## Ledger

| Commit | Date | Fix | Regression tests changed in the same commit |
| --- | --- | --- | --- |
| `128872d` | 2026-10-14 | Web findings badge count and webhook toggle persistence across restarts | `tests/unit/test_web_security_ui.py`, `tests/unit/test_web_ui.py`, `tests/unit/test_web_ui_behavior.py` |
| `e34e3b0` | 2026-10-08 | Exception detail exposure in web API validation (CodeQL `py/stack-trace-exposure`, alerts #6-#10, fixed 2026-10-08) | `tests/unit/test_web_ui_review.py` |
| `6785056` | 2026-10-05 | Dashboard evidence display, scheduling and persistence | `tests/unit/test_web_ui.py`, `tests/unit/test_web_ui_behavior.py`, `tests/unit/test_web_ui_review.py` |
| `f11ca3e` | 2026-10-05 | Web probing, report delivery and daemon cleanup | `tests/unit/test_daemon_installer.py`, `tests/unit/test_getexploits.py`, `tests/unit/test_report.py`, `tests/unit/test_web_crawler.py` and others |
| `82a26aa` | 2026-10-05 | Configuration, target handling and scan-result correctness | `tests/unit/test_api.py`, `tests/unit/test_autopwn.py`, `tests/unit/test_scan_regressions.py`, `tests/unit/test_searchvuln.py`, `tests/unit/test_utils.py` |

### Excluded from the count

| Commit | Reason |
| --- | --- |
| `29584b8` | Typo in a funding YAML key; not product behavior. |
| `ade01bc` | Version bump with a test adjustment; not a defect fix. |

## Result

**5 of 5** product-defect fixes in the window (100%) added or changed automated tests in the
same commit, above the 50% requirement. CodeQL alerts #4 and #5 (DOM XSS and attribute
sanitization) and #1 (workflow permissions) were fixed outside the window (2026-04-15 and
2025-10-18).

## Keeping this current

The [contribution rules](../.github/CONTRIBUTING.md#test-policy-and-interpreting-results) require a regression
test with every bug fix. Maintainers add each new fix here at release time, or re-run the method above before
answering the criterion again.
