# ci-gate — shared static-analysis gate toolchain

One implementation of the CI analysis gate, parameterised per repository, used
by **deaf**, **elimination**, **mouse** and **neural**.

Before this existed, `gate.py`, `triage.py` and `post_summary.py` were
copy-pasted into each of those four repositories (~6,400 duplicated lines) and
had already forked: each copy carried its own hardcoded repository name, its own
SARIF driver name and its own domain rationale, so a bug fix to the gate was a
four-way manual port and the copies drifted apart silently.

## Layout

    gate.py            aggregate analyzer reports into one verdict (annotate | gate)
    triage.py          turn a findings artifact into an actionable card plan
    post_summary.py    post/update the gate summary as a sticky PR comment
    tools/gen_config.py generate a repo's .ci/gate.config.json from its own copies
    tests/             invariants, config contract, and output parity

## Consuming it

Each repository adds this directory as a **git submodule** pinned to a commit:

    git submodule add https://github.com/Duressa323/ci-gate-public.git ci/gate

and carries its identity in `.ci/gate.config.json`:

```json
{
  "display_name": "deaf",
  "board": "deaf",
  "sarif_driver": "deaf-ci-gate",
  "information_uri": "https://github.com/duressa-ship-it/deaf",
  "comment_marker": "<!-- deaf-analysis-gate -->",
  "summary_footer": "`make test` runs the DSP suite ...",
  "rationale_before_you_start": "Read `ci/TRIAGE.md`. ...",
  "rationale_comment_footer": "Reproduce with `make analyze`. ..."
}
```

The config is found by walking up from the working directory, or set explicitly
with `$GATE_CONFIG`. Every key in `gate.REQUIRED_CONFIG_KEYS` must be a non-empty
string: a missing one aborts the run rather than falling back to another
repository's name.

## Two properties this must never lose

1. **Findings are keyed by content** — `(tool, rule_id, file, message)` — never
   by line number. An unrelated edit above a finding must not resurrect an
   accepted suppression as "new". `tests/test_invariants.py` asserts this, and
   asserts that severity is *not* part of the key so an analyzer re-classifying
   error→warning does not invalidate a reviewer's decision.

2. **A scanner that produced no report is a FAILURE.** `gate` exits non-zero
   when an expected analyzer is missing, because a gate that reports "clean" for
   an analyzer that never ran is worse than no gate at all.

Both are covered by tests, and both have been checked to actually fail when the
property is broken — a test that cannot fail is not evidence.

## Tests

    python3 tests/test_invariants.py          # the two properties + config contract
    python3 tests/test_parity.py --reference-dir /path/to/pristine/copies

`test_parity.py` is the migration's safety net: it renders the same fixture
through this tool and through a repository's pre-migration copies and diffs the
bytes. It skips repositories it has no reference copy for, so a partial
checkout still runs.

## Standard library only

Deliberate: these repositories have no Python dependency policy and CI runners
guarantee nothing about what is importable.