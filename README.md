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

    git submodule add https://github.com/Duressa323/ci-gate.git ci/gate

and carries its identity in `.ci/gate.config.json`:

```json
{
  "display_name": "Example",
  "board": "example",
  "sarif_driver": "example-ci-gate",
  "information_uri": "https://github.com/your-org/example",
  "comment_marker": "<!-- example-analysis-gate -->",
  "summary_footer": "`<test command>` runs ... so static analysis covers ...",
  "rationale_before_you_start": "Read `ci/TRIAGE.md`. ...",
  "rationale_comment_footer": "Reproduce with `make analyze`. ..."
}
```

Every value above is per-repository and **must** be written for the repository
that owns the config. The pre-migration copies were derived from `deaf`, and
carrying `deaf`'s values across verbatim put its sticky comment marker and its
C/DSP test description into three unrelated repositories — two of which are
Python. `comment_marker` is a sticky-comment selector: two repositories sharing
one marker collide on a single PR comment. See each repository's
`.ci/gate.config.json` `_comment` for what was corrected.

The config is found by walking up from the working directory, or set explicitly
with `$GATE_CONFIG`. Every key in `gate.REQUIRED_CONFIG_KEYS` must be a non-empty
string: a missing one aborts the run rather than falling back to another
repository's name.

`expected_tools` is the one optional key, and only a repository whose analyzer
set differs from the C/C++ default needs it. Left unset, `gate` expects a report
from `clang-analyze`, `cppcheck`, `gitleaks`, `trivy` and `osv-scanner` — a list
that is right for no Python repository. It must be a non-empty list of non-empty
strings; an empty one is rejected rather than honoured, because it would disable
the missing-tool check below.

## Three properties this must never lose

1. **Findings are keyed by content** — `(tool, rule_id, file, message)` — never
   by line number. An unrelated edit above a finding must not resurrect an
   accepted suppression as "new". `tests/test_invariants.py` asserts this, and
   asserts that severity is *not* part of the key so an analyzer re-classifying
   error→warning does not invalidate a reviewer's decision.

2. **A scanner that produced no report is a FAILURE.** `gate` exits non-zero
   when an expected analyzer is missing, because a gate that reports "clean" for
   an analyzer that never ran is worse than no gate at all.

3. **A report the gate cannot READ is also a failure.** Property 2 covers a
   report that is absent; this covers one that exists but whose shape the parser
   does not recognise. `parse_json_report` dispatches on the top-level keys and
   raises on anything else, so an unknown schema is exit 2 rather than a
   confident zero. The bug that motivated it: bandit has no SARIF output, so its
   native `{results: ...}` fell through to the SARIF reader, matched no `runs`
   key, and every bandit finding was discarded while the gate reported the tool
   as clean.

Report formats read: clang plists, cppcheck XMLv2, SARIF, bandit's native JSON,
and the gate's own normalised `{findings: ...}`.

All three are covered by tests, and all have been checked to actually fail when
the property is broken — a test that cannot fail is not evidence.

## Tests

    python3 tests/test_invariants.py          # properties 1, 2 + config contract
    python3 tests/test_python_tooling.py      # property 3, per-repo tool sets
    python3 tests/test_parity.py --reference-dir /path/to/pristine/copies

`test_parity.py` is the migration's safety net: it renders the same fixture
through this tool and through a repository's pre-migration copies and diffs the
bytes. It skips repositories it has no reference copy for, so a partial
checkout still runs.

## Standard library only

Deliberate: these repositories have no Python dependency policy and CI runners
guarantee nothing about what is importable.