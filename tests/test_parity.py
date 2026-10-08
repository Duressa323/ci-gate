#!/usr/bin/env python3
"""
Byte-for-byte parity between a repository's ORIGINAL per-repo gate toolchain
and the shared, config-driven one.

Why this test exists
--------------------
Sharing one implementation across four repositories is only safe if the
shared tool renders exactly what each repository's own copy rendered before.
"Looks equivalent" is not a standard: the gate's output is a PR comment and a
set of kanban cards that a human acts on, and a stray space or a reworded
sentence is a silent behaviour change in all four repos at once.

So this harness does not assert anything about the shared tool.  It captures
the output of BOTH implementations, from the same fixture, in separate
subprocesses, and diffs the bytes.  A difference fails.  The golden files under
tests/fixtures/ are the captured output of each repository's PRE-MIGRATION
copy, so the comparison is against independently-produced truth rather than
against this tool's own current behaviour — a golden regenerated from the
shared tool would agree with it by construction and prove nothing.

    python3 tests/test_parity.py                    # golden mode (the default)
    python3 tests/test_parity.py --reference-dir D  # re-derive from live copies

Two modes, because the goldens and the original copies answer different
questions:

* **Golden mode** (default, runs with no arguments, in CI).  Compares the
  shared tool's render against tests/fixtures/<repo>.json.  This is the check
  that must never be skipped: it is what stops a future edit to gate.py or to
  a repository's config from changing rendered output unnoticed.

* **Reference mode** (`--reference-dir`).  Recomputes the same comparison
  directly from a checkout of the original per-repo copies.  Those copies are
  gone from the consuming repositories, so this is how the goldens are audited
  and re-derived; it needs the originals and is not available from a submodule
  checkout.

Intentional deviations
----------------------
The migration was not a pure refactor.  Every deviation recorded in
ALLOWED_DEVIATIONS below corrects rendered output that the copy-paste had got
wrong for that repository; each is reviewed and carries its reason.  The
allowlist is the audit trail: a NEW difference fails, and an entry that no
longer applies fails too, so neither a regression nor a silent "fix" can pass
unnoticed.

This replaces an earlier version of this test that skipped unless
`--reference-dir` was passed.  Its docstring claimed fixtures were committed
under tests/fixtures/; that directory did not exist, so the test skipped on
every run — including in CI — and parity was never actually proven.  Golden
mode exists so that the default invocation is a real check rather than a green
skip.
"""

import argparse
import difflib
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.dirname(HERE)
FIXTURES = os.path.join(HERE, "fixtures")

# Rendered by importing the implementation under test and calling its own
# public functions with a fixed finding, so the probe exercises the real code
# path rather than a reimplementation of it.
PROBE = r'''
import json, sys
sys.path.insert(0, sys.argv[1])
import gate, triage

finding = gate.Finding.make("cppcheck", "error", "src/x.c", 42,
                            "Null pointer dereference: p", "nullPointer")
warn = gate.Finding.make("cppcheck", "warning", "src/y.c", 7,
                         "Unused variable: tmp", "unusedVariable")
secret = gate.Finding.make("gitleaks", "error", "", 0,
                           "hardcoded credential", "generic-api-key")

baseline = {finding["hash"]: {"justification": "reviewed 2026-10-04"}}
group = triage.Group({
    "tool": "cppcheck", "rule_id": "nullPointer", "severity": "error",
    "findings": [dict(finding, occurrences=[{"file": "src/x.c", "line": 42}])],
})
new_action = {"group": group, "action": "update", "origin": "new"}
old_action = {"group": group, "action": "new-card", "origin": "pre-existing"}
nogroup = triage.Group({
    "tool": "gitleaks", "rule_id": "generic-api-key", "severity": "error",
    "findings": [dict(secret, occurrences=[])],
})
empty_group = triage.Group({
    "tool": "cppcheck", "rule_id": "", "severity": "note",
    "findings": [dict(warn, occurrences=[{"file": "", "line": 0}])],
})

findings = [finding, warn, secret]
out = {
    "sarif": gate.to_sarif(findings, None),
    "summary_pass": gate.summary_markdown(findings, [finding], [warn, secret],
                                          baseline, False),
    "summary_fail": gate.summary_markdown(findings, [finding], [warn, secret],
                                          baseline, True, ["trivy"]),
    "summary_clean": gate.summary_markdown([], [], [], {}, False),
    "annotations": [gate.annotation(f) for f in sorted(findings,
                                                        key=gate.sort_key)],
    "BOARD": triage.BOARD,
    "GATE_DRIVER": triage.GATE_DRIVER,
    "titles": [g.title for g in (group, nogroup, empty_group)],
    "card_body_new": triage.card_body(new_action),
    "card_body_old": triage.card_body(old_action),
    "comment": triage.update_comment(new_action),
    "doc_line2": gate.__doc__.split("\n")[1],
}
print(json.dumps(out, sort_keys=True, indent=2))
'''

# ---------------------------------------------------------------------------
# Reviewed deviations from each repository's pre-migration output.
#
# Read this table as the changelog of the migration's behaviour changes: every
# entry is a correction of output the copy-paste had got wrong for that
# repository, and nothing outside this table may differ.
#
# Each value is (reason, golden_digest, shared_digest) -- the first 16 hex
# chars of a sha256 over each side's rendering of that field.  Pinning BOTH
# sides is what makes this table an audit trail rather than a hole.  Keying the
# allowlist by field NAME alone meant that once `summary_pass` was reviewed for
# mouse, any later edit to it also passed: a tampered golden that changed
# `make analyze` to `make TAMPERED` reported green, and pinning only the
# shared side did not catch it either, because the tamper was on the golden
# side.  A reviewed change now moves exactly one pair of digests, by hand, so
# a regression on either side fails.  Regenerate the digests with:
#
#     python3 -c "import importlib.util,json; \\
#       s=importlib.util.spec_from_file_location('t','tests/test_parity.py'); \\
#       m=importlib.util.module_from_spec(s); s.loader.exec_module(m); \\
#       ..."
#
# or just read it off the AssertionError, which prints the actual digest.
# ---------------------------------------------------------------------------
ALLOWED_DEVIATIONS = {
    "deaf": {
    },
    "elimination": {
        # elimination's own copy already carried a rewritten rationale specific
        # to a C99 + ncurses grid game.  That is preserved here as this repo's
        # override rather than flattened into shared code, and the summary
        # footer describes elimination's tests/ instead of deaf's DSP suite.
        "card_body_new": (
            "preserve elimination's grid-game rationale",
            "9476d40151ea1404",
            "7387ab18675be981"),
        "card_body_old": (
            "preserve elimination's grid-game rationale",
            "7b439c3871fd9fe5",
            "12e11783034c4b97"),
        "comment": (
            "preserve elimination's grid-game rationale",
            "537518670c7e55d7",
            "cb86099a2d131a28"),
        "summary_clean": (
            "footer describes elimination's tests/, not deaf's DSP suite",
            "175b69a80965f477",
            "6d72bff2ca3f3097"),
        "summary_fail": (
            "footer describes elimination's tests/, not deaf's DSP suite",
            "351452d0f01d7b80",
            "0515a537d17e66d0"),
        "summary_pass": (
            "footer describes elimination's tests/, not deaf's DSP suite",
            "6ad22b6dae521be8",
            "c90658dc000c69f4"),
    },
    "mouse": {
        # mouse is a stdlib-only Python Tkinter app with no Makefile and no DSP
        # suite, so the inherited footer described tests it does not have.  The
        # path fix matches deaf's entry above.
        "card_body_new": (
            "dead ci/triage.py path -> ci/gate/triage.py",
            "e0f6e11c7250ce41",
            "aa164ce48234390b"),
        "card_body_old": (
            "dead ci/triage.py path -> ci/gate/triage.py",
            "ce6b05cdaeb246ad",
            "8c4fce780397f4a8"),
        "summary_clean": (
            "footer describes mouse's guard tests, not deaf's DSP suite",
            "d214048374eb443f",
            "7f1d93244acfd4c0"),
        "summary_fail": (
            "footer describes mouse's guard tests, not deaf's DSP suite",
            "a59f116a4597f51e",
            "6a42edb95198f9fd"),
        "summary_pass": (
            "footer describes mouse's guard tests, not deaf's DSP suite",
            "4c8ee5d85b26bfab",
            "6507f1734edb7b48"),
    },
    "neural": {
        # The worst of the four: neural's config was deaf's verbatim, so it
        # carried deaf's sticky comment marker (two repositories sharing one
        # marker collide on a single PR comment), deaf's C/DSP suite and
        # `make test` in a Python repository that has neither, and deaf's
        # signed-shift/aliasing rationale for a neural-network platform.
        "card_body_new": (
            "neural's own domain rationale, not deaf's DSP rationale",
            "cdfea8a47d0c3712",
            "df21df73661bb7ab"),
        "card_body_old": (
            "neural's own domain rationale, not deaf's DSP rationale",
            "12e15797bcf9c469",
            "3fa6a96b1edf3947"),
        "comment": (
            "neural's own reproduce step and domain rationale",
            "23bbdf8f41f10686",
            "a7db5fade28e2eff"),
        "summary_clean": (
            "footer describes pytest tests/, not deaf's DSP suite",
            "d4ed21c5e629828f",
            "7b53a7716a4c8538"),
        "summary_fail": (
            "footer describes pytest tests/, not deaf's DSP suite",
            "e7682f905f7e44b5",
            "df7cb76879d786b3"),
        "summary_pass": (
            "footer describes pytest tests/, not deaf's DSP suite",
            "acf2609b205d05b7",
            "0751c10a30dbc896"),
    },
}


def field_digest(value):
    """A short, stable digest of one rendered field, for the allowlist."""
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()[:16]

REPOS = ("deaf", "elimination", "mouse", "neural")


def run_probe(ci_dir, config=None):
    """Run the probe against one implementation; return parsed JSON or raise."""
    env = dict(os.environ)
    env.pop("GATE_CONFIG", None)
    if config:
        env["GATE_CONFIG"] = os.path.abspath(config)
    with tempfile.TemporaryDirectory() as tmp:
        script = os.path.join(tmp, "probe.py")
        with open(script, "w", encoding="utf-8") as fh:
            fh.write(PROBE)
        proc = subprocess.run([sys.executable, script, os.path.abspath(ci_dir)],
                              capture_output=True, text=True, env=env, cwd=tmp)
    if proc.returncode != 0:
        raise AssertionError("probe failed for %s:\n%s"
                             % (ci_dir, proc.stderr.strip()))
    return json.loads(proc.stdout)


def live_config_dir():
    """The `.ci/` directory of the repository this run sits inside, if any.

    Searches upward from the tool checkout AND from the working directory.
    The tool's own location is not enough: the common invocation is
    `cd <repo> && python3 ci/gate/tests/test_parity.py`, where the submodule
    under test is <repo>/ci/gate and the config is two levels above it -- but
    a developer auditing a checkout may equally run the canonical copy from
    elsewhere with the repository as their cwd, in which case the only
    `.ci/` reachable is the one under the cwd.  Anchoring on cwd alone was the
    earlier failure: this suite reported "not inside a consuming repository"
    and skipped the one check that ties a live config to its golden.
    """
    seen = []
    for base in (os.path.dirname(TOOL), os.getcwd()):
        here = os.path.abspath(base)
        while True:
            if here in seen:
                break
            seen.append(here)
            path = os.path.join(here, ".ci", "gate.config.json")
            if os.path.isfile(path):
                return os.path.dirname(path)
            parent = os.path.dirname(here)
            if parent == here:
                break
            here = parent
    return None


def config_for(repo):
    """The config to render `repo` with.

    The fixture copy in tests/fixtures/, except when `repo` is the repository
    this test is running inside -- then its live config, so an edit to a
    consuming repository's identity is checked against its golden rather than
    only against the fixture.

    The earlier version returned the live config for EVERY repo whenever it
    found one, so running this suite from inside deaf rendered all four
    repositories with deaf's identity.  Three of them then differed from their
    goldens for a reason that had nothing to do with the code under test, and
    the failures pointed at the wrong cause.  The fixture is the default
    precisely because it is per-repo and always present; the live config
    substitutes only for the one repo that owns it.
    """
    if repo == live_repo_name():
        live = live_config_dir()
        if live:
            return os.path.join(live, "gate.config.json")
    return os.path.join(FIXTURES, repo + ".config.json")


def live_repo_name():
    """The name of the consuming repository this checkout sits inside, or None.

    Derived from the live config's own `board`, which is the one field every
    repository must set and the one the gate renders verbatim, rather than from
    the directory name: a checkout may be cloned under any name.
    """
    live = live_config_dir()
    if not live:
        return None
    try:
        with open(os.path.join(live, "gate.config.json"), encoding="utf-8") as fh:
            return str(json.load(fh).get("board") or "") or None
    except (OSError, ValueError):
        return None


def diff_fields(before, after):
    return sorted(k for k in set(before) | set(after)
                  if before.get(k) != after.get(k))


def _diff_text(repo, before, after, fields):
    """A readable diff of the fields that changed.

    Renders each side as sorted JSON rather than splitting on newlines: the
    probe's `sarif` field is a nested object, not a string, so a text diff
    raised AttributeError and replaced a real parity failure with a crash in
    the failure reporter -- hiding the very drift the test exists to report.
    """
    out = []
    for key in fields:
        out.append("  field %r:" % key)
        old, new = before.get(key), after.get(key)
        if isinstance(old, str) and isinstance(new, str):
            out += list(difflib.unified_diff(
                old.split("\n"), new.split("\n"),
                fromfile="before (per-repo %s)" % repo,
                tofile="after (shared tool)",
                lineterm=""))[:40]
        else:
            out += ["    before: " + json.dumps(old, sort_keys=True)[:600],
                    "    after : " + json.dumps(new, sort_keys=True)[:600]]
    return out


def _is_entry(value):
    """Whether an ALLOWED_DEVIATIONS value is a (reason, golden, shared) triple.

    A bare string is the pre-digest form and is treated as a mistake rather
    than silently accepted, so the allowlist cannot be widened back to
    name-only by a careless edit.
    """
    return (isinstance(value, (tuple, list)) and len(value) == 3
            and all(isinstance(v, str) and v for v in value[1:]))


class ParityTest(unittest.TestCase):
    def setUp(self):
        # unittest.main() strips the --reference-dir flag before building the
        # suite, so it is read out of sys.argv here rather than re-parsed.
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("--reference-dir", default=os.environ.get(
            "PARITY_REFERENCE_DIR", ""))
        known, _ = parser.parse_known_args()
        self.reference_dir = known.reference_dir

    def assert_no_unreviewed_drift(self, repo, before, after):
        """Shared fields must match; differing fields must be allowlisted.

        An allowlisted field must not merely be allowlisted -- it must still
        render the value a human reviewed.  The digest in ALLOWED_DEVIATIONS is
        checked against the actual output, so a second change to a field whose
        first change was already approved is a failure, not a free pass.
        """
        allowed = ALLOWED_DEVIATIONS.get(repo, {})
        actual = diff_fields(before, after)

        unexpected = [f for f in actual if f not in allowed]
        stale = [f for f in sorted(allowed) if f not in actual]
        renamed = [f for f in sorted(allowed)
                   if f in actual and not _is_entry(allowed[f])]
        rechanged = []
        for f in sorted(allowed):
            if f in actual and _is_entry(allowed[f]):
                _, pinned_golden, pinned_shared = allowed[f]
                for side, doc, pinned in (("golden", before, pinned_golden),
                                          ("shared", after, pinned_shared)):
                    now = field_digest(doc.get(f))
                    if now != pinned:
                        rechanged.append("%s %s side (reviewed %s, now %s)"
                                        % (f, side, pinned, now))
        if unexpected or stale or renamed or rechanged:
            self.fail(
                "unreviewed parity drift in %s\n"
                "  changed but not allowlisted: %s\n"
                "  allowlisted but unchanged:   %s\n"
                "  allowlisted entries not in (reason, golden, shared) form: %s\n"
                "  allowlisted but a pinned side changed again: %s\n"
                "A changed field must be diffed by hand and added to "
                "ALLOWED_DEVIATIONS with its reason AND both pinned "
                "digests; an entry that no longer applies must be "
                "removed.  Otherwise neither a regression nor a silent "
                "change can pass unnoticed.\n\n%s"
                % (repo, unexpected, stale, renamed, rechanged,
                   "\n".join(_diff_text(repo, before, after, actual))))

    # -- golden mode: the default, and what CI runs ------------------------

    def test_golden_fixtures_exist_for_every_repo(self):
        """No repo may silently lose its parity coverage."""
        missing = [r for r in REPOS
                   if not os.path.isfile(os.path.join(FIXTURES, r + ".json"))]
        self.assertEqual(missing, [],
                         "no golden fixture for %s — parity would silently "
                         "stop being checked for that repo" % (missing,))

    def test_shared_tool_matches_golden_for_every_repo(self):
        checked = []
        for repo in REPOS:
            golden_path = os.path.join(FIXTURES, repo + ".json")
            if not os.path.isfile(golden_path):
                continue
            with self.subTest(repo=repo):
                with open(golden_path, encoding="utf-8") as fh:
                    golden = json.load(fh)
                after = run_probe(TOOL, config=config_for(repo))
                self.assert_no_unreviewed_drift(repo, golden, after)
                checked.append(repo)
        self.assertEqual(sorted(checked), sorted(REPOS),
                         "golden mode compared %d of %d repos; a parity test "
                         "that quietly checks nothing is a false green"
                         % (len(checked), len(REPOS)))

    # -- the allowlist cannot be a hole ------------------------------------

    def test_an_allowlisted_field_cannot_change_again(self):
        """A second change to an already-reviewed field must fail.

        This is the meta-test for the false green that motivated pinning the
        reviewed value.  Keying ALLOWED_DEVIATIONS by field NAME meant that
        once `summary_pass` had been reviewed for mouse, any later edit to it
        also passed -- a golden tampered from `Mouse static analysis` to
        `Mouse STATIC ANALYSIS` reported green, and the allowlist would have
        blessed any real regression in that field forever.

        Both sides are checked, because a tamper can land on either: pinning
        only the shared tool's output leaves the golden itself unpoliced, which
        is how the first attempt at this fix was still green.
        """
        repo = "mouse"
        field = "summary_pass"
        _, pinned_golden, pinned_shared = ALLOWED_DEVIATIONS[repo][field]
        golden = json.load(open(os.path.join(FIXTURES, repo + ".json"),
                                encoding="utf-8"))
        after = run_probe(TOOL, config=config_for(repo))
        self.assertEqual(field_digest(golden[field]), pinned_golden)
        self.assertEqual(field_digest(after[field]), pinned_shared)

        # 1. the golden side moves: same fields differ, pinned digest does not
        tampered = json.loads(json.dumps(golden))
        tampered[field] = tampered[field] + "\nINJECTED"
        with self.assertRaises(AssertionError) as ctx:
            self.assert_no_unreviewed_drift(repo, tampered, after)
        self.assertIn("golden side", str(ctx.exception))

        # 2. the shared side moves, with the golden left alone
        moved = json.loads(json.dumps(after))
        moved[field] = moved[field] + "\nINJECTED"
        with self.assertRaises(AssertionError) as ctx:
            self.assert_no_unreviewed_drift(repo, golden, moved)
        self.assertIn("shared side", str(ctx.exception))

        # 3. unchanged input still passes, so the check above is not vacuous
        self.assert_no_unreviewed_drift(repo, golden, after)

    def test_allowlist_rejects_the_bare_string_form(self):
        """An entry without a pinned digest is a mistake, not a legacy shape."""
        self.assertFalse(_is_entry("just a reason"))
        self.assertFalse(_is_entry(("reason", "only-one-digest")))
        self.assertTrue(_is_entry(("reason", "0" * 16, "1" * 16)))

    # -- reference mode: re-derive the goldens from the original copies ----

    def test_shared_tool_matches_reference_copies(self):
        """Compare against live pre-migration copies, where available."""
        if not self.reference_dir:
            self.skipTest("no --reference-dir given")
        compared = []
        for repo in REPOS:
            ref = os.path.join(self.reference_dir, repo)
            if not os.path.isdir(ref):
                continue
            with self.subTest(repo=repo):
                before = run_probe(os.path.join(ref, "ci"))
                after = run_probe(TOOL, config=config_for(repo))
                self.assert_no_unreviewed_drift(repo, before, after)
                compared.append(repo)
        self.assertTrue(compared, "no reference copies were actually compared")

    def test_goldens_still_match_the_reference_copies(self):
        """A stale golden is worse than none: it would bless a regression."""
        if not self.reference_dir:
            self.skipTest("no --reference-dir given")
        checked = []
        for repo in REPOS:
            ref = os.path.join(self.reference_dir, repo)
            golden_path = os.path.join(FIXTURES, repo + ".json")
            if not (os.path.isdir(ref) and os.path.isfile(golden_path)):
                continue
            with self.subTest(repo=repo):
                with open(golden_path, encoding="utf-8") as fh:
                    golden = json.load(fh)
                fresh = run_probe(os.path.join(ref, "ci"))
                self.assertEqual(
                    diff_fields(golden, fresh), [],
                    "tests/fixtures/%s.json no longer matches %s's "
                    "pre-migration output, so the golden is stale and would "
                    "bless a regression" % (repo, repo))
                checked.append(repo)
        self.assertTrue(checked)

    # -- the config contract ----------------------------------------------

    def test_no_shared_logic_in_configs(self):
        """A config carries identity and prose, never code."""
        for repo in REPOS:
            path = os.path.join(FIXTURES, repo + ".config.json")
            self.assertTrue(os.path.isfile(path), path)
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
            allowed = set(gate_keys())
            self.assertEqual(
                set(doc) - allowed, set(),
                "%s config has keys outside the documented set: %s"
                % (repo, sorted(set(doc) - allowed)))
            for key in required_keys():
                self.assertTrue(str(doc.get(key) or "").strip(),
                                "%s config is missing %s" % (repo, key))

    def test_live_configs_match_fixtures(self):
        """A consuming repo's config must equal the fixture it is pinned with.

        Skipped in a bare ci-gate checkout, where there is no live config.  In a
        consuming repository this is what catches a config edited without
        regenerating the golden: the drift shows up here rather than as a
        mystery in whichever repo's PR comment changes shape first.
        """
        live = live_config_dir()
        if not live:
            self.skipTest("no live .ci/gate.config.json; not inside a "
                          "consuming repository")
        repo = live_repo_name()
        if repo not in REPOS:
            self.skipTest("live config declares board=%r, which is not one of "
                          "the repositories this suite knows: %s"
                          % (repo, list(REPOS)))
        path = os.path.join(live, "gate.config.json")
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        with open(os.path.join(FIXTURES, repo + ".config.json"),
                  encoding="utf-8") as fh:
            fixture = json.load(fh)
        # _comment is repository-local documentation, not tool input.
        doc = {k: v for k, v in doc.items() if k != "_comment"}
        self.assertEqual(
            doc, fixture,
            "%s's live .ci/gate.config.json differs from the committed "
            "fixture. Re-derive the fixture after reviewing the diff."
            % repo)

    def test_required_keys_cannot_be_silently_weakened(self):
        """Pin the required-key set itself.

        gate.DEFAULT_CONFIG supplies a value for every key, so deleting an
        entry from REQUIRED_CONFIG_KEYS makes an incomplete config load
        successfully instead of aborting — the config contract silently stops
        holding, and nothing else in the suite notices: the fixtures are all
        complete, so both config checks still pass.  Asserting the exact set
        here is what makes that mutation fail.

        The expected set is duplicated on purpose.  Reading it back out of
        gate.REQUIRED_CONFIG_KEYS would compare the constant with itself and
        pass no matter what it contained.
        """
        self.assertEqual(
            sorted(load_gate().REQUIRED_CONFIG_KEYS),
            ["board", "comment_marker", "display_name", "information_uri",
             "rationale_before_you_start", "rationale_comment_footer",
             "sarif_driver", "summary_footer"],
            "REQUIRED_CONFIG_KEYS changed; every key here must abort the run "
            "when absent, because the gate would otherwise render a "
            "placeholder or another repository's identity into a PR comment")

    def test_defaults_are_obvious_placeholders(self):
        """Each built-in default must announce itself as unconfigured.

        The defaults exist for one case: running the tool with no config file
        at all.  They must never be a plausible-looking value, because that is
        what made the `raw`-vs-`out` bug hard to see — "UNCONFIGURED" for the
        board reads as a sentinel, but a real-looking driver name or URL reads
        as a working configuration.

        Every repository supplies all eight keys, so no test can observe these
        values through normal use; asserting them here is what stops a default
        from drifting into something that looks legitimate.
        """
        defaults = load_gate().DEFAULT_CONFIG

        # Exact values, asserted individually.  An earlier version of this test
        # looked for placeholder *substrings* ("UNCONFIGURED", "CI-GATE", ...)
        # and a mutation setting sarif_driver to "MUTANT-ci-gate" satisfied the
        # substring check while being no placeholder at all — the test passed on
        # exactly the value it exists to reject.  Each value is pinned instead.
        self.assertEqual(defaults["display_name"], "this repository")
        self.assertEqual(defaults["board"], "UNCONFIGURED")
        self.assertEqual(defaults["sarif_driver"], "ci-gate")
        self.assertEqual(defaults["information_uri"],
                         "https://example.invalid/ci-gate")
        self.assertEqual(defaults["comment_marker"], "<!-- ci-gate-analysis -->")
        self.assertTrue(
            defaults["summary_footer"].startswith("UNCONFIGURED:"),
            "DEFAULT_CONFIG['summary_footer'] must announce itself as "
            "unconfigured; got %r" % defaults["summary_footer"])
        # The two rationale keys are None on purpose: "{x}".format(x=None)
        # renders the literal string "None" into a card body, so an empty
        # default is the only safe placeholder for a value that is interpolated
        # into an instruction a reviewer may follow.
        for key in ("rationale_before_you_start", "rationale_comment_footer"):
            self.assertIsNone(
                defaults[key],
                "DEFAULT_CONFIG[%r] must be None; a string here renders into a "
                "card body as if it were this repository's own guidance"
                % key)

    def test_no_default_can_mask_a_missing_required_key(self):
        """A config missing one required key must abort, key by key.

        Proves the guarantee above end to end: for each required key, delete it
        from an otherwise-complete config and assert the load raises.  This is
        the property the defaults could otherwise hide.
        """
        gate = load_gate()
        with tempfile.TemporaryDirectory() as tmp:
            for key in gate.REQUIRED_CONFIG_KEYS:
                doc = dict(gate.DEFAULT_CONFIG)
                doc.update({"rationale_before_you_start": "a",
                            "rationale_comment_footer": "b"})
                doc.pop(key)
                path = os.path.join(tmp, "gate.config.json")
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump(doc, fh)
                with self.assertRaises(
                        SystemExit,
                        msg="config missing %r loaded successfully because "
                            "DEFAULT_CONFIG supplied a fallback for it" % key):
                    gate.load_config(path)

    def test_allowlist_covers_exactly_the_known_repos(self):
        """A stale entry for a renamed repo must not pass silently."""
        self.assertEqual(sorted(ALLOWED_DEVIATIONS), sorted(REPOS))
        for repo, fields in ALLOWED_DEVIATIONS.items():
            for field, entry in fields.items():
                self.assertTrue(
                    _is_entry(entry),
                    "%s.%s allowlist entry is not a "
                    "(reason, golden, shared) triple: %r" % (repo, field, entry))
                reason, golden_digest, shared_digest = entry
                self.assertTrue(reason.strip(),
                                "%s.%s has an allowlist entry with no reason"
                                % (repo, field))
                for label, digest in (("golden", golden_digest),
                                      ("shared", shared_digest)):
                    self.assertRegex(
                        digest, r"^[0-9a-f]{16}$",
                        "%s.%s pins a malformed %s digest %r; it must be 16 hex "
                        "chars as produced by field_digest()"
                        % (repo, field, label, digest))


def load_gate():
    """Import the tool's gate module from the tool directory, not from cwd.

    A cached import would be a hazard here: the parity tests mutate nothing,
    but a stale sys.modules entry from an earlier sys.path would make these
    assertions test a different copy of the code than the one being shipped.
    """
    if TOOL not in sys.path:
        sys.path.insert(0, TOOL)
    import gate
    return gate


def gate_keys():
    """Ask the tool itself which keys exist, so the test cannot drift."""
    gate = load_gate()
    return (set(gate.DEFAULT_CONFIG) | set(gate.REQUIRED_CONFIG_KEYS)
            | {"_comment"})


def required_keys():
    return set(load_gate().REQUIRED_CONFIG_KEYS)


if __name__ == "__main__":
    argv = [a for a in sys.argv[1:] if not a.startswith("--")]
    unittest.main(argv=argv or ["test_parity.py"], verbosity=2)