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
subprocesses, and diffs the bytes.  A difference fails.  The fixtures are
committed under tests/fixtures/ so the comparison is reproducible on a clean
checkout with no analyzers installed.

    python3 tests/test_parity.py --reference-dir /path/to/pristine/copies

`--reference-dir` holds one subdirectory per repository, each containing that
repository's pre-migration gate.py / triage.py / post_summary.py.  Repositories
whose directory is absent are skipped, so a partial checkout still runs.
"""

import argparse
import difflib
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.dirname(HERE)

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


class ParityTest(unittest.TestCase):
    REPOS = ("deaf", "elimination", "mouse", "neural")

    def setUp(self):
        # unittest.main() strips the --reference-dir flag before building the
        # suite, so it is read out of sys.argv here rather than re-parsed.
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("--reference-dir", default=os.environ.get(
            "PARITY_REFERENCE_DIR", ""))
        known, _ = parser.parse_known_args()
        self.reference_dir = known.reference_dir

    def reference_for(self, repo):
        if not self.reference_dir:
            self.skipTest("no --reference-dir given")
        path = os.path.join(self.reference_dir, repo)
        if not os.path.isdir(path):
            self.skipTest("no reference copy for %s" % repo)
        return path

    def test_shared_tool_matches_every_repo(self):
        """Each repo's rendered output == its own pre-migration copy."""
        checked, skipped = [], []
        for repo in self.REPOS:
            ref = self.reference_for(repo)
            with self.subTest(repo=repo):
                before = run_probe(os.path.join(ref, "ci"))
                config = os.path.join(ref, ".ci", "gate.config.json")
                self.assertTrue(os.path.isfile(config),
                                "%s has no .ci/gate.config.json" % repo)
                after = run_probe(TOOL, config=config)

                if before == after:
                    checked.append(repo)
                    continue

                # Name every field that moved, then show one diff: a bare
                # assertEqual on a 400-line JSON blob reports "differ" and
                # leaves the reader to find the changed string themselves.
                diffs = [k for k in before if before[k] != after.get(k)]
                detail = []
                for key in diffs:
                    detail.append("  field %r:" % key)
                    detail += list(difflib.unified_diff(
                        before[key].split("\n"),
                        after.get(key, "").split("\n"),
                        fromfile="before (per-repo %s)" % repo,
                        tofile="after (shared tool)",
                        lineterm=""))[:40]
                skipped.append(repo)
                self.fail("output drift in %d field(s) for %s:\n%s"
                          % (len(diffs), repo, "\n".join(detail)))
        self.assertTrue(checked or not skipped,
                        "no repository was actually compared")

    def test_no_shared_logic_in_configs(self):
        """A config carries identity and prose, never code."""
        for repo in self.REPOS:
            ref = self.reference_for(repo)
            config = os.path.join(ref, ".ci", "gate.config.json")
            self.assertTrue(os.path.isfile(config), config)
            with open(config, encoding="utf-8") as fh:
                doc = json.load(fh)
            allowed = set(gate_keys())
            self.assertEqual(
                set(doc) - allowed, set(),
                "%s config has keys outside the documented set: %s"
                % (repo, sorted(set(doc) - allowed)))
            for key in required_keys():
                self.assertTrue(str(doc.get(key) or "").strip(),
                                "%s config is missing %s" % (repo, key))


def gate_keys():
    """Ask the tool itself which keys exist, so the test cannot drift."""
    sys.path.insert(0, TOOL)
    try:
        import gate
        return (set(gate.DEFAULT_CONFIG) | set(gate.REQUIRED_CONFIG_KEYS)
                | {"_comment"})
    finally:
        sys.path.remove(TOOL)


def required_keys():
    sys.path.insert(0, TOOL)
    try:
        import gate
        return set(gate.REQUIRED_CONFIG_KEYS)
    finally:
        sys.path.remove(TOOL)


if __name__ == "__main__":
    argv = [a for a in sys.argv[1:] if not a.startswith("--")]
    unittest.main(argv=argv or ["test_parity.py"], verbosity=2)