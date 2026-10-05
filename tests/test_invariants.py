#!/usr/bin/env python3
"""
The two properties the shared gate must never lose.

These are asserted here, against the SHARED tool, because the risk the task
this came from describes is exactly that a refactor or a config change quietly
breaks one of them.  Both are cheap to check and expensive to discover missing:

  1. Findings are keyed by CONTENT — (tool, rule_id, file, message) — never by
     line number, so an unrelated edit above a finding cannot resurrect an
     accepted suppression as "new".

  2. A scanner that produced NO report is a FAILURE.  A gate that reports
     "clean" for an analyzer that never ran is worse than no gate, so `gate`
     exits non-zero when an expected tool is missing.

Plus the config contract: a missing, malformed or incomplete config must be a
loud failure, never a silent fallback to another repository's identity.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.dirname(HERE)
sys.path.insert(0, TOOL)

import gate  # noqa: E402


class ContentHashKeying(unittest.TestCase):
    """Property 1: identity is the finding's content, not its position."""

    def test_line_number_is_not_part_of_the_hash(self):
        a = gate.Finding.make("cppcheck", "error", "src/x.c", 10, "null deref", "r1")
        b = gate.Finding.make("cppcheck", "error", "src/x.c", 999, "null deref", "r1")
        self.assertEqual(
            a["hash"], b["hash"],
            "moving a finding 989 lines down changed its identity, so any "
            "unrelated edit above it would resurface an accepted suppression "
            "as a NEW finding")

    def test_every_identity_component_changes_the_hash(self):
        base = gate.Finding.make("cppcheck", "error", "src/x.c", 10, "msg", "r1")
        for field, other in (
            ("tool", "clang-analyze"),
            ("rule_id", "r2"),
            ("file", "src/y.c"),
            ("message", "other message"),
        ):
            changed = gate.Finding.make(
                other if field == "tool" else "cppcheck",
                "error",
                "src/y.c" if field == "file" else "src/x.c",
                10,
                "other message" if field == "message" else "msg",
                "r2" if field == "rule_id" else "r1",
            )
            self.assertNotEqual(base["hash"], changed["hash"],
                                "%s is not part of the content hash" % field)

    def test_severity_is_not_part_of_the_hash(self):
        """Severity is a judgement about impact, not about which finding it is.

        An analyzer re-classifying error->warning must not invalidate an
        accepted suppression; otherwise triage churns on tool upgrades.
        """
        err = gate.Finding.make("cppcheck", "error", "src/x.c", 1, "m", "r")
        warn = gate.Finding.make("cppcheck", "warning", "src/x.c", 1, "m", "r")
        self.assertEqual(err["hash"], warn["hash"])

    def test_shifting_lines_keeps_a_baseline_entry_matching(self):
        """The end-to-end property, through split_baseline()."""
        finding = gate.Finding.make("cppcheck", "error", "src/x.c", 10, "m", "r")
        baseline = {finding["hash"]: {"justification": "intentional"}}
        moved = gate.Finding.make("cppcheck", "error", "src/x.c", 480, "m", "r")
        preexisting, new = gate.split_baseline([moved], baseline)
        self.assertEqual(len(preexisting), 1)
        self.assertEqual(new, [],
                         "an unrelated edit above the finding resurrected it")


class MissingScannerIsAFailure(unittest.TestCase):
    """Property 2: a tool that never reported fails the gate."""

    def _run_gate(self, reports, expect):
        with tempfile.TemporaryDirectory() as tmp:
            for name, body in reports.items():
                path = os.path.join(tmp, name)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(body)
            out = os.path.join(tmp, "out")
            proc = subprocess.run(
                [sys.executable, os.path.join(TOOL, "gate.py"), "gate",
                 "--reports", tmp, "--out-dir", out, "--expect"] + list(expect),
                capture_output=True, text=True)
            summary = ""
            path = os.path.join(out, "summary.md")
            if os.path.exists(path):
                with open(path, encoding="utf-8") as fh:
                    summary = fh.read()
            return proc, summary

    @staticmethod
    def _sarif(tool):
        return json.dumps({
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": tool}}, "results": [{
                "ruleId": "R", "level": "error",
                "message": {"text": "a finding"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "src/x.c"},
                    "region": {"startLine": 3}}}],
            }]}],
        })

    def test_missing_tool_exits_nonzero(self):
        proc, summary = self._run_gate(
            {"cppcheck.json": json.dumps(
                {"tool": "cppcheck", "findings": []})},
            ["cppcheck", "gitleaks"])
        self.assertNotEqual(proc.returncode, 0,
                            "gitleaks produced no report and the gate still "
                            "exited 0 — a crashed scanner just read as clean")
        self.assertIn("no report", proc.stderr)

    def test_all_tools_present_exits_zero(self):
        proc, _ = self._run_gate(
            {"cppcheck.json": json.dumps(
                {"tool": "cppcheck", "findings": []}),
             "gitleaks.json": json.dumps(
                {"tool": "gitleaks", "findings": []})},
            ["cppcheck", "gitleaks"])
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_no_reports_at_all_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "empty"))
            proc = subprocess.run(
                [sys.executable, os.path.join(TOOL, "gate.py"), "gate",
                 "--reports", os.path.join(tmp, "empty"), "--expect", "cppcheck"],
                capture_output=True, text=True)
        self.assertNotEqual(proc.returncode, 0)

    def test_summary_names_the_tools_that_did_not_report(self):
        proc, summary = self._run_gate(
            {"cppcheck.json": json.dumps(
                {"tool": "cppcheck", "findings": []})},
            ["cppcheck", "trivy"])
        self.assertIn("Analyzers that did not report", summary)
        self.assertIn("trivy", summary)


class AnnotateMustNotManufactureAResult(unittest.TestCase):
    """Property 2, at the step that produces the gate's evidence.

    Every test in MissingScannerIsAFailure above hand-writes the
    `{"tool": ..., "findings": []}` document the gate reads, which is correct
    for testing `gate` and useless for testing `annotate` -- the step that
    writes it.  So the property was asserted only from the consuming side,
    and the producing side went unguarded.

    That is how a live false green shipped.  `annotate --tool X --out X.json`
    called collect_strict() on expand_reports(); for a report directory that
    exists but is EMPTY -- what a crashed or uninstalled scanner leaves
    behind, because every workflow does `mkdir -p` before running it --
    expand_reports returns [] and collect([]) returns [], not None.  The
    `findings is None` guard did not fire, so annotate took the success path
    and wrote {"tool": "gitleaks", "findings": []}.

    That file is the only evidence the gate uses to decide a tool reported
    (tools_present reads doc["tool"] out of it), so the manufactured report
    made the gate conclude the scanner had run and print PASS with it counted
    among the tools that reported.  Reproduced against a consuming
    repository's own ci.yml step sequence: gate exit 0, "2 tool(s) reported",
    gitleaks never invoked.  All three defensive layers were defeated at
    once -- the install step had run, `if-no-files-found: error` could not
    fire because annotate had just written into the very directory it was
    meant to prove empty, and the missing-tool check passed on the
    manufactured report.  The ofio green run (37242692938), reproduced.

    The asymmetry these tests pin: cmd_gate has guarded empty input since it
    was written, and cmd_annotate did not.  One function was hardened
    against exactly this and its sibling was not.
    """

    def _annotate(self, tool, make_report):
        """Run `annotate` over a report dir prepared by make_report(dir)."""
        with tempfile.TemporaryDirectory() as tmp:
            report_dir = os.path.join(tmp, tool)
            os.makedirs(report_dir)
            make_report(report_dir)
            out = os.path.join(tmp, "%s.findings.json" % tool)
            proc = subprocess.run(
                [sys.executable, os.path.join(TOOL, "gate.py"), "annotate",
                 report_dir, "--tool", tool, "--out", out],
                capture_output=True, text=True)
            written = None
            if os.path.exists(out):
                with open(out, "r", encoding="utf-8") as fh:
                    written = json.load(fh)
            return proc, written

    @staticmethod
    def _write_clean_sarif(report_dir):
        """A scanner that RAN and found nothing: a real, parseable report."""
        with open(os.path.join(report_dir, "report.sarif"), "w",
                  encoding="utf-8") as fh:
            json.dump({
                "version": "2.1.0",
                "runs": [{"tool": {"driver": {"name": "ruff"}},
                          "results": []}],
            }, fh)

    def test_annotate_on_empty_dir_exits_error(self):
        proc, _ = self._annotate("gitleaks", lambda d: None)
        self.assertEqual(
            proc.returncode, gate.EXIT_ERROR,
            "annotate exited %d on a report directory containing no report. It "
            "must exit %d: the scanner did not run, and writing an empty "
            "finding list here is what made the gate report a never-run "
            "scanner as clean." % (proc.returncode, gate.EXIT_ERROR))

    def test_annotate_on_empty_dir_writes_no_findings_document(self):
        _, written = self._annotate("gitleaks", lambda d: None)
        self.assertIsNone(
            written,
            "annotate wrote %r for a scanner that never produced a report. "
            "That document is the sole input to the gate's missing-tool "
            "check, so its existence is what tells the gate the tool "
            "reported." % (written,))

    def test_annotate_does_not_claim_zero_findings(self):
        proc, _ = self._annotate("gitleaks", lambda d: None)
        self.assertNotIn(
            "0 finding(s) from gitleaks", proc.stdout,
            "annotate announced a clean scan for a tool that never ran")

    def test_annotate_still_accepts_a_genuinely_clean_scan(self):
        """The guard must not break the case it is easy to break.

        A clean scan and a scanner that never ran both leave zero findings.
        The difference is that one leaves a REPORT.  Rejecting the clean-scan
        case would make "no findings" indistinguishable from "no scan" and
        would pressure someone into deleting the check rather than fixing the
        scanner, so this is pinned deliberately rather than left to chance.
        """
        proc, written = self._annotate("ruff", self._write_clean_sarif)
        self.assertEqual(
            proc.returncode, gate.EXIT_CLEAN,
            "annotate exited %d on a VALID report with zero findings. That is "
            "a scanner that ran and found nothing, which must succeed."
            % proc.returncode)
        self.assertIsNotNone(written,
                             "a genuinely clean scan must still be recorded")
        self.assertEqual((written or {}).get("findings"), [])

    def test_a_refused_annotate_leaves_the_gate_failing_closed(self):
        """End to end: refuse at annotate, and the gate still says FAIL.

        Defence in depth.  If a future change to annotate ever stops refusing,
        this fails too, so the property does not rest on one guard.
        """
        with tempfile.TemporaryDirectory() as tmp:
            analysis = os.path.join(tmp, "analysis")
            # One tool works; the other's directory exists but is empty.
            ruff_dir = os.path.join(analysis, "ruff")
            os.makedirs(ruff_dir)
            self._write_clean_sarif(ruff_dir)
            os.makedirs(os.path.join(analysis, "gitleaks"))
            baseline = os.path.join(tmp, "baseline.json")
            with open(baseline, "w", encoding="utf-8") as fh:
                json.dump({"findings": []}, fh)
            for tool in ("ruff", "gitleaks"):
                subprocess.run(
                    [sys.executable, os.path.join(TOOL, "gate.py"), "annotate",
                     os.path.join(analysis, tool), "--tool", tool,
                     "--out", os.path.join(analysis,
                                           "%s.findings.json" % tool)],
                    capture_output=True, text=True)
            proc = subprocess.run(
                [sys.executable, os.path.join(TOOL, "gate.py"), "gate",
                 "--reports", analysis, "--baseline", baseline,
                 "--out-dir", os.path.join(tmp, "out"),
                 "--expect", "ruff", "gitleaks"],
                capture_output=True, text=True)
        self.assertNotEqual(
            proc.returncode, gate.EXIT_CLEAN,
            "gate exited 0 (PASS) with gitleaks never having produced a "
            "report. This is the ofio false green reproduced locally: a green "
            "pipeline that never ran a scanner it claimed to have run.")
        self.assertIn("gitleaks", proc.stdout + proc.stderr,
                      "the failure does not name the tool that produced no "
                      "report, so the reader is told the pipeline is broken "
                      "but not why")


class ConfigContract(unittest.TestCase):
    def _load(self, doc):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "gate.config.json")
            with open(path, "w", encoding="utf-8") as fh:
                if isinstance(doc, str):
                    fh.write(doc)
                else:
                    json.dump(doc, fh)
            return gate.load_config(path)

    def test_complete_config_loads(self):
        doc = dict(gate.DEFAULT_CONFIG)
        doc.update({"rationale_before_you_start": "a",
                    "rationale_comment_footer": "b"})
        self.assertEqual(self._load(doc)["display_name"],
                         gate.DEFAULT_CONFIG["display_name"])

    def test_missing_required_key_is_rejected(self):
        doc = dict(gate.DEFAULT_CONFIG)
        del doc["sarif_driver"]
        with self.assertRaises(SystemExit):
            self._load(doc)

    def test_empty_required_key_is_rejected(self):
        doc = dict(gate.DEFAULT_CONFIG)
        doc.update({"rationale_before_you_start": "a",
                    "rationale_comment_footer": "b"})
        doc["board"] = "   "
        with self.assertRaises(SystemExit):
            self._load(doc)

    def test_malformed_json_is_rejected(self):
        with self.assertRaises(SystemExit):
            self._load("{not json")

    def test_non_object_json_is_rejected(self):
        with self.assertRaises(SystemExit):
            self._load("[1, 2, 3]")

    def test_absent_rationale_can_never_render_as_none(self):
        """The regression this guards: "{x}".format(x=None) -> "None"."""
        doc = dict(gate.DEFAULT_CONFIG)
        for key in ("rationale_before_you_start", "rationale_comment_footer"):
            self.assertIsNone(gate.DEFAULT_CONFIG[key])
            with self.assertRaises(SystemExit):
                self._load(doc)

    def test_config_is_found_by_walking_up(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, ".ci"))
            deep = os.path.join(tmp, "a", "b", "c")
            os.makedirs(deep)
            doc = dict(gate.DEFAULT_CONFIG)
            doc.update({"display_name": "walked",
                        "rationale_before_you_start": "a",
                        "rationale_comment_footer": "b"})
            with open(os.path.join(tmp, ".ci", "gate.config.json"), "w") as fh:
                json.dump(doc, fh)
            self.assertEqual(gate.find_config(start=deep),
                             os.path.join(tmp, ".ci", "gate.config.json"))

    def test_config_lookup_does_not_depend_on_the_working_directory(self):
        """A gate invoked from the wrong directory must not render as unconfigured.

        The regression this guards: find_config() walked up from os.getcwd()
        only, so running the gate from anywhere but the repository root found
        no config and fell through to DEFAULT_CONFIG -- "this repository" and
        board "UNCONFIGURED" rendered into a PR comment that a reviewer has no
        way to distinguish from a genuinely unconfigured gate.

        A submodule makes this reachable rather than theoretical: the tool is
        invoked as `python3 ci/gate/gate.py` from the repository root in CI,
        but a developer running it from inside ci/gate/, from tests/, or via an
        absolute path hits a different answer for the same repository.

        Asserted through a subprocess, because CONFIG is resolved at import
        time -- changing os.getcwd() inside this process would not re-run the
        lookup, so the test would pass against the very bug it exists to catch.
        """
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, ".ci"))
            os.makedirs(os.path.join(tmp, "ci", "gate"))
            doc = dict(gate.DEFAULT_CONFIG)
            doc.update({"display_name": "walked", "board": "walked-board",
                        "rationale_before_you_start": "a",
                        "rationale_comment_footer": "b"})
            with open(os.path.join(tmp, ".ci", "gate.config.json"), "w") as fh:
                json.dump(doc, fh)
            # The tool is vendored at <tmp>/ci/gate, as the submodule places it.
            shutil.copy(os.path.join(TOOL, "gate.py"),
                        os.path.join(tmp, "ci", "gate", "gate.py"))

            probe = ("import sys; sys.path.insert(0, %r); "
                     "import gate; print(gate.CONFIG['board'])" %
                     os.path.join(tmp, "ci", "gate"))
            for cwd in (tmp, os.path.join(tmp, "ci", "gate"), "/"):
                proc = subprocess.run([sys.executable, "-c", probe],
                                      capture_output=True, text=True, cwd=cwd)
                self.assertEqual(
                    proc.returncode, 0,
                    "gate failed to import from cwd=%s: %s"
                    % (cwd, proc.stderr.strip()))
                self.assertEqual(
                    proc.stdout.strip(), "walked-board",
                    "from cwd=%s the gate loaded board %r instead of the "
                    "repository's own; it resolved its identity from the "
                    "working directory rather than from where it lives"
                    % (cwd, proc.stdout.strip()))


if __name__ == "__main__":
    unittest.main(verbosity=2)