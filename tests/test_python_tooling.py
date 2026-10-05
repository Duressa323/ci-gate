#!/usr/bin/env python3
"""
Python-toolchain support in the shared gate, and the fail-closed property.

These properties did not exist when this tool was written for C/C++ repos, and
each one is a way the gate could report "clean" without having looked:

  3. A report the gate CANNOT READ is a FAILURE, not an empty result.  The
     original JSON dispatch was "has `findings`? gate JSON. Otherwise? SARIF."
     bandit emits `{errors, generated_at, metrics, results}` and has no SARIF
     output at all, so every bandit finding was silently discarded while the
     gate printed "0 finding(s) from bandit" and exited 0.

  4. The expected tool set is PER-REPOSITORY.  A shared default naming
     clang/cppcheck/trivy is right for no Python repository: demanding a
     clang report from one fails every run forever, while failing to demand a
     report the repository does run is the fail-open above.

  5. Absolute paths are normalised.  `path` feeds the content hash, so a
     `file:///home/runner/...` URI makes the same finding hash differently on
     every machine -- unsuppressable -- and leaks the runner's home directory
     into a PR comment.

Every test here is checked to FAIL against the pre-fix parser (see the module
docstring of the mouse card that introduced them); a test that cannot fail is
not evidence.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.dirname(HERE)
sys.path.insert(0, TOOL)

import gate  # noqa: E402

# A real bandit 1.9.4 report, reduced to three findings spanning the severity
# range.  Shape copied verbatim from `bandit -f json`, not invented: keys are
# results/metrics/generated_at/errors, and each result carries test_id,
# issue_severity, issue_confidence, issue_text, filename, line_number.
BANDIT_REPORT = {
    "errors": [],
    "generated_at": "2026-10-04T00:00:00Z",
    "metrics": {"_totals": {"CONF_HIGH": 2, "CONF_LOW": 1, "SEV_HIGH": 1,
                            "SEV_LOW": 2, "SEV_MEDIUM": 0}},
    "results": [
        {"code": "B602/B602",
         "col_offset": 4, "filename": "main.py", "issue_confidence": "HIGH",
         "issue_severity": "HIGH", "issue_text": "subprocess call with "
         "shell=True identified, security issue.", "line_number": 3,
         "line_range": [3], "more_info": "https://bandit.readthedocs.io/",
         "test_id": "B602", "test_name": "subprocess_popen_with_shell_equals_true"},
        {"code": "B324/B324",
         "col_offset": 4, "filename": "main.py", "issue_confidence": "HIGH",
         "issue_severity": "HIGH", "issue_text": "Use of weak MD5 hash for "
         "security. Consider usedforsecurity=False.", "line_number": 5,
         "line_range": [5], "more_info": "https://bandit.readthedocs.io/",
         "test_id": "B324", "test_name": "hashlib"},
        {"code": "B404/B404",
         "col_offset": 0, "filename": "main.py", "issue_confidence": "LOW",
         "issue_severity": "LOW", "issue_text": "Consider possible security "
         "implications associated with the subprocess module.",
         "line_number": 1, "line_range": [1],
         "more_info": "https://bandit.readthedocs.io/",
         "test_id": "B404", "test_name": "import_subprocess"},
    ],
}


def bandit_report(**overrides):
    doc = json.loads(json.dumps(BANDIT_REPORT))
    doc.update(overrides)
    return doc


class BanditReportIsRead(unittest.TestCase):
    """Property 3: bandit's native shape must not read as zero findings."""

    def test_bandit_results_shape_yields_findings(self):
        findings = gate.parse_bandit_json(json.dumps(bandit_report()))
        self.assertEqual(len(findings), 3,
                         "bandit's native `results` shape parsed as %d "
                         "findings; every bandit finding is being discarded"
                         % len(findings))

    def test_severity_maps_from_bandit_issue_severity(self):
        findings = gate.parse_bandit_json(json.dumps(bandit_report()))
        by_rule = {f["rule_id"]: f["severity"] for f in findings}
        self.assertEqual(by_rule["B602"], "error")
        self.assertEqual(by_rule["B324"], "error")
        # LOW is advisory: reported, visible, but not blocking on its own.
        self.assertEqual(by_rule["B404"], "note")

    def test_high_severity_blocks_but_low_does_not(self):
        findings = gate.parse_bandit_json(json.dumps(bandit_report()))
        blocking = [f for f in findings if f["severity"] in gate.BLOCKING_SEVERITIES]
        self.assertEqual(sorted(f["rule_id"] for f in blocking), ["B324", "B602"])

    def test_unknown_severity_is_not_invented_upward(self):
        doc = bandit_report()
        doc["results"][0]["issue_severity"] = "CATASTROPHIC"
        findings = gate.parse_bandit_json(json.dumps(doc))
        self.assertEqual(findings[0]["severity"], "note",
                         "an unrecognised bandit severity must not be "
                         "promoted to a blocking error")

    def test_confidence_is_carried_not_dropped(self):
        findings = gate.parse_bandit_json(json.dumps(bandit_report()))
        self.assertIn("confidence: LOW", findings[2]["message"],
                      "issue_confidence was dropped; a LOW-confidence finding "
                      "is a different thing to review from the same rule at "
                      "HIGH")

    def test_line_number_is_recorded_but_not_hashed(self):
        a = gate.parse_bandit_json(json.dumps(bandit_report()))[0]
        doc = bandit_report()
        doc["results"][0]["line_number"] = 999
        b = gate.parse_bandit_json(json.dumps(doc))[0]
        self.assertEqual(a["line"], 3)
        self.assertEqual(a["hash"], b["hash"])

    def test_bandit_errors_are_not_findings(self):
        """A crashed plugin is a scanner fault, not a finding about the code."""
        doc = bandit_report()
        doc["errors"] = ["Exception occurred when executing tests"]
        findings = gate.parse_bandit_json(json.dumps(doc))
        self.assertEqual(sorted(f["rule_id"] for f in findings),
                         ["B324", "B404", "B602"],
                         "bandit's `errors` list must not be read as findings, "
                         "and must not suppress the real ones either")
        self.assertNotIn("Exception occurred",
                         " ".join(f["message"] for f in findings))


class UnreadableReportIsAFailure(unittest.TestCase):
    """Property 3, end to end: the CLI must not exit 0 on an unknown shape."""

    def _run(self, doc, tool="bandit", cmd="annotate"):
        tmp = tempfile.mkdtemp()
        report = os.path.join(tmp, "report.json")
        with open(report, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(doc))
        if cmd == "gate":
            # `gate` takes --reports (a directory), not a positional report and
            # no --tool: it discovers every report and reads the tool name from
            # each one.
            argv = [sys.executable, os.path.join(TOOL, "gate.py"), "gate",
                    "--reports", tmp, "--expect", tool, "--out-dir",
                    os.path.join(tmp, "out")]
        else:
            argv = [sys.executable, os.path.join(TOOL, "gate.py"), cmd,
                    report, "--tool", tool]
        return subprocess.run(argv, capture_output=True, text=True)

    def test_unknown_json_shape_exits_two_on_annotate(self):
        proc = self._run({"totals": {"SEV_HIGH": 1}, "unexpected": "shape"})
        self.assertEqual(proc.returncode, gate.EXIT_ERROR,
                         "an unreadable report exited %d; it must exit %d so "
                         "the job fails instead of reporting zero findings"
                         % (proc.returncode, gate.EXIT_ERROR))
        self.assertIn("unreadable analyzer report", proc.stderr)
        self.assertIn("unrecognised report shape", proc.stderr)

    def test_unknown_json_shape_exits_two_on_gate(self):
        proc = self._run({"totals": {}}, cmd="gate")
        self.assertEqual(proc.returncode, gate.EXIT_ERROR)
        self.assertIn("ABORTED", proc.stderr)

    def test_top_level_array_is_reported_not_crashed(self):
        """`gitleaks -f json` emits a bare array; say so, do not traceback."""
        proc = self._run([{"Description": "key", "Secret": "x"}],
                         tool="gitleaks")
        self.assertEqual(proc.returncode, gate.EXIT_ERROR)
        self.assertIn("-f sarif", proc.stderr,
                      "the diagnostic should name the fix, not just the shape")

    def test_unreadable_report_never_prints_a_zero_finding_notice(self):
        proc = self._run({"unexpected": "shape"})
        self.assertNotIn("0 finding(s)", proc.stdout,
                         "printing '0 finding(s)' for a report it could not "
                         "read is the fail-open this closes")

    def test_recognised_shapes_still_parse(self):
        """The strict dispatch must not reject what it used to accept."""
        sarif = {"runs": [{"tool": {"driver": {"name": "ruff"}}, "results": [{
            "ruleId": "F401", "level": "warning",
            "message": {"text": "unused import"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "main.py"},
                "region": {"startLine": 2}}}]}]}]}
        for doc, tool in ((sarif, "ruff"),
                          ({"tool": "cppcheck", "findings": []}, "cppcheck"),
                          (bandit_report(), "bandit")):
            with self.subTest(tool=tool):
                self.assertEqual(self._run(doc, tool=tool).returncode,
                                 gate.EXIT_CLEAN)

    def test_missing_file_still_raises(self):
        with self.assertRaises(ValueError):
            gate.parse_report("/nonexistent/report.sarif") \
                if os.path.exists("/nonexistent") else \
                gate.parse_json_report({"nope": 1}, name="r.json")


class AbsolutePathsAreNormalised(unittest.TestCase):
    """Property 5: `path` feeds the content hash, so it must be stable."""

    def test_file_uri_becomes_repo_relative(self):
        out = gate.normalise_uri("file:///home/runner/work/mouse/mouse/main.py",
                                 root="/home/runner/work/mouse/mouse")
        self.assertEqual(out, "main.py")

    def test_no_home_directory_leaks_into_a_finding(self):
        doc = {"runs": [{"results": [{
            "ruleId": "F401", "level": "warning",
            "message": {"text": "unused import"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {
                    "uri": "file:///home/runner/work/mouse/mouse/main.py"},
                "region": {"startLine": 2}}}]}]}]}
        findings = gate.parse_sarif(json.dumps(doc), "ruff",
                                    root="/home/runner/work/mouse/mouse")
        self.assertEqual(findings[0]["file"], "main.py")
        self.assertNotIn("/home/runner", findings[0]["file"])

    def test_identical_finding_hashes_identically_on_two_machines(self):
        """The property that makes a baseline entry usable at all."""
        def build(root):
            doc = {"runs": [{"results": [{
                "ruleId": "F401", "level": "warning",
                "message": {"text": "unused import"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "file://%s/main.py" % root},
                    "region": {"startLine": 2}}}]}]}]}
            return gate.parse_sarif(json.dumps(doc), "ruff", root=root)[0]

        runner = build("/home/runner/work/mouse/mouse")
        laptop = build("/Users/someone/Code/mouse")
        self.assertEqual(runner["hash"], laptop["hash"],
                         "the same finding hashes differently per machine, so "
                         "a baseline entry written on one can never match on "
                         "another and the finding becomes unsuppressable")

    def test_percent_escapes_are_decoded(self):
        self.assertEqual(
            gate.normalise_uri("src/my%20file.py", root="/repo"),
            os.path.join("src", "my file.py"))

    def test_relative_path_is_left_alone(self):
        self.assertEqual(gate.normalise_uri("main.py", root="/repo"), "main.py")

    def test_path_outside_the_root_stays_absolute(self):
        out = gate.normalise_uri("file:///etc/passwd", root="/repo")
        self.assertEqual(out, "/etc/passwd",
                         "a path outside the repo must not be mangled into a "
                         "../.. chain that hides that it is not a repo file")


class ExpectedToolsArePerRepository(unittest.TestCase):
    """Property 4: the C/C++ default must not govern a Python repository."""

    def _config(self, tmp, tools):
        ci = os.path.join(tmp, ".ci")
        os.makedirs(ci, exist_ok=True)
        doc = dict(gate.DEFAULT_CONFIG)
        doc.update({"display_name": "test", "board": "test",
                    "sarif_driver": "test-ci-gate",
                    "information_uri": "https://example.invalid/x",
                    "comment_marker": "<!-- test -->", "summary_footer": "f",
                    "rationale_before_you_start": "a",
                    "rationale_comment_footer": "b"})
        if tools is not None:
            doc["expected_tools"] = tools
        path = os.path.join(ci, "gate.config.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        return path

    def test_config_overrides_the_c_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._config(tmp, ["ruff", "bandit"])
            cfg = gate.load_config(path)
        self.assertEqual(cfg["expected_tools"], ["ruff", "bandit"])

    def test_absent_key_falls_back_to_the_c_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = gate.load_config(self._config(tmp, None))
        self.assertIsNone(cfg["expected_tools"],
                          "omitting the key must leave the C/C++ default in "
                          "place, or every existing C repo breaks at once")

    def test_empty_list_is_rejected(self):
        """An empty list would silently disable the missing-tool check."""
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit):
                gate.load_config(self._config(tmp, []))

    def test_non_list_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            for bad in ("ruff", {"ruff": True}, 3, [1, 2]):
                with self.subTest(value=bad):
                    with self.assertRaises(SystemExit):
                        gate.load_config(self._config(tmp, bad))

    def test_blank_tool_name_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(SystemExit):
                gate.load_config(self._config(tmp, ["ruff", "  "]))

    def test_tools_line_names_the_declared_tools(self):
        original = gate.CONFIG
        try:
            gate.CONFIG = dict(original, expected_tools=["ruff", "bandit"])
            line = gate.tools_line()
            self.assertIn("`ruff`", line)
            self.assertIn("`bandit`", line)
            self.assertNotIn("clang", line,
                             "the summary must not advertise a C toolchain "
                             "this repository does not run")
        finally:
            gate.CONFIG = original

    def test_unset_tools_line_keeps_the_original_wording(self):
        original = gate.CONFIG
        try:
            gate.CONFIG = dict(original, expected_tools=None)
            self.assertEqual(gate.tools_line(), gate.DEFAULT_TOOLS_LINE)
        finally:
            gate.CONFIG = original

    def test_clean_line_does_not_claim_four_analyzers(self):
        original = gate.CONFIG
        try:
            gate.CONFIG = dict(original, expected_tools=["ruff", "bandit"])
            line = gate.clean_line(("ruff", "bandit"))
            self.assertNotIn("four", line.lower())
            self.assertNotIn("CVE", line)
            self.assertIn("ruff", line)
        finally:
            gate.CONFIG = original


class GateEndToEnd(unittest.TestCase):
    """The whole path, through the real CLI, with a real bandit report."""

    def test_bandit_finding_fails_the_gate_end_to_end(self):
        tmp = tempfile.mkdtemp()
        analysis = os.path.join(tmp, "analysis", "bandit")
        os.makedirs(analysis)
        raw = os.path.join(analysis, "report.json")
        with open(raw, "w", encoding="utf-8") as fh:
            json.dump(bandit_report(), fh)
        out = os.path.join(tmp, "analysis", "bandit.json")

        proc = subprocess.run(
            [sys.executable, os.path.join(TOOL, "gate.py"), "annotate", raw,
             "--tool", "bandit", "--out", out],
            capture_output=True, text=True)
        self.assertEqual(proc.returncode, gate.EXIT_CLEAN, proc.stderr)
        self.assertIn("3 finding(s) from bandit", proc.stdout)

        gate_proc = subprocess.run(
            [sys.executable, os.path.join(TOOL, "gate.py"), "gate",
             "--reports", os.path.join(tmp, "analysis"), "--out-dir",
             os.path.join(tmp, "gate-out"), "--expect", "bandit",
             "--baseline", os.path.join(tmp, "absent-baseline.json")],
            capture_output=True, text=True)
        self.assertEqual(gate_proc.returncode, gate.EXIT_ACTIONABLE,
                         "a HIGH-severity bandit finding did not fail the "
                         "gate: %s" % gate_proc.stderr)

        with open(os.path.join(tmp, "gate-out", "findings.json"),
                  encoding="utf-8") as fh:
            doc = json.load(fh)
        self.assertEqual(doc["new"], 3)
        self.assertEqual(doc["gate"], "fail")
        self.assertEqual(doc["tools_reported"], ["bandit"])
        self.assertEqual(doc["tools_missing"], [])

    def test_missing_bandit_report_fails_the_gate(self):
        """The fail-open this whole file exists to prevent."""
        tmp = tempfile.mkdtemp()
        analysis = os.path.join(tmp, "analysis")
        os.makedirs(analysis)
        with open(os.path.join(analysis, "ruff.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({"tool": "ruff", "findings": []}, fh)
        proc = subprocess.run(
            [sys.executable, os.path.join(TOOL, "gate.py"), "gate",
             "--reports", analysis, "--out-dir", os.path.join(tmp, "out"),
             "--expect", "ruff", "bandit"],
            capture_output=True, text=True)
        self.assertEqual(proc.returncode, gate.EXIT_ACTIONABLE)
        self.assertIn("bandit", proc.stderr)
        self.assertIn("no report", proc.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
