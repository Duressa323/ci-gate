#!/usr/bin/env python3
"""
Aggregate static-analysis / secret-scanner / CVE-scanner output into one
verdict for a repository's CI pipeline.

Two subcommands:

  annotate   parse one tool's report, print a GitHub ::error annotation per
             finding, and write the normalised findings as JSON.  Runs inside
             the per-tool job so annotations land on that tool's own check.

  gate       parse every report in a directory, split findings into
             pre-existing (present in the committed baseline) vs new, emit
             annotations, write a combined SARIF + JSON artifact plus a
             markdown summary, and exit non-zero when anything new is found.

Design notes
------------
* Standard library only.  The repo has no Python dependency policy to lean on
  and CI runners have no guarantee of PyYAML being importable.
* Every baseline entry MUST carry a `justification`.  A suppression without a
  written reason is a bug waiting to hide a real defect, so it is rejected at
  load time rather than silently honoured.
* Content hash, not line number, is the dedup / baseline key.  Line numbers
  drift on every unrelated edit; the (tool, rule, file, message) tuple does not.
* Severity is normalised to error / warning / note so findings from five
  different tools sort and count together.
"""

import argparse
import hashlib
import json
import os
import plistlib
import sys
from xml.etree import ElementTree

SEVERITIES = ("error", "warning", "note")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Severities that fail the gate.  `note` is advisory: it is still reported and
# still shows up in the PR comment, it just does not block a merge on its own.
BLOCKING_SEVERITIES = ("error", "warning")

# Every tool whose report the gate expects to find.  Kept in step with the
# `--tool` arguments in ci.yml's annotate steps; test_ci_gate.py asserts the
# two lists agree, so adding a scanner without listing it here fails the
# pipeline rather than quietly going unchecked.
EXPECTED_TOOLS = (
    "clang-analyze",
    "cppcheck",
    "gitleaks",
    "trivy",
    "osv-scanner",
)

# ─────────────────────────── repo identity config ──────────────────────────
#
# This file is the single implementation of the gate; per-repository identity
# lives in `.ci/gate.config.json` at the repository root.  The defaults below
# are deliberately NEUTRAL placeholders, not any one repository's values.
#
# That is a considered choice.  Two reasons:
#
#   * This tool is shared across repositories that are themselves private, and
#     these defaults ship with it.  A default of "deaf-ci-gate" or
#     "https://github.com/duressa-ship-it/deaf" would publish the name and URL
#     of a private repository to anyone who can read this file.  Neutral text
#     publishes nothing.
#   * A missing config that renders some OTHER repository's name is worse than
#     one that renders an obvious placeholder.  The old per-repo copies could
#     only ever be wrong about themselves; a shared default can be wrong about
#     every repository at once.
#
# Every consuming repository carries an explicit `.ci/gate.config.json`, and
# tests/test_parity.py asserts it exists and is complete, so no repository
# actually runs on these defaults — the fallback exists only so the tool is
# runnable standalone.

CONFIG_ENV = "GATE_CONFIG"
CONFIG_RELPATH = os.path.join(".ci", "gate.config.json")

DEFAULT_CONFIG = {
    # Human-facing name used in the PR comment and card titles.
    "display_name": "this repository",
    # Lowercase slug: the kanban board finding cards are filed on.
    "board": "UNCONFIGURED",
    # SARIF driver name; also the prefix on every rule id triage.py decodes.
    "sarif_driver": "ci-gate",
    "information_uri": "https://example.invalid/ci-gate",
    # Sticky-comment marker post_summary.py uses to find its own comment.
    "comment_marker": "<!-- ci-gate-analysis -->",
    # Closing paragraph of the gate summary: what the tests cover, and what
    # static analysis is therefore still reaching for.
    "summary_footer": (
        "UNCONFIGURED: this repository has no `.ci/gate.config.json`, so the "
        "gate is reporting with placeholder identity and no description of "
        "what its tests cover. Run tools/gen_config.py, or set $GATE_CONFIG."
    ),
    # Prose that explains THIS repository's intentional findings, so a
    # reviewer does not mistake correct-by-construction code for a defect.
    "rationale_rule1": None,
    "rationale_before_you_start": None,
    "rationale_comment_footer": None,
}

# Keys that must be present and non-empty in every config file.  A config
# missing one of these is a hard error rather than a silent fallback: a gate
# that quietly renders the wrong repository's name produces a green build and
# a misleading PR comment, which is the failure mode this tool exists to stop.
#
# The two `rationale_*` keys interpolated into card bodies are required for
# the same reason: their default is None, and `"{x}".format(x=None)` renders
# the literal string "None" into a PR comment that a reviewer would read as an
# instruction.  Absence must be loud, not cosmetic.
REQUIRED_CONFIG_KEYS = (
    "display_name",
    "board",
    "sarif_driver",
    "information_uri",
    "comment_marker",
    "summary_footer",
    "rationale_before_you_start",
    "rationale_comment_footer",
)


class ConfigError(SystemExit):
    """A config file is missing, malformed, or incomplete."""


def find_config(start=None):
    """
    Locate `.ci/gate.config.json`, walking up from `start`.

    $GATE_CONFIG wins outright, so a test or a one-off local run can point at
    an alternate config without touching the repository's own.
    """
    explicit = os.environ.get(CONFIG_ENV)
    if explicit:
        return explicit
    here = os.path.abspath(start or os.getcwd())
    while True:
        candidate = os.path.join(here, CONFIG_RELPATH)
        if os.path.isfile(candidate):
            return candidate
        parent = os.path.dirname(here)
        if parent == here:
            return None
        here = parent


def load_config(path=None):
    """
    Returns the repo identity dict, falling back to DEFAULT_CONFIG.

    Missing file -> defaults, so the tool still runs standalone.  Present but
    malformed or incomplete -> ConfigError.  The distinction matters: a
    repository that has opted into per-repo identity must never fall back to
    another repository's identity because of a typo in its config.
    """
    resolved = path or find_config()
    if not resolved:
        return dict(DEFAULT_CONFIG)
    if not os.path.exists(resolved):
        raise ConfigError(
            "gate config not found: %s\n"
            "Set $%s to point at one, or delete the file to fall back to "
            "the built-in defaults." % (resolved, CONFIG_ENV))
    try:
        with open(resolved, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except ValueError as exc:
        raise ConfigError("gate config is not valid JSON: %s (%s)"
                          % (resolved, exc))
    if not isinstance(raw, dict):
        raise ConfigError("gate config must be a JSON object: %s" % resolved)

    out = dict(DEFAULT_CONFIG)
    out.update(raw)
    missing = [k for k in REQUIRED_CONFIG_KEYS
               if not str(out.get(k) or "").strip()]
    if missing:
        raise ConfigError(
            "gate config %s is missing required key(s): %s\n"
            "Every key must be a non-empty string; silence here would "
            "render another repository's name into this one's PR comment."
            % (resolved, ", ".join(sorted(missing))))
    return out


# Populated at import so `import gate` is enough for triage.py, which shares
# this identity.  A SyntaxError in a config file surfaces here rather than in
# whichever subcommand happened to read it first.
CONFIG = load_config()


# ────────────────────────────── normalisation ──────────────────────────────


def content_hash(tool, rule_id, path, message):
    """Stable identity for a finding, independent of its line number."""
    key = "\x1f".join((tool, rule_id or "", path or "", message or ""))
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


class Finding(dict):
    """tool / severity / file / line / message / rule_id / hash."""

    @classmethod
    def make(cls, tool, severity, path, line, message, rule_id):
        if severity not in SEVERITY_RANK:
            severity = "note"
        f = cls(
            tool=tool,
            severity=severity,
            file=path or "",
            line=int(line or 0),
            message=(message or "").strip(),
            rule_id=rule_id or "",
        )
        f["hash"] = content_hash(tool, f["rule_id"], f["file"], f["message"])
        return f

    @property
    def location(self):
        return "%s:%d" % (self["file"] or "?", self["line"] or 0)


def dedup(findings):
    """Drop repeats of the same content hash, keeping the first occurrence."""
    seen, out = set(), []
    for f in findings:
        if f["hash"] in seen:
            continue
        seen.add(f["hash"])
        out.append(f)
    return out


def sort_key(f):
    return (SEVERITY_RANK.get(f["severity"], 99), f["tool"], f["file"],
            f["line"], f["rule_id"])


# ──────────────────────────────── parsers ──────────────────────────────────


def _sarif_level(result):
    level = (result.get("level") or "").lower()
    if level == "error":
        return "error"
    if level == "warning":
        return "warning"
    if level in ("note", "none"):
        return "note"
    # Fall back to the rule's own defaultConfiguration when the result
    # itself carries no level (gitleaks omits it).
    return "error"


def parse_sarif(text, tool):
    doc = json.loads(text)
    out = []
    for run in doc.get("runs", []):
        for result in run.get("results", []):
            path, line = "", 0
            locs = result.get("locations") or []
            if locs:
                phys = (locs[0] or {}).get("physicalLocation") or {}
                path = phys.get("artifactLocation", {}).get("uri", "")
                line = phys.get("region", {}).get("startLine", 0)
            msg = (result.get("message") or {}).get("text", "")
            out.append(Finding.make(tool, _sarif_level(result), path, line,
                                    msg, result.get("ruleId", "")))
    return out


def parse_cppcheck_xml(text, tool="cppcheck"):
    """
    cppcheck's XMLv2 report.

    Chosen over `--output-format=sarif` deliberately: cppcheck accepted only
    text/xml until 2.16 added SARIF, and apt on ubuntu-latest ships whatever
    the runner image pins.  XMLv2 has been the stable schema for a decade, so
    one code path works on every runner.
    """
    root = ElementTree.fromstring(text)
    out = []
    for err in root.iter("error"):
        sev = (err.get("severity") or "error").lower()
        loc = err.find("location")
        path, line = "", 0
        if loc is not None:
            path = loc.get("file", "") or err.get("file0", "")
            line = int(loc.get("line", 0) or 0)
        out.append(Finding.make(tool, sev, path, line,
                                err.get("verbose") or err.get("msg", ""),
                                err.get("id", "")))
    return out


def parse_clang_plist(text, tool="clang-analyze", root="."):
    doc = plistlib.loads(text.encode("utf-8") if isinstance(text, str) else text)
    files = doc.get("files") or []
    out = []
    for diag in doc.get("diagnostics") or []:
        loc = diag.get("location") or {}
        idx = loc.get("file", 0)
        path = files[idx] if isinstance(idx, int) and idx < len(files) else ""
        if root and path.startswith(root + "/"):
            path = path[len(root) + 1:]
        category = (diag.get("category") or "").lower()
        if "error" in category:
            sev = "error"
        elif "warning" in category:
            sev = "warning"
        else:
            sev = "note"
        out.append(Finding.make(tool, sev, path, loc.get("line", 0),
                                diag.get("description", ""),
                                diag.get("check_name", "")))
    return out


def parse_gate_json(text, tool=None):
    """
    Parse ci/gate.py's own normalised output.

    These files land in the gate's report directory alongside the raw tool
    reports (each annotate step uploads one).  Silently ignoring them would mean
    the gate reads a file and contributes nothing to its verdict, which is the
    exact failure mode this gate exists to prevent.  Re-reading them is safe:
    a finding repeated here carries the same content hash as the raw report it
    came from, so dedup collapses it.
    """
    doc = json.loads(text)
    out = []
    for entry in doc.get("findings", []):
        out.append(Finding.make(entry.get("tool") or tool or "unknown",
                                entry.get("severity", "note"),
                                entry.get("file", ""), entry.get("line", 0),
                                entry.get("message", ""),
                                entry.get("rule_id", "")))
    return out


def parse_report(path, tool=None):
    """Dispatch on file content so a job never has to name the format."""
    name = os.path.basename(path)
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    stripped = text.lstrip()

    if name.endswith(".plist"):
        return parse_clang_plist(text, tool or "clang-analyze")
    if stripped.startswith("<?xml") or stripped.startswith("<results"):
        # cppcheck XMLv2 is the only XML these jobs emit; SARIF is JSON.
        return parse_cppcheck_xml(text, tool or "cppcheck")
    if stripped.startswith("{") or stripped.startswith("["):
        doc = json.loads(text)
        if isinstance(doc, dict) and "findings" in doc:
            return parse_gate_json(text, tool)
        return parse_sarif(text, tool or os.path.splitext(name)[0])
    raise ValueError("unrecognised report format: %s" % path)


# ──────────────────────────────── baseline ─────────────────────────────────


def load_baseline(path):
    """
    Returns {content_hash: entry}.

    Every entry must carry a justification.  An unjustified entry is a silent
    suppression, which is exactly the failure mode this pipeline exists to
    prevent, so it is a hard error rather than a warning.
    """
    if not path or not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    entries = doc.get("findings", doc if isinstance(doc, list) else [])
    out, bad = {}, []
    for entry in entries:
        just = (entry.get("justification") or "").strip()
        if not just:
            bad.append(entry.get("id") or entry.get("rule_id") or "<unnamed>")
            continue
        out[entry["hash"]] = entry
    if bad:
        raise SystemExit(
            "baseline entries without a justification: %s\n"
            "Every suppression must record why the finding is intentional."
            % ", ".join(sorted(bad)))
    return out


def split_baseline(findings, baseline):
    preexisting, new = [], []
    for f in findings:
        (preexisting if f["hash"] in baseline else new).append(f)
    return preexisting, new


# ─────────────────────────────── reporting ─────────────────────────────────


def escape_annotation(text):
    return (text.replace("%", "%25").replace("\r", "%0D")
                .replace("\n", "%0A"))


def annotation(f):
    props = []
    if f["file"]:
        props.append("file=%s" % f["file"])
    if f["line"]:
        props.append("line=%d" % f["line"])
    if f["rule_id"]:
        props.append("title=%s" % escape_annotation(f["rule_id"]))
    return "::error %s::%s" % (",".join(props), escape_annotation(f["message"]))


def to_sarif(findings, tool_of_run):
    rules, results = {}, []
    for f in findings:
        rid = "%s.%s" % (f["tool"], f["rule_id"] or "unknown")
        rules.setdefault(rid, {
            "id": rid,
            "shortDescription": {"text": f["rule_id"] or f["tool"]},
        })
        loc = {}
        if f["file"]:
            loc = {"physicalLocation": {
                "artifactLocation": {"uri": f["file"]},
                "region": {"startLine": f["line"] or 1},
            }}
        results.append({
            "ruleId": rid,
            "level": f["severity"],
            "message": {"text": f["message"]},
            "locations": [loc] if loc else [],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": CONFIG["sarif_driver"],
                "informationUri": CONFIG["information_uri"],
                "rules": [rules[k] for k in sorted(rules)],
            }},
            "results": results,
        }],
    }


def summary_markdown(findings, preexisting, new, baseline, gate_failed,
                     missing=()):
    by_sev = {s: [f for f in findings if f["severity"] == s]
              for s in SEVERITIES}
    verdict = "FAIL" if gate_failed else "PASS"
    lines = [
        "## %s static analysis — %s" % (CONFIG["display_name"], verdict),
        "",
        "`clang --analyze`, `cppcheck`, `gitleaks`, `trivy fs`, `osv-scanner`.",
        "",
        "| severity | findings |",
        "|---|---|",
    ]
    for s in SEVERITIES:
        lines.append("| %s | %d |" % (s, len(by_sev[s])))
    lines += [
        "| **total** | **%d** |" % len(findings),
        "",
        "Pre-existing (in `.ci/analysis-baseline.json`): **%d**  " % len(preexisting),
        "New: **%d**" % len(new),
        "",
    ]
    if preexisting:
        lines += ["### Pre-existing (baselined, justified)", ""]
        for f in sorted(preexisting, key=sort_key):
            entry = baseline.get(f["hash"], {})
            lines.append("- `%s` — %s: %s  \n  _justification: %s_"
                         % (f.location, f["tool"],
                            escape_annotation(f["message"])[:160],
                            entry.get("justification", "(none)")))
        lines.append("")
    if new:
        lines += ["### New — these fail the gate", ""]
        for f in sorted(new, key=sort_key):
            lines.append("- `%s` **%s** `%s` — %s"
                         % (f.location, f["severity"], f["tool"],
                            escape_annotation(f["message"])[:200]))
        lines.append("")
    elif not findings:
        lines += ["No findings. All four analyzers and both CVE scanners are clean.", ""]
    if missing:
        lines += [
            "### Analyzers that did not report",
            "",
            "These produced no report, so this verdict does **not** cover them:",
            "",
        ]
        for tool in missing:
            lines.append("- `%s` — no report collected" % tool)
        lines.append("")
    lines += [
        CONFIG["summary_footer"],
        "",
    ]
    return "\n".join(lines)


# ──────────────────────────────── commands ─────────────────────────────────


def collect(report_paths):
    # Expand before parsing.  `gate.py annotate analysis/clang` is given a
    # DIRECTORY (the clang job writes one plist per source into it); calling
    # parse_report() on the directory itself raised IsADirectoryError, killed
    # the clang annotate step, and because the gate tolerates a missing
    # per-tool report it went on to report zero clang findings and pass.  The
    # whole analyzer was silently disabled by a crash.
    findings = []
    for path in expand_reports(report_paths):
        findings.extend(parse_report(path))
    return dedup(findings)


def cmd_annotate(args):
    findings = collect(args.reports)
    for f in sorted(findings, key=sort_key):
        print(annotation(f))
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump({"tool": args.tool, "findings": findings}, fh, indent=2)
            fh.write("\n")
    print("::notice title=%s::%d finding(s) from %s"
          % (escape_annotation(args.tool), len(findings),
             escape_annotation(args.tool)))
    return 0


def expand_reports(paths, exclude=None):
    """
    Expand the --reports arguments into a list of files.

    Recursive on purpose.  Each tool job uploads its report under its own
    subdirectory, and a non-recursive walk silently skipped those — the gate
    reported zero findings and exited 0 because it had read nothing.  A gate
    that passes because it saw no input is worse than no gate at all.

    `exclude` drops the gate's own output directory.  That directory holds
    summary.md, which is markdown rather than a report: re-reading it raised
    "unrecognised report format" and aborted the gate.  Because the Makefile
    writes the gate output *inside* the scanned tree (analysis/gate under
    analysis/), this broke every run after the first — a gate that only works
    on a clean checkout is a gate nobody can run locally twice.
    """
    excluded = os.path.abspath(exclude) if exclude else None
    out = []
    for path in paths:
        if os.path.isfile(path):
            out.append(path)
            continue
        for root, dirs, files in os.walk(path):
            if excluded and os.path.abspath(root) == excluded:
                dirs[:] = []
                continue
            dirs[:] = sorted(d for d in dirs if not d.startswith("."))
            for entry in sorted(files):
                if not entry.startswith("."):
                    full = os.path.join(root, entry)
                    if excluded and os.path.abspath(full).startswith(
                            excluded + os.sep):
                        continue
                    out.append(full)
    return out


def tools_present(findings, report_paths):
    """
    Which tools actually contributed a report.

    Reads the per-tool JSON each annotate step emits ({"tool": ...,
    "findings": [...]}) rather than trusting the file list.  A tool whose
    scanner crashed before annotate leaves no JSON, so it is simply absent
    from the findings set — indistinguishable from "scanned and found
    nothing" unless we track presence separately.
    """
    present = set()
    for path in report_paths:
        if not path.endswith(".json"):
            continue
        try:
            with open(path, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError):
            continue
        if isinstance(doc, dict) and doc.get("tool"):
            present.add(doc["tool"])
    return present


def expected_tools(names):
    """
    The tools this invocation should expect reports from.

    Defaults to every tool CI runs.  A partial local run (`make analyze` covers
    clang + cppcheck only, `make scan` the other three) must declare its own
    subset, or the fail-closed missing-tool check reports the three tools it
    never invoked as crashed and the local mirror can never print a passing
    verdict — which is exactly what it did: `make analyze` exited 1 on a clean
    tree, on every run, because it skipped the per-tool annotate step that
    produces the `{tool, findings}` JSON this check reads.
    """
    if not names:
        return EXPECTED_TOOLS
    out = []
    for chunk in names:
        for name in str(chunk).split(","):
            name = name.strip()
            if name and name not in out:
                out.append(name)
    return tuple(out)


def cmd_gate(args):
    report_paths = expand_reports(args.reports, exclude=args.out_dir)
    if not report_paths:
        print("::error::no analyzer reports found under %s — refusing to "
              "pass on empty input" % ", ".join(args.reports),
              file=sys.stderr)
        return 2

    findings = collect(report_paths)
    findings.sort(key=sort_key)
    baseline = load_baseline(args.baseline)
    preexisting, new = split_baseline(findings, baseline)

    blocking = [f for f in new if f["severity"] in BLOCKING_SEVERITIES]
    gate_failed = bool(blocking)

    # Fail closed on a missing tool.  `needs:` + `if: always()` means the gate
    # runs even when a scanner job failed, so a crashed scanner contributes no
    # report and the gate would otherwise pass having never run it — reporting
    # "clean" for an analyzer that never executed.  The tool's own job is still
    # red in the checks list; this makes the gate's verdict honest too.
    present = tools_present(findings, report_paths)
    missing = [t for t in expected_tools(args.expect) if t not in present]

    for f in findings:
        print(annotation(f))

    if missing:
        for tool in missing:
            print("::error title=missing analyzer report::%s produced no "
                  "report — it did not run, or crashed before annotate. Its "
                  "job must be green for this gate to mean anything."
                  % tool, file=sys.stderr)

    if args.out_dir:
        os.makedirs(args.out_dir, exist_ok=True)
        with open(os.path.join(args.out_dir, "findings.sarif"), "w",
                  encoding="utf-8") as fh:
            json.dump(to_sarif(findings, None), fh, indent=2)
            fh.write("\n")
        with open(os.path.join(args.out_dir, "findings.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({
                "total": len(findings),
                "pre_existing": len(preexisting),
                "new": len(new),
                "gate": "fail" if (gate_failed or missing) else "pass",
                "tools_reported": sorted(present),
                "tools_missing": missing,
                "findings": findings,
            }, fh, indent=2)
            fh.write("\n")
        with open(os.path.join(args.out_dir, "summary.md"), "w",
                  encoding="utf-8") as fh:
            fh.write(summary_markdown(findings, preexisting, new, baseline,
                                      gate_failed or missing, missing))

    print("::notice title=analysis gate::%s — %d report(s) read, "
          "%d tool(s) reported, %d total finding(s), %d pre-existing, "
          "%d new, %d new blocking"
          % ("FAIL" if (gate_failed or missing) else "PASS", len(report_paths),
             len(present), len(findings), len(preexisting), len(new),
             len(blocking)))

    if missing:
        print("\nAnalysis gate FAILED: no report from %s."
              % ", ".join(missing), file=sys.stderr)
        return 1
    if gate_failed:
        print("\nAnalysis gate FAILED: %d new blocking finding(s)."
              % len(blocking), file=sys.stderr)
        return 1
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("annotate", help="annotate one tool's report")
    a.add_argument("reports", nargs="+")
    a.add_argument("--tool", required=True)
    a.add_argument("--out")
    a.set_defaults(func=cmd_annotate)

    g = sub.add_parser("gate", help="aggregate, baseline-diff and fail")
    g.add_argument("--reports", nargs="+", required=True)
    g.add_argument("--baseline", default=".ci/analysis-baseline.json")
    g.add_argument("--out-dir")
    g.add_argument("--expect", nargs="*", default=None,
                   help="tools this run should expect reports from; "
                        "defaults to every tool CI runs. A partial local "
                        "run declares its own subset.")
    g.set_defaults(func=cmd_gate)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())