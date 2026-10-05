#!/usr/bin/env python3
"""
Turn a `static-analysis-findings` artifact into an actionable triage plan:
normalised findings, a readable report, and ready-to-apply `hermes kanban
create` invocations.

Why this exists
---------------
ci/gate.py makes CI fail and report.  This makes the report actionable: it
answers the two questions a reviewing worker cannot answer from a red check
alone — *is this mine, or was it already here?* and *do I add a card, or update
the one I am already holding?*

The decision rule (also in ci/TRIAGE.md)
----------------------------------------
1. Allowlisted (justified suppression)  -> dropped.  No card, no update.
2. New       (not in the baseline)      -> this change introduced it -> UPDATE
                                          the card currently in flight.
3. Pre-existing (in the baseline)       -> inherited, unrelated to the change
                                          under review -> NEW card.

Rule 1 is not optional for a codebase with intentional findings.  Some domains
— fixed-point DSP, a grid puzzle's board bounds, a network protocol's framing —
have arithmetic where a "defect" is the specification.  Signed shifts,
deliberate aliasing and wraparound are then the algorithm, not defects.  A
triage rule that treats every finding as a defect produces cards nobody should
action, which teaches reviewers to ignore triage.  So suppressions live in
.ci/analysis-allowlist.json, a checked-in file where every entry carries a
`justification` AND a `reason_class` — never a silent -Wno- buried in a
Makefile.

Each repository states its own version of that rationale in `ci/TRIAGE.md` and
in the `rationale_*` keys of `.ci/gate.config.json`, which is what the prose
below interpolates.  Nothing here is specific to one repository.

Credentials
-----------
This helper NEVER creates a card.  It emits shell text for a human or an agent
to apply after reading it.  CI therefore needs no kanban credentials to run
triage, and a compromised runner cannot write to the board.  tests/
test_triage.py asserts the module imports no subprocess at all.

Exit codes
----------
0  nothing actionable (clean, or everything allowlisted)
1  actionable findings — new groups to fold into the in-flight card, and/or
   pre-existing groups needing their own card
2  configuration error (unreadable artifact, unjustified allowlist entry)
"""

import argparse
import json
import os
import shlex
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "ci"))

import gate  # noqa: E402  (path set above)

# Where finding cards go.  Decided once, in ci/TRIAGE.md, and asserted by
# tests so a finding card cannot quietly migrate to another board.  Comes from
# the repository's own config so the shared tool cannot disagree with the
# board decision its own TRIAGE.md records.
BOARD = gate.CONFIG["board"]

# The driver name ci/gate.py stamps on the SARIF it writes, and the prefix it
# uses for each rule id ("<tool>.<rule_id>").  Read from the baseline file's
# own schema note rather than duplicated here so the two cannot drift.
GATE_DRIVER = gate.CONFIG["sarif_driver"]

# Prose that names THIS repository's intentional findings.  Long enough that
# hand-editing it per repo is exactly the drift this tool exists to remove, so
# it lives in `.ci/gate.config.json` and is rendered, not reimplemented.
DISPLAY = gate.CONFIG["display_name"]
RATIONALE_BEFORE_YOU_START = gate.CONFIG["rationale_before_you_start"]
RATIONALE_COMMENT_FOOTER = gate.CONFIG["rationale_comment_footer"]

DEFAULT_BASELINE = os.path.join(ROOT, ".ci", "analysis-baseline.json")
DEFAULT_ALLOWLIST = os.path.join(ROOT, ".ci", "analysis-allowlist.json")

# Suppression categories.  A free-text justification alone does not make a
# suppression reviewable; requiring the reviewer to also say *which kind* of
# intentionality they are asserting does.  Adding a category here is a visible,
# diffable act — it forces a human to look.
REASON_CLASSES = (
    "intentional-signed-shift",
    "intentional-wraparound",
    "intentional-aliasing",
    "intentional-saturation",
    "intentional-precision-trade",
    "tool-limitation",
    "not-a-defect",
)

SEVERITY_PRIORITY = {"error": 70, "warning": 50, "note": 30}

CARD_TITLE_MAX = 96

# Where output goes unless told otherwise.  Deliberately OUTSIDE analysis/:
# the gate scans analysis/ recursively, so anything triage writes inside it
# becomes gate input on the next run, and markdown is not a report format.
DEFAULT_OUT_DIR = os.path.join(ROOT, "triage")

# Exit codes.  These are a contract with CI, not incidental: the triage step
# ends in `if: always()` and cannot fail the job on findings (the gate step
# already does that), so it distinguishes "there are findings to action" (1,
# expected) from "triage itself is broken" (2, must fail loudly).  Keeping 2
# distinct from 1 is what stops a crash from reading as a clean run.
EXIT_CLEAN = 0
EXIT_ACTIONABLE = 1
EXIT_ERROR = 2


class Group(dict):
    """Findings sharing one root cause: (tool, rule_id)."""

    @property
    def locations(self):
        """Every place this group was reported, first line first.

        One finding object can carry several occurrences (see dedup_merging),
        so a group of one finding can still be a group of many locations.

        A finding with no file contributes nothing: SARIF permits a result with
        no `locations` at all (gitleaks emits those), and rendering `?:0` reads
        as a real path rather than as "the analyzer did not say".  Callers must
        handle the empty case; _location_block does.
        """
        out = []
        for f in self["findings"]:
            for occ in (f.get("occurrences") or
                        [{"file": f["file"], "line": f["line"]}]):
                if occ["file"]:
                    out.append("%s:%d" % (occ["file"], occ["line"] or 0))
        return out

    @property
    def count(self):
        return sum(occurrence_count(f) for f in self["findings"])

    @property
    def files(self):
        seen, out = set(), []
        for f in self["findings"]:
            for occ in (f.get("occurrences") or
                        [{"file": f["file"], "line": f["line"]}]):
                if occ["file"] and occ["file"] not in seen:
                    seen.add(occ["file"])
                    out.append(occ["file"])
        return out

    @property
    def title(self):
        rule = self["rule_id"] or "unclassified"
        files = self.files          # property, not self["files"]
        if not files:
            # A finding with no location is legal SARIF: gitleaks reports a
            # secret with no single file, and ci/gate.py's own comment on
            # _sarif_level notes gitleaks omits `level` too.  Indexing
            # files[0] here raised IndexError, and because the CI step ends
            # `|| true` the traceback was indistinguishable from a clean run —
            # a fail-open in the pipeline whose parent card exists to remove
            # them.  Name the tool instead of inventing a path.
            where = "no location reported"
        elif len(files) == 1:
            where = files[0]
        else:
            where = "%s +%d more file(s)" % (files[0], len(files) - 1)
        head = "%s: %s %s in %s" % (BOARD, self["tool"], rule, where)
        return head if len(head) <= CARD_TITLE_MAX else head[:CARD_TITLE_MAX - 1] + "…"


# ─────────────────────────────── allowlist ────────────────────────────────


def load_allowlist(path):
    """
    Returns {content_hash: entry}, keyed by the same content hash gate.py uses.

    Every entry MUST carry a non-empty `justification` and a `reason_class`
    drawn from REASON_CLASSES.  Both are hard errors, not warnings: a
    suppression nobody can explain is indistinguishable from triage, and a
    suppression nobody can categorise cannot be reviewed when the DSP rationale
    changes two years from now.
    """
    if not path or not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    entries = doc.get("suppressions", doc.get("findings", []))

    out, bad = {}, []
    for entry in entries:
        label = "%s %s" % (entry.get("tool") or "?",
                           entry.get("rule_id") or entry.get("hash") or "?")
        just = (entry.get("justification") or "").strip()
        if not just:
            bad.append("%s — no justification" % label)
            continue
        reason = (entry.get("reason_class") or "").strip()
        if reason not in REASON_CLASSES:
            bad.append("%s — reason_class %r not in %s"
                       % (label, reason, ", ".join(REASON_CLASSES)))
            continue
        digest = (entry.get("hash") or "").strip()
        if not digest:
            bad.append("%s — no hash" % label)
            continue
        out[digest] = entry
    if bad:
        raise SystemExit(
            "allowlist entries rejected:\n  - %s\n"
            "A suppression is only reviewable if it says why. `triage.py "
            "allowlist` prints correctly-hashed entries to start from."
            % "\n  - ".join(sorted(bad)))
    return out


# ───────────────────────────── classification ─────────────────────────────


def parse_artifact(path):
    """
    Parse one report, preserving tool attribution.

    ci/gate.py parses a SARIF report by taking the tool name from the FILENAME,
    which is right for the per-tool artifacts (a directory uploaded as
    `static-analysis-findings-clang` is all clang) and wrong for any SARIF that
    declares its own driver. Two cases matter:

    1. The gate's aggregate `findings.sarif` names its driver `deaf-ci-gate` and
       prefixes every ruleId with the originating tool ("cppcheck.nullPointer"),
       so both the tool and the bare rule id have to be decoded back out.
    2. Any OTHER SARIF names the real tool in its driver ("cppcheck"). Falling
       through to gate.parse_report would attribute it to the filename stem, so
       a report saved as `f.sarif` yields tool="f" — a hash that matches no
       baseline entry and no allowlist entry.

    That is not cosmetic. The content hash covers `tool`, so a mislabelled tool
    yields a hash that matches neither the baseline nor the allowlist — and a
    suppression that does not match does not warn, it silently stops working.
    A justified suppression is exactly the kind of thing that fails invisibly:
    the finding reappears as "new", the reviewer is handed a card for correct
    fixed-point DSP, and nothing anywhere says the allowlist broke.

    So a declared driver always wins over the filename for SARIF, and the gate
    driver additionally has its tool-prefixed rule ids split apart.
    """
    if not path.endswith(".sarif"):
        return gate.parse_report(path)
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    if not text.lstrip().startswith("{"):
        return gate.parse_report(path)
    try:
        doc = json.loads(text)
    except ValueError:
        return gate.parse_report(path)

    driver = ""
    for run in doc.get("runs", []):
        driver = ((run.get("tool") or {}).get("driver") or {}).get("name", "")
        break
    # Hand the declared driver to gate as the tool for anything that is not the
    # gate's own aggregate. Only the aggregate needs its rule ids split.
    is_gate = driver == GATE_DRIVER
    if not is_gate:
        return gate.parse_report(path, driver or None)

    out = []
    for run in doc.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "") or ""
            tool, sep, bare = rule_id.partition(".")
            if not sep:
                # Not tool-prefixed: fall back rather than invent an empty tool.
                tool, bare = GATE_DRIVER, rule_id
            locs = result.get("locations") or []
            phys = ((locs[0] or {}).get("physicalLocation") or {}) if locs else {}
            out.append(gate.Finding.make(
                tool, gate._sarif_level(result),
                phys.get("artifactLocation", {}).get("uri", ""),
                phys.get("region", {}).get("startLine", 0),
                (result.get("message") or {}).get("text", ""), bare))
    return out


def dedup_merging(findings):
    """
    Collapse repeats of the same content hash, MERGING their distinct locations.

    gate.dedup() keeps the first occurrence and drops the rest. That is right
    for a pass/fail gate — one duplicate must not count twice — but wrong for
    triage: three identical integer-conversion warnings in one file are three
    things to look at, and collapsing them to one location hides two. The
    content hash deliberately excludes line number (so an unrelated edit
    upstream does not resurrect a finding), which is exactly why the locations
    have to be carried alongside rather than discarded.

    Locations are deduped TOO, because the same finding legitimately arrives
    twice: the gate's aggregate findings.json holds every finding AND the raw
    per-tool reports it was built from sit in the same directory, so pointing
    triage at `analysis/gate` collects each finding from both paths. Merging
    those blindly reported every location twice — `biquad.c:24, biquad.c:24` —
    which reads as two defects where there is one.
    """
    by_hash = {}
    order = []
    for f in findings:
        digest = f["hash"]
        seen = by_hash.get(digest)
        if seen is None:
            f["occurrences"] = [{"file": f["file"], "line": f["line"]}]
            by_hash[digest] = f
            order.append(digest)
            continue
        loc = {"file": f["file"], "line": f["line"]}
        if loc not in seen["occurrences"]:
            seen["occurrences"].append(loc)
    return [by_hash[h] for h in order]


def occurrence_count(finding):
    """How many places this finding was reported."""
    return max(1, len(finding.get("occurrences") or []))


def report_files(report_paths, exclude=None):
    """
    Report paths that are in scope.

    Excludes `exclude` (the caller's own --out-dir) and every file the parser
    would not recognise. Both are needed, and neither is sufficient alone:

    - Name lists cannot work. The per-group card bodies are named from finding
      data (`cppcheck-integer-conversion-new.md`), so the next one we forget is
      an "unrecognised report format" abort — which is exactly how
      `triage.py allowlist`, the command every generated card body tells the
      worker to run, died on triage's own output.
    - Whole-directory exclusion cannot work either. A gate output directory
      legitimately holds findings.json and findings.sarif, which ARE reports,
      next to summary.md, which is not. Dropping the directory throws away the
      aggregate the gate published; keeping it aborts on the markdown.

    So the question is asked of the content instead, which is what
    gate.parse_report itself dispatches on. A helper that dies on a stray file
    is a helper people stop running; a helper that silently drops a real report
    is worse, so skipped paths are counted and reported on stderr.
    """
    excluded = [os.path.abspath(exclude)] if exclude else []
    kept, skipped = [], []
    for path in gate.expand_reports(report_paths):
        full = os.path.abspath(path)
        if any(full == e or full.startswith(e + os.sep) for e in excluded):
            continue
        if is_report_like(full):
            kept.append(path)
        else:
            skipped.append(path)
    if skipped:
        # Visible, not silent: an unrecognised file might be a report in a
        # format this parser does not yet handle, and that must not read as
        # "nothing to see".
        print("triage: skipped %d non-report file(s): %s"
              % (len(skipped), ", ".join(sorted(skipped)[:5])
                 + (" …" if len(skipped) > 5 else "")),
              file=sys.stderr)
    return kept


def is_report_like(path):
    """
    True when gate.parse_report would recognise this file's CONTENT.

    Mirrors that function's dispatch order without parsing: .plist for clang,
    XML for cppcheck, JSON for the gate's aggregate and for SARIF. Markdown
    card bodies and the emitted shell text start with neither, so they are
    skipped without a filename ever having to be named here.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return False
    if os.path.basename(path).endswith(".plist"):
        return True
    stripped = text.lstrip()
    return (stripped.startswith("<?xml") or stripped.startswith("<results")
            or stripped.startswith("{") or stripped.startswith("["))


def collect_artifact(report_paths, exclude=None):
    """
    Every finding in every report, deduped by content hash.

    `exclude` drops a generated-output directory.  Needed because the gate
    writes findings.json, findings.sarif and summary.md inside the tree being
    scanned: summary.md is markdown rather than a report, and re-reading it
    raises "unrecognised report format" and aborts triage.  Without this,
    `triage --reports analysis` dies on the gate's own output — and because
    `make analyze` puts that output under analysis/, it dies on the second run
    of the normal local workflow, not just in CI.
    """
    findings = []
    for path in report_files(report_paths, exclude):
        findings.extend(parse_artifact(path))
    return dedup_merging(findings)


def classify(findings, baseline, allowlist):
    """
    Split findings three ways.  Order matters: the allowlist is consulted
    first, so a justified suppression wins over "this is new".  Otherwise a
    DSP-intentional finding that a refactor happened to re-word would resurface
    as new and generate a card for code that is correct by construction.
    """
    suppressed, new, preexisting = [], [], []
    for f in findings:
        if f["hash"] in allowlist:
            suppressed.append(f)
        elif f["hash"] in baseline:
            preexisting.append(f)
        else:
            new.append(f)
    return suppressed, new, preexisting


def group_root_cause(findings):
    """
    Collapse findings into one group per (tool, rule_id).

    (tool, rule_id) is the analyzer's own identity for a defect class, which
    makes it the most defensible available proxy for "root cause".  Grouping by
    raw finding instead would put twenty identical integer-conversion warnings
    on twenty cards and bury the single reviewer who should read them; the card
    body lists every location so a reviewer can split a class that turns out to
    span genuinely unrelated causes.
    """
    buckets = {}
    for f in findings:
        buckets.setdefault((f["tool"], f["rule_id"] or "(unclassified)"),
                           []).append(f)

    out = []
    for (tool, rule), members in sorted(buckets.items()):
        members.sort(key=lambda x: (x["file"], x["line"]))
        # Most severe member decides the group severity: SEVERITY_RANK is
        # ordered error < warning < note.
        severity = min((m["severity"] for m in members),
                       key=lambda s: gate.SEVERITY_RANK.get(s, 99))
        out.append(Group(tool=tool, rule_id=rule, severity=severity,
                         findings=members))
    return out


def route(groups, action, card=None, origin="new"):
    """
    Attach a routing decision to each group.

    `action` is "update" (fold into `card`) or "new-card" (own card).  Taking
    the decision from the caller rather than inferring it from whether a card
    was supplied is what keeps the two paths independent: a pre-existing group
    must never inherit "update" just because a card happens to be in flight.

    `origin` is WHY the group needs action — "new" (introduced by the change
    under review) or "pre-existing" (in the baseline).  It is carried
    separately from `action` because the two are independent: with no card in
    flight a NEW finding also becomes "new-card", so `action` alone cannot say
    whether a card is warranted by the finding being new or merely by there
    being no card to fold it into.  Inferring provenance back from `action`
    labels every new finding "pre-existing" the moment `--new-card` is passed,
    which is exactly what CI does — the report then tells a reviewer that the
    defect they just introduced is inherited and unrelated.

    Returns a list of action dicts so the renderer, the report and the emitted
    shell all read from one decision rather than re-deriving it.
    """
    return [{
        "action": action,
        "origin": origin,
        "card": card if action == "update" else None,
        "group": g,
        "priority": SEVERITY_PRIORITY.get(g["severity"], 30),
    } for g in groups]


# ─────────────────────────────── rendering ────────────────────────────────


def _bullet_block(group):
    lines = []
    for f in group["findings"]:
        lines.append("- `%s:%d` — %s"
                     % (f["file"] or "?", f["line"] or 0, f["message"]))
    return "\n".join(lines)


def _location_block(group):
    """
    The Locations list, which has to survive a finding with no file.

    SARIF permits a result with no `locations` at all (gitleaks emits exactly
    those), so "`<unknown>`" has to be a real possibility here rather than
    something Group.files quietly filters away and the renderer then indexes
    into.
    """
    locs = group.locations
    if not locs:
        return "- no location reported by the analyzer"
    return "\n".join("- `%s`" % loc for loc in locs)


def card_body(action):
    """Markdown opening post for a new finding card."""
    g = action["group"]
    # Provenance comes from `origin`, not from `action`: a NEW finding gets a
    # card here whenever no card is in flight, and calling that "pre-existing
    # and unrelated" would tell the next worker to ignore their own defect.
    kind = ("introduced by the change under review"
            if action["origin"] == "new"
            else "pre-existing and unrelated to the change under review")
    return """\
## {display} static-analysis finding: {tool} / {rule}

**Severity:** {severity}
**Tool:** {tool}
**Rule id:** {rule}
**Findings in this group:** {count}

This finding is {kind}. Per the decision rule in `ci/TRIAGE.md`, it gets its
own card rather than being folded into the card currently in flight.

### Locations

{locations}

{messages}

### Before you start

{rationale_before}

Do not add the finding to `.ci/analysis-baseline.json` to make CI green. The
baseline exists for findings reviewed and accepted; a real defect gets fixed.

### Verification

    make analyze
""".format(display=DISPLAY, tool=g["tool"], rule=g["rule_id"] or "(unclassified)",
           severity=g["severity"], count=g.count,
           kind=kind,
           rationale_before=RATIONALE_BEFORE_YOU_START,
           locations=_location_block(g),
           messages=_bullet_block(g))


def update_comment(action):
    """Comment body for the in-flight card. Kept short enough to read inline."""
    g = action["group"]
    return """\
**New static-analysis finding — {tool} / {rule} ({severity})**

Introduced by this change, so per `ci/TRIAGE.md` it folds into this card rather
than becoming a new one.

{locations}

{messages}

{rationale_footer}
""".format(tool=g["tool"], rule=g["rule_id"] or "(unclassified)",
           severity=g["severity"],
           rationale_footer=RATIONALE_COMMENT_FOOTER,
           locations="\n".join("- `%s`" % loc for loc in g.locations),
           messages=_bullet_block(g))


def render_report(ctx):
    suppressed, n, p = ctx["suppressed"], ctx["new"], ctx["preexisting"]
    updates = [a for a in ctx["actions"] if a["action"] == "update"]
    # Buckets are chosen by `origin`, NOT by `action`.  A new finding that got
    # its own card only because no card was in flight is still a NEW finding,
    # and telling the reviewer it is "inherited, unrelated to the change" is
    # the one misreading that makes them ignore the defect they just wrote.
    new_cards = [a for a in ctx["actions"]
                 if a["action"] == "new-card" and a["origin"] == "new"]
    old_cards = [a for a in ctx["actions"]
                 if a["action"] == "new-card" and a["origin"] == "pre-existing"]
    actionable = len(updates) + len(new_cards) + len(old_cards)

    verdict = "ACTION REQUIRED" if actionable else "nothing actionable"
    lines = [
        "## %s findings triage — %s" % (DISPLAY, verdict),
        "",
        "Rule (full text in `ci/TRIAGE.md`): allowlisted → dropped; "
        "**new → update the card in flight**; **pre-existing → new card**.",
        "Cards go to the **`%s`** board." % BOARD,
        "",
        "| bucket | count |",
        "|---|---|",
        "| suppressed (allowlisted, justified) | %d |" % len(suppressed),
        "| new (introduced by this change) | %d |" % len(n),
        "| pre-existing (in baseline) | %d |" % len(p),
        "| actionable groups | **%d** |" % actionable,
        "",
    ]

    if suppressed:
        lines += ["### Suppressed — allowlisted, no card", ""]
        for f in sorted(suppressed, key=gate.sort_key):
            entry = ctx["allowlist"].get(f["hash"], {})
            lines.append("- `%s` %s/%s — %s  \n  _suppressed: %s (%s)_"
                         % (f.location, f["tool"], f["rule_id"] or "?",
                            f["message"][:120],
                            entry.get("justification", ""),
                            entry.get("reason_class", "")))
        lines.append("")

    if updates:
        target = ctx["current_card"] or "(none — passed as --new-card)"
        lines += ["### New — update the card in flight", "",
                  "Findings introduced by this change belong on `%s`, not on a "
                  "new card: the reviewer already holds that context." % target,
                  ""]
        for i, a in enumerate(updates, 1):
            g = a["group"]
            lines.append("%d. **%s** `%s` — %d finding(s), %s"
                         % (i, g.title, g["severity"], g.count,
                            ", ".join(g.locations)))
        lines.append("")

    if new_cards:
        lines += ["### New, no card in flight — new cards", "",
                  "Introduced by this change, but no card is in flight to fold "
                  "them into, so each root cause gets its own card.", ""]
        for i, a in enumerate(new_cards, 1):
            g = a["group"]
            lines.append("%d. **%s** `%s` — %d finding(s)"
                         % (i, g.title, g["severity"], g.count))
        lines.append("")

    if old_cards:
        lines += ["### Pre-existing — new cards", "",
                  "Inherited findings, unrelated to the change under review. "
                  "One card per root cause, not per raw finding.", ""]
        for i, a in enumerate(old_cards, 1):
            g = a["group"]
            lines.append("%d. **%s** `%s` — %d finding(s)"
                         % (i, g.title, g["severity"], g.count))
        lines.append("")

    if not actionable:
        lines += ["Nothing to action. Either the analyzers are clean or every "
                  "finding is a justified suppression.", ""]

    lines += [
        "No card has been created. This helper emits shell text; applying it is "
        "a deliberate act by whoever reads this report.",
        "",
    ]
    return "\n".join(lines)


def render_commands(ctx, out_dir):
    """
    Shell invocations for a human to apply.  Never executed by this module.

    Bodies are written to files and referenced with --body-file rather than
    inlined with --body: these bodies contain newlines and lines beginning
    with `-`, which shell quoting would mangle.
    """
    lines = [
        "#!/bin/sh",
        "# %s findings triage — generated by ci/triage.py. NOT executed."
        % DISPLAY,
        "#",
        "# Review each block, then run this file, or copy the lines you agree",
        "# with. Bodies live as files so quoting cannot corrupt them.",
        "# Board: %s.  Rule: ci/TRIAGE.md" % BOARD,
        "",
        "set -eu",
        "",
    ]
    written = set()
    for action in ctx["actions"]:
        g = action["group"]
        if action["action"] == "update":
            # No card body here: an update is an inline comment, so writing
            # one would leave an orphan .md on disk that nothing references
            # and that report_files() then has to filter back out again.
            lines.append("# --- update %s: %s" % (action["card"], g.title))
            lines.append("hermes kanban --board %s comment %s %s"
                         % (BOARD, shlex.quote(action["card"]),
                            shlex.quote(update_comment(action))))
            lines.append("")
            continue

        stem = _slug(g, action["origin"])
        body_path = os.path.join(out_dir, "%s.md" % stem)
        # Belt and braces: _slug already separates origins, but two groups
        # differing only in file would still collide.  A collision here means
        # one card's body silently overwrites another's, so make it
        # impossible rather than merely unlikely.
        suffix = 2
        while body_path in written:
            body_path = os.path.join(out_dir, "%s-%d.md" % (stem, suffix))
            suffix += 1
        written.add(body_path)
        with open(body_path, "w", encoding="utf-8") as fh:
            fh.write(card_body(action))

        lines.append("# --- new card: %s" % g.title)
        lines.append("hermes kanban --board %s create %s \\"
                     % (BOARD, shlex.quote(g.title)))
        lines.append("  --body-file %s --assignee engineer --priority %d"
                     % (shlex.quote(body_path), action["priority"]))
        lines.append("")
    return "\n".join(lines)


def _slug(g, origin="new"):
    """
    Filename stem for a group's card body.

    `origin` is part of the stem, and it has to be.  Keyed on (tool, rule_id)
    alone, a `new` group and a `pre-existing` group from the same analyzer
    resolve to the SAME body path — and since new groups are routed before
    pre-existing ones, the pre-existing body always won the write.  The card
    for the defect the reviewer had just introduced then shipped a body
    reading "This finding is pre-existing and unrelated to the change under
    review": exactly the mislabelling the origin field exists to prevent,
    reintroduced through the file-writing layer instead of through route().

    Provenance was correct in triage.json and wrong in the artefact the worker
    actually reads, so the bug hid behind a test that only inspected the JSON.
    """
    raw = "%s-%s-%s" % (g["tool"], g["rule_id"] or "unclassified", origin)
    keep = [c if (c.isalnum() or c in "-_") else "-" for c in raw.lower()]
    return "-".join(part for part in "".join(keep).split("-") if part)


# ──────────────────────────────── commands ────────────────────────────────


def _build_context(args):
    findings = collect_artifact(args.reports, exclude=args.out_dir)
    baseline = gate.load_baseline(args.baseline)
    allowlist = load_allowlist(args.allowlist)

    current_card = args.current_card
    if args.new_card:
        current_card = None

    suppressed, new, preexisting = classify(findings, baseline, allowlist)

    # New findings fold into the card in flight; with no card in flight they
    # need one of their own.  Pre-existing findings always need their own card,
    # whatever the worker happens to be holding.
    new_action = "new-card" if current_card is None else "update"
    actions = route(group_root_cause(new), new_action, current_card, origin="new")
    actions += route(group_root_cause(preexisting), "new-card", origin="pre-existing")

    return {
        "findings": findings,
        "baseline": baseline,
        "allowlist": allowlist,
        "suppressed": suppressed,
        "new": new,
        "preexisting": preexisting,
        "actions": actions,
        "current_card": current_card,
    }


def cmd_triage(args):
    # Check for readable input BEFORE parsing. A helper that reports "nothing
    # to action" having read nothing is the exact failure mode this pipeline
    # exists to prevent — the gate already learned this the hard way, when a
    # crashed scanner left no report and the gate called it clean.
    if not report_files(args.reports, args.out_dir):
        print("triage: no analyzer reports found under %s — refusing to report "
              "on empty input" % ", ".join(args.reports), file=sys.stderr)
        return EXIT_ERROR
    try:
        ctx = _build_context(args)
    except SystemExit as exc:
        print("triage: %s" % exc, file=sys.stderr)
        return EXIT_ERROR
    except (ValueError, OSError) as exc:
        # A report that starts out looking valid and then fails to parse is a
        # broken INPUT, not a finding. Uncaught, it exited 1 — the same code as
        # "there are actionable findings", so CI read a truncated artifact
        # (an interrupted download, a half-written plist) as a real triage
        # result. Distinct codes, or the distinction is not enforced.
        print("triage: cannot read reports: %s" % exc, file=sys.stderr)
        return EXIT_ERROR

    if args.out_dir:
        os.makedirs(args.out_dir, exist_ok=True)
        with open(os.path.join(args.out_dir, "triage.json"), "w",
                  encoding="utf-8") as fh:
            json.dump({
                "board": BOARD,
                "total": len(ctx["findings"]),
                "suppressed": len(ctx["suppressed"]),
                "new": len(ctx["new"]),
                "pre_existing": len(ctx["preexisting"]),
                "findings": ctx["findings"],
                "actions": [{
                    "action": a["action"],
                    "origin": a["origin"],
                    "card": a["card"],
                    "priority": a["priority"],
                    "title": a["group"].title,
                    "tool": a["group"]["tool"],
                    "rule_id": a["group"]["rule_id"],
                    "severity": a["group"]["severity"],
                    "count": a["group"].count,
                    "locations": a["group"].locations,
                } for a in ctx["actions"]],
            }, fh, indent=2)
            fh.write("\n")
        with open(os.path.join(args.out_dir, "triage-report.md"), "w",
                  encoding="utf-8") as fh:
            fh.write(render_report(ctx))
        with open(os.path.join(args.out_dir, "apply-triage.sh"), "w",
                  encoding="utf-8") as fh:
            fh.write(render_commands(ctx, args.out_dir))

    sys.stdout.write(render_report(ctx))

    actionable = [a for a in ctx["actions"]]
    if actionable:
        print("::error title=findings triage::%d actionable group(s): "
              "%d to fold into %s, %d needing their own card."
              % (len(actionable),
                 sum(1 for a in actionable if a["action"] == "update"),
                 ctx["current_card"] or "(none)",
                 sum(1 for a in actionable if a["action"] == "new-card")),
              file=sys.stderr)
        return EXIT_ACTIONABLE
    return EXIT_CLEAN


def cmd_allowlist(args):
    """
    Print ready-to-paste allowlist entries for findings a reviewer has
    concluded are intentional.

    This exists so nobody hand-computes a sha256 to suppress a finding: the
    hash is derived from tool + rule_id + file + message, so a typo produces an
    entry that silently matches nothing.  The `justification` and
    `reason_class` fields are left as explicit TODO markers, and load_allowlist
    rejects an entry that still carries one — a suppression has to be argued
    for, not just typed.

    Generated output is excluded here for the same reason it is in cmd_triage:
    this command is documented as the follow-up to a triage run, so pointing
    it at the same tree means it must survive that run's output — including
    the per-group card bodies, whose names are data-derived and therefore
    cannot be filtered by basename.
    """
    findings = collect_artifact(args.reports, exclude=args.out_dir)
    baseline = gate.load_baseline(args.baseline)
    _, new, _ = classify(findings, baseline, {})

    out = []
    for f in sorted(new, key=gate.sort_key):
        out.append({
            "hash": f["hash"],
            "tool": f["tool"],
            "rule_id": f["rule_id"],
            "file": f["file"],
            "line": f["line"],
            "message": f["message"],
            "reason_class": "TODO-pick-one-of-%s" % ", ".join(REASON_CLASSES),
            "justification": "TODO: why is this correct as written?",
        })
    print(json.dumps({"suppressions": out}, indent=2))
    if not out:
        print("# no new findings to suppress", file=sys.stderr)
    return EXIT_CLEAN


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    sub = ap.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("triage", help="classify findings and plan cards")
    t.add_argument("--reports", nargs="+", required=True,
                   help="findings artifact(s): SARIF, gate JSON, or raw "
                        "per-tool reports")
    t.add_argument("--baseline", default=DEFAULT_BASELINE)
    t.add_argument("--allowlist", default=DEFAULT_ALLOWLIST)
    t.add_argument("--out-dir", default=DEFAULT_OUT_DIR,
                   help="where the report, JSON and emitted shell text go "
                        "(default: %s). Kept outside analysis/ on purpose — "
                        "the gate scans analysis/ recursively, so output "
                        "written there breaks the next gate run." % DEFAULT_OUT_DIR)
    t.add_argument("--current-card",
                   help="card the worker is currently working on; new "
                        "findings are folded into it")
    t.add_argument("--new-card", action="store_true",
                   help="no card in flight: route new findings to their own "
                        "cards instead")
    t.set_defaults(func=cmd_triage)

    a = sub.add_parser(
        "allowlist", epilog="Emits TODO placeholders for justification and "
        "reason_class, and refuses to load an entry that still carries one "
        "(exit 2). That is deliberate: a suppression has to be argued for, not "
        "just typed, so the generator's output is a starting point rather "
        "than something you can paste straight in.",
        help="print paste-ready suppressions")
    a.add_argument("--reports", nargs="+", required=True)
    a.add_argument("--baseline", default=DEFAULT_BASELINE)
    a.add_argument("--out-dir", default=DEFAULT_OUT_DIR,
                   help="generated-output directory to exclude from the scan, "
                        "defaulting to the same one `triage` writes to")
    a.set_defaults(func=cmd_allowlist)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())