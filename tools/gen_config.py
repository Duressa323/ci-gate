#!/usr/bin/env python3
"""
Generate `.ci/gate.config.json` for a repository from its PRISTINE copies.

The values are extracted from the per-repo gate.py / triage.py by actually
importing them and calling their own functions, not by pattern-matching the
source.  That matters: the point of this script is to guarantee the config
reproduces today's bytes exactly, and a regex that mis-captures a multi-line
string literal would quietly change a PR comment in all four repositories.

Run from the checkout of the shared tool:

    python3 tools/gen_config.py /path/to/repo

`/path/to/repo` must be a checkout whose ci/gate.py, ci/triage.py and
ci/post_summary.py are the ORIGINAL per-repo copies (i.e. before they are
replaced by the submodule).  In the normal migration that is `git show
HEAD:ci/gate.py`.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile

PROBE = r'''
import json, sys
sys.path.insert(0, sys.argv[1])
import gate, triage

f = gate.Finding.make("cppcheck", "error", "x.c", 7, "null deref", "nullPointer")
group = triage.Group({
    "tool": "cppcheck", "rule_id": "nullPointer", "severity": "error",
    "findings": [dict(f, occurrences=[{"file": "x.c", "line": 7}])],
})
action = {"group": group, "action": "new-card", "origin": "new"}
empty = gate.summary_markdown([], [], [], {}, False)
print(json.dumps({
    "display_name": empty.split("\n")[0][3:].split(" static analysis")[0],
    "board": triage.BOARD,
    "sarif_driver": gate.to_sarif([f], None)["runs"][0]["tool"]["driver"]["name"],
    "information_uri":
        gate.to_sarif([f], None)["runs"][0]["tool"]["driver"]["informationUri"],
    "comment_marker": __import__("post_summary").MARKER,
    # summary_markdown ends with ["<footer>", ""] joined by newlines, so the
    # last element is always "".  Slicing [-3:-1] picks up the blank line
    # before the footer as well; strip() removes exactly that separator and
    # nothing else, leaving the footer's own internal spacing untouched.
    "summary_footer": "\n".join(empty.split("\n")[-3:-1]).strip(),
    "rationale_before_you_start": re.search(
        r"### Before you start\n\n(.*?)\n\nDo not add the finding",
        triage.card_body(action), re.S).group(1),
    # The old literal ended "...changing the code.\n" — the trailing newline
    # came from the closing `"""` on its own line, not from the prose.  The
    # shared template supplies that newline itself, so the stored value must
    # NOT include it or every comment gains a blank line.  rstrip() removes
    # only trailing whitespace, leaving internal line breaks intact.
    "rationale_comment_footer": re.search(
        r"^Reproduce with `make analyze`\..*\Z",
        triage.update_comment(action), re.S | re.M).group(0).rstrip(),
}, sort_keys=True))
'''


def extract(ci_dir):
    """Return the identity dict a pristine per-repo copy currently produces."""
    with tempfile.TemporaryDirectory() as tmp:
        probe = os.path.join(tmp, "probe.py")
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write("import re\n" + PROBE)
        out = subprocess.run([sys.executable, probe, ci_dir],
                             capture_output=True, text=True, cwd=tmp)
    if out.returncode != 0:
        raise SystemExit("could not read identity from %s:\n%s"
                         % (ci_dir, out.stderr.strip()))
    return json.loads(out.stdout)


HEADER_COMMENT = [
    "Repo identity for the shared ci-gate toolchain (gate.py / triage.py /",
    "post_summary.py). Generated from this repository's own pre-migration",
    "copies by tools/gen_config.py, so every value below reproduces the bytes",
    "those copies produced. Edit freely: the parity test asserts the rendered",
    "output still matches, so a change here is a visible, reviewed change.",
    "rationale_* keys are the per-repo domain rationale that must not be",
    "flattened into shared code.",
]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("repo", help="path to the repository checkout")
    ap.add_argument("--out", help="where to write the config "
                                  "(default: <repo>/.ci/gate.config.json)")
    args = ap.parse_args(argv)

    ci_dir = os.path.abspath(os.path.join(args.repo, "ci"))
    identity = extract(ci_dir)
    # One dict, one dump: writing the comment header separately is how the
    # previous version produced a file with two objects and an unbalanced
    # brace, i.e. a config gate.py could not even parse.
    doc = {"_comment": HEADER_COMMENT}
    doc.update(identity)
    out = args.out or os.path.join(args.repo, ".ci", "gate.config.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False, sort_keys=True)
        fh.write("\n")
    print("wrote %s" % out)
    for key in sorted(identity):
        print("  %-28s %s" % (key, str(identity[key])[:60]))
    return 0


if __name__ == "__main__":
    sys.exit(main())