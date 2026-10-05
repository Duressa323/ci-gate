#!/usr/bin/env python3
"""
Regenerate the parity fixtures in tests/fixtures/.

The fixtures are two files per repository:

    <repo>.config.json   the identity the shared tool renders that repo with,
                         taken from the repo's own .ci/gate.config.json
    <repo>.json          the OUTPUT that repo's PRE-MIGRATION copies produced

The golden output must come from the original per-repo copies, never from the
shared tool.  A golden regenerated from the shared tool agrees with it by
construction, so the parity test would pass on any behaviour — including every
regression it exists to catch.  That is why this script requires the original
copies and refuses to write a golden it cannot source independently.

    # once, from a checkout holding the original copies:
    python3 tools/gen_fixtures.py --reference-dir /path/to/pristine/copies

    # refresh only the config side, from live repository checkouts:
    python3 tools/gen_fixtures.py --configs /path/to/deaf /path/to/neural ...

Writing a golden is never a mechanical step.  Run the parity test afterwards:
any field that changed must be diffed by hand and recorded in
tests/test_parity.py ALLOWED_DEVIATIONS with its reason, or the test will fail
on the unreviewed drift.  That is the intended order — the fixtures record
what the tool does now, the allowlist records what a human agreed to.
"""

import argparse
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.dirname(HERE)
FIXTURES = os.path.join(TOOL, "tests", "fixtures")


def _load_parity_module():
    """Import tests/test_parity.py so the probe lives in exactly one place.

    The golden is only trustworthy if it is produced by the same probe the test
    compares with; a second copy of the probe here would be free to drift from
    it and quietly render different fields.
    """
    path = os.path.join(TOOL, "tests", "test_parity.py")
    spec = importlib.util.spec_from_file_location("_parity_under_test", path)
    if spec is None or spec.loader is None:
        raise SystemExit("could not load %s to reuse its probe" % path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_json(path, doc):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False, sort_keys=True)
        fh.write("\n")
    return path


def regenerate_configs(repo_paths):
    """Copy each live repo's config in, minus its local _comment block."""
    written = []
    for repo_path in repo_paths:
        repo = os.path.basename(os.path.abspath(repo_path))
        src = os.path.join(repo_path, ".ci", "gate.config.json")
        if not os.path.isfile(src):
            raise SystemExit("no config at %s" % src)
        with open(src, encoding="utf-8") as fh:
            doc = json.load(fh)
        # _comment is repository-local documentation explaining what was
        # corrected; it is not tool input and does not belong in the fixture.
        doc.pop("_comment", None)
        out = write_json(os.path.join(FIXTURES, repo + ".config.json"), doc)
        written.append(out)
        print("config  %s" % out)
    return written


def regenerate_goldens(reference_dir):
    """Re-render each repo's PRE-MIGRATION output into a golden."""
    parity = _load_parity_module()
    written = []
    for repo in parity.REPOS:
        ref = os.path.join(reference_dir, repo)
        if not os.path.isdir(ref):
            raise SystemExit(
                "no reference copies for %s under %s\n"
                "A golden must be produced by the repository's ORIGINAL "
                "per-repo copies. Refusing to write one from the shared tool: "
                "it would agree with the tool by construction and the parity "
                "test would then pass on any behaviour."
                % (repo, reference_dir))
        golden = parity.run_probe(os.path.join(ref, "ci"))
        out = write_json(os.path.join(FIXTURES, repo + ".json"), golden)
        written.append(out)
        print("golden  %s  (%d fields)" % (out, len(golden)))
    return written


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__.split("\n")[1],
        epilog="Regenerating goldens is a reviewed change: run "
               "tests/test_parity.py afterwards and record every changed "
               "field in ALLOWED_DEVIATIONS.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--reference-dir",
                    help="directory holding each repo's pre-migration copies, "
                         "one subdirectory per repo; required to write goldens")
    ap.add_argument("--configs", nargs="+", metavar="REPO",
                    help="repository checkouts to copy configs from")
    args = ap.parse_args(argv)

    if not args.reference_dir and not args.configs:
        ap.error("nothing to do: pass --reference-dir and/or --configs")

    if args.configs:
        regenerate_configs(args.configs)
    if args.reference_dir:
        regenerate_goldens(os.path.abspath(args.reference_dir))

    print("\nNow run:  python3 tests/test_parity.py")
    print("Any changed field must be reviewed and recorded in "
          "ALLOWED_DEVIATIONS with its reason.")
    return 0


if __name__ == "__main__":
    sys.exit(main())