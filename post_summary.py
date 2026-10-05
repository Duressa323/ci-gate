#!/usr/bin/env python3
"""
Post (or update) the analysis-gate summary as a sticky PR comment.

Uses the REST API directly via urllib so the workflow step stays free of
`gh`/jq quoting, which is where YAML-plus-shell-embedded-in-YAML goes wrong.
Standard library only.

The comment carries an HTML marker so re-running the workflow updates the
existing comment instead of stacking one report per push.
"""

import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gate  # noqa: E402  (shares the repo identity config)

# Identifies this repo's own sticky comment.  Config-driven so the marker
# cannot drift from the one gate.py/triage.py reason about: two repos sharing
# a marker would have one repo's summary overwrite the other's.
MARKER = gate.CONFIG["comment_marker"]
API = "https://api.github.com"


def _request(method, url, token, payload=None):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", "Bearer %s" % token)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req) as resp:
        body = resp.read()
    return json.loads(body) if body else {}


def find_existing(repo, number, token):
    """Newest comment carrying the marker, or None."""
    url = "%s/repos/%s/issues/%d/comments?per_page=100" % (API, repo, number)
    try:
        comments = _request("GET", url, token)
    except urllib.error.HTTPError as exc:
        print("could not list comments: %s" % exc, file=sys.stderr)
        return None
    for comment in comments:
        if MARKER in (comment.get("body") or ""):
            return comment["id"]
    return None


def post(repo, number, token, summary_path):
    with open(summary_path, "r", encoding="utf-8") as fh:
        body = "%s\n%s" % (MARKER, fh.read().rstrip())
    payload = {"body": body}
    existing = find_existing(repo, number, token)
    if existing:
        _request("PATCH", "%s/repos/%s/issues/comments/%d" % (API, repo, existing),
                 token, payload)
        print("updated comment %d" % existing)
    else:
        created = _request(
            "POST", "%s/repos/%s/issues/%d/comments" % (API, repo, number),
            token, payload)
        print("created comment %s" % created.get("html_url", "?"))


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 3:
        print("usage: post_summary.py <repo> <pr-number> <summary.md>",
              file=sys.stderr)
        return 2
    repo, number, summary_path = argv[0], int(argv[1]), argv[2]
    token = os.environ.get("GITHUB_TOKEN") or ""
    if not token:
        print("GITHUB_TOKEN is not set", file=sys.stderr)
        return 2
    post(repo, number, token, summary_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())