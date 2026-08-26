#!/usr/bin/env python3
"""Validate elfguard's machine-readable output.

This lives in a file rather than inline in the CI workflow for two reasons.
The practical one: a multi-line `python3 -c '...'` inside a YAML block scalar
breaks the block's indentation rules, and the failure mode is a workflow that
will not parse at all.

The better one: validation logic embedded in CI can only run in CI. Here, the
same assertions run under `make test`, so a contributor finds out on their own
machine instead of on a red pipeline.

Usage:
    validate_output.py audit  <file.json>
    validate_output.py diff   <file.json>
    validate_output.py trend  <file.json>
    validate_output.py sarif  <file.sarif>
"""
import json
import sys


def fail(msg):
    print(f"validate: {msg}", file=sys.stderr)
    sys.exit(1)


def load(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        fail(f"{path} is not valid JSON: {exc}")
    except OSError as exc:
        fail(f"cannot read {path}: {exc}")


def check_audit(doc):
    """The machine format must never carry less than the terminal one.

    A CI job consuming JSON should be able to gate on anything a human could
    read off the table; if these keys drift apart, the JSON consumer silently
    loses the ability to see a regression that is plainly visible on screen.
    """
    results = doc.get("results")
    if not results:
        fail("no results array")
    rep = results[0]

    for key in ("score", "grade", "debt", "unproven", "findings"):
        if key in rep:
            continue
        fail(f"report is missing '{key}'")

    findings = rep["findings"]
    if not findings:
        fail("report has no findings")

    for finding in findings:
        for key in ("id", "verdict", "confidence", "evidence", "reason"):
            if key not in finding:
                fail(f"finding '{finding.get('id', '?')}' is missing '{key}'")
        if finding["verdict"] not in ("pass", "weak", "fail", "unknown", "n/a"):
            fail(f"unexpected verdict {finding['verdict']!r}")

    # UNKNOWN is not a failure. If this inverts, every stripped binary starts
    # looking insecure and the diff fills with regressions nobody caused.
    unknowns = [f for f in findings if f["verdict"] == "unknown"]
    if len(unknowns) != rep["unproven"]:
        fail(f"unproven={rep['unproven']} but {len(unknowns)} unknown findings")
    for finding in unknowns:
        if finding["confidence"].upper() != "LOW":
            fail(f"unknown finding '{finding['id']}' is not LOW confidence")

    print(f"audit ok — {len(findings)} findings, "
          f"score {rep['score']}, debt {rep['debt']}")


def check_surface(doc):
    rep = doc["results"][0]
    if "surface" not in rep:
        fail("--surface was requested but no surface object was emitted")
    surface = rep["surface"]
    for key in ("exported_functions", "imported_functions", "plt_entries",
                "indirect_calls", "branch_counts_exact"):
        if key not in surface:
            fail(f"surface is missing '{key}'")
    for key, value in surface.items():
        if isinstance(value, int) and value < 0:
            fail(f"surface.{key} is negative ({value})")
    print(f"surface ok — {surface['plt_entries']} PLT entries, "
          f"exact branch counts: {surface['branch_counts_exact']}")


def check_diff(doc):
    if doc.get("mode") != "diff":
        fail("not a diff document")
    if doc.get("posture") not in ("IMPROVED", "STABLE", "DEGRADED"):
        fail(f"unexpected posture {doc.get('posture')!r}")
    for key in ("regressions", "surface_increases", "confidence_losses",
                "dependency_regressions", "entries"):
        if key not in doc:
            fail(f"diff is missing '{key}'")

    # A regression count must be backed by entries that actually show one,
    # otherwise the exit code and the report disagree.
    counted = sum(
        1
        for entry in doc["entries"]
        for change in entry.get("mitigations", [])
        if change.get("regression")
    )
    if counted != doc["regressions"]:
        fail(f"regressions={doc['regressions']} but {counted} in entries")

    print(f"diff ok — posture {doc['posture']}, "
          f"{doc['regressions']} regressions, "
          f"{doc['surface_increases']} surface increases")


def check_trend(doc):
    points = doc.get("points")
    if not points:
        fail("trend has no points")
    for point in points:
        for key in ("build", "score", "debt", "grade"):
            if key not in point:
                fail(f"trend point is missing '{key}'")
    print(f"trend ok — {len(points)} builds")


def check_sarif(doc):
    if doc.get("version") != "2.1.0":
        fail(f"unexpected SARIF version {doc.get('version')!r}")
    runs = doc.get("runs")
    if not runs:
        fail("no runs")
    run = runs[0]

    # GitHub rejects an upload whose result references a rule the run does not
    # declare, so catch it here rather than in the code-scanning UI.
    declared = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    for result in run.get("results", []):
        if result["ruleId"] not in declared:
            fail(f"result references undeclared rule {result['ruleId']!r}")
        if result["level"] not in ("error", "warning", "note", "none"):
            fail(f"unexpected level {result['level']!r}")
        if not result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]:
            fail("result has an empty artifact location")

    print(f"sarif ok — {len(declared)} rules, {len(run.get('results', []))} results")


MODES = {
    "audit": check_audit,
    "surface": check_surface,
    "diff": check_diff,
    "trend": check_trend,
    "sarif": check_sarif,
}


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in MODES:
        print(f"usage: {sys.argv[0]} {{{'|'.join(MODES)}}} <file>",
              file=sys.stderr)
        return 2
    MODES[sys.argv[1]](load(sys.argv[2]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
