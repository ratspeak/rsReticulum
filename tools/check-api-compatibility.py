#!/usr/bin/env python3
"""Reject unapproved removals from the retained public-API compatibility floor."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LEDGER_PATH = ROOT / "api" / "stability.json"


def fail(message: str) -> None:
    print(f"api compatibility: {message}", file=sys.stderr)
    raise SystemExit(1)


def git_show(commit: str, path: str) -> str:
    result = subprocess.run(
        ["git", "show", f"{commit}:{path}"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="")
        fail(f"cannot read compatibility floor {commit}:{path}")
    return result.stdout


def load_floor_ledger(commit: str) -> dict[str, object]:
    for path in ("api/stability.json", "api-stability.json"):
        result = subprocess.run(
            ["git", "show", f"{commit}:{path}"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return json.loads(result.stdout)
    fail(f"cannot read API ledger at compatibility floor {commit}")


def approved_removals(ledger: dict[str, object], version: str) -> dict[str, set[str]]:
    """A breaking release allows exact reviewed lines, never a blanket waiver."""
    record = ledger.get("approvedBreakingChanges")
    if record is None:
        return {}
    if not isinstance(record, dict) or set(record) != {"releaseLine", "migrationGuide", "removed"}:
        fail("approved break needs releaseLine, migrationGuide and exact removed lines")
    release_line = record["releaseLine"]
    if not isinstance(release_line, str) or not re.fullmatch(r"\d+\.\d+", release_line):
        fail("approved break release line is invalid")
    if version.split(".")[:2] != release_line.split("."):
        fail("approved break does not match the current workspace release line")
    guide = record["migrationGuide"]
    if not isinstance(guide, str) or not guide.startswith("api/migrations/"):
        fail("approved break must link a public API migration guide")
    guide_path = (ROOT / guide).resolve()
    if not guide_path.is_relative_to(ROOT / "api/migrations") or not guide_path.is_file():
        fail("approved break migration guide is missing or outside its directory")
    removed = record["removed"]
    packages = {package["name"] for package in ledger["packages"]}
    if not isinstance(removed, dict) or not removed or not set(removed).issubset(packages):
        fail("approved removals must name existing packages")
    result = {}
    for package, lines in removed.items():
        if (not isinstance(lines, list) or not lines
                or not all(isinstance(line, str) and line.strip() for line in lines)
                or len(set(lines)) != len(lines)):
            fail("approved removals must be unique nonempty exact API lines")
        result[package] = set(lines)
    return result


def validate_removed(package: str, removed: set[str], approved: dict[str, set[str]]) -> None:
    allowed = approved.get(package, set())
    if removed != allowed:
        for line in sorted(removed - allowed):
            print(f"unapproved removal: {line}", file=sys.stderr)
        for line in sorted(allowed - removed):
            print(f"unused removal approval: {line}", file=sys.stderr)
        fail(f"{package} removals differ from the exact approved migration")


def main() -> None:
    metadata = subprocess.run(
        [sys.executable, "tools/check-api-baseline.py", "--metadata-only"], cwd=ROOT
    )
    if metadata.returncode != 0:
        fail("snapshot metadata or reviewed change record is invalid")
    ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
    metadata_result = subprocess.run(
        ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if metadata_result.returncode:
        fail("cannot resolve workspace release version")
    versions = {package["version"] for package in json.loads(metadata_result.stdout)["packages"]}
    if len(versions) != 1:
        fail("workspace release versions disagree")
    approved = approved_removals(ledger, versions.pop())
    floor = ledger.get("compatibilityFloor", {}).get("evidenceCommit")
    if not isinstance(floor, str):
        fail("api/stability.json has no compatibility-floor commit")
    floor_ledger = load_floor_ledger(floor)
    floor_snapshots = {
        package["name"]: package["snapshot"] for package in floor_ledger["packages"]
    }
    total_added = 0
    total_removed = 0
    for package in ledger["packages"]:
        path = package["snapshot"]
        floor_path = floor_snapshots.get(package["name"])
        if not isinstance(floor_path, str):
            fail(f"{package['name']} is absent from the compatibility floor")
        before = set(git_show(floor, floor_path).splitlines())
        after = set((ROOT / path).read_text(encoding="utf-8").splitlines())
        added = sorted(after - before)
        removed = sorted(before - after)
        total_added += len(added)
        total_removed += len(removed)
        print(f"{package['name']}: +{len(added)} -{len(removed)}")
        if removed:
            for line in removed:
                print(f"- {line}", file=sys.stderr)
        validate_removed(package["name"], set(removed), approved)
    review = ledger["snapshotSource"]["review"]
    if review["publicApiDiff"] != {
        "added": total_added,
        "removed": total_removed,
    }:
        fail("snapshot review does not match the measured API diff")
    print(f"api compatibility: reviewed (+{total_added}, -{total_removed}); "
          "unapproved removals forbidden")


if __name__ == "__main__":
    main()
