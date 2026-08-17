#!/usr/bin/env python3
"""Validate rsReticulum's source-release invariants."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
EXPECTED_RUST_VERSION = "1.85"
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")


def fail(message: str) -> None:
    raise SystemExit(f"source-release contract failed: {message}")


def command(*args: str) -> str:
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def metadata() -> dict[str, object]:
    output = command(
        "cargo",
        "metadata",
        "--format-version",
        "1",
        "--locked",
        "--no-deps",
    )
    return json.loads(output)


def check_packages(document: dict[str, object]) -> str:
    packages = document["packages"]
    assert isinstance(packages, list)
    versions = {package["version"] for package in packages}
    if len(versions) != 1:
        fail(f"workspace packages do not share one version: {sorted(versions)}")

    problems = []
    for package in packages:
        name = package["name"]
        if package["publish"] != []:
            problems.append(f"{name} is not marked publish = false")
        if package["rust_version"] != EXPECTED_RUST_VERSION:
            problems.append(
                f"{name} exposes rust-version {package['rust_version']!r}, "
                f"expected {EXPECTED_RUST_VERSION!r}"
            )
    if problems:
        fail("; ".join(problems))
    return str(versions.pop())


def check_release_workflow() -> None:
    workflow = (ROOT / ".github/workflows/release.yml").read_text()
    action_uses = re.findall(r"^\s*-\s+uses:\s+([^\s#]+)", workflow, re.MULTILINE)
    for action in action_uses:
        if action.startswith("./"):
            continue
        if "@" not in action or not SHA_PATTERN.fullmatch(action.rsplit("@", 1)[1]):
            fail(f"release action is not pinned to a commit: {action}")

    if not re.search(r"^\s*toolchain:\s*1\.85\.0\s*$", workflow, re.MULTILINE):
        fail("release workflow does not select Rust 1.85.0")
    if "ref: ${{ env.RELEASE_TAG }}" not in workflow:
        fail("release workflow does not check out RELEASE_TAG")

    release_builds = [
        line.strip()
        for line in workflow.splitlines()
        if "cargo build" in line and "--release" in line
    ]
    if not release_builds or any("--locked" not in line for line in release_builds):
        fail("every release Cargo build must use --locked")


def check_documentation(version: str) -> None:
    changelog = (ROOT / "CHANGELOG.md").read_text()
    if not re.search(r"^## Unreleased\s*$", changelog, re.MULTILINE):
        fail("CHANGELOG.md is missing an Unreleased section")
    if not re.search(
        rf"^## {re.escape(version)} - \d{{4}}-\d{{2}}-\d{{2}}\s*$",
        changelog,
        re.MULTILINE,
    ):
        fail(f"CHANGELOG.md is missing the current {version} release section")

    readme = (ROOT / "README.md").read_text()
    unlocked = re.findall(
        r"^.*cargo build --release(?![^\n]*--locked).*$", readme, re.MULTILINE
    )
    if unlocked:
        fail("README.md contains an unlocked release build command")


def check_release_tag(release_tag: str, version: str) -> None:
    expected_tag = f"v{version}"
    if release_tag != expected_tag:
        fail(f"release tag {release_tag!r} does not match {expected_tag!r}")

    try:
        tag_type = command("git", "cat-file", "-t", release_tag)
    except subprocess.CalledProcessError:
        fail(f"release tag {release_tag!r} is not present in this checkout")
    if tag_type != "tag":
        fail(f"release tag {release_tag!r} must be an annotated tag")

    head = command("git", "rev-parse", "HEAD")
    try:
        tagged_commit = command("git", "rev-list", "-n", "1", release_tag)
    except subprocess.CalledProcessError:
        fail(f"release tag {release_tag!r} is not present in this checkout")
    if head != tagged_commit:
        fail(f"HEAD {head} is not the commit named by {release_tag} ({tagged_commit})")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-tag")
    args = parser.parse_args()

    version = check_packages(metadata())
    check_release_workflow()
    check_documentation(version)
    if args.release_tag:
        check_release_tag(args.release_tag, version)
    print(f"source-release contract passed for rsReticulum {version}")


if __name__ == "__main__":
    main()
