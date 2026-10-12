#!/usr/bin/env python3
"""Verify the complete CLI archive set before checksumming or publishing it."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import tarfile
import zipfile


ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "rsReticulum"
BINS = "rnsd-rs rnstatus-rs rnpath-rs rnid-rs rnprobe-rs rncp-rs rnsh-rs rnodeconf-rs".split()
DOCS = ("README.md", "LICENSE", "CHANGELOG.md")
PLATFORMS = {"linux-x86_64": "tar.gz", "macos": "tar.gz", "windows-x86_64": "zip"}


def verify(directory: Path, tag: str) -> None:
    if not re.fullmatch(r"v\d+\.\d+\.\d+", tag):
        raise ValueError("expected a vX.Y.Z tag")
    names = {f"{PACKAGE}-{tag}-{platform}.{extension}" for platform, extension in PLATFORMS.items()}
    if {p.name for p in directory.iterdir()} != names:
        raise ValueError("release directory must contain exactly the three platform archives")
    for platform, extension in PLATFORMS.items():
        path = directory / f"{PACKAGE}-{tag}-{platform}.{extension}"
        payloads = {}
        if extension == "zip":
            with zipfile.ZipFile(path) as archive:
                for member in archive.infolist():
                    if member.is_dir():
                        continue
                    name = member.filename.replace("\\", "/")
                    if name in payloads:
                        raise ValueError(f"duplicate archive member: {name}")
                    payloads[name] = archive.read(member)
        else:
            with tarfile.open(path) as archive:
                for member in archive.getmembers():
                    if member.isdir():
                        continue
                    if not member.isfile() or member.name in payloads:
                        raise ValueError(f"invalid archive member: {member.name}")
                    if "/bin/" in member.name and not member.mode & 0o111:
                        raise ValueError(f"binary is not executable: {member.name}")
                    stream = archive.extractfile(member)
                    assert stream is not None
                    payloads[member.name] = stream.read()
        suffix = ".exe" if extension == "zip" else ""
        expected = {f"{PACKAGE}/{doc}" for doc in DOCS} | {f"{PACKAGE}/bin/{name}{suffix}" for name in BINS}
        if set(payloads) != expected:
            raise ValueError(f"incorrect file inventory in {path.name}: {sorted(payloads)}")
        for doc in DOCS:
            if payloads[f"{PACKAGE}/{doc}"] != (ROOT / doc).read_bytes():
                raise ValueError(f"{path.name}: {doc} does not match the qualified source")
        for name in BINS:
            data = payloads[f"{PACKAGE}/bin/{name}{suffix}"]
            valid = (
                data.startswith(b"\x7fELF") if platform.startswith("linux") else
                data.startswith(b"MZ") if platform.startswith("windows") else
                data[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe")
            )
            if not valid:
                raise ValueError(f"{path.name}: {name} is not a native binary for {platform}")
    checksums = "".join(f"{hashlib.sha256((directory / name).read_bytes()).hexdigest()}  {name}\n" for name in sorted(names))
    (directory / "SHA256SUMS").write_text(checksums)
    print(f"verified {PACKAGE} {tag}: three platform archives, native binaries, source documentation, and checksums")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    verify(args.directory, args.tag)


if __name__ == "__main__":
    main()
