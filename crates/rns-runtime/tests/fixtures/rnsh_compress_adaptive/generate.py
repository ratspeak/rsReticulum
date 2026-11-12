#!/usr/bin/env python3
"""Chunking decisions of upstream adaptive stream compression.

rnsh's compress_adaptive (rnsh/session.py, rnsh/initiator.py) is the same
algorithm as RNS.RawChannelWriter.write (RNS/Buffer.py). This calls
RawChannelWriter.write with a stub channel at channel.mdu = 425 (Link MDU 431)
and records, per input, [processed_length, compressed, payload_len].

The upstream tree is RATSPEAK_UPSTREAM_RETICULUM_DIR if set, else
upstream/Reticulum in the workspace.

Run: python3 generate.py [out_file]   (default: cases.json next to this file)
"""
import json, os, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__))
WORKSPACE = os.path.abspath(os.path.join(HERE, *[".."] * 6))
RNS_DIR = os.environ.get("RATSPEAK_UPSTREAM_RETICULUM_DIR") or os.path.join(WORKSPACE, "upstream", "Reticulum")
sys.path.insert(0, RNS_DIR)
import RNS
from RNS.Buffer import RawChannelWriter
assert RNS.__version__ == "1.6.0", RNS.__version__
COMMIT = subprocess.run(["git", "-C", RNS_DIR, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "cases.json")

class Stub:
    mdu = 425
    def __init__(self): self.sent = []
    def send(self, m): self.sent.append(m)
    def is_ready_to_send(self): return True

# Input bytes only; the expected values come from RawChannelWriter.write.
def lcg(n, seed=1):
    out = bytearray(); x = seed
    for _ in range(n):
        x = (x * 1103515245 + 12345) & 0x7fffffff
        out.append((x >> 16) & 0xff)
    return bytes(out)

inputs = [
    ("lcg_20", "at most 32 bytes: never compressed", lcg(20)),
    ("lcg_33", "incompressible, under max_data_len: sent whole", lcg(33)),
    ("lcg_1000", "incompressible: raw chunk capped at max_data_len", lcg(1000)),
    ("lcg_20000", "over MAX_CHUNK_LEN and incompressible", lcg(20000)),
    ("a_33", "compressible but bz2 output not shorter than the segment", b"A" * 33),
    ("a_20000", "compressible: segment capped at MAX_CHUNK_LEN", b"A" * 20000),
    ("a600_lcg600", "first try too large, half segment compresses", b"A" * 600 + lcg(600)),
    ("lcg600_a600", "no try fits: raw fallback", lcg(600) + b"A" * 600),
]
lines = []
for name, rule, data in inputs:
    ch = Stub(); w = RawChannelWriter(0, ch)
    n = w.write(data); m = ch.sent[0]
    lines.append(json.dumps({"name": name, "rule": rule, "expect": [n, bool(m.compressed), len(m.data)]}))
meta = json.dumps({"generator": "crates/rns-runtime/tests/fixtures/rnsh_compress_adaptive/generate.py",
                   "upstream": "RNS " + RNS.__version__, "commit": COMMIT, "channel_mdu": Stub.mdu})
with open(OUT, "w") as f:
    f.write('{"meta": ' + meta + ',\n "cases": [\n  ' + ",\n  ".join(lines) + "\n]}\n")
