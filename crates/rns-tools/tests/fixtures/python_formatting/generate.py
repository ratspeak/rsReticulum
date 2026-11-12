#!/usr/bin/env python3
"""Upstream formatting vectors for rnpath-rs and rnprobe-rs.

Calls RNS.prettytime, rnpath.pretty_date (with datetime.now pinned) and the
Python float repr/round that rnpath and rnprobe print with.

Usage: generate.py [OUT]  (default: python_formatting.json beside this file)
"""
import datetime, json, os, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
WORKSPACE = os.path.abspath(os.path.join(HERE, "..", "..", "..", "..", "..", ".."))
RNS_DIR = os.environ.get("RATSPEAK_UPSTREAM_RETICULUM_DIR") or os.path.join(WORKSPACE, "upstream", "Reticulum")
sys.path.insert(0, RNS_DIR)
os.environ["TZ"] = "UTC"
time.tzset()
import RNS
from RNS.Utilities import rnpath
assert RNS.__version__ == "1.6.0", RNS.__version__

NOW = 1700000000.25
class PinnedNow(datetime.datetime):
    @classmethod
    def now(cls, tz=None): return datetime.datetime.fromtimestamp(NOW)

def commit():
    try: return subprocess.check_output(["git", "-C", RNS_DIR, "rev-parse", "HEAD"], text=True).strip()
    except Exception: return None

out = {"provenance": {"generator": "crates/rns-tools/tests/fixtures/python_formatting/generate.py",
                      "upstream": "Reticulum", "version": RNS.__version__, "commit": commit()}}
out["prettytime_compact"] = [[t, RNS.prettytime(t, compact=True)] for t in
    [0.0, 0.4, 1.0, 59.9, 61.5, 3600.0, 3661.0, 86400.0, 519000.7, 90061.0, -125.0]]
out["prettytime"] = [[t, RNS.prettytime(t)] for t in
    [0.0, 1.0, 1.004, 52.666, 11692.67, 90061.5, 3600.0, 7322.999, -5.5]]
datetime.datetime = PinnedNow
out["pretty_date_now"] = NOW
out["pretty_date"] = [[int(NOW - d), rnpath.pretty_date(int(NOW - d))] for d in
    [0, 9, 35, 60, 69, 70, 119, 7199, 7200, 86399, 86400, 172800, 518400, 604800, 2592000, 2678400, 31449600, 31536000, 69120000, -5]]
out["float_repr"] = [[x, repr(x)] for x in
    [0.0, -0.0, 1.0, 0.99, 127.8714, 1794280242.0036132, 1e16, 1.5e16, 1e-05, 0.0001, 1000000000000000.0, -87.0]]
out["round_repr"] = [[x, n, repr(round(x, n))] for x, n in
    [(0.99, 3), (1.0, 3), (127.8714, 3), (33.33333333, 2), (2.675, 2), (0.0625, 3), (1.4925, 3), (100.0, 2)]]
path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "python_formatting.json")
with open(path, "w") as f:
    f.write("{\n" + ",\n".join(f" {json.dumps(k)}: {json.dumps(v, ensure_ascii=False)}" for k, v in out.items()) + "\n}\n")
