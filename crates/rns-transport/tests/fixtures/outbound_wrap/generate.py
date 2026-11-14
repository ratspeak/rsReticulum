#!/usr/bin/env python3
"""HEADER_2 wrap goldens from upstream RNS 1.6.0.

Every expected value is what upstream Transport.outbound hands to a capture-only interface.
The upstream tree is RATSPEAK_UPSTREAM_RETICULUM_DIR if set, else upstream/Reticulum.

Run: python3 generate.py [out_dir]   (writes outbound_wrap.json)
"""
import json, os, shutil, subprocess, sys, tempfile, time
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, *[".."] * 5))
WORKSPACE = os.path.dirname(REPO)
RNS_DIR = os.environ.get("RATSPEAK_UPSTREAM_RETICULUM_DIR") or os.path.join(WORKSPACE, "upstream", "Reticulum")
sys.path.insert(0, RNS_DIR)
import RNS
from RNS.Interfaces.Interface import Interface
assert RNS.__version__ == "1.6.0", RNS.__version__
OUT_DIR = sys.argv[1] if len(sys.argv) > 1 else HERE

cfg = tempfile.mkdtemp(prefix="ratspeak-outbound-rules-")
with open(os.path.join(cfg, "config"), "w") as f:
    f.write("[reticulum]\n  share_instance = No\n  enable_transport = No\n\n[logging]\n  loglevel = 0\n\n[interfaces]\n")
r = RNS.Reticulum(configdir=cfg, loglevel=0)


class Capture(Interface):
    def __init__(self, name, bitrate=10_000_000, online=True, mode=Interface.MODE_FULL):
        super().__init__()
        self.name, self.bitrate, self.online, self.mode = name, bitrate, online, mode
        self.IN = self.OUT = True
        self.frames = []
    def process_outgoing(self, data): self.frames.append(bytes(data))
    def __str__(self): return "Capture[" + self.name + "]"


def reset(ifaces):
    RNS.Transport.interfaces[:] = ifaces
    RNS.Transport.path_table.clear()
    RNS.Transport.path_requests.clear()


out = {"generator": os.path.relpath(os.path.abspath(__file__), REPO).replace(os.sep, "/"),
       "rns_version": RNS.__version__,
       "rns_commit": subprocess.check_output(["git", "-C", RNS_DIR, "rev-parse", "HEAD"]).decode().strip()}
dest = RNS.Destination(RNS.Identity(), RNS.Destination.OUT, RNS.Destination.SINGLE, "outbound", "rules")
nh = bytes.fromhex("ab" * 16)

# Transport.py:1622-1665: HEADER_2 wrap by path hops and shared-instance attachment.
wrap_cases = []
for hops, shared, header2 in [(0, False, False), (1, False, False), (1, True, False), (2, False, False), (2, True, False), (2, False, True), (1, False, True)]:
    a = Capture("a"); reset([a])
    now = time.time()
    RNS.Transport.path_table[dest.hash] = [now, nh, hops, now + 3600, [], a, b"\x00" * 32, now]
    r.is_connected_to_shared_instance = shared
    p = RNS.Packet(dest, b"wrap", create_receipt=False)
    p.pack()
    packed = p.raw
    if header2:
        # Packet.pack cannot build a HEADER_2 DATA packet; _outbound reads only header_type here.
        p.header_type = RNS.Packet.HEADER_2
    res = RNS.Transport.outbound(p)
    r.is_connected_to_shared_instance = False
    wrap_cases.append({"path_hops": hops, "shared_client": shared, "already_header2": header2, "packed": packed.hex(),
                       "sent": bool(res), "emitted": [f.hex() for f in a.frames]})
out["wrap"] = wrap_cases
reset([])

with open(os.path.join(OUT_DIR, "outbound_wrap.json"), "w") as f:
    def field(k, v):
        if isinstance(v, list) and v and isinstance(v[0], dict):
            return json.dumps(k) + ": [\n" + ",\n".join(json.dumps(c) for c in v) + "\n]"
        return json.dumps(k) + ": " + json.dumps(v)
    f.write("{\n" + ",\n".join(field(k, v) for k, v in out.items()) + "\n}\n")
shutil.rmtree(cfg, ignore_errors=True)
sys.stdout.flush()
os._exit(0)
