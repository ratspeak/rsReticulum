#!/usr/bin/env python3
"""Upstream RNS 1.6.0 rncp fetch decisions (RNS/Utilities/rncp.py:172-208).

Runs upstream rncp.listen() with networking stubbed out, captures the
fetch_request handler it registers, and calls it. For each request the golden
records the path upstream checks with os.path.isfile, or null when upstream
answers REQ_FETCH_NOT_ALLOWED. It also records how Link.handle_request packs
each fetch_request return value (Link.py:933) and the status the upstream
fetch client derives from it (rncp.py:463-474). Writes rncp_fetch.tsv:
"case" rows are jail, request, path ("<none>" for no jail / not allowed);
"reply" rows are name, packed response hex, client status.
"""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
WORKSPACE = os.path.abspath(os.path.join(HERE, *[".."] * 6))
RNS_DIR = os.environ.get("RATSPEAK_UPSTREAM_RETICULUM_DIR") or os.path.join(WORKSPACE, "upstream", "Reticulum")
sys.path.insert(0, RNS_DIR)
import subprocess
import RNS
assert RNS.__version__ == "1.6.0", RNS.__version__
assert os.path.realpath(RNS.__file__).startswith(os.path.realpath(RNS_DIR) + os.sep), RNS.__file__
import RNS.Utilities.rncp as rncp

HOME = "/home/rncp"
os.environ["HOME"] = HOME

class Stop(Exception):
    pass

class FakeDestination:
    handler = None
    IN, SINGLE, ALLOW_ALL, ALLOW_LIST = RNS.Destination.IN, RNS.Destination.SINGLE, RNS.Destination.ALLOW_ALL, RNS.Destination.ALLOW_LIST
    def __init__(self, *a, **kw): self.hash = bytes(16)
    def set_link_established_callback(self, cb): pass
    def register_request_handler(self, path, response_generator=None, allow=None, allowed_list=None):
        FakeDestination.handler = response_generator
    def announce(self): pass

def capture(jail):
    FakeDestination.handler = None
    rncp.fetch_jail = None
    real_sleep = rncp.time.sleep
    def stop_sleep(_):
        raise Stop()
    RNS.Reticulum = lambda *a, **kw: None
    RNS.Destination = FakeDestination
    RNS.log = lambda *a, **kw: None
    rncp.prepare_identity = lambda path: None
    rncp.threading.Thread = lambda target=None, daemon=None: type("T", (), {"start": lambda self: None})()
    rncp.time.sleep = stop_sleep
    try:
        rncp.listen(None, disable_auth=True, fetch_allowed=True, jail=jail)
    except Stop:
        pass
    finally:
        rncp.time.sleep = real_sleep
    return FakeDestination.handler

checked = []
real_isfile = os.path.isfile
def recording_isfile(p):
    checked.append(p)
    return False
RNS.Transport.active_links = []

def decide(handler, data):
    checked.clear()
    os.path.isfile = recording_isfile
    try:
        result = handler("fetch_file", data, b"\0" * 16, b"\0" * 16, None, 0.0)
    finally:
        os.path.isfile = real_isfile
    if result == rncp.REQ_FETCH_NOT_ALLOWED:
        return None
    assert result is False and len(checked) == 1, (result, checked)
    return checked[0]

JAILED = {
    "/srv/rncp": ["f.txt", "/srv/rncp/f.txt", "/etc/passwd", "//etc/passwd", "../x", "a/../b",
                  "./a//b/", "/srv/rncp/../rncp/x", "../rncpx/f", "..", "", "sub/..", "~/x",
                  "/srv/rncp/a/srv/rncp/b", "/srv/rncp/"],
    "/srv/rncp/": ["f.txt"],
    "/srv/./rncp/../rncp": ["f.txt"],
    "/": ["etc/x", "/etc/x", "../x"],
}
UNJAILED = ["/a/../b", "~/x", "~", "//x", "///x"]

cases = []
for jail, requests in JAILED.items():
    handler = capture(jail)
    for data in requests:
        cases.append({"jail": jail, "request": data, "path": decide(handler, data)})
handler = capture(None)
for data in UNJAILED:
    cases.append({"jail": None, "request": data, "path": decide(handler, data)})

import RNS.vendor.umsgpack as umsgpack
RID = bytes(range(16))
def client_status(response):
    if response == False: return "not_found"
    if response == None: return "remote_error"
    if response == rncp.REQ_FETCH_NOT_ALLOWED: return "fetch_not_allowed"
    return "found"
replies = []
# The client compares with ==, so 0 and 240.0 match False and 240 too.
for name, value in [("not_allowed", rncp.REQ_FETCH_NOT_ALLOWED), ("not_found", False), ("found", True), ("no_link", None),
                    ("int_zero", 0), ("float_240", 240.0), ("int_241", 241)]:
    packed = umsgpack.packb([RID, value])
    replies.append({"name": name, "packed": packed.hex(), "status": client_status(umsgpack.unpackb(packed)[1])})
# Responses an older rncp-rs sent: the single byte 0xF0 is fixint -16.
for name, raw in [("legacy_fixint_f0", bytes([0xF0])), ("bytes_value", b"\xf0")]:
    packed = umsgpack.packb([RID, umsgpack.unpackb(raw) if name == "legacy_fixint_f0" else raw])
    replies.append({"name": name, "packed": packed.hex(), "status": client_status(umsgpack.unpackb(packed)[1])})

commit = subprocess.check_output(["git", "-C", RNS_DIR, "rev-parse", "HEAD"]).decode().strip()
generator = os.path.relpath(os.path.abspath(__file__), os.path.join(WORKSPACE, "rsReticulum")).replace(os.sep, "/")
NONE = "<none>"
dest = os.path.join(sys.argv[1] if len(sys.argv) > 1 else HERE, "rncp_fetch.tsv")
with open(dest, "w") as f:
    f.write(f"# generator\t{generator}\n# rns_version\t{RNS.__version__}\n# rns_commit\t{commit}\n# home\t{HOME}\n")
    for c in cases:
        f.write("\t".join(["case", c["jail"] or NONE, c["request"], c["path"] or NONE]) + "\n")
    for r in replies:
        f.write("\t".join(["reply", r["name"], r["packed"], r["status"]]) + "\n")
