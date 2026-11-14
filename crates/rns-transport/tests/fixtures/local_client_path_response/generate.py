#!/usr/bin/env python3
"""A local client's path response to a pending external path request, recorded by driving
upstream RNS 1.6.0 Transport in-process (no daemon): the announce-table entry and what
jobs() sends on two external interfaces (Transport.py:2626-2648, :906-950).
Usage: generate.py [OUT_DIR]
"""
import json, os, tempfile
from _common import RNS, provenance, out_path
T = RNS.Transport
RNS.log = lambda *a, **k: None
out = {"provenance": provenance(__file__)}

RNS.Reticulum.storagepath = tempfile.mkdtemp(prefix="local-client-")
RNS.Reticulum.cachepath = os.path.join(RNS.Reticulum.storagepath, "cache")
os.makedirs(os.path.join(RNS.Reticulum.cachepath, "announces"), exist_ok=True)
RNS.Reticulum._Reticulum__transport_enabled = False
T.USE_INBOUND_QUEUE = False; T.ready = True; T.identity = RNS.Identity()

from RNS.Interfaces.Interface import Interface as _Base
class _StubReticulum(RNS.Reticulum):
    # Only supplies the private ic_* config fields (None -> upstream class defaults).
    def __init__(self): pass
    def __getattr__(self, n): return None
RNS.Reticulum._Reticulum__instance = _StubReticulum()
class Iface(_Base):
    def __init__(self, name):
        super().__init__()
        self.name = name; self.mode = _Base.MODE_FULL; self.sent = []
        self.OUT = True; self.IN = True; self.online = True; self.bitrate = 1_000_000
        self.HW_MTU = RNS.Reticulum.MTU; self.announce_cap = 2.0
        self.ifac_size = None; self.ifac_identity = None; self.announce_rate_target = None
        self.announce_rate_grace = None; self.announce_rate_penalty = None; self.tunnel_id = None
        self.reports_phy_stats = False
    def should_ingress_limit(self): return False
    def protocol_violation(self, d=None): raise RuntimeError(d)
    def get_hash(self): return (self.name.encode() + bytes(32))[:32]
    def process_outgoing(self, raw): self.sent.append(raw); self.txb += len(raw)
    def __str__(self): return self.name
class SharedParent(Iface):
    is_local_shared_instance = True
class LocalClientIface(Iface):
    def __init__(self, name): super().__init__(name); self.parent_interface = SharedParent("shared-parent")

class Owner2:
    is_connected_to_shared_instance = False
    def _used_destination_data(self, h): pass
T.owner = Owner2()
T.packet_hashlist = set(); T.packet_hashlist_prev = set()
T.path_table = {}; T.announce_table = {}; T.path_states = {}; T.held_announces = {}
T.pending_local_path_requests = {}; T.announce_rate_table = {} if not hasattr(T, "announce_rate_table") else T.announce_rate_table
T.destinations = []; T.destinations_map = {}
ext_a = Iface("ext-a"); ext_b = Iface("ext-b"); lc = LocalClientIface("local-client")
T.interfaces = [ext_a, ext_b, lc]
T.local_client_interfaces = [lc]
T.cache = staticmethod(lambda *a, **k: None)

cident = RNS.Identity()
cdest = RNS.Destination(cident, RNS.Destination.IN, RNS.Destination.SINGLE, "t16", "localclient")
T.destinations = []; T.destinations_map = {}
pr_packet = cdest.announce(path_response=True, send=False)
pr_packet.pack()
pr_raw = pr_packet.raw
T.pending_local_path_requests[cdest.hash] = ext_a
T.inbound(pr_raw, lc)
entry = T.announce_table.get(cdest.hash)
out["local_pr"] = {
    "announce_raw": pr_raw.hex(),
    "destination_hash": cdest.hash.hex(),
    "pending_cleared": cdest.hash not in T.pending_local_path_requests,
    "announce_table_entry": None if entry is None else {
        "retries": entry[2], "block_rebroadcasts": entry[7],
        "attached_interface": None if entry[8] is None else str(entry[8])},
    "sent_directly_to_waiting_iface_during_inbound": [r.hex() for r in ext_a.sent],
}
# Run the announce-retransmit part of jobs() once and capture packets on interfaces
ext_a.sent.clear(); ext_b.sent.clear(); lc.sent.clear()
T.announces_last_checked = 0
try:
    T.jobs()
except Exception as e:
    out["local_pr"]["jobs_error"] = repr(e)
def describe(raws):
    res = []
    for r in raws:
        p = RNS.Packet(None, r); p.unpack()
        res.append({"raw": r.hex(), "header_type": p.header_type, "context": p.context,
                    "packet_type": p.packet_type, "destination_hash": p.destination_hash.hex(),
                    "transport_id": None if p.transport_id is None else p.transport_id.hex()})
    return res
out["local_pr"]["after_jobs"] = {"ext-a": describe(ext_a.sent), "ext-b": describe(ext_b.sent)}
out["local_pr"]["transport_identity_hash"] = T.identity.hash.hex()
out["consts"] = {"PATH_RESPONSE": RNS.Packet.PATH_RESPONSE, "NONE": RNS.Packet.NONE,
                 "HEADER_2": RNS.Packet.HEADER_2, "PATHFINDER_R": T.PATHFINDER_R}
out["local_pr"]["ext_a_sent_before_jobs"] = out["local_pr"].pop("sent_directly_to_waiting_iface_during_inbound")
with open(out_path("local_client_path_response.json"), "w") as f:
    f.write("{\n" + ",\n".join(f" {json.dumps(k)}: {json.dumps(v)}" for k, v in out.items()) + "\n}\n")
os._exit(0)
