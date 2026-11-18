#!/usr/bin/env python3
"""Path-table lifecycle goldens from upstream RNS.

Drives upstream Transport.jobs() and Transport.outbound() on synthetic tables
and records what upstream leaves in them: never-used linger on a leaf and on a
transport node, instance-local (0-hop) paths, the hop limiter, the never-used
pool cap and its used-count scaling, the outbound use mark and the rediscovery
after a link that never established. Every expected value is read back from
upstream's own tables.

Usage: generate.py [OUT]  (default: path_table_lifecycle.json beside this file)
Until the pin lift, set RATSPEAK_UPSTREAM_RETICULUM_DIR to upstream/candidate/Reticulum.
"""
import json, os, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, *[".."] * 5))
WORKSPACE = os.path.dirname(REPO)
RNS_DIR = os.environ.get("RATSPEAK_UPSTREAM_RETICULUM_DIR") or os.path.join(WORKSPACE, "upstream", "Reticulum")
sys.path.insert(0, RNS_DIR)
import RNS
from RNS.Transport import Transport
from RNS.Interfaces.Interface import Interface
assert RNS.__version__ == "1.6.1", RNS.__version__
T = sys.modules["RNS.Transport"]
RNS.loglevel = RNS.LOG_CRITICAL
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "path_table_lifecycle.json")


class FakeIface:
    def __init__(self, name, bitrate, mode=Interface.MODE_FULL):
        self.name = name; self.bitrate = bitrate; self.mode = mode; self.sent = []
        self.ifac_identity = None; self.OUT = True; self.IN = True; self.FWD = False; self.RPT = False
        self.announce_queue = []; self.tunnel_id = None; self.phy_keepalive = False; self.online = True
    def process_outgoing(self, raw): self.sent.append(raw)
    def __str__(self): return f"FakeIface[{self.name}]"


class FakeOwner:
    def __init__(self, shared_client=False): self.is_connected_to_shared_instance = shared_client


def reset(now, ifaces, linger, transport=False, shared_client=False):
    for table in ("path_table", "path_states", "reverse_table", "link_table", "tunnels", "path_requests",
                  "inflight_path_requests", "discovery_path_requests", "pending_links_map", "active_links_map",
                  "announce_table", "held_announces", "pending_local_path_requests"):
        setattr(Transport, table, {})
    Transport.pending_links = []; Transport.active_links = []; Transport.receipts = []
    Transport.interfaces = list(ifaces); Transport.announce_cache = None; Transport.mgmt_destinations = []
    Transport.owner = FakeOwner(shared_client); Transport.unused_path_linger = linger
    RNS.Reticulum.transport_enabled = staticmethod(lambda: transport)
    Transport.pending_discovery_prs.clear()
    # Only the table cull and link checks run; every other job is "just done".
    for attr in ("links_last_checked", "receipts_last_checked", "announces_last_checked",
                 "pending_prs_last_checked", "cache_last_cleaned", "destinations_last_cleaned",
                 "rate_table_last_culled", "kd_last_flush", "ac_last_flush", "interface_last_jobs",
                 "last_mgmt_announce", "blackhole_last_checked", "last_collect", "last_mem_trim"):
        setattr(Transport, attr, now + 3600)
    Transport.mem_dirty = False; Transport.should_collect = False
    Transport.tables_last_culled = 0.0; Transport.pool_size_last_checked = 0.0


Transport.handle_disovery_path_requests = staticmethod(lambda: None)


def path_entry(ts, expires, iface, used, hops=1):
    return [ts, None, hops, expires, [], iface, None, used]


def h16(i):
    return i.to_bytes(16, "big")


WEEK = Transport.PATH_TIMEOUT
BITRATES = {"fast": 10_000_000, "slow": 9600, "zero": 0, "none": None, "edge": 25000}


def linger(linger_s, transport):
    L = linger_s
    # (label, interface, age, used age, hops); "gone" is an interface Transport no longer has.
    specs = [("fast_young", "fast", L - 60, None, 1), ("fast_old", "fast", L + 1, None, 1),
             ("fast_old_used", "fast", L * 20, 5.0, 1), ("slow_past_x1", "slow", L + 60, None, 1),
             ("slow_past_x10", "slow", L * 10 + 1, None, 1), ("slow_inside_x10", "slow", L * 10 - 60, None, 1),
             ("zero_bitrate_old", "zero", L + 1, None, 1), ("none_bitrate_old", "none", L + 1, None, 1),
             ("edge_bitrate_old", "edge", L + 1, None, 1), ("expired_used", "fast", 60, 5.0, 1),
             ("local_old_unused", "fast", L * 20, None, 0), ("local_expired", "fast", 60, None, 0),
             ("local_on_gone_iface", "gone", 60, 5.0, 0)]
    ifaces = {k: FakeIface(k, b) for k, b in BITRATES.items()}
    gone = FakeIface("gone", 10_000_000)
    now = time.time()
    reset(now, ifaces.values(), linger_s, transport)
    entries = []
    for i, (label, kind, age, used_age, hops) in enumerate(specs):
        ts = now - age
        exp = (now - 10) if label in ("expired_used", "local_expired") else ts + WEEK
        used = 0 if used_age is None else now - used_age
        iface = gone if kind == "gone" else ifaces[kind]
        Transport.path_table[h16(i + 1)] = path_entry(ts, exp, iface, used, hops)
        entries.append({"label": label, "iface": kind, "age_s": age, "expires_rel_s": exp - now,
                        "used_age_s": used_age, "hops": hops})
    Transport.jobs()
    for i, e in enumerate(entries):
        e["survives"] = h16(i + 1) in Transport.path_table
    return {"transport_enabled": transport, "linger_s": linger_s, "entries": entries}


POOL = {"count": 2100, "slow_every": 3, "expiry_base_s": 3600, "expiry_step_s": 240, "expiry_mod": 700,
        "used_count": 5}


def pool_inputs(i):
    kind = "slow" if i % POOL["slow_every"] == 0 else "fast"
    return kind, POOL["expiry_base_s"] + ((i * 7919) % POOL["expiry_mod"]) * POOL["expiry_step_s"]


def pool():
    ifaces = {"fast": FakeIface("fast", 10_000_000), "slow": FakeIface("slow", 9600)}
    now = time.time()
    reset(now, ifaces.values(), Transport.UNUSED_PATH_LINGER, True)
    for i in range(POOL["count"]):
        kind, exp_rel = pool_inputs(i)
        Transport.path_table[h16(i + 1)] = path_entry(now - 30, now + exp_rel, ifaces[kind], 0)
    for j in range(POOL["used_count"]):
        Transport.path_table[h16(POOL["count"] + j + 1)] = path_entry(now - 30, now + 60, ifaces["fast"], now - 1)
    Transport.jobs()
    removed = [i for i in range(POOL["count"]) if h16(i + 1) not in Transport.path_table]
    used_survive = all(h16(POOL["count"] + j + 1) in Transport.path_table for j in range(POOL["used_count"]))
    return dict(POOL, removed=removed, used_survive=used_survive)


def hop_limit():
    a = FakeIface("a", 10_000_000)
    now = time.time()
    reset(now, [a], Transport.UNUSED_PATH_LINGER, True)
    saved, Transport.HOP_LIMITER = Transport.HOP_LIMITER, 4
    hops = [0, 3, 4, 5, 9]
    for i, h in enumerate(hops):
        Transport.path_table[h16(i + 1)] = path_entry(now - 30, now + WEEK, a, now - 1, h)
    Transport.jobs()
    Transport.HOP_LIMITER = saved
    return {"hop_limiter": 4, "entries": [{"hops": h, "survives": h16(i + 1) in Transport.path_table}
                                          for i, h in enumerate(hops)]}


def pool_scaling(used_count):
    a = FakeIface("a", 10_000_000)
    now = time.time()
    reset(now, [a], Transport.UNUSED_PATH_LINGER, True)
    unused = 2100
    for i in range(unused):
        Transport.path_table[h16(i + 1)] = path_entry(now - 30, now + 3600 + i, a, 0)
    for j in range(used_count):
        Transport.path_table[h16(unused + j + 1)] = path_entry(now - 30, now + 60, a, now - 1)
    Transport.jobs()
    left = sum(1 for i in range(unused) if h16(i + 1) in Transport.path_table)
    return {"unused": unused, "used": used_count, "removed": unused - left,
            "used_survive": all(h16(unused + j + 1) in Transport.path_table for j in range(used_count))}


def outbound(hops):
    a = FakeIface("a", 10_000_000)
    now = time.time()
    reset(now, [a], Transport.UNUSED_PATH_LINGER, False)
    Transport.identity = RNS.Identity()
    RNS.Reticulum.get_instance = staticmethod(lambda: Transport.owner)
    dest = RNS.Destination(RNS.Identity(), RNS.Destination.OUT, RNS.Destination.SINGLE, "pathlifecycle", "out")
    ts0 = now - 3600.0
    Transport.path_table[dest.hash] = [ts0, h16(9) if hops > 1 else None, hops, ts0 + WEEK, [], a, None, 0]
    pkt = RNS.Packet(dest, b"hello", create_receipt=False); pkt.pack()
    before = time.time()
    Transport.outbound(pkt)
    e = Transport.path_table[dest.hash]
    return {"hops": hops, "age_s": 3600.0, "sent": len(a.sent) == 1,
            "timestamp_unchanged": e[T.IDX_PT_TIMESTAMP] == ts0, "expires_unchanged": e[T.IDX_PT_EXPIRES] == ts0 + WEEK,
            "used_is_send_time": e[T.IDX_PT_USED] >= before}


class FakeLink:
    def __init__(self, h, lid):
        self.status = RNS.Link.CLOSED; self.destination = type("D", (), {"hash": h})(); self.link_id = lid


def pending_link(transport, shared_client, last_request_age, hops=1):
    a = FakeIface("a", 10_000_000)
    now = time.time()
    reset(now, [a], Transport.UNUSED_PATH_LINGER_LEAF, transport, shared_client)
    Transport.links_last_checked = 0.0
    dh = h16(7)
    Transport.path_table[dh] = path_entry(now - 10, now + WEEK, a, now - 1, hops)
    if last_request_age is not None:
        Transport.path_requests[dh] = now - last_request_age
    link = FakeLink(dh, h16(8))
    Transport.pending_links.append(link); Transport.pending_links_map[link.link_id] = link
    Transport.jobs()
    return {"transport_enabled": transport, "shared_client": shared_client, "last_request_age_s": last_request_age,
            "hops": hops, "path_kept": dh in Transport.path_table,
            "rediscovery_queued": [e[0] for e in Transport.pending_discovery_prs] == [dh]}


commit = subprocess.run(["git", "-C", RNS_DIR, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
out = {
    "provenance": {"generator": "crates/rns-transport/tests/fixtures/path_table_lifecycle/generate.py",
                   "upstream": "Reticulum", "version": RNS.__version__, "commit": commit},
    "linger_leaf": linger(Transport.UNUSED_PATH_LINGER_LEAF, False),
    "linger_transport": linger(Transport.UNUSED_PATH_LINGER, True),
    "hop_limit": hop_limit(),
    "pool_cap": pool(),
    "pool_scaling": [pool_scaling(n) for n in (2048, 2500, 4000)],
    "outbound": [outbound(1), outbound(3)],
    "pending_link_rediscovery": [pending_link(False, False, None), pending_link(False, False, 10),
                                 pending_link(False, False, 25), pending_link(False, True, None),
                                 pending_link(True, False, None)],
}
with open(OUT, "w") as f:
    f.write("{\n")
    items = list(out.items())
    for n, (k, v) in enumerate(items):
        if isinstance(v, dict) and "entries" in v:
            body = json.dumps({kk: vv for kk, vv in v.items() if kk != "entries"})[:-1]
            rows = ",\n    ".join(json.dumps(e) for e in v["entries"])
            f.write(f' "{k}": {body}, "entries": [\n    {rows}\n  ]}}')
        elif isinstance(v, list):
            rows = ",\n    ".join(json.dumps(e) for e in v)
            f.write(f' "{k}": [\n    {rows}\n  ]')
        else:
            f.write(f' "{k}": {json.dumps(v)}')
        f.write(",\n" if n < len(items) - 1 else "\n")
    f.write("}\n")
print("wrote", OUT)
os._exit(0)
