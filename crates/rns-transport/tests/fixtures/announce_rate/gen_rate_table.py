#!/usr/bin/env python3
"""Upstream AnnounceRateTable check and cull results for the rate table tests.

Calls RNS 1.6.0 RNS.Storage.AnnounceRateTable.check_and_update and cull directly.
"""
import json, sys
from _common import RNS, provenance, out_path
from RNS.Storage import AnnounceRateTable
from RNS.Transport import Transport
D = b"\x11" * 16
T0 = 1_800_000_000.0

def seq(calls, target, grace, penalty):
    t = AnnounceRateTable(max_timestamps=Transport.MAX_RATE_TIMESTAMPS)
    out = []
    for dt in calls:
        r = t.check_and_update(D, T0 + dt, target, grace, penalty)
        e = dict(t.items())[D]
        out.append({"dt": dt, "blocked": r, "n_timestamps": len(e["timestamps"]),
                    "rate_violations": e["rate_violations"],
                    "blocked_until_minus_t0": e["blocked_until"] - T0 if e["blocked_until"] else 0.0,
                    "last_minus_t0": e["last"] - T0})
    return out

g = {"provenance": provenance(__file__),
     "RATE_TABLE_RETAIN": Transport.RATE_TABLE_RETAIN,
     "MAX_RATE_TIMESTAMPS": Transport.MAX_RATE_TIMESTAMPS}
# target 60, grace 0, penalty 100: 3 announces 1 ms apart.
g["blocked_appends_timestamp"] = {"target": 60.0, "grace": 0, "penalty": 100.0,
    "steps": seq([0.0, 0.001, 0.002], 60.0, 0, 100.0)}

# cull: blocked entry whose last is older than retain survives while blocked.
t = AnnounceRateTable()
t.check_and_update(D, T0, 60.0, 0, 7200.0)
t.check_and_update(D, T0 + 1, 60.0, 0, 7200.0)   # blocked until T0+60+7200
now = T0 + Transport.RATE_TABLE_RETAIN + 100
culled = t.cull(now, Transport.RATE_TABLE_RETAIN, 1024, 1024)
g["cull_keeps_blocked"] = {"cull_now_minus_t0": now - T0, "ttl": Transport.RATE_TABLE_RETAIN,
    "culled": culled, "survives": D in t}
# Unblocked stale entry is culled.
t2 = AnnounceRateTable(); t2.check_and_update(D, T0, 60.0, 0, 7200.0)
g["cull_removes_unblocked_stale"] = {"culled": t2.cull(now, Transport.RATE_TABLE_RETAIN, 1024, 1024), "survives": D in t2}

with open(out_path("rate_table.json"), "w") as f:
    f.write("{\n" + ",\n".join(json.dumps(k) + ": " + json.dumps(v) for k, v in g.items()) + "\n}\n")
