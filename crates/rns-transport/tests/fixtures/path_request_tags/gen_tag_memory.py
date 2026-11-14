"""Capture upstream 1.6.0 path-request tag memory:
duplicate tags have no time expiry, the tag set rotates into a previous generation once it
holds more than max_pr_tags entries at a jobs pass (Transport.py:990-994)."""
import sys, os, json, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import *
out = os.path.join(OUT_DIR, "tag_memory.json")
T, work = start("tag-memory", transport=False)
rx = Dummy("rx")
T.interfaces.append(rx)
local = RNS.Destination(RNS.Identity.from_bytes(bytes([0x52]) * 64), RNS.Destination.IN, RNS.Destination.SINGLE, "prw", "tags")
answers = []
local.announce = lambda *a, **k: answers.append(k.get("tag"))
real_time = time.time

def at(offset):
    time.time = lambda: real_time() + offset

def jobs():
    T.tables_last_culled = 0; T.pending_prs_last_checked = 0
    T.jobs()

def answered(tag):
    T.packet_hashlist.swap(); T.packet_hashlist.swap()  # clear both generations so only the tag gate decides
    n = len(answers)
    T.inbound(pr_packet(local.hash + tag), rx)
    time.sleep(0.3)
    return len(answers) > n

res = {"generator": repo_path(__file__), "rns_version": RNS.__version__, "rns_commit": rns_commit(),
       "max_pr_tags": T.max_pr_tags,
       "local_destination_hash": local.hash.hex()}
cases = []
tag = bytes([0x02]) * 16
cases.append({"case": "first_request", "tag": tag.hex(), "answered": answered(tag)})
at(121.0); jobs()
cases.append({"case": "replay_after_121s_and_jobs", "tag": tag.hex(), "answered": answered(tag)})
time.time = real_time

def rotation(filler, label):
    T.discovery_pr_tags = set(); T.discovery_pr_tags_prev = set()
    oldest = bytes([0xEE]) * 16
    T.discovery_pr_tags.add(local.hash + oldest)
    for i in range(filler):
        T.discovery_pr_tags.add(bytes([0xA0]) * 28 + i.to_bytes(4, "big"))
    jobs()
    r = {"case": label, "seeded_tags": filler + 1, "current_after_jobs": len(T.discovery_pr_tags),
         "prev_after_jobs": len(T.discovery_pr_tags_prev), "tag": oldest.hex()}
    r["answered"] = answered(oldest)
    return r
cases.append(rotation(T.max_pr_tags - 1, "at_max_no_rotation"))
cases.append(rotation(T.max_pr_tags, "above_max_rotates"))
# Second rotation forgets the first generation.
T.discovery_pr_tags = set(); T.discovery_pr_tags_prev = set()
oldest = bytes([0xEF]) * 16
T.discovery_pr_tags.add(local.hash + oldest)
for i in range(T.max_pr_tags): T.discovery_pr_tags.add(bytes([0xA1]) * 28 + i.to_bytes(4, "big"))
jobs()
for i in range(T.max_pr_tags + 1): T.discovery_pr_tags.add(bytes([0xA2]) * 28 + i.to_bytes(4, "big"))
jobs()
cases.append({"case": "second_rotation_forgets", "tag": oldest.hex(), "answered": answered(oldest)})
res["tag_cases"] = cases

with open(out, "w") as f:
    f.write("{\n" + ",\n".join(
        (" %s:[\n%s\n ]" % (json.dumps(k), ",\n".join("  " + json.dumps(c, sort_keys=True) for c in v)))
        if isinstance(v, list) else " %s:%s" % (json.dumps(k), json.dumps(v))
        for k, v in sorted(res.items())) + "\n}\n")
print(open(out).read()); finish(work)
