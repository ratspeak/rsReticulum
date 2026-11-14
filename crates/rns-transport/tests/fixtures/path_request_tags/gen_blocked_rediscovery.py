"""Capture which tags upstream 1.6.0 puts on the blocked-interface rediscovery
fan-out (Transport.handle_disovery_path_requests, Transport.py:4058-4080)."""
import sys, os, json, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import *
out = os.path.join(OUT_DIR, "blocked_rediscovery.json")
T, work = start("blocked-rediscovery", transport=False)

res = {"generator": repo_path(__file__), "rns_version": RNS.__version__, "rns_commit": rns_commit(),
       "enable_transport": False, "STAMP_PRS": T.STAMP_PRS}
def prs(iface):
    return [parse(s).data.hex() for s in iface.sent if parse(s).destination_hash == T.pr_destination_hash]

# Three plain interfaces, the first blocked.
a = Dummy("a"); b = Dummy("b"); c = Dummy("c")
T.interfaces[:] = [a, b, c]
dest2 = bytes.fromhex("5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e")
T.pending_discovery_prs.append((dest2, a))
T.handle_disovery_path_requests()
pa, pb, pc = prs(a), prs(b), prs(c)
res["blocked_rediscovery"] = {"destination_hash": dest2.hex(), "blocked": "a",
    "a_payloads": pa, "b_payloads": pb, "c_payloads": pc,
    "b_tags": [bytes.fromhex(p)[32:48].hex() for p in pb], "c_tags": [bytes.fromhex(p)[32:48].hex() for p in pc],
    "payload_lens": [len(bytes.fromhex(p)) for p in pb + pc]}
res["blocked_rediscovery"]["same_tag_on_all_unblocked"] = len(set(res["blocked_rediscovery"]["b_tags"] + res["blocked_rediscovery"]["c_tags"])) == 1
json.dump(res, open(out, "w"), indent=1, sort_keys=True)
print(json.dumps(res, indent=1)); finish(work)
