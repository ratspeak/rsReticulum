#!/usr/bin/env python3
"""Record upstream RNS discovery auto-connect and announce decisions.

Run from anywhere; RNS comes from RATSPEAK_UPSTREAM_RETICULUM_DIR, else
<workspace>/upstream/Reticulum. Writes decisions.json beside this file.
Every expected value is what the upstream functions return for the input.
"""
import json, os, stat, subprocess, sys, tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
UPSTREAM = os.environ.get("RATSPEAK_UPSTREAM_RETICULUM_DIR") or str(HERE.parents[4] / "upstream" / "Reticulum")
sys.path.insert(0, UPSTREAM)
_stdout = sys.stdout
sys.stdout = sys.stderr
import RNS
import RNS.Discovery as D
import RNS.vendor.configobj as configobj
assert RNS.__version__ == "1.6.0", RNS.__version__
commit = subprocess.run(["git", "-C", UPSTREAM, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
R = RNS.Reticulum
disc = object.__new__(D.InterfaceDiscovery)

# Transport gate and implementation floor (Discovery.py:780-790).
qualified = []
for impl, version, transport, unverified in [
    ("RNS", "1.6.0", True, False), ("RNS", "1.6.0", False, False), ("RNS", "1.5.10", True, False),
    ("RNS", "1.5.7", True, False), ("RNS", "1.5.6", True, False),
    ("rsRNS", "1.4.0", True, False), ("rsRNS", "1.4.0", True, True), ("rsRNS", "1.4.0", False, True),
    ("RNS", "1.5.5", False, True),
]:
    R.should_autoconnect_unverified_implementations = staticmethod(lambda u=unverified: u)
    info = {"type": "BackboneInterface", "transport": transport, "impl_name": impl, "version": version}
    qualified.append({"impl_name": impl, "version": version, "transport": transport,
                      "allow_unverified": unverified, "qualified": bool(disc.autoconnect_qualified(info))})

# Cost admission (Discovery.py:804-813): passing it reaches endpoint_hash.
R._Reticulum__transport_enabled = False
reached = []
def record_and_stop(info):
    reached.append(True)
    raise RuntimeError("stop after the cost gate")
disc.endpoint_hash = record_and_stop
disc.autoconnect_count = lambda: 0
R.should_autoconnect_discovered_interfaces = staticmethod(lambda: True)
R.max_autoconnected_interfaces = staticmethod(lambda: 1)
R.should_autoconnect_unverified_implementations = staticmethod(lambda: False)
RNS.trace_exception = lambda e: None
costs = []
for dst_cost, pr_cost, dst_value, pr_value in [
    (23.5, 15.8, 25.0, 15.8), (25.0, 15.8, 25.0, 15.8), (25.002, 15.8, 25.0, 15.8),
    (30.0, 15.8, 25.0, 15.8), (23.5, 16.0, 25.0, 15.8), (None, None, 0.0, 0.0),
    (0.0, 0.0, 0.0, 0.0), (8.0, 8.0, 8.0, 8.0), (8.0, 8.0, 7.99, 8.0),
]:
    RNS.Transport.DESTINATION_VALUE = dst_value
    RNS.Transport.PR_VALUE = pr_value
    info = {"type": "BackboneInterface", "name": "Hub", "transport": True, "impl_name": "RNS",
            "version": "1.6.0", "dst_cost": dst_cost, "pr_cost": pr_cost}
    reached.clear()
    disc.autoconnect(info)
    costs.append({"dst_cost": dst_cost, "pr_cost": pr_cost, "dst_value": dst_value,
                  "pr_value": pr_value, "accepted": bool(reached)})

# reachable_on validation (Discovery.py:982-1007).
def valid(value):
    try: return bool(D.is_ip_address(value) or D.is_hostname(value))
    except Exception: return False
hosts = [{"value": v, "valid": valid(v)} for v in [
    "relay.example.org", "relay.example.org.", "10.0.0.1", "fe80::1", "localhost", "not a host!",
    "1.2.3", "host_name.example", "-bad.example", "a" * 64 + ".example", "xn--bcher-kva.example",
    "example.123", "", "a.b-.c",
]]

# location_cmd output, through get_interface_announce_data (Discovery.py:136-160).
from RNS.Interfaces.RNodeInterface import RNodeInterface
ann = object.__new__(D.InterfaceAnnouncer)
ann.stamp_cache = {}
ann.stamper = type("S", (), {"generate_stamp": staticmethod(lambda h, stamp_cost, expand_rounds: (b"\0" * 32, 0))})
RNS.Transport.identity = RNS.Identity()
locations = []
work = Path(tempfile.mkdtemp())
for idx, output in enumerate(["51.5,-0.1,30", "1,2", "91,0,0", "0,181,0", "0,-181,0", "0,0,-5000",
                              "abc,0,0", " 10 , 20 , 30 \n", "0,0,1000001", "-90,180,-4000"]):
    script = work / f"loc{idx}"
    script.write_text(f"#!/bin/sh\nprintf '%s' '{output}'\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    r = RNodeInterface.__new__(RNodeInterface)
    for k, v in dict(discovery_stamp_value=8, discovery_location=str(script), _destination_cost=None,
                     _pr_cost=None, discovery_name="r", discovery_latitude=None, discovery_longitude=None,
                     discovery_height=None, discovery_lxmf_address=None, kiss_framing=False,
                     frequency=868000000, bandwidth=125000, sf=7, cr=5, discovery_publish_ifac=False,
                     ifac_netname=None, ifac_netkey=None, discovery_encrypt=False,
                     reachable_on=None).items():
        setattr(r, k, v)
    data = ann.get_interface_announce_data(r)
    locations.append({"output": output, "location": None if data is None else
                      [r.discovery_latitude, r.discovery_longitude, r.discovery_height]})

# autoconnect_interface_mode aliases (Reticulum.py:715-728).
modes = {}
for alias in ["full", "access_point", "accesspoint", "ap", "pointtopoint", "ptp", "roaming",
              "boundary", "gateway", "gw", "internal", "Gateway", "point_to_point", "bogus"]:
    R._Reticulum__autoconnect_interface_mode = None
    r = object.__new__(R)
    r.requested_loglevel = None; r.requested_verbosity = None
    r.config = configobj.ConfigObj(["[reticulum]", f"autoconnect_interface_mode = {alias}"])
    try: r._Reticulum__apply_config()
    except AttributeError: pass
    modes[alias] = R.autoconnect_interface_mode()

# Collision naming (Discovery.py:771-779).
class If:
    def __init__(self, name): self.name = name
names = []
for existing, name in [([], "Hub"), (["Hub"], "Hub"), (["Hub", "Hub (2)"], "Hub"), (["Hub", "Hub (3)"], "Hub"),
                       (["Hub (2)"], "Hub")]:
    RNS.Transport.interfaces = [If(n) for n in existing]
    names.append({"existing": existing, "name": name, "result": disc.autoconnect_interface_name(name)})

out = {"generator": "crates/rns-runtime/tests/fixtures/discovery_autoconnect/gen_decisions.py",
       "rns_version": RNS.__version__, "rns_commit": commit,
       "qualified": qualified, "costs": costs, "hosts": hosts, "locations": locations,
       "modes": modes, "names": names}
lines = ["{"]
items = list(out.items())
for i, (k, v) in enumerate(items):
    end = "," if i < len(items) - 1 else ""
    if isinstance(v, list):
        lines.append(f' "{k}": [')
        lines += ["  " + json.dumps(c) + ("," if j < len(v) - 1 else "") for j, c in enumerate(v)]
        lines.append(" ]" + end)
    else:
        lines.append(f' "{k}": {json.dumps(v)}{end}')
lines.append("}")
(HERE / "decisions.json").write_text("\n".join(lines) + "\n")
