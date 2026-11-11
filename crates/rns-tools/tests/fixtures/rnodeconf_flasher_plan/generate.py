#!/usr/bin/env python3
"""Flasher argv vectors for rnodeconf-rs, from upstream get_flasher_call.

get_flasher_call is a closure inside rnodeconf.main(); its source is lifted
with ast and run against stub globals (args, UPD_DIR, EXT_DIR, sys.executable) and a
PATH holding empty avrdude/adafruit-nrfutil/unzip stubs. Nothing is flashed.
Every ESP32 firmware file the upstream branches or model table name is run at
versions either side of each version gate (1.55, 1.59); a later version is kept
only when its argv differs from the previous one beyond the version string.
"argv": null means upstream returns nothing or raises (unparsable version).

Usage: generate.py [OUT]  (default: vectors.json beside this file)
"""
import ast, json, os, subprocess, sys, tempfile, textwrap, types

HERE = os.path.dirname(os.path.abspath(__file__))
WORKSPACE = os.path.abspath(os.path.join(HERE, "..", "..", "..", "..", "..", ".."))
RNS_DIR = os.environ.get("RATSPEAK_UPSTREAM_RETICULUM_DIR") or os.path.join(WORKSPACE, "upstream", "candidate", "Reticulum")
sys.path.insert(0, RNS_DIR)
HOME = tempfile.mkdtemp(prefix="rnodeconf-home-")
os.environ["HOME"] = HOME  # rnodeconf creates ~/.config/rnodeconf at import
import RNS
assert RNS.__version__ == "1.6.0", RNS.__version__
assert os.path.realpath(RNS.__file__).startswith(os.path.realpath(RNS_DIR) + os.sep), RNS.__file__
from RNS.Utilities import rnodeconf as rc
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "vectors.json")

src = open(rc.__file__).read()
fn = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef) and n.name == "get_flasher_call")
UPD = tempfile.mkdtemp(prefix="rnodeconf-upd-")
EXT = tempfile.mkdtemp(prefix="rnodeconf-ext-")
stubbin = tempfile.mkdtemp(prefix="rnodeconf-bin-")
for tool in ("avrdude", "adafruit-nrfutil", "unzip"):
    p = os.path.join(stubbin, tool); open(p, "w").write("#!/bin/sh\n"); os.chmod(p, 0o755)
os.environ["PATH"] = stubbin + os.pathsep + os.environ["PATH"]
VERSIONS = ["1.54", "1.55", "1.58", "1.59"]
for v in VERSIONS + ["not-a-number"]:
    os.makedirs(os.path.join(UPD, v), exist_ok=True)
    open(os.path.join(UPD, v, "esptool.py"), "w").write("#!/bin/sh\n")
ns = {"ROM": rc.ROM, "UPD_DIR": UPD, "EXT_DIR": EXT, "CNF_DIR": HOME + "/.config/rnodeconf", "os": os, "RNS": RNS,
      "args": types.SimpleNamespace(port="/dev/ttyUSB0", baud_flash="921600"),
      "selected_version": None, "sys": types.SimpleNamespace(executable="python3"),
      "graceful_exit": lambda c=0: (_ for _ in ()).throw(SystemExit(c))}
RNS.loglevel = RNS.LOG_CRITICAL
exec(textwrap.dedent(ast.get_source_segment(src, fn)), ns)

branch_names = {c.comparators[0].value for c in ast.walk(fn) if isinstance(c, ast.Compare)
                and isinstance(c.left, ast.Name) and c.left.id == "fw_filename"
                and isinstance(c.comparators[0], ast.Constant)}
fws = sorted(branch_names | {m[4] for m in rc.models.values() if m[4]} | {"rnode_firmware_unknown.zip"})

def call(plat, f, v):
    ns["selected_version"] = v
    try: argv = ns["get_flasher_call"](plat, f)
    except (SystemExit, ValueError): argv = None
    return None if argv is None else [a.replace(UPD, "/cache/update").replace(EXT, "/cache/extracted") for a in argv]

def commit():
    try: return subprocess.check_output(["git", "-C", RNS_DIR, "rev-parse", "HEAD"], text=True).strip()
    except Exception: return None

cases = []
def keep(plat, f, versions):
    prev = cases  # sentinel: nothing kept yet
    for v in versions:
        argv = call(plat, f, v)
        norm = None if argv is None else [a.replace("/" + v + "/", "/V/") for a in argv]
        if norm != prev:
            cases.append({"platform": plat, "fw": f, "version": v, "argv": argv})
        prev = norm

for f in fws:
    if f.endswith(".hex"): keep(rc.ROM.PLATFORM_AVR, f, ["1.59"])
    elif f in branch_names or f == "rnode_firmware_unknown.zip": keep(rc.ROM.PLATFORM_ESP32, f, VERSIONS)
keep(rc.ROM.PLATFORM_NRF52, "rnode_firmware_rak4631.zip", ["1.59"])  # every nRF52 file takes one branch
keep(rc.ROM.PLATFORM_AVR, "rnode_firmware_unknown.hex", ["1.59"])
keep(rc.ROM.PLATFORM_ESP32, "rnode_firmware_t3s3.zip", ["not-a-number"])
keep(0x00, "rnode_firmware_t3s3.zip", ["1.59"])

with open(OUT, "w") as fh:
    fh.write(json.dumps({"provenance": {"generator": "crates/rns-tools/tests/fixtures/rnodeconf_flasher_plan/generate.py",
                         "upstream": "RNS " + RNS.__version__ + " RNS/Utilities/rnodeconf.py get_flasher_call",
                         "commit": commit()},
                         "ctx": {"python": "python3", "port": "/dev/ttyUSB0", "baud_flash": "921600",
                                 "update_dir": "/cache/update", "extracted_dir": "/cache/extracted"}})[:-1] + ', "cases": [\n')
    fh.write(",\n".join(json.dumps(c, separators=(",", ":")) for c in cases))
    fh.write("\n]}\n")
print(len(cases), "cases", file=sys.stderr)
