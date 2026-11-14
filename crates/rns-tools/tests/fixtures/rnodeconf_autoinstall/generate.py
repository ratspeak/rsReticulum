#!/usr/bin/env python3
"""Autoinstall menu choices for rnodeconf-rs, from upstream rnodeconf --autoinstall.

The `if args.autoinstall:` block of rnodeconf.main() is lifted with ast and run
with a stand-in port list and RNode (nothing is opened or flashed). Each case
feeds menu answers through input() and stops at the confirmation, then records
the product, model, platform, MCU and firmware file upstream selected, or the
message it exited with.

Usage: generate.py [OUT]  (default: choices.json beside this file)
"""
import ast, io, json, os, sys, tempfile
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
WORKSPACE = os.path.abspath(os.path.join(HERE, "..", "..", "..", "..", "..", ".."))
RNS_DIR = os.environ.get("RATSPEAK_UPSTREAM_RETICULUM_DIR") or os.path.join(WORKSPACE, "upstream", "Reticulum")
sys.path.insert(0, RNS_DIR)
os.environ["HOME"] = tempfile.mkdtemp(prefix="rnodeconf-home-")
import RNS
assert RNS.__version__ == "1.6.0", RNS.__version__
assert os.path.realpath(RNS.__file__).startswith(os.path.realpath(RNS_DIR) + os.sep), RNS.__file__
from RNS.Utilities import rnodeconf as rc
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "choices.json")

src = open(rc.__file__).read()
main = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef) and n.name == "main")
block = next(n for n in ast.walk(main) if isinstance(n, ast.If) and ast.unparse(n.test) == "args.autoinstall")
code = compile(ast.Module(body=[block], type_ignores=[]), rc.__file__, "exec")


class Port:
    device, product, serial_number = "/dev/stand-in", "stand-in", "0001"


class Device:
    detected = provisioned = signature_valid = False
    def __init__(self, serial): pass
    def readLoop(self): pass
    def device_probe(self): pass
    def download_eeprom(self): pass
    def disconnect(self): pass


class Args:
    autoinstall, port, use_extracted = True, Port.device, False


class Stop(Exception):
    pass


def run(answers):
    feed = list(answers)
    def ask(*_):
        if not feed:
            raise EOFError("EOF when reading a line")
        return feed.pop(0)
    def stop(code=0):
        raise Stop(code)
    ns = dict(vars(rc))
    ns.update(args=Args(), input=ask, clear=lambda: None, graceful_exit=stop, exit=stop, RNode=Device,
              rnode_open_serial=lambda path: None)
    ns["list_ports"] = type("lp", (), {"comports": staticmethod(lambda: [Port()])})
    buf = io.StringIO()
    with redirect_stdout(buf):
        try:
            exec(code, ns)
        except Stop:
            pass
    text = buf.getvalue().rstrip("\n").splitlines()
    if "Is the above correct? [y/N] OK, aborting now." in (text[-1] if text else ""):
        return {"product": ns["selected_product"], "model": ns["selected_model"], "platform": ns["selected_platform"],
                "mcu": ns["selected_mcu"], "fw_filename": ns["fw_filename"]}
    return {"stop": text[-1].removeprefix("? ") if text else ""}  # the prompt shares the line


# Answers per device: (device answer, needs an Enter for its notice, list of answer tails).
NOTICE = {n for n in range(2, 17)}
TAILS = {1: [["1"], ["2"], ["3"], ["4"], ["5"], ["6"], ["7"]],
         2: [[m, t] + (["1"] if m == "3" else []) for m in ("1", "2", "3") for t in ("1", "2", "3")] + [["3", "1", "2"], ["3", "1", "3"], ["4"], ["1", "4"]],
         10: [[c] for c in ("1", "2", "3", "4", "5", "6")]}
for n, top in {3: 4, 4: 4, 5: 4, 6: 4, 7: 4, 8: 4, 9: 3, 11: 4, 12: 4, 13: 2, 14: 2, 15: 4, 16: 2}.items():
    TAILS[n] = [[str(c)] for c in range(1, top + 2)]
cases = []
for n in range(1, 17):
    for tail in TAILS[n]:
        answers = [str(n)] + ([""] if n in NOTICE else []) + tail + ["n"]
        cases.append({"answers": answers, **run(answers)})
for answers in (["0"], ["17"], ["x"], ["2"], ["", "n"], ["3", "", "x"], ["8", "", "2", "n"], ["2", "", " 1 ", "1", "n"]):
    cases.append({"answers": answers, **run(answers)})
with open(OUT, "w") as f:
    f.write('{"provenance": ' + json.dumps({"generator": "crates/rns-tools/tests/fixtures/rnodeconf_autoinstall/generate.py",
                                             "rns_version": RNS.__version__}) + ',\n"cases": [\n')
    f.write(",\n".join(json.dumps(c, separators=(",", ":")) for c in cases))
    f.write("\n]}\n")
print(len(cases), "cases")
