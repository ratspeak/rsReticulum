"""Shared bootstrap for the path-request tag generators. Runs upstream RNS 1.6.0 only.

The upstream tree is RATSPEAK_UPSTREAM_RETICULUM_DIR if set, else upstream/Reticulum
in the workspace. Each generator takes an optional output directory (default: this directory).
"""
import os, sys, shutil, time, subprocess, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, *[".."] * 5))
WORKSPACE = os.path.dirname(REPO)
RNS_DIR = os.environ.get("RATSPEAK_UPSTREAM_RETICULUM_DIR") or os.path.join(WORKSPACE, "upstream", "Reticulum")
sys.path.insert(0, RNS_DIR)
import RNS
from RNS.Interfaces.Interface import Interface
assert RNS.__version__ == "1.6.0", RNS.__version__
assert os.path.realpath(RNS.__file__).startswith(os.path.realpath(RNS_DIR) + os.sep), RNS.__file__
RNS_REF = "upstream Reticulum " + RNS.__version__
OUT_DIR = sys.argv[1] if len(sys.argv) > 1 else HERE

def repo_path(path):
    """Path relative to the repository root, as recorded in the goldens."""
    return os.path.relpath(os.path.abspath(path), REPO).replace(os.sep, "/")

def rns_commit():
    return subprocess.check_output(["git", "-C", RNS_DIR, "rev-parse", "HEAD"]).decode().strip()

def start(name, transport, **kwargs):
    """Boot upstream Reticulum in a fresh temp config dir. Returns (Transport, workdir)."""
    workdir = tempfile.mkdtemp(prefix="ratspeak-%s-" % name)
    with open(os.path.join(workdir, "config"), "w") as f:
        f.write("[reticulum]\n  enable_transport = %s\n  share_instance = No\n\n[logging]\n  loglevel = 2\n\n[interfaces]\n"
                % ("Yes" if transport else "No"))
    RNS.Reticulum(configdir=workdir, loglevel=2, **kwargs)
    while not RNS.Transport.ready if hasattr(RNS.Transport, "ready") else False: time.sleep(0.05)
    return RNS.Transport, workdir

def finish(workdir):
    shutil.rmtree(workdir, ignore_errors=True)
    sys.stdout.flush(); os._exit(0)

class Dummy(Interface):
    """Capture-only interface."""
    def __init__(self, name, mode=None, recursive_prs=False):
        super().__init__()
        self.name = name; self.online = True; self.IN = True; self.OUT = True
        self.bitrate = 10_000_000; self.mode = mode if mode is not None else Interface.MODE_FULL; self.HW_MTU = 500
        self.sent = []
        self.ifac_size = None; self.ifac_identity = None; self.ifac_netname = None; self.ifac_netkey = None
        self.ingress_control = False; self.egress_control = False
        self.announce_rate_target = None; self.announce_rate_grace = None; self.announce_rate_penalty = None
        self.announces_from_internal = True; self.announces_to_internal = True; self.recursive_prs = recursive_prs
        self._destination_cost = None; self._pr_cost = None; self.discoverable = False
    def process_outgoing(self, data): self.sent.append(bytes(data)); self.txb += len(data)
    def __str__(self): return "Dummy[" + self.name + "]"

def pr_packet(data):
    """Wrap a PR payload with upstream's own Packet packer (no reimplementation)."""
    dst = RNS.Destination(None, RNS.Destination.OUT, RNS.Destination.PLAIN, RNS.Transport.APP_NAME, "path", "request")
    p = RNS.Packet(dst, data, packet_type=RNS.Packet.DATA, transport_type=RNS.Transport.BROADCAST, header_type=RNS.Packet.HEADER_1)
    p.pack()
    return p.raw

def parse(raw):
    p = RNS.Packet(None, raw); p.unpack(); return p
