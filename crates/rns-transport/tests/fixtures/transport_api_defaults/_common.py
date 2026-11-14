"""Shared bootstrap for the scripts in this directory. Runs upstream RNS 1.6.0 only.

The upstream tree is RATSPEAK_UPSTREAM_RETICULUM_DIR if set, else upstream/Reticulum
in the workspace. Generators take an optional output directory (default: this directory).
"""
import os, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, *[".."] * 5))
WORKSPACE = os.path.dirname(REPO)
RNS_DIR = os.environ.get("RATSPEAK_UPSTREAM_RETICULUM_DIR") or os.path.join(WORKSPACE, "upstream", "Reticulum")
sys.path.insert(0, RNS_DIR)
import RNS
assert RNS.__version__ == "1.6.0", RNS.__version__
assert os.path.realpath(RNS.__file__).startswith(os.path.realpath(RNS_DIR) + os.sep), RNS.__file__
RNS_REF = "upstream Reticulum " + RNS.__version__

def repo_path(path):
    """Path relative to the repository root, as recorded in the goldens."""
    return os.path.relpath(os.path.abspath(path), REPO).replace(os.sep, "/")

def rns_commit():
    return subprocess.check_output(["git", "-C", RNS_DIR, "rev-parse", "HEAD"]).decode().strip()

def provenance(script):
    return {"generator": repo_path(script), "rns_version": RNS.__version__, "rns_commit": rns_commit(), "rns_path": RNS_REF}

def out_path(name):
    return os.path.join(sys.argv[1] if len(sys.argv) > 1 else HERE, name)
