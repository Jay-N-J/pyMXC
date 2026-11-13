"""Shows what a sandboxed program can and cannot reach. Run it both ways:

    python examples\\reach_outside.py                                   (not sandboxed)
    python pymxc.py --run "python examples\\reach_outside.py"           (sandboxed, no network)
    python pymxc.py --run "python examples\\reach_outside.py" --network internet
"""
import os
import socket
import tempfile
from pathlib import Path


def attempt(label, action):
    try:
        action()
        print(f"ALLOWED  {label}")
    except Exception as exc:
        print(f"BLOCKED  {label}  ({type(exc).__name__})")


def write_then_remove(path):
    path.write_text("x", encoding="utf-8")
    path.unlink()


home = Path.home()
print("PYMXC_SANDBOXED =", os.environ.get("PYMXC_SANDBOXED", "(not set)"))
attempt("write a file in the current folder", lambda: write_then_remove(Path("reach_outside_probe.txt")))
attempt("list file names in the user profile", lambda: os.listdir(home))
attempt("write a file in the user profile", lambda: write_then_remove(home / "reach_outside_probe.txt"))
attempt("create a temporary folder", lambda: os.rmdir(tempfile.mkdtemp()))
attempt("connect to the internet (1.1.1.1:443)", lambda: socket.create_connection(("1.1.1.1", 443), 5).close())
