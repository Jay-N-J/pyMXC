"""The one-line integration: this whole program runs inside the sandbox.

    python examples\\one_line_app.py

Copy pymxc.py next to your own script and add the import line below as its
first line. Here pymxc.py is one folder up, so the path is added first.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pymxc; pymxc.enable(read_write=["one_line_app_data"])   # <-- the one line

# Everything below runs sandboxed (when this Windows provides the sandbox).
print("sandboxed:", pymxc.is_sandboxed())
print("arguments:", sys.argv[1:])

# The program may write only where READ_WRITE says. "one_line_app_data" is
# relative to this script's folder; pymxc created it.
here = Path(__file__).resolve().parent
saved = here / "one_line_app_data" / "saved.txt"
saved.write_text("hello from inside\n", encoding="utf-8")
print("write in my data folder: ALLOWED")
saved.unlink()

# The folder holding the code stays read only: this code starts outside the
# sandbox next time, so the sandboxed program must not be able to change it.
try:
    (here / "planted.py").write_text("print('x')\n", encoding="utf-8")
    print("write next to my code: ALLOWED  <-- not sandboxed")
    (here / "planted.py").unlink()
except OSError as exc:
    print("write next to my code: BLOCKED", f"({type(exc).__name__})")

outside = Path.home() / "pymxc_should_not_exist.txt"
try:
    outside.write_text("escaped\n", encoding="utf-8")
    print("write in the user profile: ALLOWED  <-- not sandboxed")
    outside.unlink()
except OSError as exc:
    print("write in the user profile: BLOCKED", f"({type(exc).__name__})")
