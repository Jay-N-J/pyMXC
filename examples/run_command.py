"""Sandbox the commands your program starts, not the program itself.

    python examples\\run_command.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pymxc

state = pymxc.status()
print(f"sandbox: {state.code.name} - {state.message}\n")

# A string runs through cmd.exe; a list of arguments runs directly.
result = pymxc.run([sys.executable, "-c", "print('hello from the command')"])
print("output:   ", result.stdout.strip())
print("exit code:", result.returncode)
print("sandboxed:", result.sandboxed)

# The command cannot write outside its workspace.
target = Path.home() / "pymxc_should_not_exist.txt"
result = pymxc.run(f'echo escaped> "{target}"')
print("\nwrite to the user profile:", "BLOCKED" if not target.exists() else "ALLOWED  <-- not sandboxed")
target.unlink(missing_ok=True)

# A time limit stops the command and everything it started.
result = pymxc.run([sys.executable, "-c", "import time; time.sleep(30)"], timeout_seconds=2)
print("\ntimed out:", result.timed_out, "| status:", result.status.name)

# Refuse to run at all when there is no sandbox.
result = pymxc.run("echo strict", on_unavailable="error")
if result.returncode is None:
    print("\nnot run:", result.message)
else:
    print("\nstrict run:", result.stdout.strip(), "| sandboxed:", result.sandboxed)
