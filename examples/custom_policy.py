"""A policy with more than the defaults, and streaming output with Popen.

    python examples\\custom_policy.py
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pymxc

root = Path(tempfile.mkdtemp(prefix="pymxc_example_"))
project, reference, output = root / "project", root / "reference", root / "output"
for folder in (project, reference, output, project / ".secrets"):
    folder.mkdir()
(reference / "data.txt").write_text("reference data\n", encoding="utf-8")
(project / ".secrets" / "token.txt").write_text("do not read me\n", encoding="utf-8")

script = project / "job.py"
script.write_text(
    "import pathlib, sys\n"
    "ref, out, secret = map(pathlib.Path, sys.argv[1:4])\n"
    "print('read reference:', (ref / 'data.txt').read_text().strip())\n"
    "(out / 'result.txt').write_text('done')\n"
    "print('wrote output: yes')\n"
    "for label, action in (('change reference', lambda: (ref / 'x.txt').write_text('x')),\n"
    "                      ('read secret', lambda: secret.read_text())):\n"
    "    try:\n"
    "        action(); print(label + ': ALLOWED')\n"
    "    except OSError:\n"
    "        print(label + ': BLOCKED')\n",
    encoding="utf-8")

policy = dict(
    workspace=str(project),
    read_only=[str(reference)],            # may read, may not change
    read_write=[str(output)],              # may read and change
    deny=[str(project / ".secrets")],      # blocked although it is inside the workspace
    network="off",
    no_windows=True,                       # a command-line job has no need to open windows
    clipboard="none",
    hide_secret_env=True,                  # do not pass API keys and tokens along
)

proc = pymxc.Popen([sys.executable, str(script), str(reference), str(output),
                    str(project / ".secrets" / "token.txt")], merge_stderr=True, **policy)
for line in proc.stdout:                   # arrives as the job prints it
    print("  job |", line.rstrip())
print("exit code:", proc.wait(), "| sandboxed:", proc.sandboxed)
print("warnings from pymxc:", len(proc.warnings))   # the texts are in proc.warnings; show them your own way
