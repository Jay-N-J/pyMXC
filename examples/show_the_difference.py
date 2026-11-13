"""Show what the MXC sandbox changes on THIS computer, as a one-page report.

    python examples\\show_the_difference.py            (writes pymxc_report.html and opens it)
    python examples\\show_the_difference.py --no-open --out C:\\temp\\report.html

It runs the same small test program three times:
  1. the ordinary way, with no sandbox;
  2. inside the sandbox with pymxc's default settings;
  3. inside the sandbox with stricter settings (no clipboard at all, API keys hidden).
Each time the test program tries things an untrusted program might do, and the
report shows which attempts got through. Nothing is simulated.

What the test touches, and cleans up again:
  - a file  pymxc_demo_private.txt  in your user folder (created, then deleted);
  - a saved credential named  pymxc-demo  in Windows Credential Manager (added, then removed);
  - a registry key  HKEY_CURRENT_USER\\Software\\pymxc_demo  (created, then deleted);
  - a text file in your Startup folder (created, then deleted at once);
  - one connection to 1.1.1.1 and one name lookup of example.com.
It reads whether the clipboard holds anything, but never its contents. Nothing
leaves this computer and the report contains no file names or secrets.
"""
import argparse
import datetime
import html
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # pymxc.py is one folder up
import pymxc

# The test program. It prints one JSON object: {probe id: [succeeded, detail]}.
# succeeded is true, false, or null when the attempt could not be judged.
PROBE = r'''
import ctypes, json, os, socket, subprocess, sys, tempfile
from pathlib import Path

home = Path(os.environ.get("USERPROFILE") or Path.home())
private = home / "pymxc_demo_private.txt"
out = {}

def attempt(name, action):
    try:
        result = action()
        out[name] = [result, ""] if result is None or isinstance(result, bool) else [True, str(result)]
    except Exception as exc:
        out[name] = [False, type(exc).__name__]

def write_then_delete(path):
    path.write_text("pymxc demo", encoding="utf-8")
    path.unlink()
    return True

def registry():
    import winreg
    winreg.CloseKey(winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\pymxc_demo"))
    winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r"Software\pymxc_demo")
    return True

def credential():
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    found = ctypes.c_void_p()
    if not advapi.CredReadW("pymxc-demo", 1, 0, ctypes.byref(found)):
        raise PermissionError("no access")
    advapi.CredFree(found)
    return True

def clipboard():
    user = ctypes.WinDLL("user32", use_last_error=True)
    user.GetClipboardData.restype = ctypes.c_void_p
    if not user.OpenClipboard(None):
        raise PermissionError("no access")
    try:
        first = user.EnumClipboardFormats(0)
        if not first:
            return None  # empty clipboard: nothing to judge
        if not user.GetClipboardData(first):
            raise PermissionError("no access")
        return True
    finally:
        user.CloseClipboard()

def other_program():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.restype = ctypes.c_void_p
    handle = kernel.OpenProcess(0x0010, False, int(os.environ["PYMXC_DEMO_PID"]))  # read its memory
    if not handle:
        raise PermissionError("no access")
    kernel.CloseHandle(ctypes.c_void_p(handle))
    return True

def project_files():
    Path("demo_output.txt").write_text("ok", encoding="utf-8")
    return Path("demo_output.txt").read_text(encoding="utf-8") == "ok"

def temp_files():
    folder = tempfile.mkdtemp()
    Path(folder, "t.txt").write_text("ok", encoding="utf-8")
    return True

startup = Path(os.environ.get("APPDATA", str(home))) / "Microsoft/Windows/Start Menu/Programs/Startup"

attempt("read_private", lambda: "demo-private-contents" in private.read_text(encoding="utf-8"))
attempt("list_profile", lambda: len(os.listdir(home)) > 0)
attempt("change_private", lambda: private.open("a", encoding="utf-8").close() or True)
attempt("write_profile", lambda: write_then_delete(home / "pymxc_demo_written.txt"))
attempt("startup", lambda: write_then_delete(startup / "pymxc_demo.txt"))
attempt("registry", registry)
attempt("credential", credential)
attempt("env_key", lambda: os.environ.get("DEMO_API_KEY") == "demo-secret-value")
attempt("clipboard", clipboard)
attempt("other_program", other_program)
attempt("internet", lambda: socket.create_connection(("1.1.1.1", 443), 5).close() or True)
attempt("dns", lambda: bool(socket.getaddrinfo("example.com", 443)))
attempt("run_python", lambda: sum(range(10)) == 45)
attempt("project_files", project_files)
attempt("temp_files", temp_files)
attempt("helper", lambda: subprocess.run("cmd /c echo ok", capture_output=True, text=True).stdout.strip() == "ok")
print(json.dumps(out))
'''

# (id, what the program tries, why it matters)
RISKS = [
    ("Your files", [
        ("read_private", "Read a private file in your user folder", "Documents, notes, source code, exports"),
        ("list_profile", "List what is in your user folder", "Learns what you have, to pick targets"),
        ("change_private", "Change or overwrite one of your files", "Corrupts or encrypts your work"),
        ("write_profile", "Create new files in your user folder", "Drops files where you will not look"),
    ]),
    ("Your secrets", [
        ("credential", "Read a password saved in Windows", "Credential Manager: git, network and app logins"),
        ("env_key", "Read an API key kept in an environment variable",
         "The test variable is named DEMO_API_KEY. Other variables stay readable."),
        ("clipboard", "Read the clipboard", "Whatever you last copied, including passwords"),
    ]),
    ("Your computer", [
        ("startup", "Make itself start at every sign-in", "Writes into your Startup folder"),
        ("registry", "Change your Windows settings", "Writes to the registry under your account"),
        ("other_program", "Reach into another running program", "Opens its memory for reading"),
    ]),
    ("The network", [
        ("internet", "Connect to the internet", "The way stolen data leaves"),
        ("dns", "Look up a web address", "Finds servers, and can leak data on its own"),
    ]),
]
USEFUL = [
    ("run_python", "Run Python code", ""),
    ("project_files", "Read and write files in its own project folder", ""),
    ("temp_files", "Use temporary files", ""),
    ("helper", "Start a helper program", ""),
]
STRICT = dict(clipboard="none", hide_secret_env=True, ui_isolation="container")
COLUMNS = [
    ("plain", "No sandbox", "How programs normally run"),
    ("default", "MXC sandbox", "pymxc default settings"),
    ("strict", "MXC sandbox, strict", 'clipboard="none", hide_secret_env=True'),
]


def collect():
    """Run the test program each way. Returns ({column: results or None}, notes, timing)."""
    home = Path(os.environ.get("USERPROFILE") or Path.home())
    private = home / "pymxc_demo_private.txt"
    workspace = Path(tempfile.mkdtemp(prefix="pymxc_demo_"))
    probe = workspace / "probe.py"
    probe.write_text(PROBE, encoding="utf-8")
    env = dict(os.environ, DEMO_API_KEY="demo-secret-value", PYMXC_DEMO_PID=str(os.getpid()))
    quiet = dict(capture_output=True, creationflags=0x08000000) if sys.platform == "win32" else dict(capture_output=True)
    results, notes = {}, []

    def parse(text):
        try:
            return json.loads(text.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return None

    try:
        private.write_text("demo-private-contents\n", encoding="utf-8")
        if sys.platform == "win32":
            subprocess.run(["cmdkey", "/generic:pymxc-demo", "/user:demo", "/pass:demo-password"], **quiet)
        done = subprocess.run([sys.executable, str(probe)], cwd=workspace, env=env, capture_output=True, text=True)
        results["plain"] = parse(done.stdout)
        if pymxc.available():
            for name, options in (("default", {}), ("strict", STRICT)):
                # Reset the file between runs so each run faces the same test.
                private.write_text("demo-private-contents\n", encoding="utf-8")
                run = pymxc.run([sys.executable, str(probe)], workspace=str(workspace), env=env,
                                timeout_seconds=120, on_unavailable="error", **options)
                results[name] = parse(run.stdout) if run.sandboxed else None
                if results[name] is None:
                    notes.append(f"{name}: {run.status.name} {run.message} {run.stderr[-200:]}")
        timing = measure(workspace, quiet)
    finally:
        private.unlink(missing_ok=True)
        (home / "pymxc_demo_written.txt").unlink(missing_ok=True)
        if sys.platform == "win32":
            subprocess.run(["cmdkey", "/delete:pymxc-demo"], **quiet)
        import shutil
        shutil.rmtree(workspace, ignore_errors=True)
    return results, notes, timing


def measure(workspace, quiet, rounds=5):
    """Median seconds to start and finish a do-nothing Python, each way."""
    def median(run_once):
        times = []
        for _ in range(rounds):
            start = time.perf_counter()
            run_once()
            times.append(time.perf_counter() - start)
        return sorted(times)[len(times) // 2]

    plain = median(lambda: subprocess.run([sys.executable, "-c", "pass"], cwd=workspace, **quiet))
    boxed = None
    if pymxc.available():
        boxed = median(lambda: pymxc.run([sys.executable, "-c", "pass"], workspace=str(workspace)))
    return plain, boxed


# ---- the page -----------------------------------------------------------------

CSS = """
:root{--page:#f9f9f7;--surface:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--muted:#898781;--line:#e1e0d9;
--good:#0ca30c;--critical:#d03b3b;--track:#f0efec}
@media (prefers-color-scheme:dark){:root{--page:#0d0d0d;--surface:#1a1a19;--ink:#f0efec;--ink2:#c3c2b7;
--line:#2c2c2a;--track:#383835}}
*{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--ink);font:15px/1.5 system-ui,"Segoe UI",sans-serif}
main{max-width:1040px;margin:0 auto;padding:32px 16px 56px}
h1{font-size:28px;line-height:1.2;margin:0 0 8px}
h2{font-size:18px;margin:40px 0 4px}
p{margin:0 0 12px;color:var(--ink2);max-width:72ch}
.meta{color:var(--muted);font-size:13px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px;margin:24px 0 8px}
.tile{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:16px}
.tile h3{margin:0;font-size:14px;font-weight:600}
.tile .sub{color:var(--muted);font-size:12px;min-height:18px}
.hero{font-size:52px;font-weight:650;line-height:1.1;margin-top:8px;font-variant-numeric:tabular-nums}
.hero small{font-size:18px;font-weight:500;color:var(--ink2)}
.caption{color:var(--ink2);font-size:13px}
.bar{display:flex;gap:2px;height:8px;margin:12px 0 6px}
.bar i{display:block;border-radius:4px;min-width:0}
.bar .x{background:var(--critical)}.bar .b{background:var(--good)}.bar .n{background:var(--track)}
.legend{display:flex;gap:16px;flex-wrap:wrap;color:var(--ink2);font-size:13px;margin:8px 0 0}
.wrap{overflow-x:auto;background:var(--surface);border:1px solid var(--line);border-radius:10px;margin-top:12px}
table{border-collapse:collapse;width:100%;min-width:680px}
th,td{padding:10px 14px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line)}
tr:last-child td{border-bottom:0}
thead th{font-size:13px;font-weight:600}
thead th:first-child{width:36%}
thead th span{display:block;font-weight:400;color:var(--muted);font-size:12px}
tr.group td{background:var(--page);font-size:12px;font-weight:600;color:var(--ink2);
text-transform:uppercase;letter-spacing:.04em;padding:6px 14px}
td.what span{display:block;color:var(--muted);font-size:12px}
td.cell{white-space:nowrap}
tbody tr:not(.group):hover td{background:var(--track)}
.chip{display:inline-flex;align-items:center;gap:8px;font-weight:600}
.dot{width:18px;height:18px;border-radius:50%;display:inline-grid;place-items:center;color:#fff;
font-size:12px;font-weight:700;flex:none}
.dot.x{background:var(--critical)}.dot.b{background:var(--good)}.dot.n{background:var(--muted)}
.why{display:block;color:var(--muted);font-size:12px;font-weight:400;margin-left:26px}
.note{border-left:3px solid var(--line);padding:4px 0 4px 14px;margin-top:24px}
footer{margin-top:40px;color:var(--muted);font-size:13px}
code{font:13px ui-monospace,Consolas,monospace}
"""


def chip(kind, label, detail=""):
    mark = {"x": "!", "b": "&#10003;", "n": "&ndash;"}[kind]
    why = f'<span class="why">{html.escape(detail)}</span>' if detail else ""
    return f'<span class="chip"><span class="dot {kind}" aria-hidden="true">{mark}</span>{label}</span>{why}'


def cell(result, risky):
    """One table cell: for a risky action, success is bad; for a useful one, good."""
    if result is None:
        return '<td class="cell">' + chip("n", "Not run") + "</td>"
    ok, detail = result
    if ok is None:
        return '<td class="cell">' + chip("n", "Not tested", "nothing to read") + "</td>"
    detail = {"PermissionError": "access denied", "gaierror": "lookup refused",
              "FileNotFoundError": "not visible"}.get(detail, detail)
    if risky:
        return '<td class="cell">' + (chip("x", "Got through") if ok else chip("b", "Blocked", detail)) + "</td>"
    return '<td class="cell">' + (chip("b", "Works") if ok else chip("x", "Fails", detail)) + "</td>"


def build(results, notes, timing):
    state = pymxc.status()
    risk_ids = [probe for _, rows in RISKS for probe, _, _ in rows]
    columns = [c for c in COLUMNS if results.get(c[0])]

    def count(column, ids, wanted):
        return sum(1 for i in ids if results[column].get(i, [None])[0] is wanted)

    tiles = []
    for key, title, sub in columns:
        through, blocked = count(key, risk_ids, True), count(key, risk_ids, False)
        skipped = len(risk_ids) - through - blocked
        parts = "".join(f'<i class="{cls}" style="flex:{n}"></i>'
                        for cls, n in (("x", through), ("b", blocked), ("n", skipped)) if n)
        tiles.append(
            f'<div class="tile"><h3>{html.escape(title)}</h3><div class="sub">{html.escape(sub)}</div>'
            f'<div class="hero">{through}<small> of {len(risk_ids)}</small></div>'
            f'<div class="caption">risky actions got through</div>'
            f'<div class="bar" role="img" aria-label="{through} got through, {blocked} blocked">{parts}</div></div>')

    head = "".join(f"<th>{html.escape(t)}<span>{html.escape(s)}</span></th>" for _, t, s in columns)
    rows = []
    for group, items in RISKS:
        rows.append(f'<tr class="group"><td colspan="{len(columns) + 1}">{html.escape(group)}</td></tr>')
        for probe, what, why in items:
            cells = "".join(cell(results[key].get(probe), True) for key, _, _ in columns)
            rows.append(f'<tr><td class="what">{html.escape(what)}<span>{html.escape(why)}</span></td>{cells}</tr>')
    useful_rows = []
    for probe, what, _ in USEFUL:
        cells = "".join(cell(results[key].get(probe), False) for key, _, _ in columns)
        useful_rows.append(f'<tr><td class="what">{html.escape(what)}</td>{cells}</tr>')

    if "default" in results and results["default"]:
        plain_n, boxed_n = count("plain", risk_ids, True), count("default", risk_ids, True)
        strict_n = count("strict", risk_ids, True) if results.get("strict") else None
        lead = (f"Run the ordinary way, a program on this computer could do <b>{plain_n} of {len(risk_ids)}</b> "
                f"risky things we tried. Inside the MXC sandbox the same program managed <b>{boxed_n}</b>"
                + (f", and <b>{strict_n}</b> with stricter settings." if strict_n is not None else "."))
    else:
        lead = (f"The MXC sandbox is not available on this computer, so only the unprotected run is shown. "
                f"{html.escape(state.message)}")

    plain_t, boxed_t = timing
    cost = ""
    if boxed_t is not None:
        cost = (f'<div class="note"><p><b>What it costs.</b> Starting a small Python program took '
                f'{plain_t * 1000:.0f} ms without the sandbox and {boxed_t * 1000:.0f} ms inside it on this '
                f'computer (median of 5). That is paid once per program start, not while it runs.</p></div>')
    problems = "".join(f"<p>{html.escape(n)}</p>" for n in notes)
    when = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>What the MXC sandbox changes</title><style>{CSS}</style></head><body><main>
<h1>What the MXC sandbox changes on this computer</h1>
<p>{lead}</p>
<p class="meta">Measured {when} on Windows build {html.escape(state.windows_build or platform.platform())},
Python {platform.python_version()}. Every result below comes from actually trying it.</p>
<div class="tiles">{"".join(tiles)}</div>
<div class="legend"><span>{chip("x", "Got through: the program succeeded")}</span>
<span>{chip("b", "Blocked: Windows refused")}</span></div>
{problems}
<h2>What an untrusted program tried</h2>
<p>Think of code written by an AI model, a script from the internet, or a package you have not read.
The same test program ran in each column.</p>
<div class="wrap"><table><thead><tr><th>The program tries to</th>{head}</tr></thead>
<tbody>{"".join(rows)}</tbody></table></div>
<h2>What still works</h2>
<p>The sandbox takes away reach, not ability. The program can still do its job in its own folder.</p>
<div class="wrap"><table><thead><tr><th>The program needs to</th>{head}</tr></thead>
<tbody>{"".join(useful_rows)}</tbody></table></div>
{cost}
<div class="note"><p><b>Reading the middle column.</b> pymxc's defaults block files, saved passwords,
persistence, the network and reading the clipboard, and leave your environment variables alone so
ordinary programs keep working. The strict column adds <code>hide_secret_env=True</code> and
<code>clipboard="none"</code>, which also stops the program from putting anything on the clipboard.</p>
<p><b>About environment variables.</b> A sandboxed program receives your environment variables, which is
how your own app gets its API key. <code>hide_secret_env=True</code> removes the ones whose names look
like keys, tokens or passwords; it goes by name, so it does not hide ordinary variables or a secret kept
under an unremarkable name. For commands you do not trust, pass an explicit <code>env=</code> with only
what they need.</p>
<p>To let a program reach one service only, such as an LLM API, use
<code>network="hosts"</code>.</p></div>
<footer>Made by <code>examples\\show_the_difference.py</code> with pymxc {pymxc.__version__}.
The test created and removed one file, one saved credential and one registry key, all named pymxc_demo.
No file names, clipboard contents or secrets are in this report.</footer>
</main></body></html>"""


def main():
    ap = argparse.ArgumentParser(description="Show what the MXC sandbox changes on this computer.")
    ap.add_argument("--out", default="pymxc_report.html", help="where to write the report")
    ap.add_argument("--no-open", action="store_true", help="do not open the report in the browser")
    args = ap.parse_args()
    print("Running the same test program with and without the sandbox (about 10 seconds)...")
    results, notes, timing = collect()
    if not results.get("plain"):
        raise SystemExit("The test program did not run; no report was written.")
    out = Path(args.out).resolve()
    out.write_text(build(results, notes, timing), encoding="utf-8")
    print(f"Report written to {out}")
    for note in notes:
        print("Note:", note)
    if not args.no_open:
        import webbrowser
        webbrowser.open(out.as_uri())


if __name__ == "__main__":
    main()
