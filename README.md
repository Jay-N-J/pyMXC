# pymxc

Run a Python program, or the commands it starts, inside a Windows **MXC sandbox** (Microsoft Execution Containers) by adding one file and one line.

> **Unofficial, and early.** pymxc is an independent project. It is not made, endorsed or supported by Microsoft; "MXC" and "Windows" are Microsoft's names. This is version 0.1: it was built and measured on one computer, the Windows feature underneath is new, and settings may still change. See [What was tested](#what-was-tested).

```python
import pymxc; pymxc.enable()
```

- **One file.** Copy `pymxc.py` into your project. Standard library only; nothing to `pip install`.
- **Nothing to set up on Windows.** No MXC SDK, no installer, no administrator rights, no changes to folder permissions. Windows itself enforces the policy.
- **Safe to ship everywhere.** On a computer without the sandbox (older Windows, Linux, macOS) the file still imports and tells you so with a status code. By default your program then runs unsandboxed after one warning; one setting makes it refuse instead.
- **Python 3.12 or newer.**

A sandboxed program can read its own folder and the Python it runs on, write to the data folders you name, and nothing else of yours: not your documents, not your other projects, not the network, unless you allow it.

## Contents

1. [Requirements](#requirements)
2. [Quick start](#quick-start)
3. [Three ways to use it](#three-ways-to-use-it)
4. [Settings](#settings)
5. [When the sandbox is not available](#when-the-sandbox-is-not-available)
6. [Status codes](#status-codes)
7. [Recipes](#recipes)
8. [What works differently inside the sandbox](#what-works-differently-inside-the-sandbox)
9. [Limits you should know](#limits-you-should-know)
10. [Command line](#command-line)
11. [How it works](#how-it-works)
12. [What was tested](#what-was-tested)
13. [Files in this repository](#files-in-this-repository)

## Requirements

| | |
|---|---|
| Python | 3.12 or newer (older versions get a clear `ImportError`) |
| Windows | Windows 11 **24H2 build 26100.9278** or **25H2 build 26200.9278**, or later |
| Rights | An ordinary user account. No administrator rights. |
| Install | Nothing. The sandbox is part of Windows once the updates above are in. |

Check a computer in one command:

```
python pymxc.py --probe
```

It prints a short report and exits with `0` when the sandbox is usable. Any other exit code is a [status code](#status-codes) saying why not.

## Quick start

1. Copy `pymxc.py` next to your program's main script.
2. Add this as the first line of the script you start:

   ```python
   import pymxc; pymxc.enable(read_write=["data"])
   ```

3. Run your program as you always do.

Your program now restarts itself inside the sandbox and carries on from there. It can read its own folder and write to `data` inside it (created if missing); the rest of your user profile is out of reach; there is no network. Change any of that in the [settings](#settings).

The program's own folder is read-only on purpose. The code in it starts *outside* the sandbox every time you launch the program, so a sandboxed program that could change that folder could make anything run unsandboxed on the next start. A program that saves nothing needs only `pymxc.enable()`.

To see it work, run `python examples\one_line_app.py`:

```
sandboxed: True
arguments: []
write in my data folder: ALLOWED
write next to my code: BLOCKED (PermissionError)
write in the user profile: BLOCKED (PermissionError)
```

### See what it buys you

```
python examples\show_the_difference.py
```

This runs one small test program three times (no sandbox, sandbox with default settings, sandbox with strict settings) and opens a one-page report, `pymxc_report.html`, showing which of 12 risky actions got through each time: reading your files, reading a saved password, starting at every sign-in, reaching the internet, and so on. It also shows that the program's own work still succeeds, and what the sandbox costs in start-up time.

On the computer this was developed on, the result was 12 of 12 with no sandbox, 1 of 12 with the defaults (environment variables stay readable so ordinary programs keep working) and 0 of 12 with strict settings. Starting a program took 32 ms without the sandbox and 70 ms inside it.

Every result is measured on your computer, not simulated. The test creates and removes one file in your user folder, one saved credential and one registry key, all named `pymxc_demo`; the script's header lists exactly what it touches. The report contains no file names, clipboard contents or secrets, so it is safe to share.

## Three ways to use it

### 1. `enable()` — sandbox your whole program

```python
import pymxc; pymxc.enable(read_write=["data"])

# the rest of your program; it saves its files in the "data" folder
```

With more options:

```python
import pymxc
pymxc.enable(network="internet", read_write=["data", r"C:\work\output"])
```

What it does:

- **Outside the sandbox**, it starts the same program again (same interpreter, same arguments, `python -m` included) inside a sandbox, waits for it, and exits with its exit code. It does not return.
- **Inside the sandbox** (the restarted copy), it returns `True` and your program continues.
- **When the sandbox is not available**, it returns `False` and your program continues *without* a sandbox, after one warning. See [the fallback settings](#when-the-sandbox-is-not-available) to refuse instead.

Things to know:

- Put it first. Code above the call runs twice: once outside the sandbox and once inside.
- **The program's folder is read-only inside the sandbox.** List the folders it saves to in `read_write`; a relative path is relative to the script's folder, and a folder that does not exist is created. `workspace_access="rw"` makes the whole folder writable and prints a warning, because the program could then change the code that starts outside the sandbox next time.
- **Read saved API keys before the call.** Windows Credential Manager (and so the `keyring` package) returns nothing inside the sandbox. Read the key above the `enable()` line and put it in `os.environ`; the sandboxed copy receives it. Keys already in an environment variable need nothing extra.

  ```python
  import os, pymxc
  if not pymxc.is_sandboxed() and not os.environ.get("LLM_API_KEY"):
      import keyring
      os.environ["LLM_API_KEY"] = keyring.get_password("your-app", "api-key") or ""
  pymxc.enable(network="hosts", network_hosts=["api.example.com"])
  ```
- `input()`, `print()`, Ctrl+C, redirected output (`> out.txt`) and pipes all keep working. After Ctrl+C your program gets five seconds to finish its own clean-up before it is stopped; a second Ctrl+C stops it at once.
- It needs a script, a module (`python -m`) or a frozen program to restart. In an interactive session or `python -c` it behaves as if the sandbox were unavailable.
- `pymxc.is_sandboxed()` tells you at any time whether you are inside. It asks Windows, so setting `PYMXC_SANDBOXED` by hand does not count.

### 2. `run()` — sandbox one command

Use this when your program stays outside the sandbox and starts things that should not be trusted, such as code written by an AI agent.

```python
import pymxc

result = pymxc.run("python tool.py --fast")           # a string runs through cmd.exe
result = pymxc.run([sys.executable, "tool.py", arg])  # a list runs the program directly

print(result.returncode)   # the command's exit code, or None if it did not run
print(result.stdout, result.stderr)
print(result.sandboxed)    # True when it ran inside the sandbox
print(result.timed_out)
print(result.status)       # a pymxc.Status code
print(result.message)      # plain-language explanation when something went wrong
print(result.ok)           # True when it ran and exited with 0
```

`run()` always returns a `Result`. It does not raise because the sandbox is missing, a setting is wrong, or the program could not be started; look at `status` and `message` instead.

| Argument | Meaning |
|---|---|
| `command` | A string (through `cmd.exe`, so `&&`, `>` and `%VAR%` work) or a list of arguments (no shell; `&` and quotes in arguments are passed as they are) |
| `cwd` | Working folder. Default: the workspace. |
| `env` | Environment variables. Default: your program's own. |
| `input` | Text or bytes sent to the command's standard input |
| any setting | In lower case: `network="internet"`, `timeout_seconds=30`, `deny=[...]` |

The workspace for `run()` is the current folder unless you pass `workspace=`.

### 3. `Popen()` — start a command and stay in control

For long-running commands, live output, or typing into the command.

```python
proc = pymxc.Popen([sys.executable, "-u", "server.py"], network="internet", merge_stderr=True)
for line in proc.stdout:        # arrives as the command prints it
    print(line, end="")
proc.wait()                     # or proc.wait(timeout=10), proc.poll(), proc.kill()
```

It has the familiar parts of `subprocess.Popen`: `stdout`, `stderr`, `stdin` (pass `stdin=True`), `pid`, `poll()`, `wait()`, `kill()`, `returncode`. `kill()` stops the command and everything it started. `proc.sandboxed` says whether it is contained, and `proc.warnings` lists settings that were adjusted.

Unlike `run()`, `Popen()` raises: `PolicyError` for a bad setting, `SandboxLaunchError` when Windows will not start the program, `SandboxUnavailable` when there is no sandbox and you asked for `"error"`.

### `status()` — ask first

```python
state = pymxc.status()
if state:                          # truthy when the sandbox is usable
    ...
print(state.code, state.message)   # e.g. Status.WINDOWS_TOO_OLD and the reason
print(state.windows_build)         # e.g. "26200.9974"
```

## Settings

Every setting lives in the **SETTINGS block at the top of `pymxc.py`**, with its default active and every other choice on a commented line beside it. You never need this README to see what is possible.

There are three ways to change a setting. The later ones win:

1. Edit the SETTINGS block in your copy of `pymxc.py`.
2. Set it from your code before the call: `pymxc.NETWORK = "internet"`.
3. Pass it in lower case to one call: `pymxc.run(cmd, network="internet")`.

A misspelled option raises `TypeError` and lists the valid names.

### When there is no sandbox

| Setting | Default | Other values |
|---|---|---|
| `ON_UNAVAILABLE` | `"warn"`: one warning, then run without the sandbox | `"silent"`: run without it, say nothing. `"error"`: do not run. |

### Files

| Setting | Default | Meaning |
|---|---|---|
| `WORKSPACE` | `None` | The folder the program works in. `None` means the script's folder for `enable()` and the current folder for `run()` and `Popen()`. |
| `WORKSPACE_ACCESS` | `None` | `"rw"`: read and change. `"ro"`: read only. `None` means read only for `enable()` (the workspace holds the program's own code) and read and change for `run()` and `Popen()`. |
| `READ_WRITE` | `[]` | More folders or files the program may read and change. A relative path is relative to the workspace. A folder that does not exist is created. |
| `READ_ONLY` | `[]` | More folders or files the program may only read. A relative path is relative to the workspace. |
| `DENY` | `[]` | Blocked even when inside a granted folder. A relative path is relative to the workspace. A path that does not exist yet is blocked when it appears; the folder it would be in must exist. |
| `GRANT_PYTHON_RUNTIME` | `True` | Read access to the running Python: interpreter, standard library, installed packages |
| `PYTHON_ON_PATH` | `True` | `python` in a command means the running Python. See [below](#what-works-differently-inside-the-sandbox). |
| `GRANT_PIP_CONFIG` | `False` | `True`: read access to `pip.ini` and the certificate files it names (the files only, not their folders), so pip inside the sandbox uses your package mirror. Off by default because `pip.ini` can hold index passwords. |
| `GRANT_GIT_CONFIG` | `False` | Read access to `~\.gitconfig`, `~\.config\git`, `~\.condarc` |
| `LIST_DRIVE_ROOTS` | `False` | `True` lets the program list file *names* (not contents) anywhere on the drives it uses, including inside your user profile. Some batch files and tools need it. |

Paths that do not exist are skipped with a warning.

### Network

| Setting | Default | Meaning |
|---|---|---|
| `NETWORK` | `"off"` | `"off"`: none. `"internet"`: public internet only; private address ranges are blocked. `"intranet"`: private address ranges only (intranet, VPN, local network); no public internet. `"all"`: both. `"hosts"`: only the HTTPS hosts in `NETWORK_HOSTS`. `"custom"`: only what `NETWORK_RULES` or `NETWORK_PROXY` allow. See [public and private addresses](#public-and-private-addresses). |
| `NETWORK_HOSTS` | `[]` | For `"hosts"`: the only web hosts the program may reach, by name |
| `NETWORK_UPSTREAM_PROXY` | `"auto"` | For `"hosts"`: how the filter reaches the hosts. `"auto"`: direct first, then the proxy from `HTTPS_PROXY` or Windows' proxy settings. `""`: direct only. A URL: direct first, then that proxy. |
| `NETWORK_RULES` | `[]` | For `"custom"`: addresses the program may connect to |
| `NETWORK_PRIVATE` | `False` | For `"custom"`: the rules include intranet, VPN or local addresses |
| `NETWORK_PROXY` | `""` | For `"custom"`: send everything through a proxy of your own on this computer, for example `"http://127.0.0.1:8080"`. Replaces the rules. |
| `ALLOW_INBOUND` | `False` | The program may accept incoming connections |
| `ALLOW_LOOPBACK` | `False` | The program may talk to other programs on this computer over `127.0.0.1` |

#### Public and private addresses

`"internet"`, `"intranet"` and `"all"` differ in which addresses the program may connect to:

| `NETWORK` | Public internet | Private addresses |
|---|---|---|
| `"internet"` | yes | no |
| `"intranet"` | no | yes |
| `"all"` | yes | yes |

- **"Private" means the address ranges reserved for it:** `10.x`, `172.16`–`172.31.x`, `192.168.x`, `169.254.x`, `100.64`–`100.127.x`, and `fc00::/7` and `fe80::/10` for IPv6. That covers home and office networks, most intranets and VPNs, and the metadata address of cloud machines.
- **pymxc gives Windows these ranges itself.** Left to Windows, the line depends on how it classes the network you are on: on a network it treats as public, a program allowed "the internet" also reaches the router and every other local device. With the ranges spelled out, each mode means the same on every network.
- **An organisation that uses public address ranges internally is not covered.** Its servers count as "internet" here. List its ranges with `NETWORK = "custom"`, or its servers with `"hosts"`.
- **`"intranet"` and `"all"` also let the program accept connections from the local network.** Windows grants private-network access in both directions only.
- **A proxy on a private address** (common in organisations) is out of reach under `"internet"`; use `"all"`.

#### Allowing only named hosts (`NETWORK = "hosts"`)

This is the setting for "let the program call its LLM API and nothing else".

```python
pymxc.enable(network="hosts", network_hosts=["api.example.com"])   # your provider's API host
```

A full example is in [Recipes](#recipes).

| Entry | Allows |
|---|---|
| `"api.example.com"` | That host on port 443 |
| `"*.googleapis.com"` | Every subdomain of `googleapis.com` (not `googleapis.com` itself) |
| `"internal.example.com:8443"` | That host on port 8443 |

How it works: pymxc starts a small filter inside *your* program, outside the sandbox, listening on `127.0.0.1`. Windows lets the sandboxed program connect to that filter and to nothing else. The filter passes a connection on only when the requested host is listed. It does not decrypt anything; traffic stays encrypted between the program and the host.

What to know:

- **The program must use the standard proxy settings.** pymxc sets `HTTPS_PROXY` and `HTTP_PROXY` for it. `requests`, `httpx`, `urllib`, pip and the Google, Anthropic and OpenAI SDKs follow them. Code that opens raw sockets gets no connection.
- **HTTPS only.** Plain `http://` requests are refused.
- **Blocked attempts are reported.** `run()` lists them in `result.warnings`; `enable()` prints one line per blocked host on stderr. That is how you find a host you forgot to list.
- **A listed host can receive anything the program can read.** Allowing an LLM API means file contents can be sent to that API.
- **Other programs on your computer can use the filter too** while it runs, but only to reach the hosts you listed.

#### Allowing addresses (`NETWORK = "custom"`)

Rule format: `"address[/prefix][:port[-port]]"`, optionally starting with `tcp` or `udp`.

```python
NETWORK_RULES = ["10.0.0.0/8:443"]             # a range, TCP port 443
NETWORK_RULES = ["192.168.1.5"]                # one address, any port
NETWORK_RULES = ["tcp 10.1.2.0/24:8000-8100"]  # a range of ports
NETWORK_RULES = ["udp 10.0.0.53:53", "2001:db8::/32"]
```

Addresses are numeric. Windows has no host-name rules for this sandbox; to allow by name, use `NETWORK = "hosts"` above.

### Windows, clipboard and input

By default nothing in this group is restricted, so graphical programs behave normally, with one exception: a command started with `run()` or `Popen()` cannot read the clipboard. Microsoft's MXC defaults are the opposite. The strict value is shown last in each row.

| Setting | Default | Other values |
|---|---|---|
| `NO_WINDOWS` | `False` | `True`: no windows or graphics at all. tkinter, Qt and message boxes fail. Best for command-line tools. |
| `CLIPBOARD` | `None` | `"all"`, `"read"` (paste only), `"write"` (copy only), `"none"`. `None` means `"all"` for `enable()`, so your own program can paste, and `"write"` for `run()` and `Popen()`, so a command you do not trust cannot read what you last copied. |
| `UI_ISOLATION` | `"desktop"` | `"handles"` (cannot reach other programs' windows), `"atoms"` (private atom table), `"container"` (both) |
| `DESKTOP_CONTROL` | `True` | `False`: cannot switch desktops, log off or shut down |
| `SYSTEM_SETTINGS` | `"all"` | `"parameters"`, `"display"`, `"none"`: which system-wide UI settings the program may change |
| `IME` | `True` | `False`: input method editors cannot load into the program |
| `INPUT_INJECTION` | `True` | `False`: cannot send synthetic keys and mouse input |

### Running

| Setting | Default | Meaning |
|---|---|---|
| `TIMEOUT_SECONDS` | `None` | `run()`: stop the command, and everything it started, after this many seconds |
| `ENCODING` | `"utf-8"` | `run()`: how output is decoded. `None` uses the Windows system code page; `"oem"` suits `cmd.exe` built-ins such as `dir`. |
| `HIDE_SECRET_ENV` | `False` | By default the program receives all your environment variables, API keys included. `True` drops the ones whose names look like keys, tokens or passwords. It goes by name only; for untrusted commands, pass `env=` with just what they need. |
| `EXTRA_ENV` | `{}` | Environment variables to add or replace |
| `CONSOLE` | `True` | `enable()`: keep the console. `False` for programs started with `pythonw`. |
| `WAIT_FOR_CHILD_PROCESSES` | `False` | `True`: a run ends only when everything the command started has ended. For launchers that use `start /b` and exit. |
| `EXTRA_CAPABILITIES` | `[]` | Windows AppContainer capability names to add |

### MXC options with no equivalent here

`pymxc.py` drives the Windows process sandbox, which MXC calls `processcontainer`. These MXC settings belong to other parts of MXC: the other backends (`lxc`, `bubblewrap`, `seatbelt`, `wslc`, `isolation_session`, `windows_sandbox`, `microvm`, `hyperlight`), container lifecycle phases, SDK telemetry (this file sends nothing anywhere), the `captureDenials` report, `allowedProxyPeer`, `leastPrivilege` and `fallback.allowDaclMutation`. Windows offers no registry, CPU or memory limits for this sandbox, in MXC or here.

## When the sandbox is not available

`ON_UNAVAILABLE` decides. It applies on Windows builds without the feature and on Linux and macOS alike.

| | `"warn"` (default) | `"silent"` | `"error"` |
|---|---|---|---|
| `enable()` | Warns once on stderr, returns `False`; your program continues unsandboxed | Returns `False` quietly | Prints the reason and exits with the status code |
| `run()` | Warns once, runs the command unsandboxed; `result.sandboxed` is `False` | Same, no warning | Does not run; `result.returncode` is `None`, `result.status` says why |
| `Popen()` | Warns once, returns an ordinary `subprocess.Popen` with `sandboxed = False` | Same, no warning | Raises `SandboxUnavailable` |

Choose `"error"` when running unsandboxed would be unsafe, for example when the command comes from an AI model:

```python
result = pymxc.run(command_from_model, on_unavailable="error")
if result.returncode is None:
    print("Not run:", result.message)
```

A run without the sandbox still follows the settings that apply to it: `hide_secret_env`, `extra_env` and `python_on_path` shape the environment, `READ_WRITE` folders are created, and output is decoded the same way.

Two things never fall back silently, whatever the setting:

- **A bad setting.** `network="intenret"` is an error, not "no sandbox", on every computer.
- **A failed launch.** If the sandbox exists but Windows will not start the program in it, the command is not run outside it instead. You get `LAUNCH_FAILED` and the reason.

## Status codes

`pymxc.Status` is an `IntEnum`. The same numbers are the exit codes of `python pymxc.py` and of `enable()` when it refuses to run.

| Code | Name | Meaning | What to do |
|---|---|---|---|
| 0 | `OK` | The sandbox is available, or the run was sandboxed | |
| 101 | `NOT_WINDOWS` | This is not Windows | Nothing; the sandbox is a Windows feature |
| 102 | `WINDOWS_TOO_OLD` | This Windows build has no sandbox | Install Windows updates (see [Requirements](#requirements)) |
| 103 | `VERSION_UNSUPPORTED` | The sandbox is there, but not at a version this file understands | Get a newer `pymxc.py` |
| 104 | `FEATURE_UNSUPPORTED` | A setting needs something this Windows build lacks, such as `DENY` | Remove the setting, or update Windows |
| 105 | `POLICY_INVALID` | A setting has a bad value | Read `message`; it names the setting |
| 106 | `LAUNCH_FAILED` | Windows refused to create the sandbox or start the program | Read `message`; usually the program's folder is not readable inside the sandbox |
| 107 | `TIMED_OUT` | The command ran longer than `TIMEOUT_SECONDS` and was stopped | |

Where the code appears:

- `pymxc.status().code`
- `result.status` from `run()`. For a run that fell back to no sandbox, it holds the reason (for example `WINDOWS_TOO_OLD`) while `result.returncode` holds the command's own exit code.
- `exception.status` on `SandboxUnavailable`, `PolicyError` and `SandboxLaunchError` (all subclasses of `pymxc.SandboxError`).

## Recipes

**An agent that runs model-written commands**

```python
result = pymxc.run(command, workspace=project_dir, timeout_seconds=120,
                   hide_secret_env=True, on_unavailable="error")
```

**A sandboxed app that may call one LLM API and nothing else**

The complete, runnable version is `examples\llm_api_chat.py`; it takes the host and the model from the `LLM_API_HOST` and `LLM_MODEL` environment variables. It works with any service that uses the OpenAI chat-completions format. Put your service's API host and one of its model names where the placeholders are.

```python
import json, os, urllib.request
import pymxc

API_HOST = "api.example.com"     # <-- your service's API host
MODEL = "your-model-name"        # <-- a model your service offers

# 1. Get the API key BEFORE entering the sandbox. Windows Credential Manager
#    cannot be read inside it; what is in os.environ here is passed along.
if not pymxc.is_sandboxed() and not os.environ.get("LLM_API_KEY"):
    import keyring
    os.environ["LLM_API_KEY"] = keyring.get_password("your-app-name", "api-key") or ""

# 2. Enter the sandbox: read its own folder, plus HTTPS to that one host. Nothing else.
pymxc.enable(network="hosts", network_hosts=[API_HOST])

# 3. Your program. This is the OpenAI chat-completions format.
request = urllib.request.Request(
    f"https://{API_HOST}/v1/chat/completions",
    data=json.dumps({"model": MODEL,
                     "messages": [{"role": "user", "content": "Say hello."}]}).encode(),
    headers={"Authorization": f"Bearer {os.environ['LLM_API_KEY']}",
             "Content-Type": "application/json"})
with urllib.request.urlopen(request, timeout=300) as response:
    print(json.load(response)["choices"][0]["message"]["content"])
```

Notes:

- **The key.** Set `LLM_API_KEY` before starting, or read your saved key above the `enable()` line as shown. Inside the sandbox, Credential Manager returns nothing.
- **Network route.** If the service can only be reached from your organisation's network or VPN, connect to that first. The host filter tries a direct connection first, then your organisation's proxy from `HTTPS_PROXY` or the Windows proxy settings. If neither is set, name it: `network_upstream_proxy="http://your-proxy:8443"`.
- **Proxies that ask for sign-in are not supported.** If your proxy answers HTTP 407, the filter cannot log in to it and reports that. Automatic proxy scripts (PAC/WPAD) are not read either; name the proxy instead.
- **When it does not connect**, pymxc prints why: either `NETWORK_HOSTS blocked a connection to ...` (a host you did not list) or `an allowed host could not be reached: ...` (the route to it failed).
- **Commands the model asks you to run** should get no network and no key, and should not run at all where there is no sandbox: `pymxc.run(command, network="off", hide_secret_env=True, on_unavailable="error")`.

Hosts of some public providers: `["generativelanguage.googleapis.com"]` (Google Gemini), `["api.anthropic.com"]`, `["api.openai.com"]`.

**Let pip install packages inside the sandbox**

```python
pymxc.run("python -m pip install --target .packages requests",
          network="hosts", network_hosts=["pypi.org", "files.pythonhosted.org"])
```

Use `network="intranet"` or `"all"` instead when your package index is on the intranet or behind a VPN. Add `grant_pip_config=True` when pip should use the mirror configured in your `pip.ini`; it is off by default because that file can hold index passwords, which the sandboxed command could then read.

**Give the program a data folder**

```python
pymxc.enable(read_write=["data"])                      # a folder next to the script
pymxc.enable(read_write=[r"C:\work\myapp-data"])       # or anywhere else
```

`enable()` keeps the program's own folder read-only, so this is how the program gets somewhere to save. For `run()` and `Popen()`, where the workspace is writable by default, `workspace_access="ro"` gives the same setup.

**Hide a folder inside the workspace**

```python
pymxc.run(cmd, deny=[".secrets", ".env"])              # relative to the workspace
pymxc.run(cmd, deny=[r"C:\work\project\.secrets"])
```

A listed path that does not exist yet (an `.env` the command might create) is blocked from the moment it appears.

**A program in a virtual environment**

Run your program with the virtual environment's Python as usual; `enable()` restarts it with that same interpreter. The base Python is granted automatically. For `run()` with a *different* environment, grant it: `read_only=[r"C:\work\other\.venv", r"C:\Python312"]`.

**A graphical program started with `pythonw`**

```python
pymxc.enable(console=False)
```

**A batch file**

```python
pymxc.run(r"call build.bat release", list_drive_roots=True)
```

**Only one internal server**

```python
pymxc.run(cmd, network="custom", network_rules=["10.20.30.40:443"], network_private=True)
```

**Change a default for the whole program**

```python
import pymxc
pymxc.NETWORK = "internet"
pymxc.ON_UNAVAILABLE = "error"
pymxc.enable()
```

## What works differently inside the sandbox

- **`python` means the running Python.** On many computers the first `python` on `PATH` is the Microsoft Store alias, which cannot start inside a sandbox ("The system cannot execute the specified program"). `PYTHON_ON_PATH` puts the running interpreter's folder first so `python tool.py` works. The `py` launcher can have the same problem; use `python` or `sys.executable`.
- **Temporary files.** Windows points `TEMP` at a private per-sandbox folder, where `tempfile.mkdtemp()` (and so pip) can fail; on build 26200.9974 it worked. pymxc does not rely on it: it creates a temp folder for each run, grants it, points `TEMP`, `TMP` and Python's `tempfile` at it, and deletes it afterwards. One exception: with `run()` or `Popen()` and a *list* command, the program sees Windows' own temp folder; a Python program can switch with `tempfile.tempdir = os.environ["PYMXC_TEMP"]`.
- **Programs given by full path.** In a command string, `C:\Tools\app.exe arg` is answered by `cmd.exe` with "Access is denied" while `"C:\Tools\app.exe" arg` runs. pymxc adds the quotes for you.
- **Settings folders.** `%APPDATA%` is not writable, and Windows discards the sandbox's own `%LOCALAPPDATA%` afterwards. Keep settings and caches in a `READ_WRITE` folder.
- **Your user profile is invisible.** That includes `~\.gitconfig` (see `GRANT_GIT_CONFIG`), SSH keys and browser data.
- **Saved credentials.** Windows Credential Manager cannot be read, so git credential helpers and `keyring` find nothing. For your own API key, read it before `enable()` as shown under [`enable()`](#1-enable--sandbox-your-whole-program).
- **Some programs cannot start at all:** `conda.exe` and `activate.bat`, Microsoft Store apps, and Office automation. `python -m pip` works.
- **Network errors look like permission errors.** A blocked connection fails with `PermissionError` / WinError 10013. Intranet, VPN and local addresses need `network="intranet"` or `"all"`, not `"internet"`.
- **Environment markers.** Inside, `PYMXC_SANDBOXED` is `1` and `PYMXC_TEMP` holds the temp folder.

When a sandboxed command fails with an access error, `result.message` says so and suggests what to grant.

## Limits you should know

- **Writable folders are fully usable.** A program that may write a folder may also change the code in it, and code that starts outside the sandbox later runs with your full permissions. `enable()` keeps the program's own folder read-only for this reason. `run()` and `Popen()` make their workspace writable by default: when the current folder holds your own program's code, pass a different `workspace=`, or `workspace_access="ro"` with a data folder in `read_write`.
- **Files written inside can be run outside later.** The sandbox contains the program while it runs; it does not vet what it leaves behind.
- **With network access, the program can send out anything it can read.** In every mode except `"off"`, Windows also looks up host names for the program, including public ones under `"intranet"`. The program cannot connect to them, but a name lookup is itself a small message that leaves the computer.
- **`LIST_DRIVE_ROOTS` reveals file names** across the drive, including inside your user profile. It is off by default.
- **`permissiveLearningMode` in `EXTRA_CAPABILITIES` turns enforcement off.** Windows only records. pymxc warns when it is set.
- **Windows only.** On Linux and macOS there is no containment, only the fallback behaviour. MXC's Linux and macOS backends are not used by this file.
- **The Windows API is young.** It arrived in the Windows updates named in [Requirements](#requirements) and may change. `python pymxc.py --selftest` shows whether enforcement works on a given computer.
- **Not included:** a report of what Windows blocked. The capability names for it can be passed in `EXTRA_CAPABILITIES`, but reading the trace is left to Windows' own tools.

## Command line

```
python pymxc.py --probe                  is the sandbox usable here? exit code 0 = yes
python pymxc.py --selftest               check that Windows enforces a policy built by this file
python pymxc.py --run "COMMAND" [options]
```

Options for `--run`:

| Option | Meaning |
|---|---|
| `--workspace DIR` | The folder the command works in (default: current) |
| `--workspace-access rw\|ro` | |
| `--network off\|internet\|intranet\|all\|hosts\|custom` | |
| `--host HOST` | Allow only this HTTPS host, for example `api.example.com`; repeatable. Implies `--network hosts`. |
| `--rule RULE` | Network rule for `--network custom`; repeatable |
| `--proxy URL` | Proxy for `--network custom` |
| `--read-write PATH`, `--read-only PATH`, `--deny PATH` | Repeatable |
| `--no-windows` | The command may not open windows |
| `--timeout SECONDS` | |
| `--required` | Do not run at all if the sandbox is unavailable |

The exit code is the command's own, or a [status code](#status-codes) (101–107) when it did not run or was stopped.

```
python pymxc.py --run "python examples\reach_outside.py"
python pymxc.py --run "python examples\reach_outside.py" --network internet
python pymxc.py --run "python agent.py" --host api.example.com
```

## How it works

MXC on Windows is built on a Windows feature called *process security environments*. Microsoft's MXC SDKs (Rust, .NET, Node) are wrappers around it; there is no Python SDK and no installer. `pymxc.py` calls the same Windows API directly through `ctypes`, which is why nothing needs to be installed.

1. **Probe.** Check that the API set is implemented and that `System32\processmodel.dll` exports the four functions needed, and ask which policy version Windows supports.
2. **Build the policy.** Turn the settings into a small FlatBuffer in Microsoft's published `ProcessSecurityEnvironment.fbs` schema: read-write paths, read-only paths, denied paths, capabilities and network rules. It is built in memory by a small encoder in the file and never written to disk.
3. **Create the environment** with `CreateProcessSecurityEnvironment`.
4. **Start the process suspended** with `CreateProcessW`, attaching the environment and an explicit list of the only handles it may inherit (its standard input and output).
5. **Put it in a job object** that ends every process in it when it is closed, and that carries the clipboard, window and input restrictions. Then resume it.
6. **Clean up** when it exits: close the handles and the environment, delete the temp folder.

Starting a sandboxed process costs a few tens of milliseconds more than an ordinary one.

## What was tested

On Windows 11 25H2 build 26200.9974 with Python 3.12, 3.13 and 3.14:

- `python pymxc.py --selftest`: the encoder produces the reference bytes, and Windows enforces the policy (writes and reads outside denied, deny path wins, network blocked, temp folder works).
- `python -m unittest discover -s tests -v`: 76 tests. They cover file access (read-write, read-only, deny, a deny path that appears later, a single granted file), network off, the host allow-list, loopback, exit codes and arguments, standard input, timeouts stopping the whole process tree, `Popen` streaming and `kill`, `enable()` for a script and for `python -m`, `enable()` keeping the program's own folder read-only, `NO_WINDOWS`, `CLIPBOARD = "none"`, the name-listing switch, temp folder cleanup, every `ON_UNAVAILABLE` mode, and the status codes.
- `enable()` in a real console window, with redirected output, and with captured output.
- `NETWORK = "hosts"` against real servers: with only `generativelanguage.googleapis.com` listed, the Google Gemini endpoint answered, `example.com` was refused, and a direct socket was blocked. pip downloaded a package with only `pypi.org` and `files.pythonhosted.org` listed.

Not tested, so treat with care:

- **Other Windows builds**, including the earliest supported ones, and ARM64.
- **A real Linux or macOS computer.** The fallback was tested by making the module believe it is not on Windows. That includes stopping a timed-out command together with everything it started.
- **Ctrl+C in a real console.** The five seconds a program gets to clean up after Ctrl+C cannot be exercised by the automated tests.
- **`ALLOW_INBOUND`, and `NETWORK_PROXY` with a proxy of your own.** `ALLOW_INBOUND` adds the Windows capability Microsoft's runner uses; whether connections then arrive was not measured. `NETWORK_PROXY` uses the same Windows policy as `"hosts"`, which was tested, but not with an outside proxy. `network="custom"` was checked with single connections: it connects to a listed address and is refused for an unlisted one.
- **`"internet"`, `"intranet"` and `"all"` were measured on one home network** that Windows classes as public, by connecting to public addresses and to the router at `192.168.1.1`: `"internet"` reached only the public addresses, `"intranet"` only the router, `"all"` both, `"off"` neither. A network Windows classes as private, a domain network and IPv6 were not measured. The automated tests only check that Windows accepts each mode, so that they pass offline.
- **A real LLM service with a real key.** `examples\llm_api_chat.py` was run against an OpenAI-format endpoint with a dummy key: the request went through the filter and the server's "invalid key" answer came back. The fall-back to an organisation's proxy was tested with a stand-in proxy, not a real one.
- **The LLM vendors' own SDKs through `"hosts"`.** The test used Python's `urllib` and pip. The SDKs follow the same proxy settings, but none was run here.
- **`DESKTOP_CONTROL`, `SYSTEM_SETTINGS`, `IME`, `INPUT_INJECTION` and `UI_ISOLATION`.** Windows accepts them; their individual effects were not measured.
- **conda environments** and frozen (PyInstaller) programs.

Run the self-test on the computers you care about:

```
python pymxc.py --selftest
```

## Files in this repository

| File | Purpose |
|---|---|
| `pymxc.py` | The module. This is the only file you need to copy. |
| `README.md` | This guide |
| `examples\one_line_app.py` | The one-line integration |
| `examples\show_the_difference.py` | Makes a one-page report of what the sandbox blocks on your computer |
| `examples\llm_api_chat.py` | A sandboxed program that may reach one LLM API and nothing else |
| `examples\run_command.py` | `run()`, timeouts and the strict fallback |
| `examples\custom_policy.py` | A fuller policy and `Popen()` streaming |
| `examples\reach_outside.py` | Prints what is ALLOWED and BLOCKED; run it with and without the sandbox |
| `tests\test_pymxc.py` | The test suite |
| `pymxc_report.html` | A sample of that report, from the computer pymxc was developed on |
| `LICENSE`, `THIRD_PARTY_NOTICES.md` | MIT license; notice for Microsoft's MXC schema |
| `SECURITY.md` | How to report a vulnerability privately |
| `pyproject.toml`, `MANIFEST.in` | Packaging for PyPI. Not needed when you copy `pymxc.py`. |

## Notices

The policy format and the call sequence come from [microsoft/mxc](https://github.com/microsoft/mxc), Copyright (c) Microsoft Corporation, MIT License. No source code from that project is included. See `THIRD_PARTY_NOTICES.md`.

pymxc is not affiliated with Microsoft. `pymxc.py` is released under the MIT License. See `LICENSE`. It comes with no warranty; a sandbox reduces risk and does not remove it.
