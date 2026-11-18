"""pymxc - run Python programs and commands inside a Windows MXC sandbox.

An independent, unofficial project: not made, endorsed or supported by
Microsoft. An early release (version 0.x): settings and behaviour may change.

One file, standard library only, Python 3.12+. Copy ``pymxc.py`` next to your
code. No packages, no installer, no administrator rights, and no changes to
folder permissions: Windows enforces the policy.

QUICK START
-----------
Sandbox your whole program (first line of the script you start)::

    import pymxc; pymxc.enable(read_write=["data"])

Its own folder is read only inside the sandbox; it saves its files in the
folders named in ``read_write`` (here ``data`` next to the script).

If your program uses an API key saved in Windows Credential Manager (keyring),
read it BEFORE that line and put it in ``os.environ``: saved credentials
cannot be read inside the sandbox. See the ``enable()`` docstring.

Sandbox one command your program starts::

    result = pymxc.run("python tool.py")
    print(result.returncode, result.stdout, result.sandboxed)

Stream output, write to stdin, or stop a long-running command::

    proc = pymxc.Popen("python server.py", network="internet")

Ask whether the sandbox works on this computer::

    print(pymxc.status().message)

Every setting in the SETTINGS block below can also be given as a lower-case
keyword argument, for example ``pymxc.run(cmd, network="internet",
read_only=[r"C:\\data"])``.

REQUIREMENTS
------------
Windows 11 24H2 build 26100.9278 or 25H2 build 26200.9278, or later. On
anything else (older Windows, Linux, macOS) this file still imports. By
default ``enable()`` then lets your own program carry on WITHOUT the sandbox
after one warning, while ``run()`` and ``Popen()`` refuse to start a command
unsandboxed. See ``ON_UNAVAILABLE`` to change either.

STATUS CODES (``pymxc.Status``; also the exit code of ``python pymxc.py``)
--------------------------------------------------------------------------
    0    OK                   sandbox available / the run was sandboxed
    101  NOT_WINDOWS          this is not Windows
    102  WINDOWS_TOO_OLD      this Windows build has no sandbox API
    103  VERSION_UNSUPPORTED  the API is present but not at a version this file knows
    104  FEATURE_UNSUPPORTED  a setting needs a feature this Windows build lacks
    105  POLICY_INVALID       a setting has a bad value
    106  LAUNCH_FAILED        Windows refused to create the sandbox or start the program
    107  TIMED_OUT            the command ran longer than TIMEOUT_SECONDS and was stopped

COMMAND LINE
------------
    python pymxc.py --probe
    python pymxc.py --selftest
    python pymxc.py --run "python -c print(1)" --workspace C:\\work\\demo --network internet

HOW IT WORKS
------------
MXC (Microsoft Execution Containers) on Windows is built on "process security
environments". This file calls that Windows API directly through ``ctypes``
(``CreateProcessSecurityEnvironment`` in System32\\processmodel.dll), the same
API Microsoft's own MXC runner uses, so nothing from the MXC SDK has to be
installed. The policy is a small FlatBuffer in Microsoft's published
``ProcessSecurityEnvironment.fbs`` schema, built in memory.

The schema and call sequence come from github.com/microsoft/mxc, Copyright (c)
Microsoft Corporation, MIT License (see THIRD_PARTY_NOTICES.md).
This file: Copyright (c) 2026 Jay-N-J, MIT License (see LICENSE).
"""

from __future__ import annotations

import sys

if sys.version_info < (3, 12):
    raise ImportError("pymxc needs Python 3.12 or newer (this is Python %d.%d)." % sys.version_info[:2])

import codecs
import configparser
import ctypes
import enum
import io
import ipaddress
import locale
import os
import re
import shutil
import signal
import struct
import subprocess
import tempfile
import threading
import time
from ctypes import wintypes
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

__version__ = "0.1.1"

__all__ = [
    "enable", "run", "Popen", "status", "available", "is_sandboxed", "probe",
    "Status", "SandboxStatus", "Result",
    "SandboxError", "SandboxUnavailable", "SandboxLaunchError", "PolicyError",
    "SandboxedPopen", "encode_spec", "parse_rule", "selftest",
]

# =============================================================================
# SETTINGS
# =============================================================================
# Edit the values here, or set them from your code (``pymxc.NETWORK = "internet"``),
# or pass the lower-case name as a keyword argument to enable(), run() or
# Popen() (``network="internet"``). A keyword argument wins over this block.
#
# Each setting shows its default first and every other choice on a commented
# line below it. To switch, comment one line and uncomment another.

# ---- When the sandbox is not available on this computer ---------------------
ON_UNAVAILABLE = None          # None = "warn" for enable() (your own program carries on),
#                              #        "error" for run() and Popen() (a command you do
#                              #        not trust is never started without the sandbox)
# ON_UNAVAILABLE = "warn"      # print one warning, then run WITHOUT the sandbox
# ON_UNAVAILABLE = "silent"    # run without the sandbox and say nothing
# ON_UNAVAILABLE = "error"     # do not run: enable() and Popen() raise SandboxUnavailable,
#                              # run() returns a Result that did not run

# ---- Files ------------------------------------------------------------------
# The workspace is the one folder the program works in.
WORKSPACE = None               # None = the script's folder for enable(),
#                              #        the current folder for run() and Popen()
# WORKSPACE = r"C:\work\project"

WORKSPACE_ACCESS = None        # None = read only for enable(),
#                              #        read and change for run() and Popen()
# WORKSPACE_ACCESS = "rw"      # the program may read and change the workspace
# WORKSPACE_ACCESS = "ro"      # the program may only read the workspace
#
# Why enable() defaults to read only: its workspace is the folder your program's
# code is in, and that code starts OUTSIDE the sandbox every time you launch it.
# A program that could change that folder could make anything run unsandboxed on
# the next start. Give it a data folder in READ_WRITE instead.

READ_WRITE = []                # more folders or files the program may read and change.
#                              # A folder that does not exist yet is created.
# READ_WRITE = ["data"]        # a relative path is relative to the workspace
# READ_WRITE = [r"C:\work\output", r"D:\cache"]

READ_ONLY = []                 # more folders or files the program may only read
# READ_ONLY = [r"C:\data\reference"]

DENY = []                      # blocked even when inside a folder granted above. A path
#                              # that does not exist yet is blocked when it appears
#                              # (the folder it would be in must exist).
# DENY = [".secrets"]          # a relative path is relative to the workspace
# DENY = [r"C:\work\project\.secrets"]

GRANT_PYTHON_RUNTIME = True    # read access to this Python: interpreter, standard
#                              # library, installed packages (needed to run Python)
# GRANT_PYTHON_RUNTIME = False

PYTHON_ON_PATH = True          # "python" in a command means this same Python: its folder
#                              # is put first on PATH. Without this, "python" may find
#                              # the Microsoft Store alias, which cannot start in a sandbox.
# PYTHON_ON_PATH = False       # leave PATH as it is

GRANT_PIP_CONFIG = False       # pip.ini stays unreadable (it can hold index passwords)
# GRANT_PIP_CONFIG = True      # read access to pip.ini and the certificate files it
#                              # names, so pip inside the sandbox uses your package mirror

GRANT_GIT_CONFIG = False       # read access to ~\.gitconfig, ~\.config\git, ~\.condarc
# GRANT_GIT_CONFIG = True

LIST_DRIVE_ROOTS = False       # the program sees only the folders granted above
# LIST_DRIVE_ROOTS = True      # the program may also list file NAMES (not contents)
#                              # anywhere on the drives it uses, including inside your
#                              # user profile. Try it when a command fails with "Access
#                              # is denied" on a path it is allowed to use: batch files
#                              # that use pushd with a full path, and tools that look
#                              # through parent folders, need it.

# ---- Network ----------------------------------------------------------------
NETWORK = "off"                # no network at all
# NETWORK = "internet"         # public internet only: private address ranges are blocked
# NETWORK = "intranet"         # private address ranges only (intranet, VPN, local
#                              # network): no public internet
# NETWORK = "all"              # both: internet plus intranet, VPN and local network
# NETWORK = "hosts"            # only the HTTPS hosts named in NETWORK_HOSTS
# NETWORK = "custom"           # only what NETWORK_RULES or NETWORK_PROXY allow

#
# "Private" means the address ranges reserved for it: 10.x, 172.16-31.x, 192.168.x,
# 169.254.x, 100.64-127.x, and fc00::/7 and fe80::/10 for IPv6. pymxc tells Windows
# these ranges itself, so "internet" and "intranet" mean the same on every network.
# Multicast and broadcast addresses (224.x-239.x, 255.255.255.255, ff00::/8) count as
# private too: they are how programs find and talk to devices on the local network.
# An organisation that uses public address ranges internally is not covered by
# them: list its ranges with NETWORK = "custom", or its servers with "hosts".
# With "intranet" and "all" the program may also accept connections from the
# local network; Windows grants private-network access in both directions only.

NETWORK_HOSTS = []             # used when NETWORK = "hosts": the only web hosts the
#                              # program may reach, by name, over HTTPS (port 443).
#                              # Typical use: an LLM API and nothing else.
# NETWORK_HOSTS = ["api.example.com"]                          # one LLM API: your provider's host
# NETWORK_HOSTS = ["generativelanguage.googleapis.com"]        # Google Gemini API
# NETWORK_HOSTS = ["api.anthropic.com", "api.openai.com"]      # several hosts
# NETWORK_HOSTS = ["*.googleapis.com"]                         # every subdomain (not googleapis.com itself)
# NETWORK_HOSTS = ["pypi.org", "files.pythonhosted.org"]       # pip install
# NETWORK_HOSTS = ["internal.example.com:8443"]                # a port other than 443
#
# How "hosts" works: pymxc runs a small filter in YOUR program, outside the
# sandbox, on 127.0.0.1. Windows lets the sandboxed program connect to that
# filter and to nothing else; the filter passes a connection on only when the
# host is listed. Traffic stays encrypted between the program and the host.
# The program must use the standard proxy settings (HTTPS_PROXY, set for you):
# requests, httpx, urllib, pip and the Google, Anthropic and OpenAI SDKs do.
# Code that opens raw sockets gets no connection at all.

NETWORK_UPSTREAM_PROXY = "auto"   # "hosts" only: how the filter itself reaches the hosts.
#                                 # "auto" tries a direct connection first, then your
#                                 # organisation's proxy as set in HTTPS_PROXY or in
#                                 # Windows' proxy settings.
# NETWORK_UPSTREAM_PROXY = ""     # direct connections only
# NETWORK_UPSTREAM_PROXY = "http://proxy.example.com:8443"   # direct first, then this proxy
#                                 # A proxy that asks for sign-in (HTTP 407) is not supported.

NETWORK_RULES = []           # used when NETWORK = "custom": addresses the program
#                              # may connect to. Numeric addresses only, no host names.
# NETWORK_RULES = ["10.0.0.0/8:443"]             # a range, one TCP port
# NETWORK_RULES = ["192.168.1.5"]                # one address, any port
# NETWORK_RULES = ["tcp 10.1.2.0/24:8000-8100"]  # a range of ports
# NETWORK_RULES = ["udp 10.0.0.53:53", "2001:db8::/32"]

NETWORK_PRIVATE = False        # "custom" only: the rules include intranet/VPN/LAN addresses
# NETWORK_PRIVATE = True

NETWORK_PROXY = ""             # "custom" only: all traffic goes through this proxy of
#                              # your own, which must listen on this computer
#                              # (127.0.0.1). Replaces NETWORK_RULES.
# NETWORK_PROXY = "http://127.0.0.1:8080"

ALLOW_INBOUND = False          # the program may accept incoming connections
# ALLOW_INBOUND = True         # (not with NETWORK "off", "hosts" or a proxy)

ALLOW_LOOPBACK = False         # the program may talk to other programs on this
# ALLOW_LOOPBACK = True        # computer over 127.0.0.1 (same conditions)

# ---- Windows, clipboard and input -------------------------------------------
# The defaults restrict little here: a command started with run() or Popen()
# cannot read the clipboard or reach other programs' windows, and that is all.
# Microsoft's MXC defaults are the opposite (everything in this group locked
# down); the strict choice is marked "MXC".
#
# A program that may open windows can also READ THE SCREEN (take screenshots).
# Only NO_WINDOWS = True stops that.
NO_WINDOWS = False             # the program may open windows
# NO_WINDOWS = True            # MXC: no windows or graphics at all. tkinter, Qt and
#                              # message boxes fail, and so does much else that loads
#                              # the window system: Python's ssl and ctypes modules
#                              # (so no HTTPS from Python, and no pip install), git,
#                              # PowerShell. Plain Python and cmd.exe built-ins still run.

CLIPBOARD = None               # None = "all" for enable() (your own program may paste),
#                              #        "write" for run() and Popen() (a command you do
#                              #        not trust cannot read what you last copied)
# CLIPBOARD = "all"            # the program may read and write the clipboard
# CLIPBOARD = "read"           # may paste from the clipboard, may not copy to it
# CLIPBOARD = "write"          # may copy to the clipboard, may not paste from it
# CLIPBOARD = "none"           # MXC: no clipboard

UI_ISOLATION = None            # None = "desktop" for enable(), "handles" for run() and Popen()
#                              #        (a command you do not trust cannot read the titles
#                              #        of your other windows). A command you allow to paste
#                              #        (CLIPBOARD "all" or "read") gets "desktop": Windows
#                              #        gives clipboard contents only to a program that can
#                              #        reach other programs' windows.
# UI_ISOLATION = "desktop"     # the program may see other programs' windows and their titles
# UI_ISOLATION = "handles"     # cannot see or message windows of other programs, and
#                              # cannot paste what they copied
# UI_ISOLATION = "atoms"       # gets a private atom table (window class / DDE names)
# UI_ISOLATION = "container"   # MXC: both of the above

DESKTOP_CONTROL = True         # the program may switch desktops, log off or shut down
# DESKTOP_CONTROL = False      # MXC: blocked

SYSTEM_SETTINGS = "all"        # the program may change system-wide display and UI settings
# SYSTEM_SETTINGS = "parameters"  # may change UI parameters, not the display mode
# SYSTEM_SETTINGS = "display"     # may change the display mode, not UI parameters
# SYSTEM_SETTINGS = "none"        # MXC: neither

IME = True                     # input method editors may load into the program
# IME = False                  # MXC: blocked

INPUT_INJECTION = True         # the program may send synthetic keys and mouse input
# INPUT_INJECTION = False      # MXC: blocked (SendInput and similar fail)

# ---- Running ----------------------------------------------------------------
TIMEOUT_SECONDS = None         # run(): no time limit
# TIMEOUT_SECONDS = 60         # run(): stop the command and everything it started

ENCODING = "utf-8"             # run(): how output is decoded. Python children are
#                              # told to print UTF-8 (PYTHONIOENCODING) to match.
# ENCODING = None              # use the Windows system code page
# ENCODING = "oem"             # the console code page (cmd.exe built-ins such as dir)

HIDE_SECRET_ENV = False        # the program gets all of your environment variables
# HIDE_SECRET_ENV = True       # drop variables that look like keys, tokens or other secrets.
#                              # It goes by name (and spots sign-in details inside a URL),
#                              # so it can miss one. Variables saved for your user account
#                              # (setx, System Properties) stay readable in the registry.

EXTRA_ENV = {}                 # environment variables to add or replace
# EXTRA_ENV = {"MY_APP_MODE": "sandboxed"}

CONSOLE = True                 # enable(): the program keeps this console, so input()
#                              # and live output work
# CONSOLE = False              # enable(): no console (GUI programs started with pythonw)

WAIT_FOR_CHILD_PROCESSES = False  # a run ends when the command itself ends; anything it
#                                 # left running in the background is stopped
# WAIT_FOR_CHILD_PROCESSES = True # a run ends only when everything it started has ended
#                                 # (for launchers that use "start /b" and exit)

EXTRA_CAPABILITIES = []        # Windows AppContainer capability names to add
# EXTRA_CAPABILITIES = ["learningModeLogging"]     # Windows records what it blocks
# EXTRA_CAPABILITIES = ["permissiveLearningMode"]  # record but do NOT block (no protection)

# ---- MXC options that do not apply here -------------------------------------
# This file drives the Windows process sandbox ("processcontainer" in MXC terms).
# These MXC settings belong to other parts of MXC and have no equivalent here:
#   containment      other backends: lxc, bubblewrap, seatbelt, wslc, isolation_session,
#                    windows_sandbox, microvm, hyperlight
#   lifecycle        provision / start / exec / stop / deprovision of long-lived containers
#   telemetry        MXC SDK telemetry (this file sends nothing anywhere)
#   captureDenials   the JSON report of blocked activity (use EXTRA_CAPABILITIES and
#                    Windows' own tracing instead)
#   allowedProxyPeer, leastPrivilege, fallback.allowDaclMutation
# Windows offers no registry, CPU or memory limits for this sandbox, in MXC or here.

_OPTION_NAMES = (
    "on_unavailable", "workspace", "workspace_access", "read_write", "read_only", "deny",
    "grant_python_runtime", "python_on_path", "grant_pip_config", "grant_git_config", "list_drive_roots",
    "network", "network_hosts", "network_upstream_proxy", "network_rules", "network_private", "network_proxy", "allow_inbound",
    "allow_loopback", "no_windows", "clipboard", "ui_isolation", "desktop_control",
    "system_settings", "ime", "input_injection", "timeout_seconds", "encoding",
    "hide_secret_env", "extra_env", "console", "wait_for_child_processes", "extra_capabilities",
)


# What None means for these settings: (in enable(), in run() and Popen()).
# enable() runs your own program from the folder its code is in; run() and
# Popen() run a command you may not trust in a folder it is meant to work in.
_CALLER_DEFAULTS = {
    "on_unavailable": ("warn", "error"),
    "workspace_access": ("ro", "rw"),
    "clipboard": ("all", "write"),
}
_CLIPBOARD_READERS = ("all", "read")
_WINDOW_ISOLATION = ("handles", "container")


def _options(overrides: dict, own_program: bool = False) -> SimpleNamespace:
    """The settings for one call. ``own_program`` is True for enable()."""
    unknown = sorted(set(overrides) - set(_OPTION_NAMES))
    if unknown:
        raise TypeError(f"unknown pymxc option(s): {', '.join(unknown)}. "
                        f"Valid options: {', '.join(_OPTION_NAMES)}")
    settings = globals()
    opts = SimpleNamespace(**{n: overrides.get(n, settings[n.upper()]) for n in _OPTION_NAMES})
    for name, (for_enable, for_commands) in _CALLER_DEFAULTS.items():
        if getattr(opts, name) is None:
            setattr(opts, name, for_enable if own_program else for_commands)
    if opts.ui_isolation is None:
        # Windows hands clipboard contents only to a program that can reach other
        # programs' windows, so a command that was allowed to paste keeps that reach.
        reach = own_program or opts.clipboard in _CLIPBOARD_READERS
        opts.ui_isolation = "desktop" if reach else "handles"
    return opts


# =============================================================================
# Status codes, results and errors
# =============================================================================

class Status(enum.IntEnum):
    OK = 0
    NOT_WINDOWS = 101
    WINDOWS_TOO_OLD = 102
    VERSION_UNSUPPORTED = 103
    FEATURE_UNSUPPORTED = 104
    POLICY_INVALID = 105
    LAUNCH_FAILED = 106
    TIMED_OUT = 107


@dataclass(frozen=True)
class SandboxStatus:
    """What ``status()`` returns. Truthy when the sandbox can be used."""
    code: Status
    available: bool
    message: str
    version: tuple | None = None      # sandbox policy version Windows supports, e.g. (1, 1)
    support: tuple = ()               # optional features: FileSystemDeny, FileSystemEnumerate, NetworkIngress
    windows_build: str = ""           # e.g. "26200.9974"

    def __bool__(self):
        return self.available


@dataclass
class Result:
    """What ``run()`` returns.

    ``sandboxed`` says whether the command ran inside the sandbox.
    ``returncode`` is the command's exit code, or None if it did not run.
    ``status`` is OK for a sandboxed run, TIMED_OUT when it was stopped, and
    otherwise the reason there was no sandbox. ``message`` explains it.
    """
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    sandboxed: bool = False
    timed_out: bool = False
    status: Status = Status.OK
    message: str = ""
    warnings: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True when the command ran and exited with 0."""
        return self.returncode == 0 and not self.timed_out


class SandboxError(RuntimeError):
    """Base class. ``status`` is the matching ``Status`` code."""
    status = Status.LAUNCH_FAILED


class SandboxUnavailable(SandboxError):
    """This computer does not provide the sandbox."""

    def __init__(self, message, status=Status.WINDOWS_TOO_OLD):
        super().__init__(message)
        self.status = status


class SandboxLaunchError(SandboxError):
    """The API exists, but creating the sandbox or the process failed.
    ``code`` is the Windows error code or HRESULT."""

    def __init__(self, message, code):
        super().__init__(message)
        self.code = code


class PolicyError(SandboxError, ValueError):
    """A setting has a bad value, or needs a feature this Windows build lacks."""

    def __init__(self, message, status=Status.POLICY_INVALID):
        super().__init__(message)
        self.status = status


# =============================================================================
# The policy: a FlatBuffer in the ProcessSecurityEnvironment schema
# =============================================================================
#
# FlatBuffers layout used here (write-only; this file never parses input):
# - buffer = uoffset to the root table, then the 4-byte identifier "PSEC";
# - a uoffset (u32) is relative to its own position and points forward, so
#   every object is laid out before the objects it references;
# - a table starts with an soffset (i32) = table_pos - vtable_pos; the vtable
#   holds its size, the table's inline size, and one u16 offset per field slot
#   (0 = absent, the reader uses the schema default);
# - strings: u32 length, UTF-8 bytes, NUL; vectors: u32 count, elements;
#   scalars little-endian at natural alignment.
#
# Root table slots (schema order): 0 version (struct u16,u16, required),
# 1 capabilities (comma-separated string), 2 disallow_win32k_system_calls,
# 3 ui_restrictions (u64), 4 fs_read_write, 5 fs_read_only, 6 fs_deny,
# 7 network_policy, 8 fs_enumerate (1.1).

_IDENTIFIER = b"PSEC"
_PROTOCOLS = {"any": 0, "tcp": 1, "udp": 2, "icmpv4": 3, "icmpv6": 4}
_SCALARS = {"u8": ("B", 1), "bool": ("B", 1), "u16": ("H", 2), "u64": ("Q", 8)}


class _Table:
    __slots__ = ("fields",)

    def __init__(self, fields):
        self.fields = [f for f in fields if f[2] is not None]


class _Str:
    __slots__ = ("data",)

    def __init__(self, text: str):
        if not isinstance(text, str):
            raise TypeError(f"expected str, got {type(text).__name__}")
        if "\x00" in text:
            raise ValueError("strings in a policy cannot contain NUL")
        self.data = text.encode("utf-8")


class _Vec:
    __slots__ = ("items",)

    def __init__(self, items):
        self.items = list(items)


class _Writer:
    def __init__(self):
        self.buf = bytearray()

    def align(self, n):
        self.buf += b"\x00" * ((-len(self.buf)) % n)

    def put(self, fmt, *values):
        pos = len(self.buf)
        self.buf += struct.pack("<" + fmt, *values)
        return pos

    def patch(self, at, target):
        if target <= at:
            raise AssertionError("uoffset must point forward")
        struct.pack_into("<I", self.buf, at, target - at)

    def emit(self, obj):
        if isinstance(obj, _Table):
            return self._table(obj)
        if isinstance(obj, _Str):
            self.align(4)
            pos = self.put("I", len(obj.data))
            self.buf += obj.data + b"\x00"
            return pos
        if isinstance(obj, _Vec):
            self.align(4)
            pos = self.put("I", len(obj.items))
            slots = [self.put("I", 0) for _ in obj.items]
            for slot, item in zip(slots, obj.items):
                self.patch(slot, self.emit(item))
            return pos
        raise TypeError(f"cannot encode {type(obj).__name__}")

    def _table(self, table):
        nslots = 1 + max((slot for slot, _, _ in table.fields), default=-1)
        vt_size = 4 + 2 * nslots
        self.align(2)
        vt_pos = len(self.buf)
        self.buf += b"\x00" * vt_size
        self.align(8)  # u64 is the widest inline scalar in this schema
        table_pos = self.put("i", 0)
        refs = []
        for slot, kind, value in table.fields:
            if kind == "ref":
                self.align(4)
                at = self.put("I", 0)
                refs.append((at, value))
            elif kind == "version":
                self.align(2)
                at = self.put("HH", *value)
            else:
                fmt, size = _SCALARS[kind]
                self.align(size)
                at = self.put(fmt, int(value))
            struct.pack_into("<H", self.buf, vt_pos + 4 + 2 * slot, at - table_pos)
        struct.pack_into("<HH", self.buf, vt_pos, vt_size, len(self.buf) - table_pos)
        struct.pack_into("<i", self.buf, table_pos, table_pos - vt_pos)
        for at, child in refs:
            self.patch(at, self.emit(child))
        return table_pos


def _strings(paths):
    items = [str(p) for p in (paths or ()) if p]
    return _Vec(_Str(p) for p in items) if items else None


def _action(value):
    """FilterAction byte (deny 0 is the schema default, so it is omitted)."""
    code = {"deny": 0, "allow": 1}[value] if isinstance(value, str) else int(value)
    return code or None


def _subnet(spec):
    # Always write the prefix length: Windows reads a missing one as /0, every address.
    try:
        network = ipaddress.ip_network(str(spec).strip(), strict=False)
    except ValueError:
        raise ValueError(f"'{spec}' is not an address or range (examples: 10.0.0.0/8, 192.168.1.5)") from None
    return _Table([(0, "ref", _Str(str(network.network_address))), (1, "u8", network.prefixlen)])


def _endpoint_rule(rule):
    destinations = []
    for d in rule.get("destinations", ()):
        subnet, excluded = (d.get("subnet"), d.get("except") or ()) if isinstance(d, dict) else (d, ())
        destinations.append(_Table([
            (0, "ref", _subnet(subnet)),
            (1, "ref", _Vec(_subnet(x) for x in excluded) if excluded else None),
        ]))
    ports = [_Table([
        (0, "u8", _PROTOCOLS[p.get("protocol", "any")] or None),
        (1, "u16", p.get("port") or None),
        (2, "u16", p.get("end_port") or None),
    ]) for p in rule.get("ports", ())]
    return _Table([(0, "ref", _Vec(destinations) if destinations else None),
                   (1, "ref", _Vec(ports) if ports else None)])


def _network_policy(network):
    network = network or {}
    # "peer" names who the program may reach over loopback; Microsoft's runner
    # sends "MXC-Loopback" for a host program that has no package identity.
    peer = (2, "ref", _Str(network["peer"]) if network.get("peer") else None)
    if network.get("proxy"):
        # Proxy and direct egress are mutually exclusive in this schema.
        return _Table([(0, "ref", _Table([(0, "ref", _Str(network["proxy"]))])), peer])
    allow, deny = network.get("allow") or (), network.get("deny") or ()
    egress = _Table([
        (0, "u8", _action(network.get("egress", "deny"))),
        (1, "ref", _Vec(_endpoint_rule(r) for r in allow) if allow else None),
        (2, "ref", _Vec(_endpoint_rule(r) for r in deny) if deny else None),
    ])
    fields = [(1, "ref", egress), peer]
    ingress = network.get("ingress")
    if ingress:
        fields.append((3, "ref", _Table([
            (0, "u8", _action(ingress.get("default", "deny"))),
            (1, "u8", _action(ingress.get("host_loopback", "deny"))),
        ])))
    return _Table(fields)


def encode_spec(*, read_write=(), read_only=(), deny=(), enumerate_paths=(),
                capabilities=(), network=None, disallow_win32k=False,
                ui_restrictions=0, version=None) -> bytes:
    """Low level: the policy bytes for ``CreateProcessSecurityEnvironment``.

    Most callers never need this; ``run()``, ``Popen()`` and ``enable()``
    build the policy from the settings. ``network`` is ``{"egress": "deny"}``
    (default), ``{"egress": "allow"}``, egress with ``allow``/``deny`` rules
    (``{"destinations": ["10.0.0.0/8"], "ports": [{"protocol": "tcp",
    "port": 443}]}``), optional ``ingress``, or ``{"proxy": "http://host:port"}``.
    ``version`` defaults to 1.1 when a 1.1 field is used (``enumerate_paths``
    or ``ingress``), else 1.0.
    """
    if version is None:
        uses_1_1 = any(enumerate_paths or ()) or bool((network or {}).get("ingress"))
        version = (1, 1) if uses_1_1 else (1, 0)
    caps = ",".join(c for c in capabilities if c)
    root = _Table([
        (0, "version", tuple(version)),
        (1, "ref", _Str(caps) if caps else None),
        (2, "bool", True if disallow_win32k else None),
        (3, "u64", ui_restrictions or None),
        (4, "ref", _strings(read_write)),
        (5, "ref", _strings(read_only)),
        (6, "ref", _strings(deny)),
        (7, "ref", _network_policy(network)),
        (8, "ref", _strings(enumerate_paths)),
    ])
    w = _Writer()
    w.put("I", 0)
    w.buf += _IDENTIFIER
    w.patch(0, w.emit(root))
    w.align(8)
    return bytes(w.buf)


# =============================================================================
# The Windows API (processmodel.dll, kernel32.dll) through ctypes
# =============================================================================

_API_SET = b"api-win-appmodel-processmodel~securityenvironment"
_EXPORTS = ("CreateProcessSecurityEnvironment", "QueryProcessSecurityEnvironmentSupport",
            "IsProcessSecurityEnvironmentVersionSupported", "CloseProcessSecurityEnvironment")
_SUPPORT_FLAGS = {0x1: "FileSystemDeny", 0x4: "FileSystemEnumerate", 0x8: "NetworkIngress"}
_MIN_BUILDS = ("Windows 11 24H2 build 26100.9278, 25H2 build 26200.9278, 26H1 build 28000.2804 "
               "or 26H2 build 26300.9550")

_LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800
_ATTR_HANDLE_LIST = 0x00020002
_ATTR_SECURITY_ENVIRONMENT = 35 | 0x00020000
_EXTENDED_STARTUPINFO_PRESENT = 0x00080000
_CREATE_SUSPENDED = 0x00000004
_CREATE_NO_WINDOW = 0x08000000
_CREATE_NEW_CONSOLE = 0x00000010
_CREATE_UNICODE_ENVIRONMENT = 0x00000400
_STARTF_USESTDHANDLES = 0x00000100
_HANDLE_FLAG_INHERIT = 0x00000001
_DUPLICATE_SAME_ACCESS = 0x00000002
_INFINITE = 0xFFFFFFFF
_WAIT_TIMEOUT = 0x00000102
_JOB_BASIC_ACCOUNTING_INFO = 1
_JOB_BASIC_UI_RESTRICTIONS = 4
_JOB_EXTENDED_LIMIT_INFO = 9
_JOB_KILL_ON_JOB_CLOSE = 0x00002000
_INVALID_HANDLE = ctypes.c_void_p(-1).value

# JOB_OBJECT_UILIMIT_* bits (winnt.h), set from the "Windows, clipboard and input" settings.
UI_HANDLES = 0x0001
UI_READCLIPBOARD = 0x0002
UI_WRITECLIPBOARD = 0x0004
UI_SYSTEMPARAMETERS = 0x0008
UI_DISPLAYSETTINGS = 0x0010
UI_GLOBALATOMS = 0x0020
UI_DESKTOP = 0x0040
UI_EXITWINDOWS = 0x0080
UI_IME = 0x0100
UI_INJECTION = 0x0200

# Address ranges reserved for private use: RFC 1918, link-local, carrier-grade NAT
# (also used by some VPNs), and IPv6 unique-local and link-local. Multicast and
# broadcast belong here too: they never leave the local network, and without them
# "internet" lets a program discover local devices (SSDP, mDNS) and hear their answers.
_PRIVATE_RANGES = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10",
                   "224.0.0.0/4", "255.255.255.255/32",
                   "fc00::/7", "fe80::/10", "ff00::/8")

INTERNET = "internetClient"
PRIVATE_NETWORK = "privateNetworkClientServer"
LOOPBACK = "networkLoopback"
_LOOPBACK_PEER = "MXC-Loopback"


class _STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.c_void_p), ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE),
    ]


class _STARTUPINFOEXW(ctypes.Structure):
    _fields_ = [("StartupInfo", _STARTUPINFOW), ("lpAttributeList", ctypes.c_void_p)]


class _PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]


class _SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                ("bInheritHandle", wintypes.BOOL)]


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = [(n, ctypes.c_uint64) for n in (
        "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
        "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class _JOB_BASIC_LIMITS(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _JOB_ACCOUNTING(ctypes.Structure):
    _fields_ = [("TotalUserTime", ctypes.c_int64), ("TotalKernelTime", ctypes.c_int64),
                ("ThisPeriodTotalUserTime", ctypes.c_int64), ("ThisPeriodTotalKernelTime", ctypes.c_int64),
                ("TotalPageFaultCount", wintypes.DWORD), ("TotalProcesses", wintypes.DWORD),
                ("ActiveProcesses", wintypes.DWORD), ("TotalTerminatedProcesses", wintypes.DWORD)]


class _JOB_EXTENDED_LIMITS(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JOB_BASIC_LIMITS), ("IoInfo", _IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


_k32 = ctypes.WinDLL("kernel32", use_last_error=True) if sys.platform == "win32" else None


def _sig(name, argtypes, restype=wintypes.BOOL):
    fn = getattr(_k32, name)
    fn.argtypes, fn.restype = argtypes, restype
    return fn


if _k32 is not None:
    _LoadLibraryExW = _sig("LoadLibraryExW", [wintypes.LPCWSTR, wintypes.HANDLE, wintypes.DWORD], wintypes.HMODULE)
    _GetProcAddress = _sig("GetProcAddress", [wintypes.HMODULE, ctypes.c_char_p], ctypes.c_void_p)
    _CreatePipe = _sig("CreatePipe", [ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(wintypes.HANDLE),
                                      ctypes.c_void_p, wintypes.DWORD])
    _SetHandleInformation = _sig("SetHandleInformation", [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD])
    _InitAttrList = _sig("InitializeProcThreadAttributeList",
                         [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_size_t)])
    _UpdateAttr = _sig("UpdateProcThreadAttribute",
                       [ctypes.c_void_p, wintypes.DWORD, ctypes.c_size_t, ctypes.c_void_p,
                        ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p])
    _DeleteAttrList = _sig("DeleteProcThreadAttributeList", [ctypes.c_void_p], None)
    _CreateProcessW = _sig("CreateProcessW", [
        wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, wintypes.BOOL,
        wintypes.DWORD, ctypes.c_void_p, wintypes.LPCWSTR, ctypes.POINTER(_STARTUPINFOEXW),
        ctypes.POINTER(_PROCESS_INFORMATION)])
    _CreateJobObjectW = _sig("CreateJobObjectW", [ctypes.c_void_p, wintypes.LPCWSTR], wintypes.HANDLE)
    _SetInformationJobObject = _sig("SetInformationJobObject",
                                    [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD])
    _AssignProcessToJobObject = _sig("AssignProcessToJobObject", [wintypes.HANDLE, wintypes.HANDLE])
    _QueryInformationJobObject = _sig("QueryInformationJobObject",
                                      [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
                                       ctypes.c_void_p])
    _TerminateJobObject = _sig("TerminateJobObject", [wintypes.HANDLE, wintypes.UINT])
    _TerminateProcess = _sig("TerminateProcess", [wintypes.HANDLE, wintypes.UINT])
    _ResumeThread = _sig("ResumeThread", [wintypes.HANDLE], wintypes.DWORD)
    _WaitForSingleObject = _sig("WaitForSingleObject", [wintypes.HANDLE, wintypes.DWORD], wintypes.DWORD)
    _GetExitCodeProcess = _sig("GetExitCodeProcess", [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)])
    _CloseHandle = _sig("CloseHandle", [wintypes.HANDLE])
    _GetStdHandle = _sig("GetStdHandle", [wintypes.DWORD], wintypes.HANDLE)
    _GetCurrentProcess = _sig("GetCurrentProcess", [], wintypes.HANDLE)
    _DuplicateHandle = _sig("DuplicateHandle", [wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE,
                                                ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD,
                                                wintypes.BOOL, wintypes.DWORD])
    _CreateFileW = _sig("CreateFileW", [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                                        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE], wintypes.HANDLE)
    _GetConsoleWindow = _sig("GetConsoleWindow", [], wintypes.HWND)
    _OpenProcess = _sig("OpenProcess", [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE)


def _check(ok, what):
    if not ok:
        code = ctypes.get_last_error()
        raise SandboxLaunchError(f"{what} failed: {ctypes.FormatError(code).strip()} ({code})", code)


class _Api:
    def __init__(self, hmod):
        def fn(name, restype, *args):
            return ctypes.WINFUNCTYPE(restype, *args)(_GetProcAddress(hmod, name.encode()))

        self.create = fn("CreateProcessSecurityEnvironment", ctypes.c_long,
                         ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE))
        self.close = fn("CloseProcessSecurityEnvironment", None, wintypes.HANDLE)
        self.query = fn("QueryProcessSecurityEnvironmentSupport", ctypes.c_long,
                        ctypes.POINTER(ctypes.c_uint64))
        self.version = fn("IsProcessSecurityEnvironmentVersionSupported", ctypes.c_long,
                          wintypes.DWORD, ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(wintypes.DWORD))


_api_lock = threading.Lock()
_api_cache: list = []
_probe_cache: list = []


def probe() -> dict:
    """Low level: what this Windows provides. Read-only; creates nothing.

    ``available`` is True when the API set is implemented, ``processmodel.dll``
    exports all four functions, and policy major version 1 is supported.
    ``version`` is (1, minor). Never raises; on other systems everything is False.
    ``status()`` gives the same answer with a code and a message.
    """
    if _probe_cache:
        return dict(_probe_cache[0])
    result = {"api_set": False, "exports": {}, "version": None, "support": [], "available": False}
    if _k32 is None:
        return result
    try:
        apiq = ctypes.WinDLL("api-ms-win-core-apiquery-l2-1-0")
        apiq.IsApiSetImplemented.argtypes = [ctypes.c_char_p]
        apiq.IsApiSetImplemented.restype = wintypes.BOOL
        result["api_set"] = bool(apiq.IsApiSetImplemented(_API_SET))
        hmod = _LoadLibraryExW("processmodel.dll", None, _LOAD_LIBRARY_SEARCH_SYSTEM32)
        if not hmod:
            return result
        result["exports"] = {n: bool(_GetProcAddress(hmod, n.encode())) for n in _EXPORTS}
        if result["api_set"] and all(result["exports"].values()):
            api = _Api(hmod)
            avail, minor = ctypes.c_ubyte(0), wintypes.DWORD(0)
            if api.version(1, ctypes.byref(avail), ctypes.byref(minor)) >= 0 and avail.value:
                result["version"] = (1, minor.value)
            flags = ctypes.c_uint64(0)
            if api.query(ctypes.byref(flags)) >= 0:
                result["support"] = [n for bit, n in _SUPPORT_FLAGS.items() if flags.value & bit]
            result["available"] = result["version"] is not None
    except (OSError, AttributeError):
        return result  # a broken probe means "not available", never a crash
    _probe_cache.append(result)
    return dict(result)


def _windows_build() -> str:
    if sys.platform != "win32":
        return ""
    build = str(sys.getwindowsversion().build)
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
            return f"{build}.{winreg.QueryValueEx(key, 'UBR')[0]}"
    except OSError:
        return build


def status() -> SandboxStatus:
    """Can the sandbox be used on this computer, and if not, why? Never raises."""
    if sys.platform != "win32":
        return SandboxStatus(Status.NOT_WINDOWS, False,
                             f"The MXC sandbox is a Windows feature; this is {sys.platform}.")
    info, build = probe(), _windows_build()
    support = tuple(info["support"])
    if info["available"]:
        version = tuple(info["version"])
        return SandboxStatus(Status.OK, True,
                             f"The Windows sandbox is available (policy version {version[0]}.{version[1]}, "
                             f"Windows build {build}).", version, support, build)
    if info["api_set"] and info["exports"] and all(info["exports"].values()):
        return SandboxStatus(Status.VERSION_UNSUPPORTED, False,
                             f"Windows build {build} has the sandbox API, but not policy version 1, "
                             f"which this version of pymxc needs.", None, support, build)
    return SandboxStatus(Status.WINDOWS_TOO_OLD, False,
                         f"Windows build {build} does not provide the sandbox. It needs {_MIN_BUILDS}, "
                         f"or later. Install the latest Windows updates.", None, support, build)


def available() -> bool:
    """True when the sandbox can be used on this computer."""
    return probe()["available"]


def _api():
    with _api_lock:
        if not _api_cache:
            current = status()
            if not current.available:
                raise SandboxUnavailable(current.message, current.code)
            _api_cache.append(_Api(_LoadLibraryExW("processmodel.dll", None, _LOAD_LIBRARY_SEARCH_SYSTEM32)))
        return _api_cache[0]


def _env_block(env):
    if env is None:
        return None
    # Each entry ends with NUL and the block with one more; an empty block is two NULs.
    text = ("".join(f"{k}={v}\0" for k, v in sorted(env.items(), key=lambda kv: kv[0].upper())) or "\0") + "\0"
    return ctypes.create_unicode_buffer(text, len(text))


def _pipe():
    """(parent read end, inheritable child write end)."""
    read, write = wintypes.HANDLE(), wintypes.HANDLE()
    _check(_CreatePipe(ctypes.byref(read), ctypes.byref(write), None, 0), "CreatePipe")
    _check(_SetHandleInformation(write, _HANDLE_FLAG_INHERIT, _HANDLE_FLAG_INHERIT), "SetHandleInformation")
    return read, write


def _inheritable_std_handle(which: int, write: bool):
    """An inheritable copy of this process's stdin/stdout/stderr, or of NUL when
    this process has none (pythonw)."""
    current = _GetCurrentProcess()
    source = _GetStdHandle(which)
    copy = wintypes.HANDLE()
    if source and source != _INVALID_HANDLE and _DuplicateHandle(
            current, source, current, ctypes.byref(copy), 0, True, _DUPLICATE_SAME_ACCESS):
        return copy
    attrs = _SECURITY_ATTRIBUTES(ctypes.sizeof(_SECURITY_ATTRIBUTES), None, True)
    access = 0x40000000 if write else 0x80000000  # GENERIC_WRITE / GENERIC_READ
    handle = _CreateFileW("NUL", access, 0x3, ctypes.byref(attrs), 3, 0, None)  # share rw, OPEN_EXISTING
    _check(handle and handle != _INVALID_HANDLE, "CreateFileW(NUL)")
    return wintypes.HANDLE(handle)


_TEARDOWN_WAIT_SECONDS = 5.0


def _job_active_processes(job) -> int:
    if not job:
        return 0
    info = _JOB_ACCOUNTING()
    if not _QueryInformationJobObject(job, _JOB_BASIC_ACCOUNTING_INFO, ctypes.byref(info),
                                      ctypes.sizeof(info), None):
        return 0
    return int(info.ActiveProcesses)


def command_line(command: str, temp_dir: str | None = None) -> str:
    """The cmd.exe line, as ``subprocess.Popen(shell=True)`` builds it.

    Windows points TEMP/TMP of a sandboxed process at its own per-sandbox
    folder whatever the environment block says. On some builds
    ``tempfile.mkdtemp`` (and so pip) cannot write inside folders it creates
    there (on 26200.9974 it can), so ``temp_dir`` (a read-write path in the
    policy) resets TEMP/TMP first and nothing depends on it. Programs started by
    the command see it; ``%TEMP%`` typed in the command itself still expands
    to the old value.
    """
    if temp_dir:
        command = f'set "TEMP={temp_dir}" & set "TMP={temp_dir}" & {command}'
    comspec = os.environ.get("ComSpec", r"C:\Windows\System32\cmd.exe")
    return f'{comspec} /c "{command}"'


class SandboxedPopen:
    """Low level: start ``command`` inside a sandbox described by ``spec`` bytes.

    ``pymxc.Popen()`` is the easy way to get one of these. It behaves like the
    common parts of ``subprocess.Popen``: ``stdout``, ``stderr`` (pipes, text
    or binary; ``merge_stderr`` sends both to ``stdout``), ``stdin`` (when
    ``stdin=True``), ``pid``, ``poll()``, ``wait(timeout)``, ``kill()``,
    ``returncode``. ``kill`` ends the whole process tree. ``sandboxed`` is True.

    ``shell=True`` (default) runs ``command`` through ``cmd.exe /c``;
    ``shell=False`` takes ``command`` as the complete command line of a
    program (build it with ``subprocess.list2cmdline``), so ``&`` or quotes in
    arguments are never interpreted. ``temp_dir`` needs ``shell=True``.

    Standard input and output, first match wins: ``new_console=True`` gives
    the program a console window of its own; ``console=True`` shares this
    console (keyboard and live output work); ``inherit_stdio=True`` hands the
    program this process's own stdin/stdout/stderr, wherever they point;
    otherwise pipes, with stdin closed unless ``stdin=True``.

    ``wait_for_tree=True`` treats the run as over only when every process the
    program started has ended too. ``ui_limits`` is a mask of ``UI_*`` bits.
    ``on_exit`` is called once, after the exit has been collected.

    Sequence (as Microsoft's own runner does it): CreateProcessSecurityEnvironment
    -> CreateProcessW suspended with the security-environment attribute (and a
    handle list holding only the child's stdio) -> assign to a kill-on-close
    job -> resume.
    """

    sandboxed = True

    def __init__(self, command, *, cwd, spec: bytes, env: dict | None = None,
                 temp_dir: str | None = None, text=True, encoding=None, errors="replace",
                 merge_stderr=False, shell=True, console=False, new_console=False,
                 inherit_stdio=False, stdin=False, wait_for_tree=False, ui_limits=0, on_exit=None):
        import msvcrt

        if temp_dir and not shell:
            raise ValueError("temp_dir needs shell=True; with shell=False set TEMP in the program")
        self.args = command
        self.returncode = None
        self.stdout = self.stderr = self.stdin = None
        self.pid = None
        self.warnings: list = []
        self._wait_for_tree = wait_for_tree
        self._on_exit = on_exit
        self._first_code = None
        self._released = False
        console = console or new_console  # either way: the console provides stdio
        pipes = not console and not inherit_stdio
        self._job = None
        self._pi = _PROCESS_INFORMATION()
        self._lock = threading.Lock()
        self._environment = wintypes.HANDLE()
        self._api = _api()
        buf = ctypes.create_string_buffer(spec, len(spec))
        hr = self._api.create(buf, len(spec), 0, ctypes.byref(self._environment))
        if hr < 0:
            raise SandboxLaunchError(f"CreateProcessSecurityEnvironment failed: HRESULT 0x{hr & 0xFFFFFFFF:08X}",
                                     hr & 0xFFFFFFFF)
        if not self._environment:  # success without a sandbox to attach: never start the program
            raise SandboxLaunchError("CreateProcessSecurityEnvironment failed: it reported success "
                                     "but returned no sandbox (HRESULT 0x8000FFFF)", 0x8000FFFF)
        child_ends, parent_ends, attrs, out_r, err_r, in_w = [], [], None, None, None, None
        try:
            stdio = None
            if pipes:
                out_r, out_w = _pipe()
                parent_ends.append(out_r)
                child_ends.append(out_w)
                if merge_stderr:
                    err_w = out_w
                else:
                    err_r, err_w = _pipe()
                    parent_ends.append(err_r)
                    child_ends.append(err_w)
                in_r, in_w = _pipe()
                _check(_SetHandleInformation(in_w, _HANDLE_FLAG_INHERIT, 0), "SetHandleInformation")
                _check(_SetHandleInformation(in_r, _HANDLE_FLAG_INHERIT, _HANDLE_FLAG_INHERIT),
                       "SetHandleInformation")
                if stdin:
                    parent_ends.append(in_w)
                else:
                    _CloseHandle(in_w)  # the child sees end-of-file at once
                    in_w = None
                child_ends.append(in_r)
                stdio = (in_r, out_w, err_w)
            elif not console:
                stdio = tuple(_inheritable_std_handle(which, write)
                              for which, write in ((-10 & 0xFFFFFFFF, False), (-11 & 0xFFFFFFFF, True),
                                                   (-12 & 0xFFFFFFFF, True)))
                child_ends.extend(stdio)

            count = 2 if stdio else 1
            size = ctypes.c_size_t(0)
            _InitAttrList(None, count, 0, ctypes.byref(size))
            attrs = ctypes.create_string_buffer(size.value)
            _check(_InitAttrList(attrs, count, 0, ctypes.byref(size)), "InitializeProcThreadAttributeList")
            env_handle = wintypes.HANDLE(self._environment.value)
            _check(_UpdateAttr(attrs, 0, _ATTR_SECURITY_ENVIRONMENT, ctypes.byref(env_handle),
                               ctypes.sizeof(wintypes.HANDLE), None, None),
                   "UpdateProcThreadAttribute(SecurityEnvironment)")
            si = _STARTUPINFOEXW()
            si.StartupInfo.cb = ctypes.sizeof(_STARTUPINFOEXW)
            if stdio:
                unique = list({h.value: h for h in stdio}.values())
                inherit = (wintypes.HANDLE * len(unique))(*unique)
                _check(_UpdateAttr(attrs, 0, _ATTR_HANDLE_LIST, inherit, ctypes.sizeof(inherit), None, None),
                       "UpdateProcThreadAttribute(HandleList)")
                si.StartupInfo.dwFlags = _STARTF_USESTDHANDLES
                si.StartupInfo.hStdInput, si.StartupInfo.hStdOutput, si.StartupInfo.hStdError = stdio
            si.lpAttributeList = ctypes.cast(attrs, ctypes.c_void_p)

            line = ctypes.create_unicode_buffer(command_line(command, temp_dir) if shell else str(command))
            block = _env_block(env)
            flags = (_CREATE_SUSPENDED | _EXTENDED_STARTUPINFO_PRESENT
                     | (_CREATE_NEW_CONSOLE if new_console else _CREATE_NO_WINDOW if pipes else 0)
                     | (_CREATE_UNICODE_ENVIRONMENT if block is not None else 0))
            # With a shared console no handles are inherited: the child attaches to it.
            _check(_CreateProcessW(None, line, None, None, bool(stdio), flags, block, str(cwd),
                                   ctypes.byref(si), ctypes.byref(self._pi)), "CreateProcessW")
            self.pid = self._pi.dwProcessId

            self._job = _CreateJobObjectW(None, None)
            _check(self._job, "CreateJobObjectW")
            limits = _JOB_EXTENDED_LIMITS()
            limits.BasicLimitInformation.LimitFlags = _JOB_KILL_ON_JOB_CLOSE
            _check(_SetInformationJobObject(self._job, _JOB_EXTENDED_LIMIT_INFO,
                                            ctypes.byref(limits), ctypes.sizeof(limits)),
                   "SetInformationJobObject")
            if ui_limits:
                mask = wintypes.DWORD(ui_limits)
                _check(_SetInformationJobObject(self._job, _JOB_BASIC_UI_RESTRICTIONS,
                                                ctypes.byref(mask), ctypes.sizeof(mask)),
                       "SetInformationJobObject(UIRestrictions)")
            _check(_AssignProcessToJobObject(self._job, self._pi.hProcess), "AssignProcessToJobObject")
            # A program that stays suspended would never exit: treat it as a failed launch.
            _check(_ResumeThread(self._pi.hThread) != 0xFFFFFFFF, "ResumeThread")
        except BaseException:
            for h in parent_ends:
                _CloseHandle(h)
            if self._pi.hProcess:
                _TerminateProcess(self._pi.hProcess, 1)  # created suspended, never resumed
            self.returncode = -1
            self._release()
            raise
        finally:
            for h in child_ends:  # the parent must not hold them, or reads never see EOF
                _CloseHandle(h)
            if attrs is not None:
                _DeleteAttrList(attrs)

        enc = encoding or locale.getpreferredencoding(False)

        def stream(handle):
            raw = os.fdopen(msvcrt.open_osfhandle(handle.value, os.O_RDONLY), "rb")
            return io.TextIOWrapper(raw, encoding=enc, errors=errors) if text else raw

        if out_r is not None:
            self.stdout = stream(out_r)
        if err_r is not None:
            self.stderr = stream(err_r)
        if in_w is not None:
            raw = os.fdopen(msvcrt.open_osfhandle(in_w.value, 0), "wb", buffering=0)
            self.stdin = io.TextIOWrapper(raw, encoding=enc, errors=errors, write_through=True) if text else raw

    def poll(self):
        """The exit code, or None while the program is still running."""
        return self._wait_ms(0)

    def wait(self, timeout=None):
        """Wait for the exit code. Raises ``subprocess.TimeoutExpired`` on timeout."""
        deadline = None if timeout is None else time.monotonic() + max(0.0, timeout)
        while True:
            # Short slices: the lock is never held for long, so kill() from
            # another thread and Ctrl+C both get through.
            left = 200 if deadline is None else max(0, min(200, int((deadline - time.monotonic()) * 1000)))
            code = self._wait_ms(left)
            if code is not None:
                return code
            if deadline is not None and time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(self.args, timeout)

    def _wait_ms(self, ms):
        with self._lock:
            if self.returncode is not None:
                return self.returncode
            if self._first_code is None:
                if _WaitForSingleObject(self._pi.hProcess, ms) == _WAIT_TIMEOUT:
                    return None
                code = wintypes.DWORD(0)
                _GetExitCodeProcess(self._pi.hProcess, ctypes.byref(code))
                self._first_code = code.value
                ms = 0
            still_running = self._wait_for_tree and self.active_processes() > 0
            if not still_running:
                self.returncode = self._first_code
        if still_running:
            if ms:  # the first process is gone, so there is no handle to wait on
                time.sleep(min(ms, 100) / 1000.0)
            return None
        self._release()
        return self.returncode

    def active_processes(self) -> int:
        """How many processes started by the program are still running."""
        return _job_active_processes(self._job)

    def kill(self):
        """End the program and everything it started."""
        with self._lock:
            if self._job:
                _TerminateJobObject(self._job, 1)

    terminate = kill

    def _release(self):
        with self._lock:
            if self.returncode is None or self._released:
                return
            self._released = True
            for name in ("hThread", "hProcess"):
                h = getattr(self._pi, name)
                if h:
                    _CloseHandle(h)
                    setattr(self._pi, name, None)
            job, self._job = self._job, None
        if job:
            # End anything the program left running, and wait until it is gone: the
            # sandbox and the temp folder are taken away only after the last process.
            _TerminateJobObject(job, 1)
            deadline = time.monotonic() + _TEARDOWN_WAIT_SECONDS
            while _job_active_processes(job) > 0 and time.monotonic() < deadline:
                time.sleep(0.01)
            _CloseHandle(job)  # kill-on-close, should anything have outlived the wait
        if self._environment:
            self._api.close(self._environment)
            self._environment = wintypes.HANDLE()
        on_exit, self._on_exit = self._on_exit, None
        if on_exit is not None:
            try:
                on_exit()
            except Exception:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        for stream in (self.stdin, self.stdout, self.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        self.wait()

    def __del__(self):
        try:
            if self.returncode is None and self._job:
                self.kill()
                self._wait_ms(5000)
        except Exception:
            pass


# =============================================================================
# From settings to a policy
# =============================================================================

_SECRET_WORDS = {"KEY", "APIKEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "CREDENTIALS",
                 "PAT", "AUTH", "DSN", "PASSPHRASE", "COOKIE", "WEBHOOK"}
_URL_WITH_PASSWORD = re.compile(r"://[^/@\s:]*:[^/@\s]+@")


def _looks_secret(name: str, value: str = "") -> bool:
    """True for a variable whose name suggests a key, token or other secret, or
    whose value is a URL that carries sign-in details before the host name."""
    parts = [p for p in re.split(r"[^A-Za-z0-9]+", name.upper()) if p]
    if any(p in _SECRET_WORDS or p.endswith(("TOKEN", "SECRET", "PASSWORD", "APIKEY")) for p in parts):
        return True
    if "PWD" in parts and len(parts) > 1:  # MYSQL_PWD, but not the shell's own PWD
        return True
    return "CONNECTIONSTRING" in "".join(parts) or bool(_URL_WITH_PASSWORD.search(value))


def _dedupe(paths, base=None) -> list:
    """Absolute paths, each once. A relative path is relative to ``base`` (default: the current folder)."""
    seen, out = set(), []
    for path in paths:
        if not path:
            continue
        text = os.path.abspath(os.path.join(str(base), str(path)) if base else str(path))
        key = os.path.normcase(text)
        if key not in seen:
            seen.add(key)
            out.append(text)
    return out


def _pip_config_files():
    files = [Path(os.environ["PIP_CONFIG_FILE"])] if os.environ.get("PIP_CONFIG_FILE") else []
    for var, *parts in (("ProgramData", "pip", "pip.ini"), ("APPDATA", "pip", "pip.ini"),
                        ("USERPROFILE", "pip", "pip.ini")):
        if os.environ.get(var):
            files.append(Path(os.environ[var], *parts))
    files.append(Path(sys.prefix) / "pip.ini")
    return [f for f in files if f.is_file()]


def _pip_cert_files(config_files):
    certs = [os.environ.get(v, "") for v in ("PIP_CERT", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE")]
    for path in config_files:
        parser = configparser.RawConfigParser()
        try:
            parser.read(path, encoding="utf-8")
        except (configparser.Error, OSError, UnicodeDecodeError):
            continue
        for section in parser.sections():
            for key in ("cert", "client-cert"):
                if parser.has_option(section, key):
                    certs.append(parser.get(section, key))
    return [Path(os.path.expandvars(c.strip().strip("'\""))) for c in certs if c.strip()]


def _python_runtime_paths() -> list:
    """The interpreter as named and as resolved (launcher shims live outside
    the prefix) and its prefixes."""
    return [sys.prefix, sys.base_prefix, Path(sys.executable).parent, Path(sys.executable).resolve().parent]


def _pip_config_paths() -> list:
    """The pip.ini files and the certificate files they name: the files themselves,
    never the folders they are in (PIP_CONFIG_FILE may point into the user profile)."""
    config = _pip_config_files()
    return config + _pip_cert_files(config)


def _git_config_paths() -> list:
    home = Path(os.environ.get("USERPROFILE") or Path.home())
    return [home / ".gitconfig", home / ".config" / "git", home / ".condarc"]


def _drive_roots(paths) -> list:
    roots = []
    for path in (os.environ.get("SystemDrive", "C:"), *map(str, paths)):
        drive = os.path.splitdrive(os.path.abspath(path))[0]
        if len(drive) == 2 and (drive + os.sep).upper() not in (r.upper() for r in roots):
            roots.append(drive + os.sep)
    return roots


def parse_rule(text: str) -> dict:
    """One NETWORK_RULES entry: ``"10.0.0.0/8:443"``, ``"192.168.1.5"``,
    ``"tcp 10.1.2.0/24:8000-8100"``, ``"udp 10.0.0.53:53"``, ``"2001:db8::/32"``.

    Addresses are numeric (Windows has no host-name rules). A port without a
    protocol means TCP. IPv6 addresses are accepted without a port. Raises
    ``ValueError`` with a readable message.
    """
    raw = text.strip()
    protocol = "any"
    head, _, rest = raw.partition(" ")
    if head.lower() in ("tcp", "udp") and rest:
        protocol, raw = head.lower(), rest.strip()
    address, port_text = raw, ""
    if raw.count(":") == 1:
        address, port_text = raw.split(":")
    try:
        network = ipaddress.ip_network(address, strict=False)
    except ValueError:
        raise ValueError(f"'{text}' is not an address or range (example: 10.0.0.0/8:443).") from None
    rule = {"destinations": [f"{network.network_address}/{network.prefixlen}"]}
    if port_text:
        first, _, last = port_text.partition("-")
        try:
            lo, hi = int(first), int(last) if last else None
            if not 1 <= lo <= 65535 or hi is not None and not lo <= hi <= 65535:
                raise ValueError
        except ValueError:
            raise ValueError(f"'{text}' has a port that is not between 1 and 65535.") from None
        port = {"protocol": protocol if protocol != "any" else "tcp", "port": lo}
        if hi:
            port["end_port"] = hi
        rule["ports"] = [port]
    elif protocol != "any":
        rule["ports"] = [{"protocol": protocol}]
    return rule


def _choice(name, value, allowed):
    if value not in allowed:
        raise PolicyError(f"{name.upper()} is {value!r}; it must be one of: "
                          + ", ".join(repr(a) for a in allowed) + ".")
    return value


def _ui_mask(opts) -> int:
    clip, sysset = UI_READCLIPBOARD | UI_WRITECLIPBOARD, UI_SYSTEMPARAMETERS | UI_DISPLAYSETTINGS
    mask = {"all": 0, "read": UI_WRITECLIPBOARD, "write": UI_READCLIPBOARD, "none": clip}[
        _choice("clipboard", opts.clipboard, ("all", "read", "write", "none"))]
    mask |= {"desktop": 0, "handles": UI_HANDLES, "atoms": UI_GLOBALATOMS,
             "container": UI_HANDLES | UI_GLOBALATOMS}[
        _choice("ui_isolation", opts.ui_isolation, ("desktop", "handles", "atoms", "container"))]
    mask |= {"all": 0, "parameters": UI_DISPLAYSETTINGS, "display": UI_SYSTEMPARAMETERS, "none": sysset}[
        _choice("system_settings", opts.system_settings, ("all", "parameters", "display", "none"))]
    if not opts.desktop_control:
        mask |= UI_DESKTOP | UI_EXITWINDOWS
    if not opts.ime:
        mask |= UI_IME
    if not opts.input_injection:
        mask |= UI_INJECTION
    if opts.no_windows:
        mask |= UI_GLOBALATOMS  # atoms are reachable without the window system, so close them too
    return mask


def _network(opts, support, warnings, host_proxy_url=None):
    """(capabilities, network policy dict) for the NETWORK settings.

    The capability and field choices follow Microsoft's MXC runner
    (base_container_helpers.rs): a proxy on this computer needs
    privateNetworkClientServer + networkLoopback and the "MXC-Loopback" peer,
    and no internetClient, so the proxy is the only way out.
    """
    mode = _choice("network", opts.network, ("off", "internet", "intranet", "all", "hosts", "custom"))
    caps, policy = [], {"egress": "deny"}
    if opts.network_hosts and mode != "hosts":
        warnings.append(f'NETWORK_HOSTS is ignored while NETWORK is "{mode}"; set NETWORK = "hosts".')
    # Windows decides per network what counts as "private": on a network it classes as
    # public, the local subnet is reachable with internetClient alone and not with
    # privateNetworkClientServer alone. So the public/private line is drawn here with
    # address rules (a deny rule wins over an allow), not with the capability.
    private = [{"destinations": list(_PRIVATE_RANGES)}]
    if mode == "internet":
        caps, policy = [INTERNET], {"egress": "allow", "deny": private}
    elif mode == "intranet":
        caps, policy = [INTERNET, PRIVATE_NETWORK], {"egress": "deny", "allow": private}
    elif mode == "all":
        caps, policy = [INTERNET, PRIVATE_NETWORK], {"egress": "allow"}
    elif mode == "hosts":
        if not host_proxy_url:
            raise PolicyError('NETWORK is "hosts" but the host filter is not running.')
        caps, policy = [PRIVATE_NETWORK, LOOPBACK], {"proxy": host_proxy_url, "peer": _LOOPBACK_PEER}
    elif mode == "custom":
        caps = [INTERNET] + ([PRIVATE_NETWORK] if opts.network_private else [])
        proxy = str(opts.network_proxy or "").strip()
        if proxy:
            caps, policy = [PRIVATE_NETWORK, LOOPBACK], {"proxy": proxy, "peer": _LOOPBACK_PEER}
        else:
            rules = []
            for rule in opts.network_rules:
                try:
                    rules.append(rule if isinstance(rule, dict) else parse_rule(str(rule)))
                except ValueError as exc:
                    raise PolicyError(f"NETWORK_RULES: {exc}") from None
            policy = {"egress": "deny", "allow": rules}
            if not rules:
                warnings.append('NETWORK is "custom" with no NETWORK_RULES and no NETWORK_PROXY: '
                                'the program has no network.')
    if opts.allow_inbound or opts.allow_loopback:
        if mode == "off":
            warnings.append('ALLOW_INBOUND and ALLOW_LOOPBACK are ignored while NETWORK is "off".')
        elif "proxy" in policy:
            warnings.append('ALLOW_INBOUND and ALLOW_LOOPBACK are ignored with NETWORK "hosts" '
                            'or NETWORK_PROXY.')
        elif "NetworkIngress" not in support:
            warnings.append("ALLOW_INBOUND and ALLOW_LOOPBACK are ignored: this Windows build "
                            "cannot allow incoming connections into the sandbox.")
        else:
            if opts.allow_inbound and PRIVATE_NETWORK not in caps:
                caps.append(PRIVATE_NETWORK)  # Windows ties accepting connections to this capability
            if opts.allow_loopback:
                caps.append(LOOPBACK)
                policy["peer"] = _LOOPBACK_PEER
    return caps, policy


# ---- NETWORK = "hosts": an allow-list HTTPS proxy that runs outside the sandbox ----

_HOST_PATTERN = re.compile(r"^(\*\.)?[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")


def _parse_host(text) -> tuple:
    """One NETWORK_HOSTS entry -> (host pattern, port). Raises PolicyError."""
    raw = str(text).strip().lower()
    if raw.startswith("http://"):
        raise PolicyError(f"NETWORK_HOSTS: '{text}' is plain HTTP; only HTTPS hosts can be listed.")
    raw = raw.removeprefix("https://").split("/", 1)[0].rstrip(".")
    host, port = raw, 443
    head, colon, tail = raw.rpartition(":")
    if colon and tail.isdigit():
        host, port = head, int(tail)
    if not _HOST_PATTERN.match(host) or not 1 <= port <= 65535:
        raise PolicyError(f"NETWORK_HOSTS: '{text}' is not a host name "
                          f"(examples: api.example.com, *.example.com, api.example.com:8443).")
    return host, port


def _upstream_proxy(setting):
    """NETWORK_UPSTREAM_PROXY -> (host, port) of the organisation's proxy, or None."""
    import urllib.parse
    import urllib.request

    text = str(setting or "").strip()
    if text.lower() == "auto":
        text = next((os.environ[k] for k in os.environ if k.upper() == "HTTPS_PROXY" and os.environ[k]), "")
        if not text:
            try:
                text = urllib.request.getproxies().get("https", "")  # the Windows proxy setting
            except Exception:
                text = ""
    if not text:
        return None
    parts = urllib.parse.urlsplit(text if "//" in text else "//" + text)
    try:
        host, port = parts.hostname, parts.port or 8080
    except ValueError:
        host = None
    if not host or parts.scheme not in ("", "http"):
        raise PolicyError(f"NETWORK_UPSTREAM_PROXY: '{text}' is not a proxy address "
                          f"(example: http://proxy.example.com:8443).")
    return host, port


def _host_rules(hosts) -> list:
    """NETWORK_HOSTS -> [(host pattern, port)]. Raises PolicyError."""
    if isinstance(hosts, (str, bytes)):
        raise PolicyError("NETWORK_HOSTS must be a list, not a single string.")
    rules = [_parse_host(h) for h in hosts if str(h).strip()]
    if not rules:
        raise PolicyError('NETWORK is "hosts" but NETWORK_HOSTS is empty: list at least one host.')
    return rules


# The host filter is spoken to by the sandboxed program, so what it accepts and
# remembers from it is limited: a plain host name, a bounded number of tunnels,
# and a bounded number of short, printable notes.
_CONNECT_HOST = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")
_MAX_TUNNELS = 128
_MAX_NOTES = 50
_MAX_NOTE_LENGTH = 300


def _remember(notes: list, text) -> str:
    """Add a note unless it is known or the list is full. Returns the note as
    it was stored, or "" when nothing was added."""
    text = "".join(c if " " <= c <= "~" else "?" for c in str(text))
    if len(text) > _MAX_NOTE_LENGTH:
        text = text[:_MAX_NOTE_LENGTH] + "..."
    if text in notes or len(notes) > _MAX_NOTES:
        return ""
    stored = text if len(notes) < _MAX_NOTES else "(more, not listed)"
    notes.append(stored)
    return stored


class _HostProxy:
    """Listens on 127.0.0.1 and tunnels HTTPS (CONNECT) to the listed hosts only.

    It runs in the program that starts the sandbox, so it has normal network
    access; the sandboxed program can reach it and nothing else. It never sees
    inside the encrypted traffic: it reads the host name the client asks for,
    then passes bytes through unchanged.
    """

    def __init__(self, hosts, on_block=None, upstream="auto"):
        import socket

        self.rules = _host_rules(hosts)
        self._slots = threading.BoundedSemaphore(_MAX_TUNNELS)
        self.upstream = _upstream_proxy(upstream)
        self._via_upstream: set = set()
        self.blocked: list = []
        self.errors: list = []
        self.on_error = None
        self._on_block = on_block
        self._socket = socket
        try:
            self._server = socket.create_server(("127.0.0.1", 0))
        except OSError as exc:
            raise SandboxLaunchError(f"The host filter could not start: {exc}", exc.errno or 0) from None
        self.url = "http://127.0.0.1:%d" % self._server.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True, name="pymxc-host-filter").start()

    def allows(self, host: str, port: int) -> bool:
        host = host.lower().rstrip(".")
        for pattern, allowed_port in self.rules:
            if port != allowed_port:
                continue
            if host == pattern or (pattern.startswith("*.") and host.endswith(pattern[1:])):
                return True
        return False

    def close(self):
        try:
            self._server.close()
        except OSError:
            pass

    def _connect(self, host, port):
        """(socket to host:port, bytes already received). Tries the direct route
        first, then the organisation's proxy; remembers which one worked."""
        ways = ["direct"] + (["proxy"] if self.upstream else [])
        if (host, port) in self._via_upstream:
            ways.reverse()
        failures = []
        for way in ways:
            sock = None
            try:
                if way == "direct":
                    return self._socket.create_connection((host, port), 8 if self.upstream else 20), b""
                sock = self._socket.create_connection(self.upstream, 20)
                sock.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
                head = b""
                while b"\r\n\r\n" not in head and len(head) < 65536:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    head += chunk
                answer = head.split(b"\r\n", 1)[0].decode("latin-1")
                if answer.split()[1:2] != ["200"]:
                    note = " (it asks for sign-in, which pymxc cannot do)" if " 407" in answer else ""
                    raise OSError(f"answered '{answer}'{note}")
                self._via_upstream.add((host, port))
                return sock, head.partition(b"\r\n\r\n")[2]
            except OSError as exc:
                if sock is not None:
                    sock.close()
                via = "directly" if way == "direct" else "through the proxy %s:%d" % self.upstream
                failures.append(f"{via}: {exc}")
        raise OSError("; ".join(failures))

    def _accept(self):
        while True:
            try:
                client, _ = self._server.accept()
            except OSError:
                return  # closed
            if not self._slots.acquire(blocking=False):
                client.close()  # too many connections at once
                continue
            threading.Thread(target=self._serve, args=(client,), daemon=True).start()

    def _refuse(self, client, target, reason):
        note = _remember(self.blocked, target)
        if note and self._on_block is not None:
            try:
                self._on_block(note)
            except Exception:
                pass
        body = f"pymxc: {reason}\n".encode("latin-1", "replace")
        client.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n"
                       b"Content-Length: %d\r\n\r\n" % len(body) + body)

    def _serve(self, client):
        upstream = None
        try:
            client.settimeout(30)
            head = b""
            while b"\r\n\r\n" not in head and len(head) < 65536:
                chunk = client.recv(4096)
                if not chunk:
                    return
                head += chunk
            header, _, rest = head.partition(b"\r\n\r\n")
            parts = header.split(b"\r\n", 1)[0].decode("latin-1").split()
            if len(parts) < 2:
                return
            method, target = parts[0].upper(), parts[1]
            if method != "CONNECT":
                self._refuse(client, target.split("?", 1)[0][:200] + " (plain HTTP; only HTTPS is allowed)",
                             "only HTTPS is allowed through NETWORK_HOSTS.")
                return
            host, _, port_text = target.rpartition(":")
            host = host.strip("[]").lower().rstrip(".")
            port = int(port_text) if port_text.isascii() and port_text.isdigit() else 0
            # Only a plain host name is matched and passed on: anything else could read
            # differently to the organisation's proxy than it does to allows().
            if not _CONNECT_HOST.match(host) or not self.allows(host, port):
                shown = f"{host[:200]}:{port}"
                self._refuse(client, shown, f"{shown} is not in NETWORK_HOSTS.")
                return
            try:
                upstream, early = self._connect(host, port)
            except OSError as exc:
                note = _remember(self.errors, f"{host}:{port}: {exc}")
                if note and self.on_error is not None:
                    try:
                        self.on_error(note)
                    except Exception:
                        pass  # the program still gets its 502 answer
                body = f"pymxc: could not reach {host}:{port}: {exc}\n".encode("latin-1", "replace")
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n"
                               b"Content-Length: %d\r\n\r\n" % len(body) + body)
                return
            client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n" + early)
            if rest:
                upstream.sendall(rest)
            client.settimeout(None)
            upstream.settimeout(None)

            def pump(source, sink):
                try:
                    while True:
                        data = source.recv(65536)
                        if not data:
                            break
                        sink.sendall(data)
                except OSError:
                    pass
                finally:
                    for sock in (source, sink):  # one side ended: end the tunnel
                        try:
                            sock.shutdown(self._socket.SHUT_RDWR)
                        except OSError:
                            pass

            back = threading.Thread(target=pump, args=(upstream, client), daemon=True)
            back.start()
            pump(client, upstream)
            back.join(5)
        except (OSError, ValueError):
            pass
        finally:
            for sock in (client, upstream):
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
            self._slots.release()


def _host_proxy(opts, on_block=None):
    """The running host filter for NETWORK = "hosts", else None."""
    if opts.network != "hosts":
        return None
    return _HostProxy(opts.network_hosts, on_block, opts.network_upstream_proxy)


@dataclass
class _Policy:
    spec: bytes
    ui_limits: int
    read_write: list
    read_only: list
    deny: list
    enumerate: list
    capabilities: list
    network: dict
    warnings: list

    @property
    def proxy_url(self):
        return self.network.get("proxy")


def _require_lists(opts, *names) -> None:
    for name in names:
        if isinstance(getattr(opts, name), (str, bytes)):
            raise PolicyError(f"{name.upper()} must be a list, not a single string.")


def _listed(opts, name, workspace) -> list:
    """A path-list setting as absolute paths; relative entries are relative to the workspace."""
    _require_lists(opts, name)
    return _dedupe(getattr(opts, name), workspace)


def _read_write_paths(opts, workspace) -> list:
    """READ_WRITE as absolute paths. An entry that does not exist yet is created
    as a folder, so the program finds it there with or without the sandbox."""
    paths = _listed(opts, "read_write", workspace)
    for path in paths:
        if not os.path.exists(path):
            try:
                os.makedirs(path, exist_ok=True)
            except OSError as exc:
                raise PolicyError(f"READ_WRITE: the folder {path} does not exist and could not "
                                  f"be created: {exc}") from None
    return paths


def _build_policy(opts, workspace, temp_dir=None, extra_read_only=(), host_proxy_url=None) -> _Policy:
    """Turn the settings into policy bytes. Raises ``PolicyError``.

    A setting that cannot be honoured is an error when ignoring it would give
    the program MORE access (deny paths) and a warning when it gives less.
    """
    info = probe()
    support = info.get("support") or []
    supported_version = tuple(info.get("version") or (1, 0))
    warnings: list = []

    workspace = os.path.abspath(str(workspace))
    if not os.path.isdir(workspace):
        raise PolicyError(f"The workspace folder was not found: {workspace}")
    access = _choice("workspace_access", opts.workspace_access, ("rw", "ro"))
    _require_lists(opts, "network_rules", "extra_capabilities")

    listed_read_write = _read_write_paths(opts, workspace)
    listed_read_only = _listed(opts, "read_only", workspace)
    deny = _listed(opts, "deny", workspace)
    for path in listed_read_only:
        if not os.path.exists(path):
            warnings.append(f"Listed path does not exist and is skipped: {path}")
    for path in deny:
        if os.path.exists(path):
            continue
        # Windows blocks a path that does not exist yet, but only inside a folder that does.
        if not os.path.isdir(os.path.dirname(path)):
            raise PolicyError(f"DENY: {path} cannot be blocked because the folder it would be in does "
                              f"not exist either. Check the spelling, or remove the entry.")
        warnings.append(f"DENY path does not exist yet (check the spelling): {path}")
    read_write = [temp_dir] + ([workspace] if access == "rw" else []) + listed_read_write
    read_only = ([workspace] if access == "ro" else []) + listed_read_only + list(extra_read_only)
    if opts.grant_python_runtime:
        read_only += _python_runtime_paths()
    if opts.grant_pip_config:
        read_only += _pip_config_paths()
    if opts.grant_git_config:
        read_only += _git_config_paths()
    read_write = [p for p in _dedupe(read_write) if os.path.exists(p)]
    read_only = [p for p in _dedupe(read_only) if os.path.exists(p)]
    if deny and "FileSystemDeny" not in support:
        raise PolicyError("This Windows build cannot block the DENY paths. Remove them, or move those "
                          "files out of the folders you grant.", Status.FEATURE_UNSUPPORTED)

    enumerate_paths = []
    if opts.list_drive_roots:
        if supported_version >= (1, 1) and "FileSystemEnumerate" in support:
            enumerate_paths = _drive_roots(read_write + read_only)
        else:
            warnings.append("LIST_DRIVE_ROOTS is ignored: this Windows build does not support it. "
                            "Start programs through PATH rather than by full path.")

    capabilities, network = _network(opts, support, warnings, host_proxy_url)
    capabilities += [str(c) for c in opts.extra_capabilities if c]
    if any(c.lower() == "permissivelearningmode" for c in capabilities):
        warnings.append("permissiveLearningMode is on: Windows records but does NOT block. "
                        "The program is not contained.")
    ui_limits = _ui_mask(opts)
    if opts.clipboard in _CLIPBOARD_READERS and opts.ui_isolation in _WINDOW_ISOLATION:
        warnings.append(f'CLIPBOARD is "{opts.clipboard}" but the program cannot paste: with UI_ISOLATION '
                        f'"{opts.ui_isolation}" Windows hides what other programs copied. Use '
                        'UI_ISOLATION "desktop" or "atoms" to allow pasting.')
    try:
        spec = encode_spec(read_write=read_write, read_only=read_only, deny=deny,
                           enumerate_paths=enumerate_paths, capabilities=capabilities, network=network,
                           disallow_win32k=bool(opts.no_windows), ui_restrictions=ui_limits)
    except (ValueError, TypeError, KeyError) as exc:
        raise PolicyError(f"The policy could not be built: {exc}") from None
    return _Policy(spec, ui_limits, read_write, read_only, deny, enumerate_paths, capabilities,
                   network, warnings)


def _check_settings(opts, workspace) -> None:
    """The checks that need no sandbox, for a computer without one: a bad setting
    is reported, and READ_WRITE folders are created, the same way everywhere.
    Raises ``PolicyError``."""
    if not os.path.isdir(str(workspace)):
        raise PolicyError(f"The workspace folder was not found: {os.path.abspath(str(workspace))}")
    _choice("workspace_access", opts.workspace_access, ("rw", "ro"))
    _require_lists(opts, "read_only", "deny", "network_rules", "extra_capabilities")
    _read_write_paths(opts, workspace)
    _ui_mask(opts)
    if opts.network == "hosts":
        _host_rules(opts.network_hosts)
    _network(opts, (), [], "http://127.0.0.1:1")  # the address only stands in for the host filter


# =============================================================================
# Starting things
# =============================================================================

SANDBOX_MARKER = "PYMXC_SANDBOXED"   # "1" in the environment of every sandboxed program
_TEMP_VAR = "PYMXC_TEMP"             # the temp folder the sandboxed program may write to

_temp_lock = threading.Lock()
_temp_counter = [0]
_warned = [False]


_TOKEN_QUERY = 0x0008
_TOKEN_IS_APP_CONTAINER = 29   # TOKEN_INFORMATION_CLASS.TokenIsAppContainer
_app_container: list = []


def _in_app_container() -> bool:
    """Ask Windows whether this process runs inside an AppContainer sandbox."""
    if _k32 is None:
        return False
    if not _app_container:
        inside, token = False, wintypes.HANDLE()
        try:
            advapi = ctypes.WinDLL("advapi32", use_last_error=True)
            advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
            advapi.OpenProcessToken.restype = wintypes.BOOL
            advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                                   wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
            advapi.GetTokenInformation.restype = wintypes.BOOL
            if advapi.OpenProcessToken(_GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)):
                value, size = wintypes.DWORD(0), wintypes.DWORD(0)
                if advapi.GetTokenInformation(token, _TOKEN_IS_APP_CONTAINER, ctypes.byref(value),
                                              ctypes.sizeof(value), ctypes.byref(size)):
                    inside = bool(value.value)
        except (OSError, AttributeError):
            inside = False
        finally:
            if token:
                _CloseHandle(token)
        _app_container.append(inside)
    return _app_container[0]


def is_sandboxed() -> bool:
    """True inside a program started by ``enable()``, ``run()`` or ``Popen()``.

    The environment marker alone is not believed: Windows must also confirm
    that this process is contained, so setting the variable by hand (or
    inheriting it by accident) cannot switch the sandbox off.
    """
    return os.environ.get(SANDBOX_MARKER) == "1" and _in_app_container()


_STILL_ACTIVE = 259
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_ERROR_INVALID_PARAMETER = 87


def _process_is_gone(pid: int) -> bool:
    """True only when Windows says no process has this id. Any doubt means False."""
    if _k32 is None:
        return False
    handle = _OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return ctypes.get_last_error() == _ERROR_INVALID_PARAMETER
    try:
        code = wintypes.DWORD(0)
        return bool(_GetExitCodeProcess(handle, ctypes.byref(code))) and code.value != _STILL_ACTIVE
    finally:
        _CloseHandle(handle)


def _sweep_temp_dirs(base: Path) -> None:
    """Remove temp folders left by programs that ended without cleaning up
    (killed, crashed), so that what a sandboxed program wrote does not linger."""
    try:
        entries = list(base.iterdir())
    except OSError:
        return
    for entry in entries:
        match = re.fullmatch(r"run-(\d+)-.+", entry.name)
        if match and int(match.group(1)) != os.getpid() and _process_is_gone(int(match.group(1))):
            _remove_temp_dir(entry)


def _new_temp_dir() -> str:
    # A plain mkdir: tempfile.mkdtemp makes owner-only folders the sandbox cannot use.
    # The name is not guessable and the folder is always new, so a run never
    # starts with files an earlier run left behind.
    base = Path(tempfile.gettempdir()) / "pymxc"
    base.mkdir(parents=True, exist_ok=True)
    with _temp_lock:
        _temp_counter[0] += 1
        n = _temp_counter[0]
        first = n == 1
    if first:
        _sweep_temp_dirs(base)
    while True:
        path = base / f"run-{os.getpid()}-{n}-{os.urandom(6).hex()}"
        try:
            path.mkdir()
            return str(path)
        except FileExistsError:
            continue


def _remove_temp_dir(path) -> None:
    if path and Path(path).parent.name == "pymxc" and Path(path).name.startswith("run-"):
        shutil.rmtree(path, ignore_errors=True)


def _child_env(env, opts, temp_dir, proxy_url=None, sandboxed=True) -> dict:
    """The environment for the program. ``sandboxed=False`` is the run without a
    sandbox: the same settings apply, only the markers are left out."""
    out = {str(k): str(v) for k, v in (os.environ if env is None else env).items()}
    if opts.hide_secret_env:
        out = {k: v for k, v in out.items() if not _looks_secret(k, v)}
    if proxy_url:
        # The proxy is the only way out, so every client must be pointed at it.
        names = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")
        out = {k: v for k, v in out.items() if k.upper() not in names}
        out["HTTP_PROXY"] = out["HTTPS_PROXY"] = proxy_url
    out.update({str(k): str(v) for k, v in dict(opts.extra_env).items()})
    if opts.python_on_path:
        key = next((k for k in out if k.upper() == "PATH"), "PATH")
        out[key] = os.pathsep.join(p for p in (os.path.dirname(sys.executable), out.get(key, "")) if p)
    present = {k.upper() for k in out}
    for name in ("SystemRoot", "SystemDrive", "ComSpec"):  # Windows programs fail without these
        if name.upper() not in present and os.environ.get(name):
            out[name] = os.environ[name]
    if sandboxed:
        out[SANDBOX_MARKER] = "1"
        if temp_dir:
            out[_TEMP_VAR] = str(temp_dir)
    return out


def _normalize(command, shell):
    """(command line text, shell flag). A list runs directly; a string runs through cmd.exe."""
    if isinstance(command, (list, tuple)):
        return subprocess.list2cmdline([str(c) for c in command]), bool(shell)
    return str(command), True if shell is None else bool(shell)


def _native(command, shell):
    """(command, shell flag) for ``subprocess`` when there is no sandbox."""
    if isinstance(command, (list, tuple)):
        return [str(c) for c in command], bool(shell)
    use_shell = True if shell is None else bool(shell)
    if sys.platform != "win32" and not use_shell:
        import shlex
        return shlex.split(str(command)), False
    return str(command), use_shell


_PROGRAM_PATH = re.compile(r'(^\s*|[&|(]\s*)([A-Za-z]:\\[^\s"&|<>^()%!]+)')


def _quote_program_paths(command: str) -> str:
    r"""Put quotes around a program given by full path without them.

    Inside the sandbox cmd.exe answers "Access is denied" to
    ``C:\Python312\python.exe x.py`` but runs ``"C:\Python312\python.exe" x.py``
    (unless LIST_DRIVE_ROOTS is on), so the quotes are added here.
    """
    def fix(match):
        path = match.group(2)
        in_quotes = command.count('"', 0, match.start(2)) % 2
        if in_quotes or not (os.path.isfile(path) or os.path.isfile(path + ".exe")):
            return match.group(0)
        return f'{match.group(1)}"{path}"'

    return _PROGRAM_PATH.sub(fix, command)


def _explain(exc: SandboxLaunchError) -> str:
    text = str(exc)
    if "CreateProcessSecurityEnvironment" in text:
        if _in_app_container():
            return ("This program is already running inside a sandbox, and Windows does not start "
                    "a sandbox from inside one. " + text)
        return "Windows did not accept the sandbox policy. " + text
    if exc.code == 623:
        return "This program cannot start inside the sandbox (Windows refused to load it). " + text
    if exc.code == 5:
        return ("Windows refused to start the program. Its folder may not be readable inside the "
                "sandbox; add it to READ_ONLY. " + text)
    if exc.code in (2, 3, 267):
        return "The program or its working folder was not found from inside the sandbox. " + text
    if exc.code == 50:
        return ("Windows refused these window, clipboard and input limits. This happens when your own "
                "program already runs in a job object that has such limits (some launchers and CI "
                'runners do this). Try clipboard="all" and ui_isolation="desktop". ' + text)
    return "The sandbox could not start the program. " + text


def _code_folders() -> list:
    """The folders that hold code which starts OUTSIDE the sandbox: the running
    program's own folder and the one this file is in."""
    folders = [Path(__file__).resolve().parent]
    if getattr(sys, "frozen", False):
        folders.append(Path(sys.executable).resolve().parent)
    elif sys.argv and sys.argv[0] not in ("", "-c", "-m") and os.path.isfile(sys.argv[0]):
        folders.append(Path(sys.argv[0]).resolve().parent)
    return folders


def _workspace_warnings(workspace, access) -> list:
    """What run() and Popen() should say about a workspace that is wider, or
    more dangerous to write to, than a folder a command is meant to work in."""
    try:
        workspace = Path(workspace).resolve()
    except OSError:
        return []
    found = []

    def holds(folder) -> bool:
        return folder == workspace or workspace in folder.parents

    profile = os.environ.get("USERPROFILE") or ""
    if profile and holds(Path(profile).resolve()):
        found.append(f"The workspace {workspace} takes in your whole user profile: the command can "
                     + ("read and change" if access == "rw" else "read")
                     + " your documents, settings and saved keys. Pass workspace= with the one "
                       "folder it should work in.")
    if access == "rw" and any(holds(folder) for folder in _code_folders()):
        found.append("The workspace is writable and holds this program's own code. The sandboxed command "
                     "can change code that runs OUTSIDE the sandbox on the next start. Pass a different "
                     'workspace=, or workspace_access="ro" with a data folder in read_write.')
    return found


def _handle_unavailable(opts, current: SandboxStatus) -> bool:
    """Apply ON_UNAVAILABLE. True = go ahead without the sandbox, False = do not run."""
    mode = opts.on_unavailable
    if mode not in ("warn", "silent", "error"):
        raise PolicyError(f"ON_UNAVAILABLE is {mode!r}; it must be 'warn', 'silent' or 'error'.")
    if mode == "error":
        return False
    if mode == "warn" and not _warned[0]:
        _warned[0] = True
        print(f"pymxc WARNING: running WITHOUT the sandbox. {current.message}", file=sys.stderr)
    return True


def _start(command, opts, *, cwd=None, env=None, shell=None, **popen_options) -> SandboxedPopen:
    """Build the policy and start ``command`` sandboxed. Raises SandboxError."""
    line, use_shell = _normalize(command, shell)
    if use_shell:
        line = _quote_program_paths(line)
    workspace = opts.workspace or cwd or os.getcwd()
    temp_dir = _new_temp_dir()
    proxy = None

    def clean_up():
        _remove_temp_dir(temp_dir)
        if proxy is not None:
            proxy.close()

    try:
        proxy = _host_proxy(opts)
        policy = _build_policy(opts, workspace, temp_dir, host_proxy_url=proxy and proxy.url)
        proc = SandboxedPopen(
            line, cwd=str(cwd or workspace), spec=policy.spec,
            env=_child_env(env, opts, temp_dir, policy.proxy_url),
            temp_dir=temp_dir if use_shell else None, shell=use_shell, ui_limits=policy.ui_limits,
            wait_for_tree=bool(opts.wait_for_child_processes), on_exit=clean_up, **popen_options)
    except BaseException:
        clean_up()
        raise
    proc.warnings = policy.warnings + _workspace_warnings(workspace, opts.workspace_access)
    proc.blocked_hosts = proxy.blocked if proxy is not None else []
    proc.host_errors = proxy.errors if proxy is not None else []
    return proc


_PROCESS_GROUPS = hasattr(os, "killpg")  # Linux and macOS


def _kill_tree(proc) -> None:
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True,
                       creationflags=_CREATE_NO_WINDOW)
    elif _PROCESS_GROUPS:
        try:  # the command was started in a process group of its own; end all of it
            os.killpg(proc.pid, getattr(signal, "SIGKILL", 9))
        except OSError:
            pass
    proc.kill()


def _text(raw: bytes, encoding: str) -> str:
    """Decode output as ``subprocess`` does in text mode: every line ends with ``\\n``."""
    return raw.decode(encoding, errors="replace").replace("\r\n", "\n").replace("\r", "\n")


def _run_unsandboxed(line, use_shell, opts, cwd, env, data, encoding, current) -> Result:
    try:
        proc = subprocess.Popen(line, shell=use_shell, cwd=cwd,
                                env=_child_env(env, opts, None, sandboxed=False),
                                stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=_PROCESS_GROUPS,
                                creationflags=_CREATE_NO_WINDOW if sys.platform == "win32" else 0)
    except OSError as exc:
        return Result(None, sandboxed=False, status=Status.LAUNCH_FAILED,
                      message=f"The program could not be started: {exc}")
    timed_out = False
    try:
        out, err = proc.communicate(data, opts.timeout_seconds or None)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_tree(proc)
        out, err = proc.communicate()
    message = "Ran WITHOUT the sandbox. " + current.message
    if timed_out:
        message = f"Stopped after {opts.timeout_seconds} seconds. " + message
    return Result(proc.returncode, _text(out, encoding), _text(err, encoding),
                  sandboxed=False, timed_out=timed_out,
                  status=Status.TIMED_OUT if timed_out else current.code, message=message)


def run(command, *, cwd=None, env=None, input=None, shell=None, **options) -> Result:
    """Run one command inside the sandbox and collect its output.

    ``command`` is a string (run through ``cmd.exe``, like
    ``subprocess.run(..., shell=True)``) or a list of arguments (run directly;
    ``&`` and quotes in arguments are never interpreted). ``cwd`` defaults to
    the workspace, ``env`` to this process's environment. ``input`` is text or
    bytes for the command's stdin. ``options`` are the SETTINGS in lower case,
    for example ``network="internet"`` or ``timeout_seconds=30``.

    Always returns a ``Result``; it does not raise when the sandbox is missing
    or the launch fails. Check ``result.sandboxed`` and ``result.status``.

    When the sandbox is not available the command is NOT run (``returncode``
    is None) unless you pass ``on_unavailable="warn"`` or ``"silent"``.
    """
    opts = _options(options)
    encoding = opts.encoding or locale.getpreferredencoding(False)
    try:
        codecs.lookup(encoding)
    except (LookupError, TypeError):
        return Result(None, status=Status.POLICY_INVALID,
                      message=f"ENCODING is {opts.encoding!r}, which Python does not know. "
                              f"Examples: 'utf-8', 'oem', None.")
    data = input.encode(encoding) if isinstance(input, str) else input
    child_env = None if env is None else dict(env)
    if encoding.lower().replace("-", "") == "utf8":
        child_env = dict(os.environ if env is None else env)
        child_env.setdefault("PYTHONIOENCODING", "utf-8")
    current = status()
    if not current.available:
        try:
            proceed = _handle_unavailable(opts, current)
            if proceed:
                _check_settings(opts, opts.workspace or cwd or os.getcwd())
        except PolicyError as exc:
            return Result(None, status=exc.status, message=str(exc))
        if not proceed:
            return Result(None, status=current.code, message="Not run. " + current.message)
        line, use_shell = _native(command, shell)
        return _run_unsandboxed(line, use_shell, opts, cwd or opts.workspace, child_env, data, encoding, current)

    try:
        proc = _start(command, opts, cwd=cwd, env=child_env, shell=shell, text=False,
                      stdin=data is not None)
    except SandboxLaunchError as exc:
        return Result(None, status=Status.LAUNCH_FAILED, message=_explain(exc))
    except SandboxError as exc:
        return Result(None, status=exc.status, message=str(exc))

    chunks = ([], [])

    def drain(stream, sink):
        with stream:
            for chunk in iter(lambda: stream.read(65536), b""):
                sink.append(chunk)

    def feed():
        try:
            with proc.stdin:
                proc.stdin.write(data)
        except OSError:
            pass  # the program closed its stdin or exited

    threads = [threading.Thread(target=drain, args=(s, c), daemon=True)
               for s, c in ((proc.stdout, chunks[0]), (proc.stderr, chunks[1]))]
    if data is not None:
        threads.append(threading.Thread(target=feed, daemon=True))
    for t in threads:
        t.start()
    timed_out = False
    try:
        proc.wait(opts.timeout_seconds or None)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        proc.wait()
    except BaseException:
        proc.kill()
        raise
    for t in threads:
        t.join(5)
    cut_short = any(t.is_alive() for t in threads[:2])
    out, err = (_text(b"".join(c), encoding) for c in chunks)
    message = f"Stopped after {opts.timeout_seconds} seconds." if timed_out else ""
    if proc.returncode and not timed_out and re.search(
            r"WinError 10013|forbidden by its access permissions|getaddrinfo failed", out + err, re.I):
        message = (f'The command was refused a network connection. NETWORK is "{opts.network}"; see the '
                   "Network settings (internet, intranet, all, hosts, custom, ALLOW_LOOPBACK) for what "
                   "to allow.")
    elif proc.returncode and not timed_out and re.search(
            r"access is denied|permission denied|PermissionError|WinError 5\b", out + err, re.I):
        message = ("The command reported an access error. Inside the sandbox it can reach only the "
                   "workspace and the paths in READ_WRITE and READ_ONLY; add what it needs there. If "
                   "it uses cd, pushd or a tool that looks through parent folders, try "
                   "list_drive_roots=True.")
    blocked = [f"NETWORK_HOSTS blocked a connection to {target}." for target in proc.blocked_hosts]
    blocked += [f"An allowed host could not be reached: {e}" for e in dict.fromkeys(proc.host_errors)]
    if cut_short:
        blocked.append("The command's output was still arriving five seconds after it ended; "
                       "stdout and stderr may be incomplete.")
    return Result(proc.returncode, out, err, sandboxed=True, timed_out=timed_out,
                  status=Status.TIMED_OUT if timed_out else Status.OK, message=message,
                  warnings=list(proc.warnings) + blocked)


def Popen(command, *, cwd=None, env=None, shell=None, text=True, encoding=None, merge_stderr=False,
          stdin=False, new_console=False, **options):
    """Start a command inside the sandbox and return at once.

    Returns a ``SandboxedPopen`` (``sandboxed`` is True): read ``stdout`` and
    ``stderr``, write ``stdin`` when ``stdin=True``, then ``wait()`` or
    ``kill()``. ``command``, ``cwd``, ``env`` and ``options`` are as in
    ``run()``. ``new_console=True`` gives the program its own console window.

    When the sandbox is not available this raises ``SandboxUnavailable``
    (ON_UNAVAILABLE "error", the default here); with "warn" or "silent" it
    returns an ordinary ``subprocess.Popen`` with ``sandboxed`` set to False.
    A bad setting raises
    ``PolicyError``; a failed launch raises ``SandboxLaunchError``.
    """
    opts = _options(options)
    current = status()
    if current.available:
        return _start(command, opts, cwd=cwd, env=env, shell=shell, text=text, encoding=encoding,
                      merge_stderr=merge_stderr, stdin=stdin, new_console=new_console)
    if not _handle_unavailable(opts, current):
        raise SandboxUnavailable(current.message, current.code)
    _check_settings(opts, opts.workspace or cwd or os.getcwd())
    line, use_shell = _native(command, shell)
    environment = _child_env(env, opts, None, sandboxed=False)
    flags = 0
    if sys.platform == "win32":
        flags = _CREATE_NEW_CONSOLE if new_console else _CREATE_NO_WINDOW
    pipe = None if new_console else subprocess.PIPE
    proc = subprocess.Popen(
        line, shell=use_shell, cwd=cwd or opts.workspace, env=environment,
        stdin=None if new_console else subprocess.PIPE if stdin else subprocess.DEVNULL,
        stdout=pipe, stderr=None if new_console else subprocess.STDOUT if merge_stderr else pipe,
        text=text, encoding=encoding if text else None, errors="replace" if text else None,
        creationflags=flags)
    proc.sandboxed = False
    proc.warnings = ["Running WITHOUT the sandbox. " + current.message]
    return proc


def _restart_args() -> tuple:
    """(the command that starts this program again the same way, started with ``python -m``?)."""
    if getattr(sys, "frozen", False):  # PyInstaller and similar: the exe is the program
        return [sys.executable, *sys.argv[1:]], False
    try:
        flags = subprocess._args_from_interpreter_flags()  # -O, -X utf8, -W ... as given
    except Exception:
        flags = []
    main = sys.modules.get("__main__")
    spec = getattr(main, "__spec__", None)
    if spec is not None and spec.name:  # started with python -m package.module
        name = spec.name[:-len(".__main__")] if spec.name.endswith(".__main__") else spec.name
        return [sys.executable, *flags, "-m", name, *sys.argv[1:]], True
    return [sys.executable, *flags, str(Path(sys.argv[0]).resolve()), *sys.argv[1:]], False


_INTERRUPT_GRACE_SECONDS = 5.0  # enable(): how long the program gets to finish after Ctrl+C


def _all_interactive() -> bool:
    try:
        return all(s is not None and s.isatty() for s in (sys.stdin, sys.stdout, sys.stderr))
    except (AttributeError, ValueError):
        return False


def enable(**options) -> bool:
    """Run the rest of this program inside the sandbox. Call it first.

    ::

        import pymxc; pymxc.enable()

    Outside the sandbox this starts the same program again inside one, waits
    for it, and exits with its exit code; it does not return. Inside (the
    restarted copy) it returns True and the program carries on, contained.
    When the sandbox is not available it returns False after a warning (the
    program carries on WITHOUT the sandbox), or raises ``SandboxUnavailable``
    if ON_UNAVAILABLE is "error".

    It never prints an error itself. A bad setting raises ``PolicyError`` and
    a launch Windows refuses raises ``SandboxLaunchError``; both are
    ``SandboxError``, carry the matching ``status`` code, and say what to do.
    Left uncaught, Python reports the error and the program ends before any
    of it has run. Catch it to report it your own way::

        try:
            pymxc.enable(on_unavailable="error")
        except pymxc.SandboxError as error:
            sys.exit(int(error.status))

    The program may read its workspace (default: the folder of the script, or
    the current folder for ``python -m``) and nothing else of yours. It may
    not change it: the code in that folder starts outside the sandbox on
    every launch, so a program that could change it could run anything
    unsandboxed next time. Name the folders it may write to; a relative path
    is relative to the workspace and a missing folder is created::

        pymxc.enable(read_write=["data"])
        pymxc.enable(network="internet", read_write=[r"C:\\work\\output"])

    ``workspace_access="rw"`` makes the whole workspace writable (with a
    warning when it holds the program's code). ``options`` are the SETTINGS
    in lower case.

    Keep settings and caches in a READ_WRITE folder: %APPDATA% is not
    writable inside the sandbox and Windows discards the sandbox's own
    %LOCALAPPDATA% afterwards.

    READ SAVED API KEYS BEFORE THIS CALL. Windows Credential Manager (and so
    the ``keyring`` package) returns nothing inside the sandbox. Whatever is
    in ``os.environ`` when enable() is called is passed to the sandboxed copy::

        import os, pymxc
        if not pymxc.is_sandboxed() and not os.environ.get("LLM_API_KEY"):
            import keyring
            os.environ["LLM_API_KEY"] = keyring.get_password("your-app", "api-key") or ""
        pymxc.enable(network="hosts", network_hosts=["api.example.com"])
    """
    opts = _options(options, own_program=True)
    if is_sandboxed():
        tmp = os.environ.get(_TEMP_VAR)
        if tmp and os.path.isdir(tmp):
            os.environ["TEMP"] = os.environ["TMP"] = tmp
            tempfile.tempdir = tmp
        return True

    current = status()
    restartable = getattr(sys, "frozen", False) or bool(sys.argv and sys.argv[0] not in ("", "-c"))
    args, module_launch = _restart_args() if restartable else ([], True)
    if getattr(sys, "frozen", False):
        home = Path(sys.executable).resolve().parent
    elif module_launch:
        home = Path.cwd().resolve()  # python -m imports from the current folder
    else:
        home = Path(sys.argv[0]).resolve().parent
    workspace = Path(opts.workspace).resolve() if opts.workspace else home

    if current.available and not restartable:
        current = SandboxStatus(Status.LAUNCH_FAILED, False,
                                "enable() can only restart a script, a module (python -m) or a frozen "
                                "program, not an interactive session or python -c.")
    if not current.available:
        try:
            proceed = _handle_unavailable(opts, current)
            if proceed:
                _check_settings(opts, workspace)  # a bad setting is an error with or without the sandbox
        except PolicyError as exc:
            # Raised from here, so the report points at the caller's enable() line.
            raise exc.with_traceback(None) from None
        if not proceed:
            raise SandboxUnavailable(f"{current.message} Refusing to run without the sandbox.", current.code)
        return False

    code_folders = (home, Path(__file__).resolve().parent)
    extra_read = []
    for folder in code_folders:  # the code itself must stay readable
        if folder != workspace and workspace not in folder.parents:
            extra_read.append(str(folder))
    cwd = Path.cwd()
    if cwd != workspace and workspace not in cwd.parents:
        cwd = workspace

    share_console = bool(opts.console) and bool(_GetConsoleWindow()) and _all_interactive()
    temp_dir = _new_temp_dir()
    proc = proxy = None
    try:
        try:
            proxy = _host_proxy(opts, on_block=lambda target: print(
                f"pymxc: NETWORK_HOSTS blocked a connection to {target}.", file=sys.stderr))
            if proxy is not None:
                proxy.on_error = lambda text: print(
                    f"pymxc: an allowed host could not be reached: {text}", file=sys.stderr)
            policy = _build_policy(opts, workspace, temp_dir, extra_read, proxy and proxy.url)
            if opts.workspace_access == "rw" and any(
                    folder == workspace or workspace in folder.parents for folder in code_folders):
                policy.warnings.append(
                    'WORKSPACE_ACCESS is "rw" and the workspace holds this program\'s code. The sandboxed '
                    "program can change code that runs OUTSIDE the sandbox on the next start. Leave "
                    "WORKSPACE_ACCESS unset and list data folders in READ_WRITE instead.")
            proc = SandboxedPopen(
                subprocess.list2cmdline(args), cwd=cwd, spec=policy.spec,
                env=_child_env(None, opts, temp_dir, policy.proxy_url), shell=False, text=False,
                console=share_console, inherit_stdio=bool(opts.console) and not share_console,
                ui_limits=policy.ui_limits, wait_for_tree=bool(opts.wait_for_child_processes))
        except SandboxLaunchError as exc:
            # The same error, with what it usually means and what to try.
            raise SandboxLaunchError(_explain(exc), exc.code) from None
        except SandboxError as exc:
            raise exc.with_traceback(None) from None
        for warning in policy.warnings:
            print(f"pymxc WARNING: {warning}", file=sys.stderr)
        if proc.stdout is not None:
            # CONSOLE = False: forward the output (a full pipe would stall the
            # program); under pythonw there is nowhere to send it, so drop it.
            def forward(stream, target):
                sink = getattr(target, "buffer", None)
                with stream:
                    for chunk in iter(lambda: stream.read1(65536), b""):
                        try:
                            if sink is not None:
                                sink.write(chunk)
                                sink.flush()
                        except (OSError, ValueError):
                            sink = None

            for stream, target in ((proc.stdout, sys.stdout), (proc.stderr, sys.stderr)):
                threading.Thread(target=forward, args=(stream, target), daemon=True).start()
        try:
            proc.wait()
        except KeyboardInterrupt:
            # With a console, Ctrl+C reached the sandboxed program too: let it finish its
            # own clean-up. Stop it if that takes too long or Ctrl+C is pressed again.
            # With CONSOLE = False it never saw the key, so it is stopped at once.
            try:
                if proc.stdout is None:
                    proc.wait(_INTERRUPT_GRACE_SECONDS)
            except (subprocess.TimeoutExpired, KeyboardInterrupt):
                pass
            if proc.returncode is None:
                proc.kill()
                proc.wait()
    finally:
        if proc is not None and proc.returncode is None:
            proc.kill()
        if proxy is not None:
            proxy.close()
        _remove_temp_dir(temp_dir)
    raise SystemExit(proc.returncode)


# =============================================================================
# Self-test and command line
# =============================================================================

# encode_spec(read_write=[r"C:\work\proj"], read_only=[r"C:\Python312"],
#             deny=[r"C:\work\proj\.secrets"], enumerate_paths=["C:\\"],
#             capabilities=[INTERNET, PRIVATE_NETWORK], network={"egress": "allow"})
# accepted by Microsoft's flatc-generated Rust bindings through the official
# flatbuffers 25.12.19 verifier, and decoded field by field by the official
# Python flatbuffers runtime.
_GOLDEN = (
    "20000000505345431600200004000800000000000c001000140018001c00000018000000010001001800000044000000"
    "5c00000074000000a0000000b400000029000000696e7465726e6574436c69656e742c707269766174654e6574776f72"
    "6b436c69656e7453657276657200000001000000040000000c000000433a5c776f726b5c70726f6a0000000001000000"
    "040000000c000000433a5c507974686f6e33313200000000010000000400000015000000433a5c776f726b5c70726f6a"
    "5c2e736563726574730008000800000004000000000000000e0000000c00000006000500040000000800000001000000"
    "010000000400000003000000433a5c00"
)


def selftest(workspace=None) -> int:
    """Check the policy encoder against verified bytes, then (when the sandbox
    is available) that Windows enforces a policy built by this file. Prints
    one PASS/FAIL line per check and returns 0 when all passed."""
    spec = encode_spec(read_write=[r"C:\work\proj"], read_only=[r"C:\Python312"],
                       deny=[r"C:\work\proj\.secrets"], enumerate_paths=["C:\\"],
                       capabilities=[INTERNET, PRIVATE_NETWORK], network={"egress": "allow"})
    ok = spec.hex() == _GOLDEN
    print(f"[{'PASS' if ok else 'FAIL'}] encoder matches the verified bytes")
    current = status()
    print(f"status: {current.code.name} - {current.message}")
    if not current.available:
        print("Skipping enforcement checks: the sandbox is not available here.")
        return 0 if ok else 1
    root = Path(workspace or tempfile.mkdtemp(prefix="pymxc_selftest_"))
    ws, outside = root / "ws", root / "outside"
    for d in (ws, outside, ws / ".secrets"):
        d.mkdir(parents=True, exist_ok=True)
    (ws / ".secrets" / "key.txt").write_text("secret", encoding="utf-8")
    (outside / "note.txt").write_text("outside", encoding="utf-8")
    py = sys.executable
    connect = ("import socket;socket.create_connection((chr(101)+chr(120)+chr(97)+chr(109)+chr(112)"
               "+chr(108)+chr(101)+chr(46)+chr(99)+chr(111)+chr(109),443),10);print(chr(67))")
    checks = [
        ("write inside the workspace", "echo hi> inside.txt && type inside.txt",
         lambda r: r.returncode == 0 and "hi" in r.stdout),
        ("write outside is denied", f'echo x> "{outside / "escape.txt"}"', lambda r: r.returncode != 0),
        ("read outside is denied", f'type "{outside / "note.txt"}"',
         lambda r: r.returncode != 0 and "outside" not in r.stdout),
        ("deny path is unreadable", f'type "{ws / ".secrets" / "key.txt"}"',
         lambda r: r.returncode != 0 and "secret" not in r.stdout),
        ("Python runs (full path)", f'"{py}" -c "print(6*7)"', lambda r: r.returncode == 0 and "42" in r.stdout),
        ("Python runs (argument list)", [py, "-c", "print(6*7)"], lambda r: r.returncode == 0 and "42" in r.stdout),
        ("tempfile.mkdtemp works", f'"{py}" -c "import tempfile,os;d=tempfile.mkdtemp();'
         f'open(os.path.join(d,chr(102)),chr(119)).write(chr(120));print(chr(79)+chr(75))"',
         lambda r: r.returncode == 0 and "OK" in r.stdout),
        ("network off blocks a connection", f'"{py}" -c "{connect}"',
         lambda r: r.returncode != 0 and "C" not in r.stdout),
    ]
    failed = 0
    try:
        for label, command, passed in checks:
            result = run(command, workspace=str(ws), deny=[str(ws / ".secrets")], timeout_seconds=60,
                         network="off", read_write=[], read_only=[], workspace_access="rw",
                         list_drive_roots=True)
            good = result.sandboxed and passed(result)
            failed += not good
            detail = f"exit {result.returncode}" if result.sandboxed else f"{result.status.name}: {result.message}"
            print(f"[{'PASS' if good else 'FAIL'}] {label} ({detail})")
        good = not (outside / "escape.txt").exists()
        failed += not good
        print(f"[{'PASS' if good else 'FAIL'}] nothing was written outside")
    finally:
        if workspace is None:
            shutil.rmtree(root, ignore_errors=True)
    return 0 if ok and not failed else 1


def _main(argv=None) -> int:
    import argparse
    import json

    ap = argparse.ArgumentParser(
        prog="pymxc", description="Run a command inside the Windows MXC sandbox.",
        epilog="Exit code: the command's own, or a pymxc status code (101-107) when it did not run.")
    ap.add_argument("--probe", action="store_true", help="report whether the sandbox works here (exit 0 = yes)")
    ap.add_argument("--selftest", action="store_true", help="check the encoder and that Windows enforces the policy")
    ap.add_argument("--run", metavar="COMMAND", help="run COMMAND sandboxed")
    ap.add_argument("--workspace", default=None, help="the folder the command works in (default: current)")
    ap.add_argument("--workspace-access", choices=("rw", "ro"), default=None)
    ap.add_argument("--network", choices=("off", "internet", "intranet", "all", "hosts", "custom"), default=None)
    ap.add_argument("--host", action="append", metavar="HOST",
                    help="allow only this HTTPS host, e.g. generativelanguage.googleapis.com "
                         "(repeatable; implies --network hosts)")
    ap.add_argument("--rule", action="append", metavar="RULE", help='network rule for --network custom, e.g. "10.0.0.0/8:443"')
    ap.add_argument("--proxy", metavar="URL", help="proxy for --network custom")
    ap.add_argument("--read-write", action="append", metavar="PATH", help="extra read-write path (repeatable)")
    ap.add_argument("--read-only", action="append", metavar="PATH", help="extra read-only path (repeatable)")
    ap.add_argument("--deny", action="append", metavar="PATH", help="blocked path (repeatable)")
    ap.add_argument("--no-windows", action="store_true", default=None, help="the command may not open windows")
    ap.add_argument("--timeout", type=float, metavar="SECONDS", default=None)
    ap.add_argument("--allow-unsandboxed", action="store_true",
                    help="if the sandbox is unavailable, warn and run the command WITHOUT it "
                         "(default: do not run)")
    ap.add_argument("--required", action="store_true",
                    help="do not run at all if the sandbox is unavailable (this is the default; "
                         "kept for older scripts)")
    args = ap.parse_args(argv)
    if args.probe:
        current = status()
        print(json.dumps({"status": current.code.name, "code": int(current.code),
                          "available": current.available, "message": current.message,
                          "windows_build": current.windows_build, "details": probe()}, indent=2))
        return int(current.code)
    if args.selftest:
        return selftest()
    if args.run:
        given = {"workspace": args.workspace, "workspace_access": args.workspace_access,
                 "network": args.network or ("hosts" if args.host else None), "network_hosts": args.host,
                 "network_rules": args.rule, "network_proxy": args.proxy,
                 "read_write": args.read_write, "read_only": args.read_only, "deny": args.deny,
                 "no_windows": args.no_windows, "timeout_seconds": args.timeout,
                 "on_unavailable": "error" if args.required else "warn" if args.allow_unsandboxed else None}
        result = run(args.run, **{k: v for k, v in given.items() if v is not None})
        for stream, text in ((sys.stdout, result.stdout), (sys.stderr, result.stderr)):
            # A redirected stream may use a code page that lacks some characters:
            # those are written as "?" so that the output is never lost to an error.
            encoding = getattr(stream, "encoding", None) or "utf-8"
            stream.write(text.encode(encoding, "replace").decode(encoding, "replace"))
        for warning in result.warnings:
            print(f"pymxc WARNING: {warning}", file=sys.stderr)
        if result.returncode is None or result.timed_out:
            print(f"pymxc: {result.status.name}: {result.message}", file=sys.stderr)
            return int(result.status)
        return result.returncode
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(_main())
