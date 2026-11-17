"""Tests for pymxc.py. From the repository root:

    py -3.12 -m unittest discover -s tests -v

The first three classes need no sandbox and run anywhere. ``LiveSandbox``
starts real sandboxed processes and is skipped where Windows lacks the sandbox.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pymxc  # noqa: E402

PY = sys.executable
UNAVAILABLE = pymxc.SandboxStatus(pymxc.Status.WINDOWS_TOO_OLD, False, "test: no sandbox here")


def no_sandbox():
    """Make pymxc believe this computer has no sandbox."""
    return mock.patch.object(pymxc, "status", return_value=UNAVAILABLE)


class Encoder(unittest.TestCase):
    def test_matches_verified_bytes(self):
        spec = pymxc.encode_spec(
            read_write=[r"C:\work\proj"], read_only=[r"C:\Python312"], deny=[r"C:\work\proj\.secrets"],
            enumerate_paths=["C:\\"], capabilities=[pymxc.INTERNET, pymxc.PRIVATE_NETWORK],
            network={"egress": "allow"})
        self.assertEqual(spec.hex(), pymxc._GOLDEN)

    def test_version_follows_the_fields_used(self):
        version = lambda spec: tuple(int.from_bytes(spec[i:i + 2], "little") for i in (0, 2))  # noqa: E731

        def root_version(**kw):
            spec = pymxc.encode_spec(**kw)
            table = int.from_bytes(spec[0:4], "little")
            vtable = table - int.from_bytes(spec[table:table + 4], "little", signed=True)
            field = int.from_bytes(spec[vtable + 4:vtable + 6], "little")
            return version(spec[table + field:])

        self.assertEqual(root_version(read_write=["C:\\a"]), (1, 0))
        self.assertEqual(root_version(enumerate_paths=["C:\\"]), (1, 1))
        self.assertEqual(root_version(network={"egress": "allow", "ingress": {"default": "allow"}}), (1, 1))

    def test_rejects_nul_in_a_path(self):
        with self.assertRaises(ValueError):
            pymxc.encode_spec(read_write=["C:\\a\x00b"])

    def test_destination_without_a_prefix_is_one_address(self):
        # Windows reads a missing prefix length as /0 (every address), so it is always written.
        spec = lambda *destinations: pymxc.encode_spec(  # noqa: E731
            network={"egress": "deny", "allow": [{"destinations": list(destinations)}]})
        self.assertEqual(spec("1.1.1.1"), spec("1.1.1.1/32"))
        self.assertEqual(spec("2001:db8::1"), spec("2001:db8::1/128"))
        self.assertEqual(spec("10.1.2.3/8"), spec("10.0.0.0/8"))
        self.assertNotEqual(spec("1.1.1.1"), spec("1.1.1.1/0"))
        self.assertEqual(spec({"subnet": "10.0.0.0/8", "except": ["10.0.0.5"]}),
                         spec({"subnet": "10.0.0.0/8", "except": ["10.0.0.5/32"]}))
        with self.assertRaises(ValueError):
            spec("example.com")


class Settings(unittest.TestCase):
    def test_unknown_option_is_named(self):
        with self.assertRaisesRegex(TypeError, "netwrok"):
            pymxc.run("echo x", netwrok="off")

    def test_keyword_beats_module_setting(self):
        with mock.patch.object(pymxc, "NETWORK", "internet"):
            self.assertEqual(pymxc._options({}).network, "internet")
            self.assertEqual(pymxc._options({"network": "all"}).network, "all")

    def test_every_option_has_a_setting(self):
        for name in pymxc._OPTION_NAMES:
            self.assertTrue(hasattr(pymxc, name.upper()), name)

    def test_network_rules(self):
        self.assertEqual(pymxc.parse_rule("10.0.0.0/8:443"),
                         {"destinations": ["10.0.0.0/8"], "ports": [{"protocol": "tcp", "port": 443}]})
        self.assertEqual(pymxc.parse_rule("192.168.1.5"), {"destinations": ["192.168.1.5/32"]})
        self.assertEqual(pymxc.parse_rule("udp 10.1.2.0/24:8000-8100")["ports"],
                         [{"protocol": "udp", "port": 8000, "end_port": 8100}])
        self.assertEqual(pymxc.parse_rule("2001:db8::/32"), {"destinations": ["2001:db8::/32"]})
        for bad in ("example.com", "10.0.0.1:0", "10.0.0.1:99999", "10.0.0.1:90-80"):
            with self.assertRaises(ValueError, msg=bad):
                pymxc.parse_rule(bad)

    def test_network_modes(self):
        def net(**kw):
            return pymxc._network(pymxc._options(kw), ["NetworkIngress"], [])

        self.assertEqual(net(), ([], {"egress": "deny"}))
        # The public/private line is drawn with address rules, the same on every network.
        private = [{"destinations": list(pymxc._PRIVATE_RANGES)}]
        self.assertIn("192.168.0.0/16", pymxc._PRIVATE_RANGES)
        self.assertEqual(net(network="internet"), ([pymxc.INTERNET], {"egress": "allow", "deny": private}))
        self.assertEqual(net(network="intranet"),
                         ([pymxc.INTERNET, pymxc.PRIVATE_NETWORK], {"egress": "deny", "allow": private}))
        self.assertEqual(net(network="all"), ([pymxc.INTERNET, pymxc.PRIVATE_NETWORK], {"egress": "allow"}))
        caps, policy = net(network="custom", network_rules=["10.0.0.0/8:443"], network_private=True)
        self.assertEqual(caps, [pymxc.INTERNET, pymxc.PRIVATE_NETWORK])
        self.assertEqual(policy["egress"], "deny")
        self.assertEqual(len(policy["allow"]), 1)
        # A proxy is the only way out: loopback to it, and no direct internet capability.
        proxied = ([pymxc.PRIVATE_NETWORK, pymxc.LOOPBACK],
                   {"proxy": "http://127.0.0.1:8080", "peer": "MXC-Loopback"})
        self.assertEqual(net(network="custom", network_proxy="http://127.0.0.1:8080"), proxied)
        self.assertEqual(pymxc._network(pymxc._options({"network": "hosts"}), [], [],
                                        "http://127.0.0.1:8080"), proxied)
        caps, policy = net(network="internet", allow_loopback=True)
        self.assertEqual((caps, policy["peer"]), ([pymxc.INTERNET, pymxc.LOOPBACK], "MXC-Loopback"))
        self.assertEqual(net(network="internet", allow_inbound=True)[0], [pymxc.INTERNET, pymxc.PRIVATE_NETWORK])

    def test_network_hosts(self):
        self.assertEqual(pymxc._parse_host("API.Example.com"), ("api.example.com", 443))
        self.assertEqual(pymxc._parse_host("https://api.example.com/v1/x"), ("api.example.com", 443))
        self.assertEqual(pymxc._parse_host("*.example.com:8443"), ("*.example.com", 8443))
        for bad in ("http://example.com", "exa mple.com", "*", "example.com:0", ""):
            with self.assertRaises(pymxc.PolicyError, msg=bad):
                pymxc._parse_host(bad)
        proxy = pymxc._HostProxy(["api.example.com", "*.googleapis.com", "host.test:8443"])
        try:
            for host, port, expected in (
                    ("api.example.com", 443, True), ("API.EXAMPLE.COM.", 443, True),
                    ("api.example.com", 80, False), ("evil-api.example.com", 443, False),
                    ("api.example.com.evil.net", 443, False), ("example.com", 443, False),
                    ("generativelanguage.googleapis.com", 443, True), ("googleapis.com", 443, False),
                    ("notgoogleapis.com", 443, False), ("host.test", 8443, True), ("host.test", 443, False),
                    ("1.1.1.1", 443, False)):
                self.assertEqual(proxy.allows(host, port), expected, (host, port))
        finally:
            proxy.close()
        for bad in ([], "api.example.com"):
            with self.assertRaises(pymxc.PolicyError, msg=bad):
                pymxc._HostProxy(bad)

    def test_host_filter_tunnels_only_listed_hosts(self):
        import socket
        import threading

        upstream = socket.create_server(("127.0.0.1", 0))
        port = upstream.getsockname()[1]

        def echo():
            conn, _ = upstream.accept()
            conn.sendall(conn.recv(100).upper())
            conn.close()

        threading.Thread(target=echo, daemon=True).start()
        proxy = pymxc._HostProxy([f"localhost:{port}"])

        def ask(request):
            with socket.create_connection(("127.0.0.1", int(proxy.url.rsplit(":", 1)[1])), 5) as s:
                s.sendall(request)
                return s, s.recv(4096)

        try:
            with socket.create_connection(("127.0.0.1", int(proxy.url.rsplit(":", 1)[1])), 5) as s:
                s.sendall(f"CONNECT localhost:{port} HTTP/1.1\r\n\r\n".encode())
                self.assertTrue(s.recv(4096).startswith(b"HTTP/1.1 200"))
                s.sendall(b"hello")
                self.assertEqual(s.recv(100), b"HELLO")
            self.assertTrue(ask(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")[1].startswith(b"HTTP/1.1 403"))
            self.assertTrue(ask(b"GET http://localhost/ HTTP/1.1\r\n\r\n")[1].startswith(b"HTTP/1.1 403"))
            self.assertEqual(proxy.blocked[0], "example.com:443")
            self.assertEqual(len(proxy.blocked), 2)
        finally:
            proxy.close()
            upstream.close()

    def test_host_filter_falls_back_to_the_organisation_proxy(self):
        import socket
        import threading

        target = socket.create_server(("127.0.0.1", 0))
        company = socket.create_server(("127.0.0.1", 0))  # stands in for the organisation's proxy
        seen = []

        def serve_target():
            conn, _ = target.accept()
            conn.sendall(conn.recv(100).upper())
            conn.close()

        def serve_company(answer):
            conn, _ = company.accept()
            seen.append(conn.recv(4096).split(b"\r\n")[0].decode())
            if answer:
                conn.sendall(answer)
                conn.close()
                return
            out = socket.create_connection(target.getsockname(), 5)
            conn.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
            out.sendall(conn.recv(100))
            conn.sendall(out.recv(100))
            conn.close()
            out.close()

        def through(proxy, host):
            with socket.create_connection(("127.0.0.1", int(proxy.url.rsplit(":", 1)[1])), 30) as s:
                s.sendall(f"CONNECT {host}:443 HTTP/1.1\r\n\r\n".encode())
                first = s.recv(4096)
                if first.startswith(b"HTTP/1.1 200"):
                    s.sendall(b"hello")
                    return s.recv(100)
                return first

        # ".invalid" never resolves, so the direct route fails and the proxy is used.
        proxy = pymxc._HostProxy(["api.unreachable.invalid"], upstream="http://127.0.0.1:%d" % company.getsockname()[1])
        try:
            threading.Thread(target=serve_target, daemon=True).start()
            threading.Thread(target=serve_company, args=(None,), daemon=True).start()
            self.assertEqual(through(proxy, "api.unreachable.invalid"), b"HELLO")
            self.assertEqual(seen, ["CONNECT api.unreachable.invalid:443 HTTP/1.1"])
            threading.Thread(target=serve_company, args=(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",),
                             daemon=True).start()
            self.assertTrue(through(proxy, "api.unreachable.invalid").startswith(b"HTTP/1.1 502"))
            self.assertIn("sign-in", proxy.errors[-1])
        finally:
            proxy.close()
            target.close()
            company.close()

    def test_upstream_proxy_setting(self):
        with mock.patch.dict(os.environ, {"HTTPS_PROXY": "http://corp.example:8443"}):
            self.assertEqual(pymxc._upstream_proxy("auto"), ("corp.example", 8443))
            self.assertIsNone(pymxc._upstream_proxy(""))
        self.assertEqual(pymxc._upstream_proxy("proxy.example:3128"), ("proxy.example", 3128))
        self.assertEqual(pymxc._upstream_proxy("http://proxy.example"), ("proxy.example", 8080))
        with self.assertRaises(pymxc.PolicyError):
            pymxc._upstream_proxy("socks5://proxy.example:1080")

    def test_proxy_environment(self):
        env = {"PATH": "X", "https_proxy": "http://corp:1", "NO_PROXY": "*"}
        out = pymxc._child_env(env, pymxc._options({}), None, "http://127.0.0.1:9")
        self.assertEqual((out["HTTPS_PROXY"], out["HTTP_PROXY"]), ("http://127.0.0.1:9",) * 2)
        self.assertNotIn("https_proxy", out)
        self.assertNotIn("NO_PROXY", out)

    def test_inbound_without_support_is_a_warning_not_more_access(self):
        warnings = []
        _, policy = pymxc._network(pymxc._options({"network": "internet", "allow_inbound": True}), [], warnings)
        self.assertNotIn("ingress", policy)
        self.assertTrue(warnings)

    def test_ui_mask(self):
        mask = lambda **kw: pymxc._ui_mask(pymxc._options(kw))  # noqa: E731
        self.assertEqual(mask(clipboard="all"), 0)
        # CLIPBOARD and UI_ISOLATION = None: a command cannot read the clipboard or reach
        # other programs' windows; your own program (enable()) can.
        self.assertIsNone(pymxc.CLIPBOARD)
        self.assertIsNone(pymxc.UI_ISOLATION)
        self.assertEqual(mask(), pymxc.UI_READCLIPBOARD | pymxc.UI_HANDLES)
        self.assertEqual(pymxc._ui_mask(pymxc._options({}, own_program=True)), 0)
        self.assertEqual(mask(clipboard="none"),
                         pymxc.UI_READCLIPBOARD | pymxc.UI_WRITECLIPBOARD | pymxc.UI_HANDLES)
        # Pasting needs reach to other programs' windows, so allowing it keeps that reach.
        self.assertEqual(mask(clipboard="read"), pymxc.UI_WRITECLIPBOARD)
        self.assertEqual(mask(ui_isolation="desktop"), pymxc.UI_READCLIPBOARD)
        self.assertEqual(mask(clipboard="all", ui_isolation="container"), pymxc.UI_HANDLES | pymxc.UI_GLOBALATOMS)
        self.assertEqual(mask(clipboard="none", ui_isolation="container", desktop_control=False,
                              system_settings="none", ime=False, input_injection=False), 0x3FF)
        with self.assertRaises(pymxc.PolicyError):
            mask(clipboard="sometimes")

    def test_pasting_with_window_isolation_is_a_warning(self):
        with tempfile.TemporaryDirectory() as ws:
            build = lambda **kw: pymxc._build_policy(pymxc._options(kw), ws).warnings  # noqa: E731
            self.assertTrue(any("cannot paste" in w for w in build(clipboard="all", ui_isolation="handles")))
            self.assertFalse(any("cannot paste" in w for w in build(clipboard="all")))
            self.assertFalse(any("cannot paste" in w for w in build()))

    def test_defaults_that_depend_on_the_caller(self):
        command, own = pymxc._options({}), pymxc._options({}, own_program=True)
        # A command you may not trust: never started unsandboxed, cannot paste or see other windows.
        self.assertEqual((command.on_unavailable, command.clipboard, command.ui_isolation, command.workspace_access),
                         ("error", "write", "handles", "rw"))
        # Your own program: carries on with a warning, behaves like any desktop program.
        self.assertEqual((own.on_unavailable, own.clipboard, own.ui_isolation, own.workspace_access),
                         ("warn", "all", "desktop", "ro"))
        with mock.patch.object(pymxc, "ON_UNAVAILABLE", "silent"):
            self.assertEqual(pymxc._options({}).on_unavailable, "silent")
            self.assertEqual(pymxc._options({}, own_program=True).on_unavailable, "silent")

    def test_private_ranges_cover_multicast_and_broadcast(self):
        import ipaddress
        ranges = [ipaddress.ip_network(r) for r in pymxc._PRIVATE_RANGES]

        def covered(text):
            address = ipaddress.ip_address(text)
            return any(address in r for r in ranges if r.version == address.version)

        for address in ("192.168.1.1", "10.9.8.7", "169.254.169.254", "239.255.255.250", "224.0.0.251",
                        "255.255.255.255", "ff02::fb", "ff02::c", "fe80::1", "fd00::1"):
            self.assertTrue(covered(address), address)
        for address in ("1.1.1.1", "8.8.8.8", "223.255.255.255", "2606:4700:4700::1111"):
            self.assertFalse(covered(address), address)

    def test_secret_looking_names(self):
        for name in ("OPENAI_API_KEY", "GITHUB_TOKEN", "GH_PAT", "MYSQL_PWD", "DOCKER_AUTH_CONFIG", "NPM_AUTH",
                     "SENTRY_DSN", "SSH_PASSPHRASE", "SESSION_COOKIE", "SLACK_WEBHOOK_URL",
                     "AZURE_STORAGE_CONNECTION_STRING", "ConnectionString"):
            self.assertTrue(pymxc._looks_secret(name), name)
        for name in ("PATH", "PWD", "OLDPWD", "KEYBOARD", "MONKEY", "PATHEXT", "AUTHOR", "PATTERN", "HOME_DIR"):
            self.assertFalse(pymxc._looks_secret(name), name)
        # A URL with a password in it is a secret whatever the variable is called.
        self.assertTrue(pymxc._looks_secret("DATABASE_URL", "postgres://app:s3cret@db.example:5432/x"))
        self.assertFalse(pymxc._looks_secret("DATABASE_URL", "postgres://db.example:5432/x"))
        self.assertFalse(pymxc._looks_secret("HOMEPAGE", "https://example.com/a@b"))
        out = pymxc._child_env({"REDIS_URL": "redis://:pw@cache:6379", "SITE": "https://example.com"},
                               pymxc._options({"hide_secret_env": True}), None)
        self.assertNotIn("REDIS_URL", out)
        self.assertIn("SITE", out)

    @unittest.skipUnless(sys.platform == "win32", "temp folders are only made for the Windows sandbox")
    def test_temp_folders_are_new_each_time_and_leftovers_are_swept(self):
        first, second = pymxc._new_temp_dir(), pymxc._new_temp_dir()
        base = Path(first).parent
        gone = subprocess.Popen([PY, "-c", "pass"])
        gone.wait()
        leftover = base / f"run-{gone.pid}-1-abcdef"   # from a program that has ended
        mine = base / f"run-{os.getpid()}-999-abcdef"  # from this one, still running
        other = base / "not-a-run-folder"
        try:
            self.assertNotEqual(first, second)
            self.assertEqual(os.listdir(first), [])
            for folder in (leftover, mine, other):
                folder.mkdir(exist_ok=True)
            (leftover / "stale.txt").write_text("x")
            del gone  # let go of the process handle, as a program that ended long ago would have
            pymxc._sweep_temp_dirs(base)
            self.assertFalse(leftover.exists())
            self.assertTrue(mine.exists() and other.exists())
        finally:
            for folder in (leftover, mine, other, Path(first), Path(second)):
                shutil.rmtree(folder, ignore_errors=True)

    def test_workspace_warnings_for_commands(self):
        code = Path(pymxc.__file__).resolve().parent
        with tempfile.TemporaryDirectory() as ws:
            self.assertEqual(pymxc._workspace_warnings(ws, "rw"), [])
        self.assertTrue(any("own code" in w for w in pymxc._workspace_warnings(code, "rw")))
        self.assertTrue(any("own code" in w for w in pymxc._workspace_warnings(code.parent, "rw")))
        self.assertFalse(any("own code" in w for w in pymxc._workspace_warnings(code, "ro")))
        if os.environ.get("USERPROFILE"):
            for access in ("rw", "ro"):
                self.assertTrue(any("user profile" in w for w in pymxc._workspace_warnings(
                    os.environ["USERPROFILE"], access)), access)

    def test_notes_are_returned_as_stored(self):
        notes = []
        self.assertEqual(pymxc._remember(notes, "a\x1b[2Jb"), "a?[2Jb")
        self.assertEqual(pymxc._remember(notes, "a\x1b[2Jb"), "")       # known already
        self.assertEqual(notes, ["a?[2Jb"])

    def test_launch_errors_are_explained(self):
        refused = pymxc._explain(pymxc.SandboxLaunchError("CreateProcessW failed: not supported (50)", 50))
        self.assertIn("job object", refused)
        denied = pymxc._explain(pymxc.SandboxLaunchError("CreateProcessW failed: Access is denied (5)", 5))
        self.assertIn("READ_ONLY", denied)

    def test_bad_values_are_policy_errors(self):
        with tempfile.TemporaryDirectory() as ws:
            for kw in ({"network": "on"}, {"workspace_access": "rwx"}, {"read_only": "C:\\one-string"},
                       {"network": "custom", "network_rules": ["example.com"]}):
                with self.assertRaises(pymxc.PolicyError, msg=kw) as caught:
                    pymxc._build_policy(pymxc._options(kw), ws)
                self.assertEqual(caught.exception.status, pymxc.Status.POLICY_INVALID)
            with self.assertRaises(pymxc.PolicyError):
                pymxc._build_policy(pymxc._options({}), os.path.join(ws, "missing"))

    def test_deny_without_support_is_refused(self):
        with tempfile.TemporaryDirectory() as ws:
            old = {"available": True, "version": (1, 0), "support": []}
            with mock.patch.object(pymxc, "probe", return_value=old):
                with self.assertRaises(pymxc.PolicyError) as caught:
                    pymxc._build_policy(pymxc._options({"deny": [ws]}), ws)
                self.assertEqual(caught.exception.status, pymxc.Status.FEATURE_UNSUPPORTED)
                policy = pymxc._build_policy(pymxc._options({"list_drive_roots": True}), ws)
                self.assertEqual(policy.enumerate, [])
                self.assertTrue(any("LIST_DRIVE_ROOTS" in w for w in policy.warnings))

    def test_missing_listed_path_is_skipped_with_a_warning(self):
        with tempfile.TemporaryDirectory() as ws:
            gone = os.path.join(ws, "gone")
            policy = pymxc._build_policy(pymxc._options({"read_only": [gone]}), ws)
            self.assertNotIn(gone, policy.read_only)
            self.assertTrue(any("gone" in w for w in policy.warnings))

    def test_missing_deny_path_is_still_denied(self):
        with tempfile.TemporaryDirectory() as ws:
            later = os.path.join(ws, "later")
            policy = pymxc._build_policy(pymxc._options({"deny": [later]}), ws)
            self.assertEqual(policy.deny, [later])
            self.assertTrue(any("later" in w for w in policy.warnings))
            # Windows refuses a deny path whose folder is missing too, so that is an error here.
            with self.assertRaisesRegex(pymxc.PolicyError, "DENY"):
                pymxc._build_policy(pymxc._options({"deny": [os.path.join(ws, "no", "such", "place")]}), ws)

    def test_relative_paths_are_relative_to_the_workspace(self):
        with tempfile.TemporaryDirectory() as ws, tempfile.TemporaryDirectory() as elsewhere:
            os.mkdir(os.path.join(ws, "ref"))
            before = os.getcwd()
            os.chdir(elsewhere)
            try:
                policy = pymxc._build_policy(pymxc._options(
                    {"read_write": ["data"], "read_only": ["ref"], "deny": [".secrets"]}), ws)
            finally:
                os.chdir(before)
            self.assertIn(os.path.join(ws, "data"), policy.read_write)
            self.assertIn(os.path.join(ws, "ref"), policy.read_only)
            self.assertEqual(policy.deny, [os.path.join(ws, ".secrets")])
            self.assertEqual(os.listdir(elsewhere), [])

    def test_missing_read_write_folder_is_created(self):
        with tempfile.TemporaryDirectory() as ws:
            deep = os.path.join(ws, "data", "cache")
            policy = pymxc._build_policy(pymxc._options({"read_write": [deep]}), ws)
            self.assertTrue(os.path.isdir(deep))
            self.assertIn(deep, policy.read_write)
            blocker = os.path.join(ws, "file.txt")
            Path(blocker).write_text("x")
            with self.assertRaisesRegex(pymxc.PolicyError, "READ_WRITE"):
                pymxc._build_policy(pymxc._options({"read_write": [os.path.join(blocker, "sub")]}), ws)

    def test_workspace_access_default_depends_on_the_caller(self):
        with tempfile.TemporaryDirectory() as ws:
            self.assertIsNone(pymxc.WORKSPACE_ACCESS)
            build = lambda own_program, **kw: pymxc._build_policy(  # noqa: E731
                pymxc._options(kw, own_program=own_program), ws)
            self.assertIn(ws, build(False).read_write)            # run() and Popen()
            self.assertIn(ws, build(True).read_only)              # enable()
            self.assertNotIn(ws, build(True).read_write)
            self.assertIn(ws, build(True, workspace_access="rw").read_write)
            self.assertIn(ws, build(False, workspace_access="ro").read_only)

    def test_pip_config_grants_files_not_folders(self):
        self.assertFalse(pymxc.GRANT_PIP_CONFIG)
        with tempfile.TemporaryDirectory() as home:
            ini, cert = Path(home, "pip.ini"), Path(home, "ca.pem")
            ini.write_text(f"[global]\ncert = {cert}\n", encoding="utf-8")
            cert.write_text("x")
            Path(home, "private.txt").write_text("x")
            with mock.patch.dict(os.environ, {"PIP_CONFIG_FILE": str(ini)}):
                granted = {os.path.normcase(str(p)) for p in pymxc._pip_config_paths()}
                policy = pymxc._build_policy(pymxc._options({"grant_pip_config": True}), home)
            self.assertIn(os.path.normcase(str(ini)), granted)
            self.assertIn(os.path.normcase(str(cert)), granted)
            self.assertNotIn(os.path.normcase(home), granted)  # the folder would expose private.txt
            self.assertIn(str(ini), policy.read_only)

    def test_empty_environment_block_is_terminated(self):
        self.assertEqual(pymxc._env_block({})[:], "\0\0")
        self.assertEqual(pymxc._env_block({"B": "2", "a": "1"})[:], "a=1\0B=2\0\0")

    def test_listing_names_needs_the_feature_not_only_the_version(self):
        with tempfile.TemporaryDirectory() as ws:
            no_flag = {"available": True, "version": (1, 1), "support": ["FileSystemDeny"]}
            with mock.patch.object(pymxc, "probe", return_value=no_flag):
                policy = pymxc._build_policy(pymxc._options({"list_drive_roots": True}), ws)
            self.assertEqual(policy.enumerate, [])
            self.assertTrue(any("LIST_DRIVE_ROOTS" in w for w in policy.warnings))

    def test_host_filter_limits_what_it_takes_from_the_program(self):
        import socket
        import threading

        company = socket.create_server(("127.0.0.1", 0))  # stands in for the organisation's proxy
        seen = []

        def serve_company():
            while True:
                try:
                    conn, _ = company.accept()
                except OSError:
                    return
                seen.append(conn.recv(4096))
                conn.close()

        threading.Thread(target=serve_company, daemon=True).start()
        proxy = pymxc._HostProxy(["*.example.com"], upstream="http://127.0.0.1:%d" % company.getsockname()[1])
        port = int(proxy.url.rsplit(":", 1)[1])

        def ask(target):
            with socket.create_connection(("127.0.0.1", port), 30) as s:
                s.sendall(f"CONNECT {target} HTTP/1.1\r\n\r\n".encode("latin-1"))
                return s.recv(200)

        try:
            # These end with the allowed suffix but are not host names: refused, never passed on.
            for target in ("evil.test:443/.example.com:443", "evil.test:443#.example.com:443",
                           "evil.test?x=.example.com:443", "a_b.example.com:443", "\x1b[2J.example.com:443"):
                self.assertTrue(ask(target).startswith(b"HTTP/1.1 403"), target)
            self.assertEqual(seen, [])
            ask("x" * 5000 + ".blocked.test:443")
            for i in range(pymxc._MAX_NOTES + 20):
                ask(f"h{i}.blocked.test:443")
            self.assertEqual(len(proxy.blocked), pymxc._MAX_NOTES + 1)
            self.assertEqual(proxy.blocked[-1], "(more, not listed)")
            self.assertTrue(all(len(b) <= pymxc._MAX_NOTE_LENGTH + 3 and b.isprintable() for b in proxy.blocked))
        finally:
            proxy.close()
            company.close()

    def test_host_filter_limits_simultaneous_connections(self):
        import socket

        with mock.patch.object(pymxc, "_MAX_TUNNELS", 2):
            proxy = pymxc._HostProxy(["example.com"], upstream="")
        port = int(proxy.url.rsplit(":", 1)[1])
        held = [socket.create_connection(("127.0.0.1", port), 10) for _ in range(2)]  # idle, slots taken
        try:
            import time
            time.sleep(0.3)
            with socket.create_connection(("127.0.0.1", port), 10) as extra:
                extra.settimeout(10)
                extra.sendall(b"CONNECT nope.test:443 HTTP/1.1\r\n\r\n")
                try:
                    answer = extra.recv(100)
                except OSError:
                    answer = b""
            self.assertEqual(answer, b"")  # closed without an answer
            self.assertEqual(proxy.blocked, [])
        finally:
            for s in held:
                s.close()
            proxy.close()

    def test_timeout_off_windows_ends_the_process_group(self):
        proc = mock.Mock(pid=4321)
        with mock.patch.object(sys, "platform", "linux"), mock.patch.object(pymxc, "_PROCESS_GROUPS", True), \
                mock.patch.object(os, "killpg", create=True) as killpg:
            pymxc._kill_tree(proc)
        killpg.assert_called_once()
        self.assertEqual(killpg.call_args.args[0], 4321)
        proc.kill.assert_called_once()

    def test_restart_command_knows_how_the_program_was_started(self):
        import types
        script = os.path.join(tempfile.gettempdir(), "app.py")
        with mock.patch.dict(sys.modules, {"__main__": types.SimpleNamespace(__spec__=None)}), \
                mock.patch.object(sys, "argv", [script, "-m", "gpt"]):
            args, module_launch = pymxc._restart_args()
        self.assertFalse(module_launch)  # "-m" here is the script's own argument
        self.assertEqual(args[-2:], ["-m", "gpt"])
        spec = types.SimpleNamespace(name="pkg.__main__")
        with mock.patch.dict(sys.modules, {"__main__": types.SimpleNamespace(__spec__=spec)}), \
                mock.patch.object(sys, "argv", ["ignored", "x"]):
            args, module_launch = pymxc._restart_args()
        self.assertTrue(module_launch)
        self.assertEqual(args[-3:], ["-m", "pkg", "x"])

    def test_the_marker_variable_alone_is_not_believed(self):
        with mock.patch.dict(os.environ, {"PYMXC_SANDBOXED": "1"}):
            self.assertFalse(pymxc.is_sandboxed())  # this test process is not contained
            with mock.patch.object(pymxc, "_in_app_container", return_value=True):
                self.assertTrue(pymxc.is_sandboxed())
        with mock.patch.dict(os.environ), mock.patch.object(pymxc, "_in_app_container", return_value=True):
            os.environ.pop("PYMXC_SANDBOXED", None)
            self.assertFalse(pymxc.is_sandboxed())

    def test_child_environment(self):
        env = {"PATH": "X", "MY_API_KEY": "s", "GITHUB_TOKEN": "s", "KEYBOARD": "us", "HOME_DIR": "h"}
        out = pymxc._child_env(env, pymxc._options({"hide_secret_env": True, "extra_env": {"A": 1}}), "T")
        self.assertNotIn("MY_API_KEY", out)
        self.assertNotIn("GITHUB_TOKEN", out)
        self.assertEqual((out["KEYBOARD"], out["A"], out["PYMXC_SANDBOXED"], out["PYMXC_TEMP"]),
                         ("us", "1", "1", "T"))
        self.assertTrue(out["PATH"].startswith(os.path.dirname(PY)))
        kept = pymxc._child_env(env, pymxc._options({"python_on_path": False}), None)
        self.assertEqual((kept["PATH"], kept["MY_API_KEY"]), ("X", "s"))


class Fallback(unittest.TestCase):
    """What happens on a computer without the sandbox."""

    def setUp(self):
        pymxc._warned[0] = False

    def test_status_codes_are_stable(self):
        self.assertEqual([int(s) for s in pymxc.Status], [0, 101, 102, 103, 104, 105, 106, 107])

    def test_commands_are_not_run_unsandboxed_unless_asked(self):
        with tempfile.TemporaryDirectory() as ws, no_sandbox(), mock.patch("sys.stderr") as err:
            marker = Path(ws, "ran.txt")
            result = pymxc.run([PY, "-c", f"open(r'{marker}', 'w').close()"])
            self.assertEqual((result.returncode, result.sandboxed, result.status),
                             (None, False, pymxc.Status.WINDOWS_TOO_OLD))
            self.assertIn("Not run", result.message)
            with self.assertRaises(pymxc.SandboxUnavailable):
                pymxc.Popen([PY, "-c", f"open(r'{marker}', 'w').close()"])
            self.assertFalse(marker.exists())
            err.write.assert_not_called()

    def test_command_line_does_not_run_unsandboxed_unless_asked(self):
        import contextlib
        import io
        with tempfile.TemporaryDirectory() as ws, no_sandbox():
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                refused = pymxc._main(["--workspace", ws, "--run", "echo ran"])
                allowed = pymxc._main(["--workspace", ws, "--run", "echo ran", "--allow-unsandboxed"])
        self.assertEqual((refused, allowed), (int(pymxc.Status.WINDOWS_TOO_OLD), 0))
        self.assertEqual(out.getvalue().split(), ["ran"])
        self.assertIn("WITHOUT the sandbox", err.getvalue())

    def test_run_warns_once_and_runs_unsandboxed(self):
        with no_sandbox(), mock.patch("sys.stderr") as err:
            first = pymxc.run([PY, "-c", "print('ran')"], on_unavailable="warn")
            pymxc.run([PY, "-c", "print('ran')"], on_unavailable="warn")
        self.assertEqual((first.returncode, first.stdout.strip(), first.sandboxed), (0, "ran", False))
        self.assertEqual(first.status, pymxc.Status.WINDOWS_TOO_OLD)
        self.assertTrue(first.ok)
        written = "".join(call.args[0] for call in err.write.call_args_list)
        self.assertEqual(written.count("WITHOUT the sandbox"), 1)

    def test_run_silent(self):
        with no_sandbox(), mock.patch("sys.stderr") as err:
            result = pymxc.run("echo quiet", on_unavailable="silent")
        self.assertEqual((result.returncode, result.sandboxed), (0, False))
        err.write.assert_not_called()

    def test_run_error_does_not_run(self):
        with tempfile.TemporaryDirectory() as ws, no_sandbox():
            marker = Path(ws, "ran.txt")
            result = pymxc.run([PY, "-c", f"open(r'{marker}', 'w').close()"], on_unavailable="error")
            self.assertIsNone(result.returncode)
            self.assertFalse(result.ok)
            self.assertEqual(result.status, pymxc.Status.WINDOWS_TOO_OLD)
            self.assertIn("Not run", result.message)
            self.assertFalse(marker.exists())

    def test_run_unsandboxed_timeout_and_input(self):
        with no_sandbox():
            slow = pymxc.run([PY, "-c", "import time; time.sleep(30)"], timeout_seconds=1,
                             on_unavailable="silent")
            echo = pymxc.run([PY, "-c", "import sys; print(sys.stdin.read().upper())"], input="abc",
                             on_unavailable="silent")
        self.assertTrue(slow.timed_out)
        self.assertEqual(slow.status, pymxc.Status.TIMED_OUT)
        self.assertEqual(echo.stdout.strip(), "ABC")

    def test_bad_on_unavailable_value(self):
        with no_sandbox():
            result = pymxc.run("echo x", on_unavailable="maybe")
        self.assertEqual((result.returncode, result.status), (None, pymxc.Status.POLICY_INVALID))

    def test_popen(self):
        with no_sandbox():
            proc = pymxc.Popen([PY, "-c", "print('plain')"], on_unavailable="silent")
            self.assertFalse(proc.sandboxed)
            self.assertEqual(proc.stdout.read().strip(), "plain")
            proc.stdout.close()
            proc.stderr.close()
            self.assertEqual(proc.wait(), 0)
            with self.assertRaises(pymxc.SandboxUnavailable) as caught:
                pymxc.Popen("echo x", on_unavailable="error")
            self.assertEqual(caught.exception.status, pymxc.Status.WINDOWS_TOO_OLD)

    def test_enable(self):
        with no_sandbox(), mock.patch("sys.stderr"):
            self.assertFalse(pymxc.enable())
            with self.assertRaises(SystemExit) as caught:
                pymxc.enable(on_unavailable="error")
        self.assertEqual(caught.exception.code, int(pymxc.Status.WINDOWS_TOO_OLD))

    def test_enable_inside_the_sandbox_returns_true(self):
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {"PYMXC_SANDBOXED": "1", "PYMXC_TEMP": tmp}), \
                mock.patch.object(pymxc, "_in_app_container", return_value=True), \
                mock.patch.object(tempfile, "tempdir", None):
            self.assertTrue(pymxc.enable())
            self.assertEqual(os.environ["TEMP"], tmp)

    def test_read_write_folders_are_created_without_the_sandbox_too(self):
        with tempfile.TemporaryDirectory() as ws, no_sandbox():
            result = pymxc.run([PY, "-c", "print(1)"], workspace=ws, read_write=["data"], on_unavailable="silent")
            self.assertEqual(result.returncode, 0)
            self.assertTrue(os.path.isdir(os.path.join(ws, "data")))
            bad = pymxc.run([PY, "-c", "print(1)"], workspace=ws, read_write="data", on_unavailable="silent")
            self.assertEqual((bad.returncode, bad.status), (None, pymxc.Status.POLICY_INVALID))

    def test_settings_apply_without_the_sandbox_too(self):
        show = "import os; print(os.environ.get('MY_API_KEY'), os.environ.get('KEPT'), 'caf\\u00e9')"
        env = {k: v for k, v in os.environ.items() if k.upper() not in ("PYTHONIOENCODING", "PYTHONUTF8")}
        env.update(MY_API_KEY="secret", KEPT="yes")
        with no_sandbox():
            hidden = pymxc.run([PY, "-c", show], env=env, hide_secret_env=True, on_unavailable="silent")
            shown = pymxc.run([PY, "-c", show], env=env, on_unavailable="silent")
            lines = pymxc.run([PY, "-c", "print('a'); print('b')"], on_unavailable="silent")
            # A bad value is refused here as it is where the sandbox exists; nothing runs.
            for bad in ({"network": "sideways"}, {"clipboard": "maybe"}, {"workspace_access": "rwx"},
                        {"network": "hosts"}, {"network": "custom", "network_rules": ["example.com"]},
                        {"encoding": "no-such-codec"}):
                result = pymxc.run([PY, "-c", "print(1)"], on_unavailable="silent", **bad)
                self.assertEqual((result.returncode, result.status), (None, pymxc.Status.POLICY_INVALID), bad)
            with self.assertRaises(pymxc.PolicyError):
                pymxc.Popen([PY, "-c", "print(1)"], on_unavailable="silent", network="sideways")
        self.assertEqual(hidden.stdout, "None yes café\n")   # UTF-8, and lines end with \n
        self.assertEqual(shown.stdout, "secret yes café\n")
        self.assertEqual(lines.stdout, "a\nb\n")
        self.assertNotIn("PYMXC_SANDBOXED", pymxc._child_env({}, pymxc._options({}), None, sandboxed=False))

    def test_other_operating_systems(self):
        # Import the file as it would load off Windows: no kernel32, no msvcrt.
        code = textwrap.dedent(f"""
            import subprocess, sys
            sys.platform = "linux"
            sys.path.insert(0, r"{ROOT}")
            import pymxc
            s = pymxc.status()
            r = pymxc.run([sys.executable, "-c", "print('ran')"], on_unavailable="silent")
            print(s.code.name, s.available, pymxc.available(), r.returncode, r.sandboxed, r.stdout.strip())
        """)
        out = subprocess.run([PY, "-c", code], capture_output=True, text=True)
        self.assertEqual(out.stdout.split(), ["NOT_WINDOWS", "False", "False", "0", "False", "ran"], out.stderr)

    def test_command_line_probe_exit_code(self):
        out = subprocess.run([PY, str(ROOT / "pymxc.py"), "--probe"], capture_output=True, text=True)
        self.assertEqual(out.returncode, int(pymxc.status().code))
        self.assertIn('"status"', out.stdout)


@unittest.skipUnless(pymxc.available(), "this computer does not provide the Windows sandbox")
class LiveSandbox(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="pymxc_test_")
        root = Path(self._tmp.name)
        self.ws, self.outside = root / "ws", root / "outside"
        self.ws.mkdir()
        self.outside.mkdir()
        (self.outside / "note.txt").write_text("outside", encoding="utf-8")
        self.addCleanup(self._tmp.cleanup)

    def run_py(self, code, **options):
        options.setdefault("workspace", str(self.ws))
        options.setdefault("timeout_seconds", 60)
        return pymxc.run([PY, "-c", textwrap.dedent(code)], **options)

    def test_write_inside_and_not_outside(self):
        result = self.run_py(f"""
            open('inside.txt', 'w').write('in')
            for target in (r'{self.outside / "escape.txt"}', r'{self.outside / "note.txt"}'):
                try:
                    open(target, 'a').close(); print('ALLOWED')
                except OSError:
                    print('BLOCKED')
            try:
                print(open(r'{self.outside / "note.txt"}').read())
            except OSError:
                print('UNREADABLE')
        """)
        self.assertTrue(result.sandboxed)
        self.assertEqual(result.status, pymxc.Status.OK)
        self.assertEqual(result.stdout.split(), ["BLOCKED", "BLOCKED", "UNREADABLE"], result.stderr)
        self.assertEqual((self.ws / "inside.txt").read_text(), "in")
        self.assertFalse((self.outside / "escape.txt").exists())

    def test_read_only_workspace(self):
        (self.ws / "data.txt").write_text("readable", encoding="utf-8")
        result = self.run_py("""
            print(open('data.txt').read())
            try:
                open('new.txt', 'w'); print('ALLOWED')
            except OSError:
                print('BLOCKED')
        """, workspace_access="ro")
        self.assertEqual(result.stdout.split(), ["readable", "BLOCKED"], result.stderr)

    def test_read_only_read_write_and_deny(self):
        secrets = self.ws / ".secrets"
        secrets.mkdir()
        (secrets / "key.txt").write_text("secret", encoding="utf-8")
        extra = self.outside / "extra"
        extra.mkdir()
        result = self.run_py(f"""
            print(open(r'{self.outside / "note.txt"}').read())
            open(r'{extra / "out.txt"}', 'w').write('x'); print('WROTE')
            try:
                open(r'{secrets / "key.txt"}').read(); print('ALLOWED')
            except OSError:
                print('BLOCKED')
        """, read_only=[str(self.outside)], read_write=[str(extra)], deny=[str(secrets)])
        self.assertEqual(result.stdout.split(), ["outside", "WROTE", "BLOCKED"], result.stderr)

    def test_network_off(self):
        result = self.run_py("""
            import socket
            try:
                socket.create_connection(('1.1.1.1', 443), 5); print('ALLOWED')
            except OSError:
                print('BLOCKED')
        """)
        self.assertEqual(result.stdout.strip(), "BLOCKED", result.stderr)

    def test_windows_accepts_every_network_mode(self):
        # No connection is made (tests must pass offline): this checks that Windows takes
        # each mode's address rules. What they reach was measured by hand; see the README.
        for mode in ("internet", "intranet", "all"):
            result = self.run_py("print('started')", network=mode)
            self.assertEqual((result.status, result.stdout.strip()), (pymxc.Status.OK, "started"),
                             (mode, result.message))

    def test_network_hosts_reaches_only_the_listed_host(self):
        # The "listed host" is a server in this test, so no internet is needed.
        # The tunnel carries any bytes, so plain HTTP inside it is enough here.
        import http.server
        import threading

        class Hello(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "5")
                self.end_headers()
                self.wfile.write(b"hello")

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Hello)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        port = server.server_address[1]
        code = f"""
            import http.client, os, socket
            proxy = os.environ['HTTPS_PROXY'].split('//')[1]
            for host, port in (('localhost', {port}), ('example.com', 443)):
                c = http.client.HTTPConnection(proxy, timeout=20)
                c.set_tunnel(host, port)
                try:
                    c.request('GET', '/'); print(c.getresponse().read().decode())
                except OSError as e:
                    print('REFUSED')
            for target in (('127.0.0.1', {port}), ('1.1.1.1', 443)):
                try:
                    socket.create_connection(target, 5); print('DIRECT')
                except OSError:
                    print('BLOCKED')
        """
        result = self.run_py(code, network="hosts", network_hosts=[f"localhost:{port}"])
        self.assertEqual(result.stdout.split(), ["hello", "REFUSED", "BLOCKED", "BLOCKED"], result.stderr)
        self.assertEqual(result.warnings, ["NETWORK_HOSTS blocked a connection to example.com:443."])
        empty = self.run_py("print(1)", network="hosts")
        self.assertEqual((empty.returncode, empty.status), (None, pymxc.Status.POLICY_INVALID))

    def test_loopback_needs_allow_loopback(self):
        import socket
        import threading

        server = socket.create_server(("127.0.0.1", 0))
        self.addCleanup(server.close)

        def serve():
            while True:
                try:
                    conn, _ = server.accept()
                except OSError:
                    return
                conn.sendall(b"hi")
                conn.close()

        threading.Thread(target=serve, daemon=True).start()
        code = f"""
            import socket
            try:
                print(socket.create_connection(('127.0.0.1', {server.getsockname()[1]}), 5).recv(2).decode())
            except OSError:
                print('BLOCKED')
        """
        self.assertEqual(self.run_py(code, network="internet").stdout.strip(), "BLOCKED")
        self.assertEqual(self.run_py(code, network="internet", allow_loopback=True).stdout.strip(), "hi")

    def test_exit_code_arguments_and_utf8(self):
        result = pymxc.run([PY, "-c", "import sys; print(sys.argv[1:], '\u00e9\u4e2d'); sys.exit(7)",
                            "a&b", "c d", 'e"f'], workspace=str(self.ws))
        self.assertEqual(result.returncode, 7)
        self.assertFalse(result.ok)
        self.assertEqual(result.stdout.strip(), "['a&b', 'c d', 'e\"f'] \u00e9\u4e2d")

    def test_shell_string_and_python_on_path(self):
        result = pymxc.run('echo one&& python -c "import sys; print(sys.executable)"', workspace=str(self.ws))
        lines = result.stdout.split()
        self.assertEqual(lines[0], "one", result.stderr)
        self.assertEqual(os.path.normcase(os.path.dirname(lines[1])), os.path.normcase(os.path.dirname(PY)))

    def test_input_and_stderr(self):
        result = self.run_py("import sys; sys.stderr.write('err'); print(sys.stdin.read().upper())", input="abc")
        self.assertEqual((result.stdout.strip(), result.stderr.strip()), ("ABC", "err"))

    def test_timeout_stops_the_whole_tree(self):
        marker = self.ws / "late.txt"
        child = f"import time; time.sleep(4); open(r'{marker}', 'w').close()"
        result = self.run_py(f"""
            import subprocess, sys, time
            subprocess.Popen([sys.executable, '-c', {child!r}])
            time.sleep(30)
        """, timeout_seconds=1)
        self.assertTrue(result.timed_out)
        self.assertEqual(result.status, pymxc.Status.TIMED_OUT)
        import time
        time.sleep(5)
        self.assertFalse(marker.exists(), "a child of the timed-out command kept running")

    def test_wait_for_child_processes(self):
        marker = self.ws / "late.txt"
        child = f"import time; time.sleep(2); open(r'{marker}', 'w').close()"
        code = f"""
            import subprocess, sys
            subprocess.Popen([sys.executable, '-c', {child!r}], stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        """
        self.run_py(code)
        self.assertFalse(marker.exists())
        result = self.run_py(code, wait_for_child_processes=True)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(marker.exists())

    def test_temp_folder_works_and_is_removed(self):
        (self.ws / "use_temp.py").write_text(textwrap.dedent("""
            import os, tempfile
            d = tempfile.mkdtemp()
            open(os.path.join(d, 'f'), 'w').write('x')
            print(os.environ['PYMXC_TEMP'])
        """), encoding="utf-8")
        result = pymxc.run("python use_temp.py", workspace=str(self.ws))  # a string: through cmd.exe
        granted = result.stdout.strip()
        self.assertTrue(granted, result.stderr)
        self.assertFalse(os.path.exists(granted))

    def test_names_outside_are_hidden_unless_listing_is_on(self):
        code = f"""
            import os
            try:
                print(len(os.listdir(r'{self.outside}')))
            except OSError:
                print('HIDDEN')
        """
        self.assertEqual(self.run_py(code).stdout.strip(), "HIDDEN")
        self.assertEqual(self.run_py(code, list_drive_roots=True).stdout.strip(), "1")

    def test_no_windows(self):
        result = self.run_py("import ctypes; ctypes.WinDLL('user32'); print('LOADED')", no_windows=True)
        self.assertNotIn("LOADED", result.stdout)
        self.assertNotEqual(result.returncode, 0)

    def test_clipboard_none_blocks_reading(self):
        code = """
            import ctypes
            u = ctypes.WinDLL('user32', use_last_error=True)
            u.GetClipboardData.restype = ctypes.c_void_p
            if u.OpenClipboard(None):
                formats = u.CountClipboardFormats()
                first = u.EnumClipboardFormats(0)
                print(formats, bool(u.GetClipboardData(first)) if first else 'empty')
                u.CloseClipboard()
        """
        allowed = self.run_py(code, clipboard="all").stdout.split()
        if not allowed or allowed[-1] != "True":
            self.skipTest("the clipboard is empty or unreadable on this desktop")
        self.assertEqual(self.run_py(code, clipboard="none").stdout.split()[-1], "False")
        self.assertEqual(self.run_py(code).stdout.split()[-1], "False")  # a command cannot read it by default

    def test_a_command_cannot_see_other_windows_by_default(self):
        code = """
            import ctypes
            u = ctypes.WinDLL('user32')
            seen = []
            proto = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
            def each(hwnd, _):
                if u.GetWindowTextLengthW(ctypes.c_void_p(hwnd)):
                    seen.append(1)
                return 1
            u.EnumWindows(proto(each), None)
            print(len(seen))
        """
        if self.run_py(code, ui_isolation="desktop").stdout.strip() in ("", "0"):
            self.skipTest("no titled windows on this desktop")
        self.assertEqual(self.run_py(code).stdout.strip(), "0")
        self.assertEqual(self.run_py(code, ui_isolation="handles", clipboard="all").stdout.strip(), "0")

    def test_workspace_holding_the_callers_code_is_a_warning(self):
        self.assertEqual(pymxc.run("echo x", workspace=str(self.ws)).warnings, [])
        (self.ws / "app").mkdir()
        with mock.patch.object(pymxc, "_code_folders", return_value=[self.ws / "app"]):
            risky = pymxc.run("echo x", workspace=str(self.ws))
            read_only = pymxc.run("echo x", workspace=str(self.ws), workspace_access="ro")
        self.assertTrue(any("own code" in w for w in risky.warnings), risky.warnings)
        self.assertEqual(read_only.warnings, [])

    def test_policy_and_launch_errors_are_results(self):
        bad = pymxc.run("echo x", workspace=str(self.ws), network="sideways")
        self.assertEqual((bad.returncode, bad.status), (None, pymxc.Status.POLICY_INVALID))
        missing = pymxc.run([str(self.ws / "no_such_program.exe")], workspace=str(self.ws))
        self.assertEqual((missing.returncode, missing.status), (None, pymxc.Status.LAUNCH_FAILED))
        self.assertTrue(missing.message)

    def test_popen_streams_and_stdin(self):
        proc = pymxc.Popen([PY, "-u", "-c", "import sys\nfor line in sys.stdin: print(line.strip() * 2)"],
                           workspace=str(self.ws), stdin=True)
        self.assertTrue(proc.sandboxed)
        proc.stdin.write("ab\n")
        self.assertEqual(proc.stdout.readline().strip(), "abab")
        proc.stdin.close()
        self.assertEqual(proc.wait(30), 0)
        proc.stdout.close()
        proc.stderr.close()

    def test_popen_kill_from_another_thread(self):
        import threading
        proc = pymxc.Popen([PY, "-c", "import time; time.sleep(60)"], workspace=str(self.ws))
        threading.Timer(1.0, proc.kill).start()
        self.assertEqual(proc.wait(30), 1)
        with self.assertRaises(pymxc.PolicyError):
            pymxc.Popen("echo x", workspace=str(self.ws), clipboard="maybe")

    def test_enable_restarts_a_script_inside_the_sandbox(self):
        app = self.ws / "app.py"
        app.write_text(textwrap.dedent(f"""
            import sys
            sys.path.insert(0, r"{ROOT}")
            import pymxc; pymxc.enable(read_only=[r"{ROOT}"])
            import tempfile
            print(pymxc.is_sandboxed(), sys.argv[1:], bool(tempfile.mkdtemp()))
            try:
                open(r'{self.outside / "escape.txt"}', 'w'); print('ALLOWED')
            except OSError:
                print('BLOCKED')
            sys.exit(5)
        """), encoding="utf-8")
        for command, cwd in (([PY, str(app), "x y"], None), ([PY, "-m", "app", "x y"], str(self.ws))):
            out = subprocess.run(command, capture_output=True, text=True, cwd=cwd, timeout=120)
            self.assertEqual(out.returncode, 5, out.stderr)
            self.assertEqual(out.stdout.split("\n")[:2], ["True ['x y'] True", "BLOCKED"], out.stderr)
        self.assertFalse((self.outside / "escape.txt").exists())

    def start_app(self, name, body, *args, enable_args="", **kw):
        """A project as a user has it: app.py with pymxc.py copied next to it."""
        proj = Path(self._tmp.name) / name
        proj.mkdir()
        shutil.copy(ROOT / "pymxc.py", proj / "pymxc.py")
        (proj / "app.py").write_text(f"import pymxc; pymxc.enable({enable_args})\n" + textwrap.dedent(body),
                                     encoding="utf-8")
        return proj, subprocess.run([PY, str(proj / "app.py"), *args], capture_output=True, text=True,
                                    timeout=120, **kw)

    def test_enable_keeps_the_code_folder_read_only(self):
        # Code in this folder starts outside the sandbox on the next launch, so the
        # sandboxed program must not be able to change or add to it.
        body = """
            import os
            here = os.path.dirname(os.path.abspath(__file__))
            for target in (__file__, os.path.join(here, 'configparser.py'),
                           os.path.join(here, '__pycache__', 'planted.pyc')):
                try:
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    open(target, 'a').close(); print('WRITABLE')
                except OSError:
                    print('PROTECTED')
            open(os.path.join(here, 'data', 'saved.txt'), 'w').write('kept'); print('SAVED')
        """
        proj, out = self.start_app("ro_app", body, enable_args='read_write=["data"]', cwd=str(self.outside))
        self.assertEqual(out.stdout.split(), ["PROTECTED"] * 3 + ["SAVED"], out.stderr)
        self.assertEqual((proj / "data" / "saved.txt").read_text(), "kept")
        self.assertFalse((proj / "configparser.py").exists())
        self.assertEqual(os.listdir(self.outside), ["note.txt"])  # "data" is relative to the script's folder
        proj, out = self.start_app("rw_app", body, enable_args='workspace_access="rw", read_write=["data"]')
        self.assertEqual(out.stdout.split(), ["WRITABLE"] * 3 + ["SAVED"], out.stderr)
        self.assertIn("WORKSPACE_ACCESS", out.stderr)

    def test_enable_script_argument_dash_m_does_not_move_the_workspace(self):
        body = """
            import os, sys
            try:
                open(os.path.join(sys.argv[-1], 'w.txt'), 'w').close(); print('ALLOWED')
            except OSError:
                print('BLOCKED')
        """
        _, out = self.start_app("dash_m", body, "-m", str(self.outside), cwd=str(self.outside))
        self.assertEqual(out.stdout.strip(), "BLOCKED", out.stderr)
        self.assertFalse((self.outside / "w.txt").exists())

    def test_marker_variable_does_not_switch_the_sandbox_off(self):
        body = f"""
            print(pymxc.is_sandboxed())
            try:
                open(r'{self.outside / "escape.txt"}', 'w').close(); print('ALLOWED')
            except OSError:
                print('BLOCKED')
        """
        _, out = self.start_app("marker", body, env={**os.environ, "PYMXC_SANDBOXED": "1"})
        self.assertEqual(out.stdout.split(), ["True", "BLOCKED"], out.stderr)
        self.assertFalse((self.outside / "escape.txt").exists())

    def test_deny_path_that_appears_later_is_blocked(self):
        result = self.run_py("""
            import os
            try:
                os.mkdir('later'); open('later/s.txt', 'w').close(); print('ALLOWED')
            except OSError:
                print('BLOCKED')
        """, deny=["later"])
        self.assertEqual(result.stdout.strip(), "BLOCKED", result.stderr)
        self.assertTrue(any("later" in w for w in result.warnings))

    def test_command_line_run(self):
        out = subprocess.run([PY, str(ROOT / "pymxc.py"), "--workspace", str(self.ws), "--run",
                              "echo hi> made.txt&& exit /b 3"], capture_output=True, text=True)
        self.assertEqual(out.returncode, 3, out.stderr)
        self.assertTrue((self.ws / "made.txt").exists())

    def test_command_line_output_survives_a_narrow_code_page(self):
        # Piped output uses the system code page, which has no CJK characters.
        env = {k: v for k, v in os.environ.items() if k.upper() not in ("PYTHONIOENCODING", "PYTHONUTF8")}
        out = subprocess.run([PY, str(ROOT / "pymxc.py"), "--workspace", str(self.ws), "--run",
                              'python -c "print(chr(65)+chr(20013)); print(chr(66))"'],
                             capture_output=True, env=env)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.splitlines()[-1], b"B")
        self.assertNotIn(b"\r\r\n", out.stdout)

    def test_output_lines_end_with_a_plain_newline(self):
        self.assertEqual(self.run_py("print('a'); print('b')").stdout, "a\nb\n")
        self.assertEqual(pymxc.run("echo hi", workspace=str(self.ws)).stdout, "hi\n")

    def test_a_single_file_can_be_granted(self):
        result = self.run_py(f"""
            import os
            print(os.path.exists(r'{self.outside / "note.txt"}'), open(r'{self.outside / "note.txt"}').read())
            try:
                os.listdir(r'{self.outside}'); print('FOLDER-READABLE')
            except OSError:
                print('FOLDER-HIDDEN')
        """, read_only=[str(self.outside / "note.txt")])
        self.assertEqual(result.stdout.split(), ["True", "outside", "FOLDER-HIDDEN"], result.stderr)

    def test_starting_a_sandbox_inside_a_sandbox_is_explained(self):
        result = self.run_py(f"""
            import sys; sys.path.insert(0, r'{ROOT}')
            import pymxc
            inner = pymxc.run('echo nested')
            print(inner.returncode, inner.status.name, inner.message)
        """, read_only=[str(ROOT)])
        self.assertIn("None LAUNCH_FAILED", result.stdout, result.stderr)
        self.assertIn("already running inside a sandbox", result.stdout)

    def test_leftover_processes_are_gone_when_run_returns(self):
        # The run is over only when everything it started has ended: nothing may still
        # be writing in the workspace (or holding the temp folder) afterwards.
        child = "import time\\nwhile True:\\n    open('tick.txt', 'a').write('x'); time.sleep(0.01)"
        self.run_py(f"""
            import subprocess, sys, time
            subprocess.Popen([sys.executable, '-c', "{child}"], stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1)
        """)
        size = (self.ws / "tick.txt").stat().st_size
        self.assertGreater(size, 0)
        import time
        time.sleep(0.5)
        self.assertEqual((self.ws / "tick.txt").stat().st_size, size)

    def test_selftest(self):
        out = subprocess.run([PY, str(ROOT / "pymxc.py"), "--selftest"], capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stdout)
        self.assertNotIn("FAIL", out.stdout)


if __name__ == "__main__":
    unittest.main()
