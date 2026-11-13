"""A sandboxed program that may talk to one LLM API and to nothing else.

It works with any service that uses the OpenAI chat-completions format. Say
which host and model to use, then run it:

    set LLM_API_HOST=api.example.com
    set LLM_MODEL=your-model-name
    set LLM_API_KEY=your-key
    python examples\\llm_api_chat.py "Say hello in five words."

What the sandbox allows this program:
  - read its own folder (the workspace), without changing it;
  - HTTPS to the one host in LLM_API_HOST, through pymxc's host filter;
  - nothing else: no other network host, no other files of yours.

The OpenAI chat-completions format is: POST /v1/chat/completions with
"Authorization: Bearer <key>". If your service can only be reached from your
organisation's network or VPN, connect to that first.
Only the standard library is used here, so there is nothing to install.
"""
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # pymxc.py is one folder up
import pymxc

API_HOST = os.environ.get("LLM_API_HOST", "").strip()   # your service's API host
MODEL = os.environ.get("LLM_MODEL", "").strip()         # a model your service offers
if not API_HOST or not MODEL:
    raise SystemExit("Say which service and model to use first, for example:\n"
                     "    set LLM_API_HOST=api.example.com\n"
                     "    set LLM_MODEL=your-model-name")
BASE_URL = f"https://{API_HOST}/v1"

# ---- 1. Get the API key BEFORE entering the sandbox ---------------------------
# Windows Credential Manager cannot be read inside the sandbox. Anything put in
# os.environ here, outside, is handed to the sandboxed copy of this program.
if not pymxc.is_sandboxed() and not os.environ.get("LLM_API_KEY"):
    try:
        import keyring  # optional; only if your app saves its key in Credential Manager
        saved = keyring.get_password("your-app-name", "api-key")  # <-- your own entry names
        if saved:
            os.environ["LLM_API_KEY"] = saved
    except Exception:
        pass

# ---- 2. Enter the sandbox ------------------------------------------------------
pymxc.enable(
    network="hosts",
    network_hosts=[API_HOST],
    # on_unavailable="error",        # refuse to run at all on a computer without the sandbox
    # network_upstream_proxy="http://your-proxy:8443",   # only if "auto" does not find your proxy
)

# ---- 3. The program itself, now sandboxed --------------------------------------


def ask(prompt: str) -> str:
    key = os.environ.get("LLM_API_KEY", "").strip()
    if not key:
        raise SystemExit("Set LLM_API_KEY first:   set LLM_API_KEY=your-key")
    body = {"model": MODEL, "messages": [{"role": "user", "content": prompt}]}
    request = urllib.request.Request(
        f"{BASE_URL}/chat/completions", data=json.dumps(body).encode("utf-8"),
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=300) as response:  # follows HTTPS_PROXY
            reply = json.load(response)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise SystemExit(f"{API_HOST} answered HTTP {exc.code}: {detail}")
    except urllib.error.URLError as exc:
        raise SystemExit(f"Could not reach {API_HOST}: {exc.reason}\n"
                         "Check the network or VPN the service needs. pymxc prints a line above "
                         "when it blocked a host or could not reach an allowed one.")
    return reply["choices"][0]["message"]["content"]


if __name__ == "__main__":
    print("sandboxed:", pymxc.is_sandboxed())
    print(ask(" ".join(sys.argv[1:]) or "Say hello in five words."))
