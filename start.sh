#!/usr/bin/env bash
# The mac/Linux counterpart of start.cmd: both hand off to apps/launcher.py,
# which starts the server in its own session, opens the browser and exits --
# closing this terminal does not stop it. Closing the page in the browser
# does, and so does the page's "stop server" button.
#
# No "press a key to close" here, unlike start.cmd: a terminal stays put
# after a command finishes, so the output is still on screen. It is the
# Windows console vanishing with its script that makes a successful launch
# look like nothing happened.
set -euo pipefail
cd "$(dirname "$0")"

# command -v is a shell built-in, so nothing on PATH can shadow the check
# itself -- the same reason start.cmd avoids where/timeout/ping.
if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v python >/dev/null 2>&1; then
  PY=python
else
  echo "Hawkeye could not start: no python3 on PATH." >&2
  echo "Install Python 3 (macOS: brew install python, Debian/Ubuntu:" >&2
  echo "sudo apt install python3), then run this again." >&2
  exit 1
fi

if ! "$PY" -m apps.launcher; then
  echo >&2
  echo "Hawkeye could not start." >&2
  echo "More detail: data/launcher.log and data/server.log" >&2
  exit 1
fi
