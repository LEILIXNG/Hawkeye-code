#!/usr/bin/env bash
# The mac/Linux counterpart of 启动前端.cmd: pick a free port, open the
# browser once the server has had a moment to bind, and run uvicorn in the
# foreground so Ctrl-C stops it.
set -euo pipefail
cd "$(dirname "$0")"

PY=python3
command -v "$PY" >/dev/null 2>&1 || PY=python

# Asked of the OS by binding, not read out of `lsof`/`ss`: a listener bound
# to one interface does not always show up in a table scan, and a successful
# bind is the same question uvicorn is about to ask.
PORT=$("$PY" - <<'PYCODE'
import socket

for port in range(8000, 8021):
    with socket.socket() as probe:
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            continue
        print(port)
        break
else:
    print(8000)
PYCODE
)

# Backgrounded with a delay so the page is requested after uvicorn is
# listening; without it the browser races the server and shows a refusal.
(
  sleep 3
  url="http://localhost:${PORT}"
  if command -v open >/dev/null 2>&1; then
    open "$url"
  elif command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$url"
  else
    echo "Open ${url} in a browser."
  fi
) &

echo "Starting Hawkeye at http://localhost:${PORT}  (Ctrl-C to stop)"
exec "$PY" -m uvicorn apps.api.main:app --port "${PORT}"
