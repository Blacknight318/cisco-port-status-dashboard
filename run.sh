#!/usr/bin/env sh
# Run only on the local machine; the dashboard never binds to a network address.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

if [ ! -x .venv/bin/python ]; then
  if command -v uv >/dev/null 2>&1; then
    uv venv .venv
    uv pip install --python .venv/bin/python -r requirements.txt
  else
    python3 -m venv .venv
    .venv/bin/python -m pip install --upgrade pip
    .venv/bin/python -m pip install -r requirements.txt
  fi
fi

exec .venv/bin/python -m uvicorn app:app --host 127.0.0.1 --port 8787
