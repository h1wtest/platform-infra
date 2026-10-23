#!/usr/bin/env sh
set -eu
HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
INFRA=$(CDPATH='' cd -- "$HERE/../.." && pwd)
: "${ACCEPTANCE_DIRECTORY:=$INFRA/.local/acceptance}"
: "${ACCEPTANCE_STATE:=$ACCEPTANCE_DIRECTORY/state.json}"
: "${ACCEPTANCE_BASE:=https://localhost:8448}"
: "${ACCEPTANCE_CA:=$INFRA/.local/ca.crt}"
if ! command -v uv >/dev/null 2>&1; then
  printf '%s\n' 'uv required; install pinned infrastructure prerequisites.' >&2
  exit 1
fi
exec uv run --no-project python "$HERE/e2e.py" --mode probe --base "$ACCEPTANCE_BASE" --state "$ACCEPTANCE_STATE" --ca "$ACCEPTANCE_CA"
