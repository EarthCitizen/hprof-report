#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR="${VENV_DIR:-$SCRIPT_DIR/.venv}"
BOOTSTRAP_PYTHON="${BOOTSTRAP_PYTHON:-python3}"

if [[ ! -x "$VENV_DIR/bin/python" && ! -x "$VENV_DIR/Scripts/python.exe" ]]; then
  "$BOOTSTRAP_PYTHON" -m venv "$VENV_DIR"
fi

if [[ -x "$VENV_DIR/bin/python" ]]; then
  VENV_PYTHON="$VENV_DIR/bin/python"
elif [[ -x "$VENV_DIR/Scripts/python.exe" ]]; then
  VENV_PYTHON="$VENV_DIR/Scripts/python.exe"
else
  echo "Could not find a Python executable in venv: $VENV_DIR" >&2
  exit 1
fi

"$VENV_PYTHON" -m pip install --upgrade pip
"$VENV_PYTHON" -m pip install -r "$SCRIPT_DIR/requirements.txt"
"$VENV_PYTHON" -m pip install -e "$SCRIPT_DIR"

EXTRA_ARGS=()
HAS_ENGINE_ARG=0
HAS_MAX_MEMORY_ARG=0
for arg in "$@"; do
  if [[ "$arg" == "--engine" || "$arg" == --engine=* ]]; then
    HAS_ENGINE_ARG=1
  fi
  if [[ "$arg" == "--max-memory-gb" || "$arg" == --max-memory-gb=* ]]; then
    HAS_MAX_MEMORY_ARG=1
  fi
done

CLI_HELP="$("$VENV_PYTHON" -m hprof_report.cli --help 2>/dev/null || true)"

if [[ "$HAS_ENGINE_ARG" -eq 0 ]]; then
  if printf '%s\n' "$CLI_HELP" | grep -q -- "--engine"; then
    EXTRA_ARGS+=(--engine "${HPROF_ENGINE:-disk}")
  fi
fi

if [[ "$HAS_MAX_MEMORY_ARG" -eq 0 ]]; then
  if printf '%s\n' "$CLI_HELP" | grep -q -- "--max-memory-gb"; then
    if [[ -n "${HPROF_MAX_MEMORY_GB:-}" ]]; then
      EXTRA_ARGS+=(--max-memory-gb "${HPROF_MAX_MEMORY_GB}")
    fi
  fi
fi

exec "$VENV_PYTHON" -m hprof_report.cli "${EXTRA_ARGS[@]}" "$@"
