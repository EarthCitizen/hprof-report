#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR="${VENV_DIR:-$SCRIPT_DIR/.venv}"
BOOTSTRAP_PYTHON="${BOOTSTRAP_PYTHON:-}"

BOOTSTRAP_CMD=()
if [[ -n "$BOOTSTRAP_PYTHON" ]]; then
  BOOTSTRAP_CMD=("$BOOTSTRAP_PYTHON")
elif command -v python3 >/dev/null 2>&1; then
  BOOTSTRAP_CMD=(python3)
elif command -v python >/dev/null 2>&1; then
  BOOTSTRAP_CMD=(python)
elif command -v py >/dev/null 2>&1; then
  BOOTSTRAP_CMD=(py -3)
else
  echo "Could not find a Python bootstrap executable (tried: python3, python, py -3)." >&2
  echo "Set BOOTSTRAP_PYTHON to a valid Python executable path." >&2
  exit 1
fi

if [[ ! -x "$VENV_DIR/bin/python" && ! -x "$VENV_DIR/Scripts/python.exe" ]]; then
  "${BOOTSTRAP_CMD[@]}" -m venv "$VENV_DIR"
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
HAS_WORKERS_ARG=0
HAS_WORK_DIR_ARG=0
HAS_CACHE_ARG=0
HAS_CACHE_DIR_ARG=0
for arg in "$@"; do
  if [[ "$arg" == "--engine" || "$arg" == --engine=* ]]; then
    HAS_ENGINE_ARG=1
  fi
  if [[ "$arg" == "--max-memory-gb" || "$arg" == --max-memory-gb=* ]]; then
    HAS_MAX_MEMORY_ARG=1
  fi
  if [[ "$arg" == "--workers" || "$arg" == --workers=* ]]; then
    HAS_WORKERS_ARG=1
  fi
  if [[ "$arg" == "--work-dir" || "$arg" == --work-dir=* ]]; then
    HAS_WORK_DIR_ARG=1
  fi
  if [[ "$arg" == "--cache" || "$arg" == "--no-cache" ]]; then
    HAS_CACHE_ARG=1
  fi
  if [[ "$arg" == "--cache-dir" || "$arg" == --cache-dir=* ]]; then
    HAS_CACHE_DIR_ARG=1
  fi
done

CLI_HELP="$("$VENV_PYTHON" -m hprof_report.cli --help 2>/dev/null || true)"

HPCACHE_ROOT="${HPROF_CACHE_ROOT:-$SCRIPT_DIR/.hprof-cache}"
HPCACHE_RESULTS="${HPROF_CACHE_DIR:-$HPCACHE_ROOT/results}"
HPCACHE_TMP="${HPROF_WORK_DIR:-$HPCACHE_ROOT/tmp}"

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

if [[ "$HAS_WORKERS_ARG" -eq 0 ]]; then
  if printf '%s\n' "$CLI_HELP" | grep -q -- "--workers"; then
    EXTRA_ARGS+=(--workers "${HPROF_WORKERS:-4}")
  fi
fi

if [[ "$HAS_WORK_DIR_ARG" -eq 0 ]]; then
  if printf '%s\n' "$CLI_HELP" | grep -q -- "--work-dir"; then
    EXTRA_ARGS+=(--work-dir "$HPCACHE_TMP")
  fi
fi

if [[ "$HAS_CACHE_DIR_ARG" -eq 0 ]]; then
  if printf '%s\n' "$CLI_HELP" | grep -q -- "--cache-dir"; then
    EXTRA_ARGS+=(--cache-dir "$HPCACHE_RESULTS")
  fi
fi

if [[ "$HAS_CACHE_ARG" -eq 0 ]]; then
  if printf '%s\n' "$CLI_HELP" | grep -q -- "--cache"; then
    EXTRA_ARGS+=(--cache)
  fi
fi

exec "$VENV_PYTHON" -m hprof_report.cli "${EXTRA_ARGS[@]}" "$@"
