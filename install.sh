#!/usr/bin/env bash
# ESCar / PcaW — one-shot installer for the AE-track lightweight simulator.
#
# Hardware-decoupled per the paper §4.6: no real CVM is required. Everything
# runs on stock Python 3.9+ with no third-party dependencies.

set -e

if ! command -v python3 >/dev/null 2>&1 && ! command -v python >/dev/null 2>&1; then
    echo "[install.sh] python is required (>= 3.9)." >&2
    exit 1
fi

PY=$(command -v python3 || command -v python)
echo "[install.sh] Using interpreter: ${PY}"

${PY} -c 'import sys; assert sys.version_info >= (3, 9), "Python 3.9+ required"'
echo "[install.sh] Python version OK."

# No external deps for the core experiments; we use stdlib only. If you
# want pretty plots, install matplotlib separately.
mkdir -p results
echo "[install.sh] Done. Run ./claims/run.sh to reproduce all experiments."
