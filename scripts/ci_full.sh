#!/usr/bin/env bash
# Full CI job — not the fast release gate.
# Usage: bash scripts/ci_full.sh
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH=.
echo "== Fast release gate =="
python scripts/release_gate.py
echo "== Full unittest discover (timeout 600s) =="
timeout 600 python -m unittest discover -s tests -t . -q || {
  echo "FULL_DISCOVER_FAILED_OR_TIMEOUT"
  exit 1
}
echo "== Full adversarial agent suite (optional) =="
if [[ "${CTF_TUTOR_FULL_ADVERSARIAL:-0}" == "1" ]]; then
  CTF_TUTOR_FULL_ADVERSARIAL=1 python -m unittest tests.test_hardening_phase4.TestAdversarialSuite -q
fi
echo "CI full job OK"
