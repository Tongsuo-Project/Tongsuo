#!/usr/bin/env bash
# Smoke Win64 ABI for ML-DSA AVX via mingw64 + Wine (not a full MSVC clone).
#
# IMPORTANT — reproduce before claiming fix:
#   1) BASELINE=1  -> build HEAD asm (no xmm6-15 saves), expect ML-DSA fail
#   2) (default)   -> overlay working-tree asm (with xmm saves), expect pass
# Without step 1, a green step 2 does not prove the harness catches the bug.
#
# Usage (from Tongsuo tree):
#   BASELINE=1 ./util/smoke-ml-dsa-win64-mingw.sh   # must FAIL on ML-DSA
#   ./util/smoke-ml-dsa-win64-mingw.sh               # with local asm fix
#
# Deps: gcc-mingw-w64-x86-64 nasm perl make wine64 git
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

WT="${WT:-/tmp/tongsuo-mingw64-wine-smoke}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"
TESTS="${TESTS:-test_ml_dsa test_ml_dsa_codecs}"
BASELINE="${BASELINE:-0}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing tool: $1" >&2
    echo "install: gcc-mingw-w64-x86-64 nasm perl make wine64" >&2
    exit 1
  }
}

need perl; need nasm; need git
need x86_64-w64-mingw32-gcc; need wine64

echo "==> static Win64 asm gate (working tree)"
perl util/check-ml-dsa-win64-asm.pl

echo "==> git worktree at $WT"
if [[ -d "$WT" ]]; then
  git worktree remove --force "$WT" 2>/dev/null || rm -rf "$WT"
fi
git worktree add --detach "$WT" HEAD

if [[ "$BASELINE" == "1" ]]; then
  echo "==> BASELINE=1: keep HEAD asm (expect ML-DSA crash / Can't spawn under Wine)"
  rm -f "$WT/crypto/ml_dsa/asm/ml_dsa_win64_xmm.pl"
  if rg -q 'ml_dsa_win64_xmm|inject_win64_xmm' "$WT/crypto/ml_dsa/asm/"*.pl 2>/dev/null; then
    echo "ERROR: HEAD already references xmm helper; baseline invalid" >&2
    exit 2
  fi
else
  echo "==> overlay working-tree asm (xmm6-15 save path)"
  mkdir -p "$WT/crypto/ml_dsa/asm" "$WT/util"
  cp -a crypto/ml_dsa/asm/*.pl "$WT/crypto/ml_dsa/asm/"
  cp -a util/check-ml-dsa-win64-asm.pl "$WT/util/" 2>/dev/null || true
fi

cd "$WT"
echo "==> Configure mingw64"
perl Configure mingw64 no-shared no-fips \
  --cross-compile-prefix=x86_64-w64-mingw32- \
  --banner="mingw64-wine-ml-dsa-smoke"

echo "==> make -j$JOBS"
make -j"$JOBS"

export WINEPREFIX="${WINEPREFIX:-$WT/.wineprefix}"
mkdir -p "$WINEPREFIX"
wine64 hostname >/dev/null 2>&1 || true

echo "==> make test EXE_SHELL=wine64 HARNESS_JOBS=1 TESTS=$TESTS"
set +e
make test HARNESS_JOBS=1 VERBOSE_FAILURE=yes \
  EXE_SHELL=wine64 \
  TESTS="$TESTS"
rc=$?
set -e

if [[ "$BASELINE" == "1" ]]; then
  if [[ $rc -eq 0 ]]; then
    echo "FAIL: BASELINE unexpectedly PASSED — harness does not reproduce Win CI symptom" >&2
    exit 3
  fi
  echo "OK: BASELINE failed as expected (rc=$rc). Environment can reproduce; now re-run without BASELINE=1."
  exit 0
fi

if [[ $rc -ne 0 ]]; then
  echo "FAIL: fixed build still failing (rc=$rc)" >&2
  exit "$rc"
fi
echo "OK: mingw64+wine smoke passed for: $TESTS"
