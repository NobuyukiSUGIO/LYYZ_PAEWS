#!/usr/bin/env bash
# Build and run the benchmark with the settings used for results/, recording the environment.
# Usage: [MCL_DIR=/usr/local] ./run_benchmark.sh [runs] [n] [validate]
# Output files are written to the repository root, so results/ is never overwritten.
set -euo pipefail

RUNS="${1:-10000}"
N="${2:-8}"
VALIDATE="${3:-10000}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

MCL_DIR="${MCL_DIR:-/usr/local}"
{
  echo '=== Machine ==='
  uname -a
  g++ --version | head -n 1
  grep -m 1 'model name' /proc/cpuinfo || true
  getconf _NPROCESSORS_ONLN || true
  if [ -d "$MCL_DIR/.git" ]; then git -C "$MCL_DIR" rev-parse HEAD || true; fi
  echo "MCL_DIR=$MCL_DIR"
} | tee paews_environment.txt

if [ ! -f "$MCL_DIR/lib/libmcl.a" ] || [ ! -f "$MCL_DIR/include/mcl/bls12_381.hpp" ]; then
  echo "Cannot locate mcl under MCL_DIR=$MCL_DIR (need include/mcl and lib/libmcl.a)" >&2
  exit 1
fi
make MCL_DIR="$MCL_DIR"

./paews_mcl_bench --n "$N" --runs "$RUNS" --validate "$VALIDATE" \
  --warmup 50 --pool 16 --csv paews_bls12_381_validate10000.csv | tee paews_run_validate10000.log
