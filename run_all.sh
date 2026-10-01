#!/usr/bin/env bash
# Reproduce every result in the paper from a pinned VCDB snapshot.
# Usage: ./run_all.sh            (clones VCDB into ./vcdb if missing)
set -euo pipefail
cd "$(dirname "$0")"

VCDB_COMMIT=f6f98c00f66ab35f5b49977a5852ce94a5bb31d1
if [ ! -d vcdb ]; then
  # fetch only the pinned commit (the full history is large)
  git init --quiet vcdb
  git -C vcdb remote add origin https://github.com/vz-risk/VCDB.git
  git -C vcdb fetch --quiet --depth 1 origin "$VCDB_COMMIT"
  git -C vcdb checkout --quiet FETCH_HEAD
fi
test "$(git -C vcdb rev-parse HEAD)" = "$VCDB_COMMIT" || { echo "vcdb/ is not at $VCDB_COMMIT"; exit 1; }
mkdir -p results

echo "== 1. Extraction, automatic campaign rule (rule A)"
python3 src/vcdb_extract.py --vcdb vcdb --out results/automatic

echo "== 2. Extraction, every victim kept (input to the hand rule)"
python3 src/vcdb_extract.py --vcdb vcdb --out results/victims --keep-campaigns > /dev/null

echo "== 3. Hand campaign rule (rule B)"
python3 src/hand_merge.py results/victims/coding_sheet.csv results/hand

echo "== 4. Stratified hand-coding sample"
python3 src/draw_sample.py

echo "== 5. Tests, agreement, alternative ordering"
python3 src/analysis.py | tee results/analysis_log.txt

echo "== 5b. Confidence intervals and power"
python3 src/power.py | tee results/power.txt

echo "== 6. SPI composites and weight sensitivity"
python3 src/spi_sensitivity.py | tee results/spi_sensitivity.txt

echo "== 7. Data-informed SPI weights"
python3 src/spi_data_weights.py | tee results/spi_data_weights.txt

echo "Done. Outputs are in results/."
