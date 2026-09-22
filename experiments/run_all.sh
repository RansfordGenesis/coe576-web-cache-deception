#!/usr/bin/env bash
# One command to reproduce everything. Requires: docker compose up -d --build
set -e
cd "$(dirname "$0")/.."
PY=${PY:-.venv/bin/python}
echo "== central experiment (DE vs CC) =="; $PY experiments/run_experiment.py
echo "== config sensitivity ==";           $PY experiments/run_config.py
echo "== extension sensitivity ==";        $PY experiments/run_extension.py
echo "== figures ==";                      $PY plots/make_plots.py
echo "== tests ==";                        $PY -m pytest -q
