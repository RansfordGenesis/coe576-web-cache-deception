# Reproducing "Web Cache Deception Escalates!" (Paper 7)

COE 576 : Network & Web Security · End-of-Semester Assessment
**Kyei Jeffrey Baafi**

A controlled laboratory reproduction of the WCD detection methodology **DE** from
Mirheidari, Golinelli, Onarlioglu, Kirda & Crispo, *"Web Cache Deception
Escalates!"*, USENIX Security 2022 (pp. 179-196).

## What this project does
1. Builds a **real, vulnerable web system**: a FastAPI origin behind a real
   **nginx** caching proxy, wired together with Docker Compose. The origin
   contains the path-confusion behaviour that WCD exploits.
2. Implements two detectors **from the paper's specification** (not their code):
   - `detector/de.py`, **DE** (Algorithm 1): content-identicality + cache-header
     heuristics, no markers, no login.
   - `detector/cc.py`, **CC**, the prior marker-injection method, for comparison.
3. Runs experiments over a **labelled dataset of 55 endpoints** (we know the
   ground truth) and produces all figures from our own measurements.

## Central result reproduced
The paper's **DE-vs-CC comparison** (Table 2): DE detects vulnerabilities CC
structurally cannot (pages that reflect no marker, the *coverage gap*).

| method | true positives | false positives | missed (FN) | precision | recall | F1 |
|--------|:--:|:--:|:--:|:--:|:--:|:--:|
| **DE** (this paper) | 22 | 11 | 0  | 0.67 | **1.00** | **0.80** |
| **CC** (prior work) | 11 | 0  | 11 | **1.00** | 0.50 | 0.67 |

Same qualitative story as the paper: DE greatly improves **coverage/recall**,
at the cost of some **precision** (it cannot tell erroneously-cached secrets from
intentionally-cached public pages).

## Extensions beyond the paper
- **A. Ground-truth accuracy**: precision/recall/F1 + confusion matrices. The
  paper explicitly *cannot* compute these in the wild (§3.3: "no ground truth ...
  a lower bound"); we can, because we built the sites.
- **B. Cache-configuration sensitivity**: detection and real-leak rates under
  three nginx configs (vulnerable / honour-headers fix / no-cache).
- **Bonus**: which file extensions trigger the vulnerability.

## Requirements
- Docker & Docker Compose (for the origin + nginx stack)
- Python 3.11+ (3.12 recommended)

## Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run the lab
```bash
# 1. bring up the vulnerable system (origin + nginx) at http://localhost:8080
docker compose up -d --build

# 2. see the attack by hand (curl): MISS -> HIT leak
bash experiments/demo_attack.sh

# 3. watch the DE detector reason through Algorithm 1
python experiments/demo_de.py

# 4. run the experiments (writes results/*.csv and results/summary.json)
python experiments/run_experiment.py      # central: DE vs CC
python experiments/run_config.py          # extension B: config sensitivity
python experiments/run_extension.py       # bonus: extensions

# 5. generate all figures into plots/*.png
python plots/make_plots.py

# 6. tests
pytest -q

# 7. tear down
docker compose down
```

## Repository layout
```
origin/       FastAPI origin app + Dockerfile + labelled endpoint registry
nginx/        vulnerable.conf, honor.conf, nocache.conf
detector/     de.py (Algorithm 1), cc.py (marker method), http.py, attack_urls.py
experiments/  run_experiment.py, run_config.py, run_extension.py, demos, metrics
plots/        make_plots.py -> fig1..fig5 (.png)
results/      generated CSV/JSON (git-ignored)
tests/        unit (no Docker) + integration (needs stack)
```

## Figures
- `fig1_replication.png`, DE vs CC detection (reproduces Table 2's story)
- `fig2_metrics.png`, precision/recall/F1 (beyond the paper)
- `fig3_confusion.png`, confusion matrices for DE and CC
- `fig4_config.png`, cache-configuration sensitivity (extension B)
- `fig5_extension.png`, extension sensitivity (bonus)

## Attribution
Detectors are our own implementations written from the paper's Algorithm 1 and
Section 2.3; we did not use the authors' released code. The paper is the sole
source of the methodology being reproduced.
