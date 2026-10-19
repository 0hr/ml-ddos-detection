# AI-based DDoS detection and mitigation pipeline.
# ML/analysis steps run in the project venv (uv). The live testbed needs root + Mininet.
PY = uv run python
OSKEN = .venv-osken/bin/osken-manager
ZIP = dataset/raw/CSV-01-12.zip
REPEAT ?= 1
REPS ?= 3
MODEL ?= models/random_forest.joblib
# flood type of the experiment's attack scenarios: udp | conn | http. Anything but udp gets
# its own run and report directories, so the UDP results are never overwritten.
ATTACK ?= udp
# connections each attacker opens at once; raise it to make the flood overwhelm the server
ATTACK_THREADS ?= 8
ifeq ($(ATTACK),udp)
RUNS_DIR ?= results/runs
REPORT_DIR ?= results/report
else
RUNS_DIR ?= results/runs_$(ATTACK)
REPORT_DIR ?= results/report_$(ATTACK)
endif

.PHONY: help setup data clean-data train robustness report test controller dashboard dashboard-dev \
        dashboard-live live experiment analyze collect collect-quick compare train-sim all
help:
	@grep -E '^[a-zA-Z_-]+:.*?# ' Makefile | sed 's/:.*# /\t/'

setup:            # install both venvs (project + os-ken controller)
	uv sync
	test -d .venv-osken || uv venv --python 3.12 .venv-osken
	uv pip install --python .venv-osken/bin/python 'os-ken<3'

data:             # stream-sample the 22 GB zip into a balanced parquet
	$(PY) ml/prepare_data.py --zip $(ZIP)

clean-data:       # inspect + clean + EDA report (results/data/eda_report.md)
	$(PY) ml/clean.py

train:            # train decision tree + random forest, evaluate, save model+schema
	$(PY) ml/train.py

robustness:       # CV, temporal holdout and leave-one-attack-out checks of the RF
	$(PY) ml/robustness.py

report:           # presentation charts + tables of the trained models (results/ml/presentation/)
	$(PY) ml/report.py

test:             # unit tests: flow meter parity, block decisions, dashboard engine
	uv run pytest -q tests fabric/tests

controller:       # run the OpenFlow 1.3 controller in the foreground (for manual use)
	$(OSKEN) controller/ddos_controller.py

dashboard:        # build the React UI and serve the live-monitor dashboard (simulate mode)
	cd monitor/web && npm install && npm run build
	$(PY) monitor/server/app.py

dashboard-dev:    # run API (simulate) + Vite dev server for the dashboard
	$(PY) monitor/server/app.py & cd monitor/web && npm install && npm run dev

dashboard-live:   # serve the dashboard for the testbed run in progress (http://127.0.0.1:8099)
	cd monitor/web && npm install && npm run build
	$(PY) monitor/server/app.py --mode live

live:             # NEEDS ROOT: interactive testbed session; start attacks from the dashboard (MODEL=...)
	sudo python3 testbed/live.py --model $(MODEL)

experiment:       # NEEDS ROOT: run all four testbed scenarios (REPEAT=3, ATTACK=http, ATTACK_THREADS=64 for a heavier flood)
	sudo python3 testbed/run_experiment.py --hosts 6 --duration 40 --repeat $(REPEAT) --model $(MODEL) \
		--attack $(ATTACK) --attack-threads $(ATTACK_THREADS) --runs-dir $(RUNS_DIR)

analyze:          # build confusion matrices / latency / availability graphs
	$(PY) ml/analyze_results.py --runs $(RUNS_DIR) --out $(REPORT_DIR)

collect:          # NEEDS ROOT: collect our own labelled dataset in Mininet (~20 min, REPS ?= 3)
	sudo python3 simulation/collect.py --reps $(REPS)

collect-quick:    # NEEDS ROOT: a 5-minute collection, to check the setup
	sudo python3 simulation/collect.py --quick

compare:          # train on our dataset and compare with CIC-DDoS2019 (simulation/results/)
	$(PY) simulation/compare.py

train-sim:        # train a deployable model on CIC-DDoS2019 + our dataset -> models/random_forest_cic_sim.joblib
	$(PY) simulation/train_model.py

all: data clean-data train test
