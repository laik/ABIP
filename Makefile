PY := .venv/bin/python
COLLECTOR := collector/target/release/abip-collector

.PHONY: setup collector gen collect train infer demo test kind-up capture clean

setup:
	python3 -m venv .venv && .venv/bin/pip install -q torch numpy

collector:
	cd collector && cargo build --release

gen:
	mkdir -p data && $(PY) scripts/gen_workload.py --count 20000 \
		--events data/raw-events.jsonl --truth data/anomaly-truth.jsonl

collect: collector
	$(COLLECTOR) --input data/raw-events.jsonl --output data/events.jsonl --tree-out data/tree.json

train:
	$(PY) -m lstm.train --events data/events.jsonl --registry models/registry --log data/training-log.json

infer:
	$(PY) -m lstm.infer --events data/events.jsonl --registry models/registry \
		--truth data/anomaly-truth.jsonl --out data/predictions.jsonl --report data/report.json

demo:
	rm -rf data models/registry
	$(MAKE) gen collect train infer

test:
	cd collector && cargo test
	$(PY) -m lstm.selfcheck

kind-up:
	bash scripts/kind-up.sh

capture:
	bash scripts/capture-events.sh

clean:
	rm -rf data models/registry