.PHONY: test lint run install bench

PYTHON ?= python3
BENCH_DOMAIN ?= example.com
BENCH_THREADS ?= 50
BENCH_TIMEOUT ?= 3

install:
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m pip install pytest

test:
	pytest -q

lint:
	$(PYTHON) -m compileall -q .

run:
	$(PYTHON) subhunter.py example.com

bench:
	$(PYTHON) subhunter.py $(BENCH_DOMAIN) --dns-only --no-passive -t $(BENCH_THREADS) -to $(BENCH_TIMEOUT)
