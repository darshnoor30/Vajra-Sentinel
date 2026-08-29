.PHONY: install install-dev run test lint format security demo-model validate clean

install:
	python -m pip install -e .

install-dev:
	python -m pip install -e ".[ml,dev,security]"

run:
	python -m app.main

test:
	python -m pytest --cov=app --cov-report=term-missing

lint:
	python -m ruff check .
	python -m ruff format --check .

format:
	python -m ruff check . --fix
	python -m ruff format .

security:
	python -m bandit -q -r app ml scripts -x tests
	python -m pip_audit . --progress-spinner off

demo-model:
	python -m ml.generate_demo_dataset
	python -m ml.train --train-csv data/demo_train.csv --test-csv data/demo_test.csv --data-origin synthetic-smoke-test

validate: lint test security
	python scripts/validate_artifact.py

clean:
	python scripts/clean_runtime.py
