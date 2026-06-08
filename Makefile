.PHONY: install test lint clean

install:
	./scripts/setup.sh

test:
	./venv/bin/python -m pytest tests/ -v --cov=core

lint:
	./venv/bin/black .
	./venv/bin/ruff check .

clean:
	rm -rf venv src-rust/target data/uro.db uro_rust_core.so .pytest_cache
	find . -type d -name "__pycache__" -exec rm -r {} +