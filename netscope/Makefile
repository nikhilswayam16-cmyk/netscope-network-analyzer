.PHONY: install run test lint sample docker

install:
	python -m pip install -e ".[dev]"

run:
	uvicorn netscope.main:app --reload --host 127.0.0.1 --port 8000

test:
	pytest

lint:
	ruff check src tests scripts

sample:
	python scripts/generate_sample.py
	cp data/demo-traffic.pcap src/netscope/data/demo-traffic.pcap

docker:
	docker compose up --build
