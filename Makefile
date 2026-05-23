PY=python3

.PHONY: test validate review install

test:
	$(PY) -m pytest -q

validate:
	$(PY) -m core.harness.validate output/vuln_scan_example_com_YYYYMMDD_HHMMSS.json

# Code review targets
review:
	$(PY) swarm_review_cli.py review --repo . --profile review-cautious

review-deep:
	$(PY) swarm_review_cli.py review --repo . --profile review-deep

review-diff:
	$(PY) swarm_review_cli.py review --diff /path/to/changes.diff --profile review-cautious

# Install SwarmReview dependencies
install:
	pip install -r requirements.txt
