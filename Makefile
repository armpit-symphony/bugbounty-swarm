PY=python3

.PHONY: test validate

test:
	$(PY) -m pytest -q

validate:
	$(PY) -m core.harness.validate output/vuln_scan_example_com_YYYYMMDD_HHMMSS.json
