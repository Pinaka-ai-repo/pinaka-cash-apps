.PHONY: setup demo test eval verify-security load release-check sbom

PYTHON ?= python

setup:
	$(PYTHON) scripts/verify_security.py --install-hooks

demo:
	$(PYTHON) -m apps.api.astra.seed_demo

test:
	$(PYTHON) -m unittest discover -s tests -p "test_*.py" -v

eval:
	$(PYTHON) -m ml.eval.harness

verify-security:
	$(PYTHON) scripts/verify_security.py --install-hooks

load:
	$(PYTHON) scripts/load_test.py

release-check: verify-security test eval load
	@echo "ASTRA Release Check Passed: Zero AWS Leaks, All Tests, Eval Cohort, and Load Gates Verified."
