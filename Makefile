.PHONY: help install lint test validate clean docs build security check

help:
	@echo "Security Playbooks Commands"
	@echo "---------------------------"
	@echo "install     Install dependencies"
	@echo "lint        Run lint checks"
	@echo "validate    Validate rules & playbooks"
	@echo "test        Run tests"
	@echo "security    Run security scanning"
	@echo "build       Build docker environment"
	@echo "check       Full pipeline"
	@echo "clean       Clean artifacts"
	@echo "docs        Docs generation"

install:
	pip install -r requirements.txt

lint:
	yamllint playbooks/ detection-rules/
	flake8 tools/

validate:
	python tools/validation/suricata_validator.py
	python tools/validation/sigma_validator.py
	python tools/validation/yara_validator.py

test:
	pytest tests/ -v --cov=tools/

security:
	trivy fs .
	bandit -r tools/

check: lint validate test security

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	rm -rf .pytest_cache .coverage htmlcov

docs:
	echo "Docs generation placeholder"
