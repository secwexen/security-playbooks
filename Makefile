install:
	pip install -r requirements.txt

install-dev:
	pip install -r dev-requirements.txt

test:
	pytest

lint:
	flake8 .

run:
	python main.py

clean:
	rm -rf __pycache__ .pytest_cache
