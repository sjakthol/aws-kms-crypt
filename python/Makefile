## Build targets
.PHONY: lint test format lint-pylint lint-black lint-mypy lint-bandit
test:
	poetry run pytest -vv --log-level=DEBUG --cov kmscrypt --cov-report term-missing

lint: lint-pylint lint-black lint-mypy lint-bandit
lint-pylint:
	poetry run pylint --max-line-length=120 --score=n kmscrypt tests
lint-black:
	poetry run black --check kmscrypt tests
lint-mypy:
	poetry run mypy kmscrypt
lint-bandit:
	poetry run bandit -q -r kmscrypt

format:
	poetry run black kmscrypt tests