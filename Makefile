test:
	uv run pytest --spec
	uv run mypy --strict sender_policy_flattener
	uv run ruff check sender_policy_flattener
	uv run ruff format --check sender_policy_flattener

test_verbose:
	uv run pytest -vvv

install_deps:
	python -m pip install --upgrade pip
	python -m pip install uv
