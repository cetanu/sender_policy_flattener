test:
	uv run pytest --spec -v
	uv run mypy --strict sender_policy_flattener

install_deps:
	python -m pip install --upgrade pip
	python -m pip install uv
