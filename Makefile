.PHONY: test wheel sync-vendor clean

test:
	uv run --group dev python -m pytest tests

wheel:
	uv build --wheel

# Maintainer-only: refreshes vendor/kyberis_core from a sibling checkout of
# the shared Kyberis API client. See vendor/README.md.
sync-vendor:
	rsync -a --delete ../kyberis-api-client/src/kyberis_core/ vendor/kyberis_core/
	find vendor -name __pycache__ -type d -exec rm -rf {} +

clean:
	rm -rf dist .venv .pytest_cache
