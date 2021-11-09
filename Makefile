PY_MODULE := pip_audit

ALL_PY_SRCS := setup.py \
	$(shell find $(PY_MODULE) -name '*.py') \
	$(shell find test -name '*.py')

# Optionally overridden by the user in the `release` target.
BUMP_ARGS :=

# Optionally overridden by the user in the `test` target.
TESTS :=

# If the user selects a specific test pattern to run, set `pytest` to fail fast
# and only run tests that match the pattern.
# Otherwise, run all tests and enable coverage assertions, since we expect
# complete test coverage.
ifneq ($(TESTS),)
	TEST_ARGS := -x -k $(TESTS)
	COV_ARGS :=
else
	TEST_ARGS :=
	COV_ARGS := --fail-under 100
endif

.PHONY: all
all:
	@echo "Run my targets individually!"

.PHONY: dev
dev:
	test -d env || python3 -m venv env
	. env/bin/activate && \
		pip install --upgrade pip && \
		pip install -e .[dev]


.PHONY: run
run:
	@. env/bin/activate && pip-audit $(ARGS)

.PHONY: lint
lint:
	. env/bin/activate && \
		black $(ALL_PY_SRCS) && \
		isort $(ALL_PY_SRCS) && \
		flake8 $(ALL_PY_SRCS) && \
		mypy $(PY_MODULE) && \
		interrogate -c pyproject.toml . && \
		git diff --exit-code

.PHONY: test
test:
	. env/bin/activate && \
		pytest --cov=pip_audit test/ $(TEST_ARGS) && \
		python -m coverage report -m $(COV_ARGS)

# NOTE(ww): pdoc3 does not support Python 3.6. Re-enable this once 3.7 is
# our minimally supported version.
# .PHONY: doc
# doc:
# 	. env/bin/activate && \
# 		PYTHONWARNINGS='error::UserWarning' pdoc --force --html pip_audit

.PHONY: package
package:
	. env/bin/activate && \
		python3 -m build

.PHONY: release
release:
	@. env/bin/activate && \
		NEXT_VERSION=$$(bump $(BUMP_ARGS)) && \
		git add pip_audit/version.py && git diff --quiet --exit-code && \
		git commit -m "version: v$${NEXT_VERSION}" && \
		git tag v$${NEXT_VERSION} && \
		echo "RUN ME MANUALLY: git push origin main && git push origin v$${NEXT_VERSION}"


.PHONY: edit
edit:
	$(EDITOR) $(ALL_PY_SRCS)
