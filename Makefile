SHELL := /bin/bash

PY_MODULE := pip_audit

ALL_PY_SRCS := $(shell find $(PY_MODULE) -name '*.py') \
	$(shell find test -name '*.py')

# Optionally overridden by the user in the `release` target.
BUMP_ARGS :=

# Optionally overridden by the user in the `test` target.
TESTS :=

# Optionally overridden by the user/CI, to limit the installation to a specific
# subset of development dependencies.
PIP_AUDIT_EXTRA := dev

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
dev: env/pyvenv.cfg

.PHONY: run
run: env/pyvenv.cfg
	@. env/bin/activate && pip-audit $(ARGS)

env/pyvenv.cfg: pyproject.toml
	# Create our Python 3 virtual environment
	python3 -m venv env
	./env/bin/python -m pip install --upgrade pip
	./env/bin/python -m pip install -e .[$(PIP_AUDIT_EXTRA)]

.PHONY: lint
lint: env/pyvenv.cfg
	. env/bin/activate && \
		black --check $(ALL_PY_SRCS) && \
		isort --check $(ALL_PY_SRCS) && \
		ruff $(ALL_PY_SRCS) && \
		mypy $(PY_MODULE) && \
		interrogate -c pyproject.toml .

.PHONY: reformat
reformat:
	. env/bin/activate && \
		ruff --fix $(ALL_PY_SRCS) && \
		black $(ALL_PY_SRCS) && \
		isort $(ALL_PY_SRCS)

.PHONY: test tests
test tests: env/pyvenv.cfg
	. env/bin/activate && \
		pytest --cov=$(PY_MODULE) $(T) $(TEST_ARGS) && \
		python -m coverage report -m $(COV_ARGS)

.PHONY: doc
doc: env/pyvenv.cfg
	. env/bin/activate && \
		command -v pdoc3 && \
		PYTHONWARNINGS='error::UserWarning' pdoc --force --html $(PY_MODULE)

.PHONY: package
package: env/pyvenv.cfg
	. env/bin/activate && \
		python3 -m build

.PHONY: check-readme
check-readme: dev
	# pip-audit --help
	@diff \
	  <( \
	    awk '/@begin-pip-audit-help@/{f=1;next} /@end-pip-audit-help@/{f=0} f' \
	      < README.md | sed '1d;$$d' \
	  ) \
	  <( \
	    $(MAKE) -s run ARGS="--help" \
	  )


.PHONY: edit
edit:
	$(EDITOR) $(ALL_PY_SRCS)
