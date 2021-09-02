PY_MODULE := pip_audit

ALL_PY_SRCS := setup.py \
	$(shell find $(PY_MODULE) -name '*.py') \
	$(shell find test -name '*.py')

.PHONY: all
all:
	@echo "Run my targets individually!"

.PHONY: dev
dev:
	test -d env || python3 -m venv env
	. env/bin/activate && \
		pip install --upgrade pip && \
		pip install -e .[dev]

.PHONY: lint
lint:
	. env/bin/activate && \
		black $(ALL_PY_SRCS) && \
		isort $(ALL_PY_SRCS) && \
		flake8 $(ALL_PY_SRCS) && \
		mypy $(PY_MODULE) && \
		git diff --exit-code

.PHONY: test
test:
	. env/bin/activate && \
		pytest --cov=pip_audit test/ && \
		python -m coverage report -m --fail-under 100

# NOTE(ww): pdoc3 does not support Python 3.6. Re-enable this once 3.7 is
# our minimally supported version.
# .PHONY: doc
# doc:
# 	. env/bin/activate && \
# 		PYTHONWARNINGS='error::UserWarning' pdoc --force --html pip_audit

.PHONY: package
package:
	. env/bin/activate && \
		python3 setup.py sdist && \
		twine upload --repository pypi dist/*

.PHONY: edit
edit:
	$(EDITOR) $(ALL_PY_SRCS)
