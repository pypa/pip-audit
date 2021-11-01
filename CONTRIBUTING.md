Contributing to pip-audit
=========================

Thank you for your interest in contributing to `pip-audit`!

The information below will help you set up a local development environment,
as well as performing common development tasks.

## Requirements

`pip-audit`'s only development environment requirement *should* be Python 3.6
or newer. Development and testing is actively performed on macOS and Linux,
but Windows and other supported platforms that are supported by Python
should also work.

If you're on a system that has GNU Make, you can use the convenience targets
included in the `Makefile` that comes in the `pip-audit` repository. But this
isn't required; all steps can be done without Make.

## Development steps

First, clone this repository:

```bash
git clone https://github.com/trailofbits/pip-audit
cd pip-audit
```

Then, set up the local development virtual environment.

If you have Make:

```bash
make dev
source env/bin/active
```

Or, manually:

```bash
# assumes that `python` is Python 3; use `python3` if not
python -m venv env
source env/bin/activate
pip install --upgrade pip
pip install -e .[dev]
```

This will install `pip-audit` as an editable package into your local environment,
which you can confirm from the command line:

```bash
pip-audit --version
```

If you see something like `pip-audit 0.0.2`, then you're all done! Any changes
you make to the `pip_audit` source tree will take effect immediately in your
local environment.

### Linting

`pip-audit` is automatically linted and formatted with a collection of tools:

* [`black`](https://github.com/psf/black): Code formatting
* [`isort`](https://github.com/PyCQA/isort): Import sorting, ordering
* [`flake8`](https://flake8.pycqa.org/en/latest/): PEP-8 linting, style enforcement
* [`mypy`](https://mypy.readthedocs.io/en/stable/): Static type checking

You can run all of the tools locally, either with Make:

```bash
make lint
```

...or manually:

```bash
# assumes that your virtual environment is active
black pip_audit/ test/
isort pip_audit/ test/
flake8 pip_audit/ test/
mypy pip_audit
```

### Testing

`pip-audit` has a [`pytest`](https://docs.pytest.org/)-based unit test suite,
including code coverage with [`coverage.py`](https://coverage.readthedocs.io/).

You can run the tests locally, either with Make:

```bash
make test
```

...or manually:

```bash
# assumes that your virtual environment is active
pytest --cov=pip_audit test/

# optionally: fail if test coverage is not 100%
python -m coverage report -m --fail-under 100
```

### Releasing

**NOTE**: If you're a non-maintaining contributor, you don't need the steps
here! They're documented for completeness and for onboarding future maintainers.

Releases of `pip-audit` are managed with [`bump`](https://github.com/di/bump)
and GitHub Actions.

```bash
# default release (patch bump)
make release

# override the default
# vX.Y.Z -> vX.Y.Z-rc.0
make release BUMP_ARGS="--pre rc.0"

# vX.Y.Z -> vN.0.0
make release BUMP_ARGS="--major"
```

`make release` will fail if there are any untracked changes in the source tree.

If `make release` succeeds, you'll see an output like this:

```
RUN ME MANUALLY: git push origin main && git push origin vX.Y.Z
```

Run that last command sequence to complete the release.
