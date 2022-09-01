Contributing to pip-audit
=========================

Thank you for your interest in contributing to `pip-audit`!

The information below will help you set up a local development environment,
as well as performing common development tasks.

## Requirements

`pip-audit`'s only development environment requirement *should* be Python 3.7
or newer. Development and testing is actively performed on macOS and Linux,
but Windows and other supported platforms that are supported by Python
should also work.

If you're on a system that has GNU Make, you can use the convenience targets
included in the `Makefile` that comes in the `pip-audit` repository detailed
below. But this isn't required; all steps can be done without Make.

## Development steps

First, clone this repository:

```bash
git clone https://github.com/pypa/pip-audit
cd pip-audit
```

Then, use one of the `Makefile` targets to run a task. The first time this is
run, this will also set up the local development virtual environment, and will
install `pip-audit` as an editable package into this environment.

Any changes you make to the `pip_audit` source tree will take effect
immediately in the virtual environment.

### Linting

You can lint locally with:

```bash
make lint
```

`pip-audit` is automatically linted and formatted with a collection of tools:

* [`black`](https://github.com/psf/black): Code formatting
* [`isort`](https://github.com/PyCQA/isort): Import sorting, ordering
* [`flake8`](https://flake8.pycqa.org/en/latest/): PEP-8 linting, style enforcement
* [`mypy`](https://mypy.readthedocs.io/en/stable/): Static type checking
* [`interrogate`](https://interrogate.readthedocs.io/en/latest/): Documentation coverage

To automatically apply any lint-suggested changes, you can run:

```bash
make reformat
```


### Testing

You can run the tests locally with:

```bash
make test
```

You can also filter by a pattern (uses `pytest -k`):

```bash
make test TESTS=test_audit_dry_run
```

To test a specific file:

```bash
make test T=path/to/file.py
```

`pip-audit` has a [`pytest`](https://docs.pytest.org/)-based unit test suite,
including code coverage with [`coverage.py`](https://coverage.readthedocs.io/).

### Documentation

If you're running Python 3.7 or newer, you can run the documentation build locally:

```bash
make doc
```

`pip-audit` uses [`pdoc3`](https://github.com/pdoc3/pdoc) to generate HTML documentation for
the public Python APIs.

Live documentation for the `main` branch is hosted
[here](https://pypa.github.io/pip-audit/). Only the public APIs are
documented, all undocumented APIs are **intentionally private and unstable.**

### Releasing

**NOTE**: If you're a non-maintaining contributor, you don't need the steps
here! They're documented for completeness and for onboarding future maintainers.

Releases of `pip-audit` are managed with [`bump`](https://github.com/di/bump)
and GitHub Actions.

The following manual steps are required:

1. Create a new development branch for the release. For example:

    ```console
    $ git checkout -b prepare-1.0.0
    ```

1. Update `pip-audit`'s `__version__` attribute. It can be found under `pip_audit/__init__.py`.

    **Note**: You can do this automatically with `bump`:

    ```console
    # See bump --help for all options
    $ bump --major
    ```

1. Commit your changes to the branch and create a new Pull Request.

1. Tag another maintainer for review. Once approved, you may merge your PR.

1. Create a new tag corresponding to the merged version change. For example:

    ```console
    # IMPORTANT: don't forget the `v` prefix!
    $ git tag v1.0.0
    ```

1. Push the new tag:

    ```console
    $ git push origin v1.0.0
    ```

1. Use the [releases page](https://github.com/pypa/pip-audit/releases) to
   create a new release, marking it as a "pre-release" if appropriate.

1. Copy the relevant
  [CHANGELOG](https://github.com/pypa/pip-audit/blob/main/CHANGELOG.md)
  entries into the release notes.

1. Save and publish the release. The CI will take care of all other tasks.



## Development practices

Here are some guidelines to follow if you're working on a new feature or changes to
`pip-audit`'s internal APIs:

* *Keep the `pip-audit` APIs as private as possible*. Nearly all of `pip-audit`'s
APIs should be private and treated as unstable and unsuitable for public use.
If you're adding a new module to the source tree, prefix the filename with an underscore to
emphasize that it's an internal (e.g., `pip_audit/_foo.py` instead of `pip_audit/foo.py`).

* *Keep the CLI consistent with `pip`*. `pip-audit`'s CLI should *roughly* mirror that
of `pip`. If you're adding a new flag or option to the CLI, check whether `pip` already
has the same functionality (e.g., HTTP timeout control) and use the same short and long mnemonics.

* *Perform judicious debug logging.* `pip-audit` uses the standard Python
[`logging`](https://docs.python.org/3/library/logging.html) module. Use
`logger.debug` early and often -- users who experience errors can submit better
bug reports when their debug logs include helpful context!

* *Update the [CHANGELOG](./CHANGELOG.md)*. If your changes are public or result
in changes to `pip-audit`'s CLI, please record them under the "Unreleased" section,
with an entry in an appropriate subsection ("Added", "Changed", "Removed", or "Fixed").
