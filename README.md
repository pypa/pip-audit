pip-audit
=========

<!--- BADGES: START --->
![CI](https://github.com/pypa/pip-audit/workflows/CI/badge.svg)
[![PyPI version](https://badge.fury.io/py/pip-audit.svg)](https://pypi.org/project/pip-audit)
[![Packaging status](https://repology.org/badge/tiny-repos/python:pip-audit.svg)](https://repology.org/project/python:pip-audit/versions)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/pypa/pip-audit/badge)](https://api.securityscorecards.dev/projects/github.com/pypa/pip-audit)
<!--- BADGES: END --->

`pip-audit` is a tool for scanning Python environments for packages
with known vulnerabilities. It uses the Python Packaging Advisory Database
(https://github.com/pypa/advisory-database) via the
[PyPI JSON API](https://warehouse.pypa.io/api-reference/json.html) as a source
of vulnerability reports.

This project is maintained in part by [Trail of Bits](https://www.trailofbits.com/)
with support from Google. This is not an official Google or Trail of Bits product.

## Index

* [Features](#features)
* [Installation](#installation)
  * [Third-party packages](#third-party-packages)
  * [GitHub Actions](#github-actions)
  * [`pre-commit` support](#pre-commit-support)
* [Usage](#usage)
  * [Exit codes](#exit-codes)
  * [Dry runs](#dry-runs)
* [Examples](#examples)
* [Troubleshooting](#troubleshooting)
* [Tips and Tricks](#tips-and-tricks)
* [Security model](#security-model)
* [Licensing](#licensing)
* [Contributing](#contributing)
* [Code of Conduct](#code-of-conduct)

## Features

* Support for auditing local environments and requirements-style files
* Support for multiple vulnerability services
  ([PyPI](https://warehouse.pypa.io/api-reference/json.html#known-vulnerabilities),
  [OSV](https://osv.dev/docs/))
* Support for emitting
  [SBOMs](https://en.wikipedia.org/wiki/Software_bill_of_materials) in
  [CycloneDX](https://cyclonedx.org/) XML or JSON
* Support for automatically fixing vulnerable dependencies (`--fix`)
* Human and machine-readable output formats (columnar, Markdown, JSON)
* Seamlessly reuses your existing local `pip` caches

## Installation

`pip-audit` requires Python 3.7 or newer, and can be installed directly via `pip`:

```bash
python -m pip install pip-audit
```

### Third-party packages

There are multiple **third-party** packages for `pip-audit`. The matrices and badges below
list some of them:

[![Packaging status](https://repology.org/badge/vertical-allrepos/python:pip-audit.svg)](https://repology.org/project/python:pip-audit/versions)
[![Packaging status](https://repology.org/badge/vertical-allrepos/pip-audit.svg)](https://repology.org/project/pip-audit/versions)
[![Conda - Platform](https://img.shields.io/conda/pn/conda-forge/pip-audit?logo=anaconda&style=flat)][#conda-forge-package]
[![Conda (channel only)](https://img.shields.io/conda/vn/conda-forge/pip-audit?logo=anaconda&style=flat&color=orange)][#conda-forge-package]

[#conda-forge-package]: https://anaconda.org/conda-forge/pip-audit

In particular, `pip-audit` can be installed via `conda`:

```bash
conda install -c conda-forge pip-audit
```

Third-party packages are **not** directly supported by this project. Please consult your package manager's
documentation for more detailed installation guidance.

### GitHub Actions

`pip-audit` has [an official GitHub Action](https://github.com/pypa/gh-action-pip-audit)!

You can install it from the
[GitHub Marketplace](https://github.com/marketplace/actions/gh-action-pip-audit), or
add it to your CI manually:

```yaml
jobs:
  pip-audit:
    steps:
      - uses: pypa/gh-action-pip-audit@v1.0.0
        with:
          inputs: requirements.txt
```

See the
[action documentation](https://github.com/pypa/gh-action-pip-audit/blob/main/README.md)
for more details and usage examples.

### `pre-commit` support

`pip-audit` has [`pre-commit`](https://pre-commit.com/) support.

For example, using `pip-audit` via `pre-commit` to audit a requirements file:

```yaml
  - repo: https://github.com/pypa/pip-audit
    rev: v2.5.5
    hooks:
      -   id: pip-audit
          args: ["-r", "requirements.txt"]

ci:
  # Leave pip-audit to only run locally and not in CI
  # pre-commit.ci does not allow network calls
  skip: [pip-audit]
```

Any `pip-audit` arguments documented below can be passed.

## Usage

You can run `pip-audit` as a standalone program, or via `python -m`:

```bash
pip-audit --help
python -m pip_audit --help
```

<!-- @begin-pip-audit-help@ -->
```
usage: pip-audit [-h] [-V] [-l] [-r REQUIREMENT] [-f FORMAT] [-s SERVICE] [-d]
                 [-S] [--desc [{on,off,auto}]] [--cache-dir CACHE_DIR]
                 [--progress-spinner {on,off}] [--timeout TIMEOUT]
                 [--path PATH] [-v] [--fix] [--require-hashes]
                 [--index-url INDEX_URL] [--extra-index-url URL]
                 [--skip-editable] [--no-deps] [-o FILE] [--ignore-vuln ID]
                 [project_path]

audit the Python environment for dependencies with known vulnerabilities

positional arguments:
  project_path          audit a local Python project at the given path
                        (default: None)

optional arguments:
  -h, --help            show this help message and exit
  -V, --version         show program's version number and exit
  -l, --local           show only results for dependencies in the local
                        environment (default: False)
  -r REQUIREMENT, --requirement REQUIREMENT
                        audit the given requirements file; this option can be
                        used multiple times (default: None)
  -f FORMAT, --format FORMAT
                        the format to emit audit results in (choices: columns,
                        json, cyclonedx-json, cyclonedx-xml, markdown)
                        (default: columns)
  -s SERVICE, --vulnerability-service SERVICE
                        the vulnerability service to audit dependencies
                        against (choices: osv, pypi) (default: pypi)
  -d, --dry-run         without `--fix`: collect all dependencies but do not
                        perform the auditing step; with `--fix`: perform the
                        auditing step but do not perform any fixes (default:
                        False)
  -S, --strict          fail the entire audit if dependency collection fails
                        on any dependency (default: False)
  --desc [{on,off,auto}]
                        include a description for each vulnerability; `auto`
                        defaults to `on` for the `json` format. This flag has
                        no effect on the `cyclonedx-json` or `cyclonedx-xml`
                        formats. (default: auto)
  --cache-dir CACHE_DIR
                        the directory to use as an HTTP cache for PyPI; uses
                        the `pip` HTTP cache by default (default: None)
  --progress-spinner {on,off}
                        display a progress spinner (default: on)
  --timeout TIMEOUT     set the socket timeout (default: 15)
  --path PATH           restrict to the specified installation path for
                        auditing packages; this option can be used multiple
                        times (default: [])
  -v, --verbose         run with additional debug logging; supply multiple
                        times to increase verbosity (default: 0)
  --fix                 automatically upgrade dependencies with known
                        vulnerabilities (default: False)
  --require-hashes      require a hash to check each requirement against, for
                        repeatable audits; this option is implied when any
                        package in a requirements file has a `--hash` option.
                        (default: False)
  --index-url INDEX_URL
                        base URL of the Python Package Index; this should
                        point to a repository compliant with PEP 503 (the
                        simple repository API); this will be resolved by pip
                        if not specified (default: None)
  --extra-index-url URL
                        extra URLs of package indexes to use in addition to
                        `--index-url`; should follow the same rules as
                        `--index-url` (default: [])
  --skip-editable       don't audit packages that are marked as editable
                        (default: False)
  --no-deps             don't perform any dependency resolution; requires all
                        requirements are pinned to an exact version (default:
                        False)
  -o FILE, --output FILE
                        output results to the given file (default: stdout)
  --ignore-vuln ID      ignore a specific vulnerability by its vulnerability
                        ID; this option can be used multiple times (default:
                        [])
```
<!-- @end-pip-audit-help@ -->

### Exit codes

On completion, `pip-audit` will exit with a code indicating its status.

The current codes are:

* `0`: No known vulnerabilities were detected.
* `1`: One or more known vulnerabilities were found.

`pip-audit`'s exit code cannot be suppressed.
See [Suppressing exit codes from `pip-audit`](#suppressing-exit-codes-from-pip-audit)
for supported alternatives.

### Dry runs

`pip-audit` supports the `--dry-run` flag, which can be used to control whether
an audit (or fix) step is actually performed.

* On its own, `pip-audit --dry-run` skips the auditing step and prints
  the number of dependencies that *would have been* audited.
* In fix mode, `pip-audit --fix --dry-run` performs the auditing step and prints
  out the fix behavior (i.e., which dependencies would be upgraded or skipped)
  that *would have been performed*.

## Examples

Audit dependencies for the current Python environment:
```
$ pip-audit
No known vulnerabilities found
```

Audit dependencies for a given requirements file:
```
$ pip-audit -r ./requirements.txt
No known vulnerabilities found
```

Audit dependencies for a requirements file, excluding system packages:
```
$ pip-audit -r ./requirements.txt -l
No known vulnerabilities found
```

Audit dependencies for a local Python project:
```
$ pip-audit .
No known vulnerabilities found
```
`pip-audit` searches the provided path for various Python "project" files. At the moment, only `pyproject.toml` is supported.

Audit dependencies when there are vulnerabilities present:
```
$ pip-audit
Found 2 known vulnerabilities in 1 package
Name  Version ID             Fix Versions
----  ------- -------------- ------------
Flask 0.5     PYSEC-2019-179 1.0
Flask 0.5     PYSEC-2018-66  0.12.3
```

Audit dependencies including descriptions:
```
$ pip-audit --desc
Found 2 known vulnerabilities in 1 package
Name  Version ID             Fix Versions Description
----  ------- -------------- ------------ --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Flask 0.5     PYSEC-2019-179 1.0          The Pallets Project Flask before 1.0 is affected by: unexpected memory usage. The impact is: denial of service. The attack vector is: crafted encoded JSON data. The fixed version is: 1. NOTE: this may overlap CVE-2018-1000656.
Flask 0.5     PYSEC-2018-66  0.12.3       The Pallets Project flask version Before 0.12.3 contains a CWE-20: Improper Input Validation vulnerability in flask that can result in Large amount of memory usage possibly leading to denial of service. This attack appear to be exploitable via Attacker provides JSON data in incorrect encoding. This vulnerability appears to have been fixed in 0.12.3. NOTE: this may overlap CVE-2019-1010083.
```

Audit dependencies in JSON format:
```
$ pip-audit -f json | python -m json.tool
Found 2 known vulnerabilities in 1 package
[
  {
    "name": "flask",
    "version": "0.5",
    "vulns": [
      {
        "id": "PYSEC-2019-179",
        "fix_versions": [
          "1.0"
        ],
        "description": "The Pallets Project Flask before 1.0 is affected by: unexpected memory usage. The impact is: denial of service. The attack vector is: crafted encoded JSON data. The fixed version is: 1. NOTE: this may overlap CVE-2018-1000656."
      },
      {
        "id": "PYSEC-2018-66",
        "fix_versions": [
          "0.12.3"
        ],
        "description": "The Pallets Project flask version Before 0.12.3 contains a CWE-20: Improper Input Validation vulnerability in flask that can result in Large amount of memory usage possibly leading to denial of service. This attack appear to be exploitable via Attacker provides JSON data in incorrect encoding. This vulnerability appears to have been fixed in 0.12.3. NOTE: this may overlap CVE-2019-1010083."
      }
    ]
  },
  {
    "name": "jinja2",
    "version": "3.0.2",
    "vulns": []
  },
  {
    "name": "pip",
    "version": "21.3.1",
    "vulns": []
  },
  {
    "name": "setuptools",
    "version": "57.4.0",
    "vulns": []
  },
  {
    "name": "werkzeug",
    "version": "2.0.2",
    "vulns": []
  },
  {
    "name": "markupsafe",
    "version": "2.0.1",
    "vulns": []
  }
]
```

Audit and attempt to automatically upgrade vulnerable dependencies:
```
$ pip-audit --fix
Found 2 known vulnerabilities in 1 package and fixed 2 vulnerabilities in 1 package
Name  Version ID             Fix Versions Applied Fix
----- ------- -------------- ------------ ----------------------------------------
flask 0.5     PYSEC-2019-179 1.0          Successfully upgraded flask (0.5 => 1.0)
flask 0.5     PYSEC-2018-66  0.12.3       Successfully upgraded flask (0.5 => 1.0)
```

## Troubleshooting

Have you resolved a problem with `pip-audit`? Help us by contributing to this
section!

### `pip-audit` shows irrelevant vulnerability reports!

In a perfect world, vulnerability feeds would have an infinite signal-to-noise
ratio: every vulnerability report would be (1) correct, and (2) applicable to
every use of every dependency.

Unfortunately, neither of these is guaranteed: vulnerability feeds are not
immune to extraneous or spam reports, and not all uses of a particular
dependency map to all potential classes of vulnerabilities.

If your `pip-audit` runs produce vulnerability reports that aren't actionable
for your particular application or use case, you can use the `--ignore-vuln ID`
option to ignore specific vulnerability reports. `--ignore-vuln` supports
aliases, so you can use a `GHSA-xxx` or `CVE-xxx` ID instead of a `PYSEC-xxx`
ID if the report in question does not have a PYSEC ID.

For example, here is how you might ignore GHSA-w596-4wvx-j9j6, which is a
common source of noisy vulnerability reports and false positives for users of
[`pytest`](https://github.com/pytest-dev/pytest):

```console
# Run the audit as normal, but exclude any reports that match GHSA-w596-4wvx-j9j6
$ pip-audit --ignore-vuln GHSA-w596-4wvx-j9j6
```

The `--ignore-vuln ID` option works with all other dependency resolution
and auditing options, meaning that it should function correctly with
requirements-style inputs, alternative vulnerability feeds, and so forth.

It can also be passed multiple times, to ignore multiple reports:

```console
# Run the audit as normal, but exclude any reports that match these IDs
$ pip-audit --ignore-vuln CVE-XXX-YYYY --ignore-vuln CVE-ZZZ-AAAA
```

### `pip-audit` takes longer than I expect!

Depending on how you're using it, `pip-audit` may have to perform its
own dependency resolution, which can take roughly as long as `pip install`
does for a project. See the [security model](#security-model) for an explanation.

You have two options for avoiding dependency resolution: *audit a pre-installed
environment*, or *ensure that your dependencies are already fully resolved*.

If you know that you've already fully configured an environment equivalent
to the one that `pip-audit -r requirements.txt` would audit, you can simply
reuse it:

```console
# Note the absence of any "input" arguments, indicating that the environment is used.
$ pip-audit

# Optionally filter out non-local packages, for virtual environments:
$ pip-audit --local
```

Alternatively, if your input is fully pinned (and optionally hashed), you
can tell `pip-audit` to skip dependency resolution with either `--no-deps`
(pinned without hashes) or `--require-hashes` (pinned including hashes).

The latter is equivalent to `pip`'s
[hash-checking mode](https://pip.pypa.io/en/stable/cli/pip_install/#hash-checking-mode)
and is preferred, since it offers additional integrity.

```console
# fails if any dependency is not fully pinned
$ pip-audit --no-deps -r requirements.txt

# fails if any dependency is not fully pinned *or* is missing hashes
$ pip-audit --require-hashes -r requirements.txt
```

## Tips and Tricks

### Running against a `pipenv` project

`pipenv` uses both a `Pipfile` and `Pipfile.lock` file to track and freeze dependencies
instead of a `requirements.txt` file. `pip-audit` cannot process the `Pipfile[.lock]`
files directly, however, these can be converted to a supported `requirements.txt` file
that `pip-audit` can run against. `pipenv` has a built-in command to convert dependencies
to a `requirements.txt` file (as of [`v2022.4.8`](https://pipenv.pypa.io/en/latest/changelog/#id206)):

```console
$ pipenv run pip-audit -r <(pipenv requirements)
```

### Suppressing exit codes from `pip-audit`

`pip-audit` intentionally does not support internally suppressing its own
exit codes.

Users who need to suppress a failing `pip-audit` invocation can use
one of the standard shell idioms for doing so:

```bash
pip-audit || true
```

or, to exit entirely:

```bash
pip-audit || exit 0
```

The exit code can also be captured and handled explicitly:

```bash
pip-audit
exitcode="${?}"
# do something with ${exitcode}
```

See [Exit codes](#exit-codes) for a list of potential codes that need handling.

## Security Model

This section exists to describe the security assumptions you **can** and **must not**
make when using `pip-audit`.

TL;DR: **If you wouldn't `pip install` it, you should not `pip audit` it.**

`pip-audit` is a tool for auditing Python environments for packages with
*known vulnerabilities*. A "known vulnerability" is a publicly reported flaw in
a package that, if uncorrected, *might* allow a malicious actor to perform
unintended actions.

`pip-audit` **can** protect you against known vulnerabilities by telling
you when you have them, and how you should upgrade them. For example,
if you have `somepackage==1.2.3` in your environment, `pip-audit` **can** tell
you that it needs to be upgraded to `1.2.4`.

You **can** assume that `pip-audit` will make a best effort to *fully resolve*
all of your Python dependencies and *either* fully audit each *or* explicitly
state which ones it has skipped, as well as why it has skipped them.

`pip-audit` is **not** a static code analyzer. It analyzes dependency trees,
not code, and it **cannot** guarantee that arbitrary dependency resolutions
occur statically. To understand why this is, refer to Dustin Ingram's
[excellent post on dependency resolution in Python](https://dustingram.com/articles/2018/03/05/why-pypi-doesnt-know-dependencies/).

As such: you **must not** assume that `pip-audit` will **defend** you against
malicious packages. In particular, it is **incorrect** to treat
`pip-audit -r INPUT` as a "more secure" variant of `pip-audit`. For all intents
and purposes, `pip-audit -r INPUT` is functionally equivalent to
`pip install -r INPUT`, with a small amount of **non-security isolation** to
avoid conflicts with any of your local environments.

`pip-audit` is first and foremost a auditing tool for *Python* packages.
You **must not** assume that `pip-audit` will detect or flag "transitive"
vulnerabilities that might be exposed through Python packages, but are not
actually part of the package itself. For example, `pip-audit`'s vulnerability
information sources are unlikely to include an advisory for a vulnerable shared
library that a popular Python package *might* use, since the Python package's
version is not strongly connected to the shared library's version.

## Licensing

`pip-audit` is licensed under the Apache 2.0 License.

`pip-audit` reuses and modifies examples from
[`resolvelib`](https://github.com/sarugaku/resolvelib), which is licensed under
the ISC license.

## Contributing

See [the contributing docs](CONTRIBUTING.md) for details.

## Code of Conduct

Everyone interacting with this project is expected to follow the
[PSF Code of Conduct](https://github.com/pypa/.github/blob/main/CODE_OF_CONDUCT.md).
