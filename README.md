pip-audit
=========

<!--- BADGES: START --->
![CI](https://github.com/trailofbits/pip-audit/workflows/CI/badge.svg)
[![PyPI version](https://badge.fury.io/py/pip-audit.svg)](https://pypi.org/project/pip-audit)
[![Packaging status](https://repology.org/badge/tiny-repos/python:pip-audit.svg)](https://repology.org/project/python:pip-audit/versions)
<!--- BADGES: END --->

`pip-audit` is a tool for scanning Python environments for packages
with known vulnerabilities. It uses the Python Packaging Advisory Database
(https://github.com/pypa/advisory-database) via the
[PyPI JSON API](https://warehouse.pypa.io/api-reference/json.html) as a source
of vulnerability reports.

This project is developed by [Trail of Bits](https://www.trailofbits.com/) with
support from Google. This is not an official Google product.

## Features

* Support for auditing local environments and requirements-style files
* Support for multiple vulnerability services
  ([PyPI](https://warehouse.pypa.io/api-reference/json.html#known-vulnerabilities),
  [OSV](https://osv.dev/docs/))
* Support for emitting
  [SBOMs](https://en.wikipedia.org/wiki/Software_bill_of_materials) in
  [CycloneDX](https://cyclonedx.org/) XML or JSON
* Human and machine-readable output formats (columnar, JSON)
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

## Usage

You can run `pip-audit` as a standalone program, or via `python -m`:

```bash
pip-audit --help
python -m pip_audit --help
```

<!-- @begin-pip-audit-help@ -->
```
usage: pip-audit [-h] [-V] [-l] [-r REQUIREMENTS] [-f FORMAT] [-s SERVICE]
                 [-d] [-S] [--desc [{on,off,auto}]] [--cache-dir CACHE_DIR]
                 [--progress-spinner {on,off}] [--timeout TIMEOUT]
                 [--path PATHS] [-v] [--fix] [--require-hashes]
                 [--index-url INDEX_URL] [--extra-index-url EXTRA_INDEX_URLS]
                 [--skip-editable]
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
  -r REQUIREMENTS, --requirement REQUIREMENTS
                        audit the given requirements file; this option can be
                        used multiple times (default: None)
  -f FORMAT, --format FORMAT
                        the format to emit audit results in (choices: columns,
                        json, cyclonedx-json, cyclonedx-xml) (default:
                        columns)
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
  --path PATHS          restrict to the specified installation path for
                        auditing packages; this option can be used multiple
                        times (default: [])
  -v, --verbose         give more output; this setting overrides the
                        `PIP_AUDIT_LOGLEVEL` variable and is equivalent to
                        setting it to `debug` (default: False)
  --fix                 automatically upgrade dependencies with known
                        vulnerabilities (default: False)
  --require-hashes      require a hash to check each requirement against, for
                        repeatable audits; this option is implied when any
                        package in a requirements file has a `--hash` option.
                        (default: False)
  --index-url INDEX_URL
                        base URL of the Python Package Index; this should
                        point to a repository compliant with PEP 503 (the
                        simple repository API) (default:
                        https://pypi.org/simple)
  --extra-index-url EXTRA_INDEX_URLS
                        extra URLs of package indexes to use in addition to
                        `--index-url`; should follow the same rules as
                        `--index-url` (default: [])
  --skip-editable       don't audit packages that are marked as editable
                        (default: False)
```
<!-- @end-pip-audit-help@ -->

### Exit codes

On completion, `pip-audit` will exit with a code indicating its status.

The current codes are:

* `0`: No known vulnerabilities were detected.
* `1`: One or more known vulnerabilities were found.

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
$ pip-audit -f json | jq
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
