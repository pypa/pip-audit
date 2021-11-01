pip-audit
=========

![CI](https://github.com/trailofbits/pip-audit/workflows/CI/badge.svg)
[![PyPI version](https://badge.fury.io/py/pip-audit.svg)](https://badge.fury.io/py/pip-audit)

`pip-audit` is a prototype tool for scanning Python environments for packages
with known vulnerabilities. It uses the Python Packaging Advisory Database
(https://github.com/pypa/advisory-db) via the
[PyPI JSON API](https://warehouse.pypa.io/api-reference/json.html) as a source
of vulnerability reports.

This project is developed by [Trail of Bits](https://www.trailofbits.com/) with
support from Google. This is not an official Google product.

## Installation

`pip-audit` requires Python 3.6 or newer, and can be installed directly via
`pip`:

```bash
python -m pip install pip-audit
```

## Usage

```
usage: pip-audit [-h] [-V] [-l] [-r REQUIREMENTS] [-f {columns,json}]
                 [-s {osv,pypi}] [-d] [--desc {on,off,auto}]
                 [--cache-dir CACHE_DIR]

audit the Python environment for dependencies with known vulnerabilities

optional arguments:
  -h, --help            show this help message and exit
  -V, --version         show program's version number and exit
  -l, --local           show only results for dependencies in the local
                        environment (default: False)
  -r REQUIREMENTS, --requirement REQUIREMENTS
                        audit the given requirements file; this option can be
                        used multiple times (default: None)
  -f {columns,json}, --format {columns,json}
                        the format to emit audit results in (default: columns)
  -s {osv,pypi}, --vulnerability-service {osv,pypi}
                        the vulnerability service to audit dependencies
                        against (default: pypi)
  -d, --dry-run         collect all dependencies but do not perform the
                        auditing step (default: False)
  --desc {on,off,auto}  include a description for each vulnerability; `auto`
                        only includes a description for the `json` format
                        (default: auto)
  --cache-dir CACHE_DIR
                        the directory to use as an HTTP cache for PyPI; uses
                        the `pip` HTTP cache by default (default: None)
```

## Examples

Auditing dependencies for the current Python environment:
```
$ pip-audit
Package Version ID Fix Versions
------- ------- -- ------------
```

Auditing dependencies for a given requirements file:
```
$ pip-audit -r ./requirements.txt
Package   Version ID            Fix Versions
--------- ------- ------------- ------------
```

Auditing dependencies for the current Python environment excluding system packages:
```
$ pip-audit -r ./requirements.txt -l
Package   Version ID            Fix Versions
--------- ------- ------------- ------------
```

Auditing dependencies when there are vulnerabilities present:
```
$ pip-audit
Package Version ID             Fix Versions
------- ------- -------------- ------------
Flask   0.5     PYSEC-2019-179 1.0
Flask   0.5     PYSEC-2018-66  0.12.3
```

## Contributing

See [the contributing docs](CONTRIBUTING.md) for details.

## Licensing

`pip-audit` is licensed under the Apache 2.0 License.

`pip-audit` reuses and modifies examples from
[`resolvelib`](https://github.com/sarugaku/resolvelib), which is licensed under
the ISC license.
