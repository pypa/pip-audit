pip-audit
=========

![CI](https://github.com/trailofbits/pip-audit/workflows/CI/badge.svg)
[![PyPI version](https://badge.fury.io/py/pip-audit.svg)](https://badge.fury.io/py/pip-audit)

`pip-audit` is a prototype tool for scanning Python environments for packages
with known vulnerabilities. It uses the Python Packaging Advisory Database
(https://github.com/pypa/advisory-db) as a source of vulnerability reports.

This project is developed by [Trail of Bits](https://www.trailofbits.com/) with
support from Google. This is not an official Google product.

## Installation

`pip-audit` requires Python 3.6 or newer, and can be installed directly via
`pip`:

```bash
pip install pip-audit
```

## Licensing

`pip-audit` is licensed under the Apache 2.0 License.

`pip-audit` reuses and modifies examples from
[`resolvelib`](https://github.com/sarugaku/resolvelib), which is licensed under
the ISC license.
