pip-audit
=========

![CI](https://github.com/trailofbits/pip-audit/workflows/CI/badge.svg)

`pip-audit` is a prototype tool for scanning Python environments for packages with known vulnerabilities. It uses the Python Packaging Advisory Database (https://github.com/pypa/advisory-db) as a source of vulnerability reports.

This project is developed by [Trail of Bits](https://www.trailofbits.com/) with support from Google. This is not an official Google product.

## Development steps

```bash
git clone https://github.com/trailofbits/pip-audit && cd pip-audit
make dev && source env/bin/activate
pip-audit --help
```
