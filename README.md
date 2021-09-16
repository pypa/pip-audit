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

## Release process

Releases of `pip-audit` are managed via [`bump`](https://github.com/di/bump)
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
