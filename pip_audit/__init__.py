"""
The `pip_audit` APIs.
"""

__version__ = "2.10.1"

# When `pip-audit` is vendored (for example as `pip audit`), set this to True
# to hide third-party CLI features and skip optional imports such as CycloneDX.
# See: https://github.com/pypa/pip-audit/issues/336
VENDORED = False
