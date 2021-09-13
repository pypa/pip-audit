"""
Command-line entrypoints for `pip-audit`.
"""

import argparse
import enum
import logging
import os

logger = logging.getLogger(__name__)
logging.basicConfig(level=os.environ.get("PIP_AUDIT_LOGLEVEL", "INFO").upper())


@enum.unique
class OutputFormat(str, enum.Enum):
    """
    Output formats supported by the `pip-audit` CLI.
    """

    Columns = "columns"
    Json = "json"

    def __str__(self):
        return self.value


@enum.unique
class VulnerabilityService(str, enum.Enum):
    """
    Python vulnerability services supported by `pip-audit`.
    """

    Osv = "osv"
    Pypi = "pypi"

    def __str__(self):
        return self.value


def audit():
    """
    The primary entrypoint for `pip-audit`.
    """
    parser = argparse.ArgumentParser(
        description="audit the Python environment for dependencies with known vulnerabilities",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-r",
        "--requirement",
        type=argparse.FileType("r"),
        action="append",
        default=[],
        dest="requirements",
        help="audit the given requirements file; this option can be used multiple times",
    )
    parser.add_argument(
        "-f",
        "--format",
        type=OutputFormat,
        choices=OutputFormat,
        default=OutputFormat.Columns,
        help="the format to emit audit results in",
    )
    parser.add_argument(
        "-s",
        "--vulnerability-service",
        type=VulnerabilityService,
        choices=VulnerabilityService,
        default=VulnerabilityService.Osv,
        help="the vulnerability service to audit dependencies against",
    )
    parser.add_argument(
        "-d",
        "--dry-run",
        action="store_true",
        help="collect all dependencies but do not perform the auditing step",
    )

    args = parser.parse_args()
    logger.debug(f"parsed arguments: {args}")
