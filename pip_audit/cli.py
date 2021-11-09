"""
Command-line entrypoints for `pip-audit`.
"""

import argparse
import enum
import logging
import os
import sys
from contextlib import ExitStack
from pathlib import Path
from typing import List, Optional

from pip_audit import __version__
from pip_audit.audit import AuditOptions, Auditor
from pip_audit.dependency_source import (
    DependencySource,
    PipSource,
    RequirementSource,
    ResolveLibResolver,
)
from pip_audit.format import ColumnsFormat, JsonFormat, VulnerabilityFormat
from pip_audit.service import OsvService, PyPIService, VulnerabilityService
from pip_audit.state import AuditSpinner
from pip_audit.util import assert_never

logger = logging.getLogger(__name__)
logging.basicConfig(level=os.environ.get("PIP_AUDIT_LOGLEVEL", "INFO").upper())


@enum.unique
class OutputFormatChoice(str, enum.Enum):
    """
    Output formats supported by the `pip-audit` CLI.
    """

    Columns = "columns"
    Json = "json"

    def to_format(self, output_desc: bool) -> VulnerabilityFormat:
        if self is OutputFormatChoice.Columns:
            return ColumnsFormat(output_desc)
        elif self is OutputFormatChoice.Json:
            return JsonFormat(output_desc)
        else:
            assert_never(self)

    def __str__(self):
        return self.value


@enum.unique
class VulnerabilityServiceChoice(str, enum.Enum):
    """
    Python vulnerability services supported by `pip-audit`.
    """

    Osv = "osv"
    Pypi = "pypi"

    def to_service(self, cache_dir: Optional[Path]) -> VulnerabilityService:
        if self is VulnerabilityServiceChoice.Osv:
            return OsvService()
        elif self is VulnerabilityServiceChoice.Pypi:
            return PyPIService(cache_dir)
        else:
            assert_never(self)

    def __str__(self):
        return self.value


@enum.unique
class VulnerabilityDescriptionChoice(str, enum.Enum):
    """
    Whether or not vulnerability descriptions should be added to the `pip-audit` output.
    """

    On = "on"
    Off = "off"
    Auto = "auto"

    def to_bool(self, format_: OutputFormatChoice) -> bool:
        if self is VulnerabilityDescriptionChoice.On:
            return True
        elif self is VulnerabilityDescriptionChoice.Off:
            return False
        elif self is VulnerabilityDescriptionChoice.Auto:
            return bool(format_.value == OutputFormatChoice.Json)
        else:
            assert_never(self)

    def __str__(self):
        return self.value


@enum.unique
class ProgressSpinnerChoice(str, enum.Enum):
    """
    Whether or not `pip-audit` should display a progress spinner.
    """

    On = "on"
    Off = "off"

    def __bool__(self) -> bool:
        return self is ProgressSpinnerChoice.On

    def __str__(self):
        return self.value


def audit() -> None:
    """
    The primary entrypoint for `pip-audit`.
    """
    parser = argparse.ArgumentParser(
        prog="pip-audit",
        description="audit the Python environment for dependencies with known vulnerabilities",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "-l",
        "--local",
        action="store_true",
        help="show only results for dependencies in the local environment",
    )
    parser.add_argument(
        "-r",
        "--requirement",
        type=argparse.FileType("r"),
        action="append",
        dest="requirements",
        help="audit the given requirements file; this option can be used multiple times",
    )
    parser.add_argument(
        "-f",
        "--format",
        type=OutputFormatChoice,
        choices=OutputFormatChoice,
        default=OutputFormatChoice.Columns,
        help="the format to emit audit results in",
    )
    parser.add_argument(
        "-s",
        "--vulnerability-service",
        type=VulnerabilityServiceChoice,
        choices=VulnerabilityServiceChoice,
        default=VulnerabilityServiceChoice.Pypi,
        help="the vulnerability service to audit dependencies against",
    )
    parser.add_argument(
        "-d",
        "--dry-run",
        action="store_true",
        help="collect all dependencies but do not perform the auditing step",
    )
    parser.add_argument(
        "--desc",
        type=VulnerabilityDescriptionChoice,
        choices=VulnerabilityDescriptionChoice,
        default=VulnerabilityDescriptionChoice.Auto,
        help="include a description for each vulnerability; "
        "`auto` only includes a description for the `json` format",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        help="the directory to use as an HTTP cache for PyPI; uses the `pip` HTTP cache by default",
    )
    parser.add_argument(
        "--progress-spinner",
        type=ProgressSpinnerChoice,
        choices=ProgressSpinnerChoice,
        default=ProgressSpinnerChoice.On,
        help="display a progress spinner",
    )

    args = parser.parse_args()
    logger.debug(f"parsed arguments: {args}")

    service = args.vulnerability_service.to_service(args.cache_dir)
    output_desc = args.desc.to_bool(args.format)
    formatter = args.format.to_format(output_desc)

    with ExitStack() as stack:
        state = stack.enter_context(AuditSpinner()) if args.progress_spinner else None

        source: DependencySource
        if args.requirements is not None:
            req_files: List[Path] = [Path(req.name) for req in args.requirements]
            source = RequirementSource(req_files, ResolveLibResolver(state), state)
        else:
            source = PipSource(local=args.local)

        auditor = Auditor(service, options=AuditOptions(dry_run=args.dry_run))

        result = {}
        pkg_count = 0
        vuln_count = 0
        for (spec, vulns) in auditor.audit(source):
            if state is not None:
                state.update_state(f"Auditing {spec.name} ({spec.version})")
            result[spec] = vulns
            if len(vulns) > 0:
                pkg_count += 1
                vuln_count += len(vulns)

    if vuln_count > 0:
        print(f"Found {vuln_count} known vulnerabilities in {pkg_count} packages", file=sys.stderr)
        print(formatter.format(result))
        sys.exit(1)
    else:
        print("No known vulnerabilities found", file=sys.stderr)
