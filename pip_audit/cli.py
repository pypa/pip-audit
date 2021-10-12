"""
Command-line entrypoints for `pip-audit`.
"""

import argparse
import enum
import logging
import os
from pathlib import Path
from typing import Any, Dict, List

from progress.spinner import Spinner as BaseSpinner  # type: ignore

from pip_audit.audit import AuditOptions, Auditor
from pip_audit.dependency_source import PipSource, RequirementSource, ResolveLibResolver
from pip_audit.format import ColumnsFormat, JsonFormat, VulnerabilityFormat
from pip_audit.service import OsvService, VulnerabilityService
from pip_audit.util import assert_never
from pip_audit.version import __version__

logger = logging.getLogger(__name__)
logging.basicConfig(level=os.environ.get("PIP_AUDIT_LOGLEVEL", "INFO").upper())


class AuditSpinner(BaseSpinner):
    def __init__(self, message: str = "", **kwargs: Dict[str, Any]):
        super().__init__(message=message, **kwargs)
        self._base_message = self.message

    def update(self):
        item = getattr(self, "iter_value", None)
        if item is not None:
            (spec, _) = item
            self.message = f"{self._base_message} {spec.package} ({spec.version})"

        i = self.index % len(self.phases)
        line = f"{self.phases[i]} {self.message}"
        self.writeln(line)


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

    def to_service(self) -> VulnerabilityService:
        if self is VulnerabilityServiceChoice.Osv:
            return OsvService()
        elif self is VulnerabilityServiceChoice.Pypi:
            raise NotImplementedError
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


def audit():
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
        default=VulnerabilityServiceChoice.Osv,
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

    args = parser.parse_args()
    logger.debug(f"parsed arguments: {args}")

    service = args.vulnerability_service.to_service()
    output_desc = args.desc.to_bool(args.format)
    formatter = args.format.to_format(output_desc)

    req_files: List[Path] = [Path(req.name) for req in args.requirements]
    if req_files:
        source = RequirementSource(req_files, ResolveLibResolver())
    else:
        source = PipSource()

    auditor = Auditor(service, options=AuditOptions(dry_run=args.dry_run))

    result = {}
    for (spec, vulns) in AuditSpinner("Auditing").iter(auditor.audit(source)):
        result[spec] = vulns

    print(formatter.format(result))
