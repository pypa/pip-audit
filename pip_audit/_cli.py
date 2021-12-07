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
from typing import List, NoReturn, Optional, Type, cast

from pip_audit import __version__
from pip_audit._audit import AuditOptions, Auditor
from pip_audit._dependency_source import (
    DependencySource,
    PipSource,
    RequirementSource,
    ResolveLibResolver,
)
from pip_audit._format import ColumnsFormat, CycloneDxFormat, JsonFormat, VulnerabilityFormat
from pip_audit._service import OsvService, PyPIService, VulnerabilityService
from pip_audit._service.interface import ResolvedDependency, SkippedDependency
from pip_audit._state import AuditSpinner, AuditState
from pip_audit._util import assert_never

logger = logging.getLogger(__name__)
logging.basicConfig(level=os.environ.get("PIP_AUDIT_LOGLEVEL", "INFO").upper())


@enum.unique
class OutputFormatChoice(str, enum.Enum):
    """
    Output formats supported by the `pip-audit` CLI.
    """

    Columns = "columns"
    Json = "json"
    CycloneDxJson = "cyclonedx-json"
    CycloneDxXml = "cyclonedx-xml"

    def to_format(self, output_desc: bool) -> VulnerabilityFormat:
        if self is OutputFormatChoice.Columns:
            return ColumnsFormat(output_desc)
        elif self is OutputFormatChoice.Json:
            return JsonFormat(output_desc)
        elif self is OutputFormatChoice.CycloneDxJson:
            return CycloneDxFormat(inner_format=CycloneDxFormat.InnerFormat.Json)
        elif self is OutputFormatChoice.CycloneDxXml:
            return CycloneDxFormat(inner_format=CycloneDxFormat.InnerFormat.Xml)
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

    def to_service(self, timeout: int, cache_dir: Optional[Path]) -> VulnerabilityService:
        if self is VulnerabilityServiceChoice.Osv:
            return OsvService(cache_dir, timeout)
        elif self is VulnerabilityServiceChoice.Pypi:
            return PyPIService(cache_dir, timeout)
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
            return bool(format_.value is OutputFormatChoice.Json)
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


def _enum_help(msg: str, e: Type[enum.Enum]) -> str:
    """
    Render a `--help`-style string for the given enumeration.
    """
    return f"{msg} (choices: {', '.join(str(v) for v in e)})"


def _fatal(msg: str) -> NoReturn:
    """
    Log a fatal error to the standard error stream and exit.
    """
    # NOTE: We buffer the logger when the progress spinner is active,
    # ensuring that the fatal message is formatted on its own line.
    logger.error(msg)
    sys.exit(1)


def audit() -> None:
    """
    The primary entrypoint for `pip-audit`.
    """
    parser = argparse.ArgumentParser(
        prog="pip-audit",
        description="audit the Python environment for dependencies with known vulnerabilities",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    dep_source_args = parser.add_mutually_exclusive_group()
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "-l",
        "--local",
        action="store_true",
        help="show only results for dependencies in the local environment",
    )
    dep_source_args.add_argument(
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
        metavar="FORMAT",
        help=_enum_help("the format to emit audit results in", OutputFormatChoice),
    )
    parser.add_argument(
        "-s",
        "--vulnerability-service",
        type=VulnerabilityServiceChoice,
        choices=VulnerabilityServiceChoice,
        default=VulnerabilityServiceChoice.Pypi,
        metavar="SERVICE",
        help=_enum_help(
            "the vulnerability service to audit dependencies against", VulnerabilityServiceChoice
        ),
    )
    parser.add_argument(
        "-d",
        "--dry-run",
        action="store_true",
        help="collect all dependencies but do not perform the auditing step",
    )
    parser.add_argument(
        "-S",
        "--strict",
        action="store_true",
        help="fail the entire audit if dependency collection fails on any dependency",
    )
    parser.add_argument(
        "--desc",
        type=VulnerabilityDescriptionChoice,
        choices=VulnerabilityDescriptionChoice,
        nargs="?",
        const=VulnerabilityDescriptionChoice.On,
        default=VulnerabilityDescriptionChoice.Auto,
        help="include a description for each vulnerability; "
        "`auto` defaults to `on` for the `json` format. This flag has no "
        "effect on the `cyclonedx-json` or `cyclonedx-xml` formats.",
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
    parser.add_argument(
        "--timeout", type=int, default=15, help="set the socket timeout"  # Match the `pip` default
    )
    dep_source_args.add_argument(
        "--path",
        type=Path,
        action="append",
        dest="paths",
        default=[],
        help="restrict to the specified installation path for auditing packages; "
        "this option can be used multiple times",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        action="store_true",
        help="give more output; this setting overrides the `PIP_AUDIT_LOGLEVEL` variable and is "
        "equivalent to setting it to `debug`",
    )

    args = parser.parse_args()
    if args.verbose:
        logging.root.setLevel("DEBUG")

    logger.debug(f"parsed arguments: {args}")

    service = args.vulnerability_service.to_service(args.timeout, args.cache_dir)
    output_desc = args.desc.to_bool(args.format)
    formatter = args.format.to_format(output_desc)

    with ExitStack() as stack:
        actors = []
        if args.progress_spinner:
            actors.append(AuditSpinner())
        state = stack.enter_context(AuditState(members=actors))

        source: DependencySource
        if args.requirements is not None:
            req_files: List[Path] = [Path(req.name) for req in args.requirements]
            source = RequirementSource(
                req_files, ResolveLibResolver(args.timeout, args.cache_dir, state), state
            )
        else:
            source = PipSource(local=args.local, paths=args.paths)

        auditor = Auditor(service, options=AuditOptions(dry_run=args.dry_run))

        result = {}
        pkg_count = 0
        vuln_count = 0
        for (spec, vulns) in auditor.audit(source):
            if spec.is_skipped():
                spec = cast(SkippedDependency, spec)
                if args.strict:
                    _fatal(f"{spec.name}: {spec.skip_reason}")
                else:
                    state.update_state(f"Skipping {spec.name}: {spec.skip_reason}")
            else:
                spec = cast(ResolvedDependency, spec)
                state.update_state(f"Auditing {spec.name} ({spec.version})")
            result[spec] = vulns
            if len(vulns) > 0:
                pkg_count += 1
                vuln_count += len(vulns)

    # TODO(ww): Refine this: we should always output if our output format is an SBOM
    # or other manifest format (like the default JSON format).
    if vuln_count > 0:
        print(f"Found {vuln_count} known vulnerabilities in {pkg_count} packages", file=sys.stderr)
        print(formatter.format(result))
        sys.exit(1)
    else:
        print("No known vulnerabilities found", file=sys.stderr)
