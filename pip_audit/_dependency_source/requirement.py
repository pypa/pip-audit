"""
Collect dependencies from one or more `requirements.txt`-formatted files.
"""

import logging
import os
import re
import shutil
from contextlib import ExitStack
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import IO, Iterator, List, Set, Union, cast

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version
from pip_api import Requirement as ParsedRequirement
from pip_api import parse_requirements
from pip_api._parse_requirements import UnparsedRequirement
from pip_api.exceptions import PipError

from pip_audit._dependency_source import (
    DependencyFixError,
    DependencyResolver,
    DependencyResolverError,
    DependencySource,
    DependencySourceError,
)
from pip_audit._fix import ResolvedFixVersion
from pip_audit._service import Dependency
from pip_audit._service.interface import ResolvedDependency, SkippedDependency
from pip_audit._state import AuditState

logger = logging.getLogger(__name__)

PINNED_SPECIFIER_RE = re.compile(r"==(?P<version>.+?)$", re.VERBOSE)


class RequirementSource(DependencySource):
    """
    Wraps `requirements.txt` dependency resolution as a dependency source.
    """

    def __init__(
        self,
        filenames: List[Path],
        resolver: DependencyResolver,
        *,
        require_hashes: bool = False,
        state: AuditState = AuditState(),
    ) -> None:
        """
        Create a new `RequirementSource`.

        `filenames` provides the list of filepaths to parse.

        `resolver` is the `DependencyResolver` instance to use.

        `require_hashes` controls the hash policy: if `True`, dependency collection
        will fail unless all requirements include hashes.

        `state` is an `AuditState` to use for state callbacks.
        """
        self._filenames = filenames
        self._resolver = resolver
        self._require_hashes = require_hashes
        self.state = state

    def collect(self) -> Iterator[Dependency]:
        """
        Collect all of the dependencies discovered by this `RequirementSource`.

        Raises a `RequirementSourceError` on any errors.
        """
        collected: Set[Dependency] = set()
        for filename in self._filenames:
            try:
                reqs = parse_requirements(filename=filename)
            except PipError as pe:
                raise RequirementSourceError("requirement parsing raised an error") from pe

            # If we're requiring hashes, we skip dependency resolution and check that each
            # requirement is accompanied by a hash and is pinned. Files that include hashes must
            # explicitly list all transitive dependencies so assuming that the requirements file is
            # valid and able to be installed with `-r`, we can skip dependency resolution.
            #
            # If at least one requirement has a hash, it implies that we require hashes for all
            # requirements
            if self._require_hashes or any(
                isinstance(req, ParsedRequirement) and req.hashes for req in reqs.values()
            ):
                yield from self._collect_hashed_deps(iter(reqs.values()))
                continue

            # Invoke the dependency resolver to turn requirements into dependencies
            req_values: List[Requirement] = [Requirement(str(req)) for req in reqs.values()]
            try:
                for _, deps in self._resolver.resolve_all(iter(req_values)):
                    for dep in deps:
                        # Don't allow duplicate dependencies to be returned
                        if dep in collected:
                            continue

                        if dep.is_skipped():  # pragma: no cover
                            dep = cast(SkippedDependency, dep)
                            self.state.update_state(f"Skipping {dep.name}: {dep.skip_reason}")
                        else:
                            dep = cast(ResolvedDependency, dep)
                            self.state.update_state(f"Collecting {dep.name} ({dep.version})")

                        collected.add(dep)
                        yield dep
            except DependencyResolverError as dre:
                raise RequirementSourceError("dependency resolver raised an error") from dre

    def fix(self, fix_version: ResolvedFixVersion) -> None:
        """
        Fixes a dependency version for this `RequirementSource`.
        """
        with ExitStack() as stack:
            # Make temporary copies of the existing requirements files. If anything goes wrong, we
            # want to copy them back into place and undo any partial application of the fix.
            tmp_files: List[IO[str]] = [
                stack.enter_context(NamedTemporaryFile(mode="w")) for _ in self._filenames
            ]
            for (filename, tmp_file) in zip(self._filenames, tmp_files):
                with filename.open("r") as f:
                    shutil.copyfileobj(f, tmp_file)

            try:
                # Now fix the files inplace
                for filename in self._filenames:
                    self.state.update_state(
                        f"Fixing dependency {fix_version.dep.name} ({fix_version.dep.version} => "
                        f"{fix_version.version})"
                    )
                    self._fix_file(filename, fix_version)
            except Exception as e:
                logger.warning(
                    f"encountered an exception while applying fixes, recovering original files: {e}"
                )
                self._recover_files(tmp_files)
                raise e

    def _fix_file(self, filename: Path, fix_version: ResolvedFixVersion) -> None:
        # Reparse the requirements file. We want to rewrite each line to the new requirements file
        # and only modify the lines that we're fixing.
        try:
            reqs = parse_requirements(filename=filename)
        except PipError as pe:
            raise RequirementFixError(f"requirement parsing raised an error: {filename}") from pe

        # Convert requirements types from pip-api's vendored types to our own
        req_list: List[Requirement] = [Requirement(str(req)) for req in reqs.values()]

        # Now write out the new requirements file
        with filename.open("w") as f:
            for req in req_list:
                if (
                    req.name == fix_version.dep.name
                    and req.specifier.contains(fix_version.dep.version)
                    and not req.specifier.contains(fix_version.version)
                ):
                    req.specifier = SpecifierSet(f"=={fix_version.version}")
                assert req.marker is None or req.marker.evaluate()
                f.write(str(req) + os.linesep)

    def _recover_files(self, tmp_files: List[IO[str]]) -> None:
        for (filename, tmp_file) in zip(self._filenames, tmp_files):
            try:
                os.replace(tmp_file.name, filename)
                # We need to tinker with the internals to prevent the file wrapper from attempting
                # to remove the temporary file like in the regular case.
                tmp_file._closer.delete = False  # type: ignore[attr-defined]
            except Exception as e:
                # Not much we can do at this point since we're already handling an exception. Just
                # log the error and try to recover the rest of the files.
                logger.warning(f"encountered an exception during file recovery: {e}")
                continue

    def _collect_hashed_deps(
        self, reqs: Iterator[Union[ParsedRequirement, UnparsedRequirement]]
    ) -> Iterator[Dependency]:
        # NOTE: Editable and hashed requirements are incompatible by definition, so
        # we don't bother checking whether the user has asked us to skip editable requirements
        # when we're doing hashed requirement collection.
        for req in reqs:
            req = cast(ParsedRequirement, req)
            if not req.hashes:
                raise RequirementSourceError(
                    f"requirement {req.name} does not contain a hash: {str(req)}"
                )
            if req.specifier is not None:
                pinned_specifier_info = PINNED_SPECIFIER_RE.match(str(req.specifier))
                if pinned_specifier_info is not None:
                    # Yield a dependency with the hash
                    pinned_version = pinned_specifier_info.group("version")
                    yield ResolvedDependency(req.name, Version(pinned_version), req.hashes)
                    continue
            raise RequirementSourceError(f"requirement {req.name} is not pinned: {str(req)}")


class RequirementSourceError(DependencySourceError):
    """A requirements-parsing specific `DependencySourceError`."""

    pass


class RequirementFixError(DependencyFixError):
    """A requirements-fixing specific `DependencyFixError`."""

    pass
