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
from typing import IO, Dict, Iterator, List, Set, Union, cast

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
        no_deps: bool = False,
        state: AuditState = AuditState(),
    ) -> None:
        """
        Create a new `RequirementSource`.

        `filenames` provides the list of filepaths to parse.

        `resolver` is the `DependencyResolver` instance to use.

        `require_hashes` controls the hash policy: if `True`, dependency collection
        will fail unless all requirements include hashes.

        `no_deps` controls the dependency resolution policy: if `True`,
        dependency resolution is not performed and the inputs are checked
        and treated as "frozen".

        `state` is an `AuditState` to use for state callbacks.
        """
        self._filenames = filenames
        self._resolver = resolver
        self._require_hashes = require_hashes
        self._no_deps = no_deps
        self.state = state
        self._dep_cache: Dict[Path, Set[Dependency]] = {}

    def collect(self) -> Iterator[Dependency]:
        """
        Collect all of the dependencies discovered by this `RequirementSource`.

        Raises a `RequirementSourceError` on any errors.
        """
        collected: Set[Dependency] = set()
        for filename in self._filenames:
            for dep in self._collect_cached_deps(filename):
                if dep in collected:
                    continue
                collected.add(dep)
                yield dep

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
            fixed = False
            for req in req_list:
                if (
                    req.name == fix_version.dep.name
                    and req.specifier.contains(fix_version.dep.version)
                    and not req.specifier.contains(fix_version.version)
                ):
                    req.specifier = SpecifierSet(f"=={fix_version.version}")
                    fixed = True
                assert req.marker is None or req.marker.evaluate()
                f.write(str(req) + os.linesep)

            # The vulnerable dependency may not be explicitly listed in the requirements file if it
            # is a subdependency of a requirement. In this case, we should explicitly add the fixed
            # dependency into the requirements file.
            if not fixed and fix_version.dep in self._collect_cached_deps(filename):
                f.write("# added by pip-audit to fix subdependency" + os.linesep)
                f.write(f"{fix_version.dep.name}=={fix_version.version}" + os.linesep)

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

    def _collect_preresolved_deps(
        self,
        reqs: Iterator[Union[ParsedRequirement, UnparsedRequirement]],
        require_hashes: bool = False,
    ) -> Iterator[Dependency]:
        """
        Collect pre-resolved (pinned) dependencies, optionally enforcing a
        hash requirement policy.
        """
        for req in reqs:
            req = cast(ParsedRequirement, req)
            if require_hashes and not req.hashes:
                raise RequirementSourceError(
                    f"requirement {req.name} does not contain a hash {str(req)}"
                )

            if not req.specifier:
                raise RequirementSourceError(f"requirement {req.name} is not pinned: {str(req)}")

            pinned_specifier = PINNED_SPECIFIER_RE.match(str(req.specifier))
            if pinned_specifier is None:
                raise RequirementSourceError(f"requirement {req.name} is not pinned: {str(req)}")

            yield ResolvedDependency(
                req.name, Version(pinned_specifier.group("version")), req.hashes
            )

    def _collect_cached_deps(self, filename: Path) -> Iterator[Dependency]:
        """
        Collect resolved dependencies for a given requirements file, retrieving them from the
        dependency cache if possible.
        """
        # See if we've already have cached dependencies for this file
        cached_deps_for_file = self._dep_cache.get(filename, None)
        if cached_deps_for_file is not None:
            return cached_deps_for_file

        # Otherwise, resolve dependencies
        try:
            reqs = parse_requirements(filename=filename)
        except PipError as pe:
            raise RequirementSourceError("requirement parsing raised an error") from pe

        new_cached_deps_for_file = set()

        # There are three cases where we skip dependency resolution:
        #
        # 1. The user has explicitly specified `--require-hashes`.
        # 2. One or more parsed requirements has hashes specified, enabling
        #    hash checking for all requirements.
        # 3. The user has explicitly specified `--no-deps`.
        require_hashes = self._require_hashes or any(
            isinstance(req, ParsedRequirement) and req.hashes for req in reqs.values()
        )
        skip_deps = require_hashes or self._no_deps
        if skip_deps:
            for dep in self._collect_preresolved_deps(
                iter(reqs.values()), require_hashes=require_hashes
            ):
                new_cached_deps_for_file.add(dep)
                yield dep
        else:
            # Invoke the dependency resolver to turn requirements into dependencies
            req_values: List[Requirement] = [Requirement(str(req)) for req in reqs.values()]
            try:
                for _, deps in self._resolver.resolve_all(iter(req_values)):
                    for dep in deps:
                        new_cached_deps_for_file.add(dep)

                        if dep.is_skipped():  # pragma: no cover
                            dep = cast(SkippedDependency, dep)
                            self.state.update_state(f"Skipping {dep.name}: {dep.skip_reason}")
                        else:
                            dep = cast(ResolvedDependency, dep)
                            self.state.update_state(f"Collecting {dep.name} ({dep.version})")

                        yield dep
            except DependencyResolverError as dre:
                raise RequirementSourceError("dependency resolver raised an error") from dre

        # Cache the collected dependencies
        self._dep_cache[filename] = new_cached_deps_for_file


class RequirementSourceError(DependencySourceError):
    """A requirements-parsing specific `DependencySourceError`."""

    pass


class RequirementFixError(DependencyFixError):
    """A requirements-fixing specific `DependencyFixError`."""

    pass
