"""
Collect dependencies from one or more `requirements.txt`-formatted files.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
from contextlib import ExitStack
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import IO, Iterator, cast

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.version import Version
from pip_requirements_parser import InstallRequirement, InvalidRequirementLine, RequirementsFile

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
        filenames: list[Path],
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
        self._dep_cache: dict[Path, dict[Requirement, set[Dependency]]] = {}

    def collect(self) -> Iterator[Dependency]:
        """
        Collect all of the dependencies discovered by this `RequirementSource`.

        Raises a `RequirementSourceError` on any errors.
        """
        collected: set[Dependency] = set()
        for filename in self._filenames:
            try:
                rf = RequirementsFile.from_file(filename)
                if rf.invalid_lines:
                    raise RequirementSourceError(
                        f"requirement file {filename} contains invalid lines: "
                        f"{str(rf.invalid_lines)}"
                    )

                reqs: list[InstallRequirement] = []
                req_names: set[str] = set()
                for req in rf.requirements:
                    if req.req is None:
                        # For URL requirements that don't have an egg fragment that lists the
                        # package name and version, `pip-requirements-parser` won't attach a
                        # `Requirement` object to the `InstallRequirement`.
                        #
                        # In this case, we can't audit the dependency so we should signal to the
                        # caller that we're skipping it.
                        yield SkippedDependency(
                            name=req.requirement_line.line,
                            skip_reason="could not deduce package/specifier pair from requirement, "
                            "please specify them with #egg=your_package_name==your_package_version",
                        )
                        continue
                    if req.marker is None or req.marker.evaluate():
                        # This means we have a duplicate requirement for the same package
                        if req.name in req_names:
                            raise RequirementSourceError(
                                f"package {req.name} has duplicate requirements: {str(req)}"
                            )
                        req_names.add(req.name)
                        reqs.append(req)

                for _, dep in self._collect_cached_deps(filename, reqs):
                    if dep in collected:
                        continue
                    collected.add(dep)
                    yield dep
            except DependencyResolverError as dre:
                raise RequirementSourceError(str(dre))

    def fix(self, fix_version: ResolvedFixVersion) -> None:
        """
        Fixes a dependency version for this `RequirementSource`.
        """
        with ExitStack() as stack:
            # Make temporary copies of the existing requirements files. If anything goes wrong, we
            # want to copy them back into place and undo any partial application of the fix.
            tmp_files: list[IO[str]] = [
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
        #
        # This time we're using the `RequirementsFile.parse` API instead of `Requirements.from_file`
        # since we want to access each line sequentially in order to rewrite the file.
        reqs = list(RequirementsFile.parse(filename=str(filename)))

        # Check ahead of time for anything invalid in the requirements file since we don't want to
        # encounter this while writing out the file. Check for duplicate requirements and lines that
        # failed to parse.
        req_names: set[str] = set()
        for req in reqs:
            if (
                isinstance(req, InstallRequirement)
                and (req.marker is None or req.marker.evaluate())
                and req.req is not None
            ):
                if req.name in req_names:
                    raise RequirementFixError(
                        f"package {req.name} has duplicate requirements: {str(req)}"
                    )
                req_names.add(req.name)
            elif isinstance(req, InvalidRequirementLine):
                raise RequirementFixError(
                    f"requirement file {filename} has invalid requirement: {str(req)}"
                )

        # Now write out the new requirements file
        with filename.open("w") as f:
            fixed = False
            for req in reqs:
                if (
                    isinstance(req, InstallRequirement)
                    and req.name == fix_version.dep.name
                    and req.specifier.contains(fix_version.dep.version)
                    and not req.specifier.contains(fix_version.version)
                ):
                    req.req.specifier = SpecifierSet(f"=={fix_version.version}")
                    fixed = True
                print(req.dumps(), file=f)

            # The vulnerable dependency may not be explicitly listed in the requirements file if it
            # is a subdependency of a requirement. In this case, we should explicitly add the fixed
            # dependency into the requirements file.
            #
            # To know whether this is the case, we'll need to resolve dependencies if we haven't
            # already in order to figure out whether this subdependency belongs to this file or
            # another.
            try:
                if not fixed:
                    installed_reqs: list[InstallRequirement] = [
                        r for r in reqs if isinstance(r, InstallRequirement)
                    ]
                    origin_reqs: set[Requirement] = set()
                    for req, dep in self._collect_cached_deps(filename, list(installed_reqs)):
                        if fix_version.dep == dep:
                            origin_reqs.add(req)
                    if origin_reqs:
                        logger.warning(
                            "added fixed subdependency explicitly to requirements file "
                            f"{filename}: {fix_version.dep.canonical_name}"
                        )
                        origin_reqs_formatted = ",".join(
                            [str(req) for req in sorted(list(origin_reqs), key=lambda x: x.name)]
                        )
                        print(
                            f"    # pip-audit: subdependency fixed via {origin_reqs_formatted}",
                            file=f,
                        )
                        print(f"{fix_version.dep.canonical_name}=={fix_version.version}", file=f)
            except DependencyResolverError as dre:
                raise RequirementFixError from dre

    def _recover_files(self, tmp_files: list[IO[str]]) -> None:
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
        reqs: Iterator[InstallRequirement],
        require_hashes: bool = False,
    ) -> Iterator[tuple[Requirement, Dependency]]:
        """
        Collect pre-resolved (pinned) dependencies, optionally enforcing a
        hash requirement policy.
        """
        for req in reqs:
            if require_hashes and not req.hash_options:
                raise RequirementSourceError(
                    f"requirement {req.name} does not contain a hash {str(req)}"
                )

            # NOTE: URL dependencies cannot be pinned, so skipping them
            # makes sense (under the same principle of skipping dependencies
            # that can't be found on PyPI). This is also consistent with
            # what `pip --no-deps` does (installs the URL dependency, but
            # not any subdependencies).
            if req.is_url:
                yield req.req, SkippedDependency(
                    name=req.name,
                    skip_reason="URL requirements cannot be pinned to a specific package version",
                )
            elif not req.specifier:
                raise RequirementSourceError(f"requirement {req.name} is not pinned: {str(req)}")
            else:
                pinned_specifier = PINNED_SPECIFIER_RE.match(str(req.specifier))
                if pinned_specifier is None:
                    raise RequirementSourceError(
                        f"requirement {req.name} is not pinned: {str(req)}"
                    )

                yield req.req, ResolvedDependency(
                    req.name,
                    Version(pinned_specifier.group("version")),
                    self._build_hash_options_mapping(req.hash_options),
                )

    def _build_hash_options_mapping(self, hash_options: list[str]) -> dict[str, list[str]]:
        """
        A helper that takes a list of hash options and returns a dictionary mapping from hash
        algorithm (e.g. sha256) to a list of values.
        """
        mapping: dict[str, list[str]] = {}
        for hash_option in hash_options:
            algorithm, hash_ = hash_option.split(":")
            if algorithm not in mapping:
                mapping[algorithm] = []
            mapping[algorithm].append(hash_)
        return mapping

    def _collect_cached_deps(
        self, filename: Path, reqs: list[InstallRequirement]
    ) -> Iterator[tuple[Requirement, Dependency]]:
        """
        Collect resolved dependencies for a given requirements file, retrieving them from the
        dependency cache if possible.
        """
        # See if we've already have cached dependencies for this file
        cached_deps_for_file = self._dep_cache.get(filename, None)
        if cached_deps_for_file is not None:
            for req, deps in cached_deps_for_file.items():
                for dep in deps:
                    yield req, dep

        new_cached_deps_for_file: dict[Requirement, set[Dependency]] = dict()

        # There are three cases where we skip dependency resolution:
        #
        # 1. The user has explicitly specified `--require-hashes`.
        # 2. One or more parsed requirements has hashes specified, enabling
        #    hash checking for all requirements.
        # 3. The user has explicitly specified `--no-deps`.
        require_hashes = self._require_hashes or any(req.hash_options for req in reqs)
        skip_deps = require_hashes or self._no_deps
        if skip_deps:
            for req, dep in self._collect_preresolved_deps(
                iter(reqs), require_hashes=require_hashes
            ):
                if req not in new_cached_deps_for_file:
                    new_cached_deps_for_file[req] = set()
                new_cached_deps_for_file[req].add(dep)
                yield req, dep
        else:
            # Invoke the dependency resolver to turn requirements into dependencies
            req_values: list[Requirement] = [r.req for r in reqs]
            for req, resolved_deps in self._resolver.resolve_all(iter(req_values)):
                for dep in resolved_deps:
                    if req not in new_cached_deps_for_file:
                        new_cached_deps_for_file[req] = set()
                    new_cached_deps_for_file[req].add(dep)

                    if dep.is_skipped():  # pragma: no cover
                        dep = cast(SkippedDependency, dep)
                        self.state.update_state(f"Skipping {dep.name}: {dep.skip_reason}")
                    else:
                        dep = cast(ResolvedDependency, dep)
                        self.state.update_state(f"Collecting {dep.name} ({dep.version})")

                    yield req, dep

        # Cache the collected dependencies
        self._dep_cache[filename] = new_cached_deps_for_file


class RequirementSourceError(DependencySourceError):
    """A requirements-parsing specific `DependencySourceError`."""

    pass


class RequirementFixError(DependencyFixError):
    """A requirements-fixing specific `DependencyFixError`."""

    pass
