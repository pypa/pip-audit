"""
Collect dependencies from one or more `requirements.txt`-formatted files.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
from contextlib import ExitStack
from dataclasses import dataclass, field
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
    RequirementHashes,
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
        skip_editable: bool = False,
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

        `skip_editable` controls whether requirements marked as "editable" are skipped.
        By default, editable requirements are not skipped.

        `state` is an `AuditState` to use for state callbacks.
        """
        self._filenames = filenames
        self._resolver = resolver
        self._require_hashes = require_hashes
        self._no_deps = no_deps
        self._skip_editable = skip_editable
        self.state = state
        self._dep_cache: dict[Path, set[Dependency]] = {}

    def collect(self) -> Iterator[Dependency]:
        """
        Collect all of the dependencies discovered by this `RequirementSource`.

        Raises a `RequirementSourceError` on any errors.
        """
        collected: dict[str, Dependency] = dict()
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
                    if self._skip_editable and req.is_editable:
                        yield SkippedDependency(
                            name=req.name, skip_reason="requirement marked as editable"
                        )
                    if req.marker is None or req.marker.evaluate():
                        # This means we have a duplicate requirement for the same package
                        if req.name in req_names:
                            raise RequirementSourceError(
                                f"package {req.name} has duplicate requirements: {str(req)}"
                            )
                        req_names.add(req.name)
                        reqs.append(req)

                for dep in self._collect_cached_deps(filename, reqs):
                    if dep.canonical_name in collected:
                        existing_dep = collected[dep.canonical_name]
                        if isinstance(dep, SkippedDependency) or isinstance(
                            existing_dep, SkippedDependency
                        ):
                            # The `continue` statement is incorrectly flagged as uncovered for
                            # Python <= 3.9.
                            #
                            # Let's add a `pass` here as a way to make sure this branch gets tested
                            # and then mark the `continue` with `no cover`.
                            #
                            # See: https://github.com/pytest-dev/pytest-cov/issues/546
                            pass
                            continue  # pragma: no cover

                        dep = cast(RequirementDependency, dep)
                        existing_dep = cast(RequirementDependency, existing_dep)

                        # If we have the same dependency generated from multiple files, we need to
                        # merge the dependee requirements.
                        combined_dep = RequirementDependency(
                            name=dep.name,
                            version=dep.version,
                            dependee_reqs=(dep.dependee_reqs | existing_dep.dependee_reqs),
                        )

                        collected[dep.canonical_name] = combined_dep
                        continue

                    collected[dep.canonical_name] = dep
            except DependencyResolverError as dre:
                raise RequirementSourceError(str(dre))

        yield from collected.values()

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
            if not fixed:
                req_dep = cast(RequirementDependency, fix_version.dep)
                if req_dep.dependee_reqs:
                    logger.warning(
                        "added fixed subdependency explicitly to requirements file "
                        f"{filename}: {fix_version.dep.canonical_name}"
                    )
                    dependee_reqs_formatted = ",".join(
                        [
                            str(req)
                            for req in sorted(list(req_dep.dependee_reqs), key=lambda x: x.name)
                        ]
                    )
                    print(
                        f"    # pip-audit: subdependency fixed via {dependee_reqs_formatted}",
                        file=f,
                    )
                    print(f"{fix_version.dep.canonical_name}=={fix_version.version}", file=f)

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
    ) -> Iterator[tuple[Requirement, Dependency]]:
        """
        Collect pre-resolved (pinned) dependencies.
        """
        for req in reqs:
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
                        f"requirement {req.name} is not pinned to an exact version: {str(req)}"
                    )

                yield req.req, RequirementDependency(
                    req.name, Version(pinned_specifier.group("version"))
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
    ) -> Iterator[Dependency]:
        """
        Collect resolved dependencies for a given requirements file, retrieving them from the
        dependency cache if possible.
        """
        # See if we've already have cached dependencies for this file
        cached_deps_for_file = self._dep_cache.get(filename, None)
        if cached_deps_for_file is not None:
            yield from cached_deps_for_file

        new_cached_deps_for_file: set[Dependency] = set()

        # Skip dependency resolution if the user has specified `--no-deps`
        if self._no_deps:
            for req, dep in self._collect_preresolved_deps(iter(reqs)):
                new_cached_deps_for_file.add(dep)
                yield dep
        else:
            require_hashes = self._require_hashes or any(req.hash_options for req in reqs)
            req_hashes = RequirementHashes()

            # If we're requiring hashes, enforce that all requirements are hashed
            if require_hashes:
                for hash_req in reqs:
                    if not hash_req.hash_options:
                        raise RequirementSourceError(
                            f"requirement {hash_req.name} does not contain a hash {str(hash_req)}"
                        )
                    req_hashes.add_req(
                        hash_req.name, self._build_hash_options_mapping(hash_req.hash_options)
                    )

            # Invoke the dependency resolver to turn requirements into dependencies
            req_values: list[Requirement] = [r.req for r in reqs]
            for dep in self._resolver.resolve(req_values, req_hashes):
                new_cached_deps_for_file.add(dep)

                if dep.is_skipped():  # pragma: no cover
                    dep = cast(SkippedDependency, dep)
                    self.state.update_state(f"Skipping {dep.name}: {dep.skip_reason}")
                else:
                    dep = cast(ResolvedDependency, dep)
                    self.state.update_state(f"Collecting {dep.name} ({dep.version})")

                yield dep

        # Cache the collected dependencies
        self._dep_cache[filename] = new_cached_deps_for_file


class RequirementSourceError(DependencySourceError):
    """A requirements-parsing specific `DependencySourceError`."""

    pass


class RequirementFixError(DependencyFixError):
    """A requirements-fixing specific `DependencyFixError`."""

    pass


@dataclass(frozen=True)
class RequirementDependency(ResolvedDependency):
    """
    Represents a fully resolved Python package from a requirements file.
    """

    dependee_reqs: set[Requirement] = field(default_factory=set, hash=False)
