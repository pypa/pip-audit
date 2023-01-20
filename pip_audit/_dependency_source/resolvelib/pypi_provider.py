"""
A `resolvelib` provider implementation that resolves against PyPI.

Closely adapted from `resolvelib`'s examples, which are copyrighted by the `resolvelib`
authors under the ISC license.
"""

from __future__ import annotations

import itertools
import logging
from email.message import EmailMessage, Message
from email.parser import BytesParser
from io import BytesIO
from operator import attrgetter
from pathlib import Path
from subprocess import CalledProcessError
from tempfile import TemporaryDirectory
from typing import Any, BinaryIO, Iterator, Mapping, cast
from urllib.parse import urljoin, urlparse
from zipfile import ZipFile

import html5lib
import requests
from cachecontrol import CacheControl
from packaging.requirements import Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name, parse_sdist_filename, parse_wheel_filename
from packaging.version import Version
from resolvelib.providers import AbstractProvider
from resolvelib.resolvers import RequirementInformation

from pip_audit._cache import caching_session
from pip_audit._state import AuditState
from pip_audit._util import python_version
from pip_audit._virtual_env import VirtualEnv, VirtualEnvError

logger = logging.getLogger(__name__)

# TODO: Final[Version] when our minimal Python is 3.8.
PYTHON_VERSION: Version = python_version()


class Candidate:
    """
    Represents a dependency candidate. A dependency being resolved may have
    multiple candidates, which go through a selection process guided by various
    weights (version, `sdist` vs. `wheel`, etc.)
    """

    def __init__(
        self,
        name: str,
        filename: Path,
        version: Version,
        *,
        url: str,
        extras: set[str],
        is_wheel: bool,
        session: CacheControl,
        timeout: int | None = None,
        state: AuditState = AuditState(),
    ) -> None:
        """
        Create a new `Candidate`.
        """

        self.name = canonicalize_name(name)
        self.filename = filename
        self.version = version
        self.url = url
        self.extras = extras
        self.is_wheel = is_wheel
        self._session = session
        self._timeout = timeout
        self._state = state

        self._metadata: Message | None = None
        self._dependencies: list[Requirement] | None = None

    def __repr__(self) -> str:  # pragma: no cover
        """
        A string representation for `Candidate`.
        """
        if not self.extras:
            return f"<{self.name}=={self.version} wheel={self.is_wheel}>"
        return f"<{self.name}[{','.join(self.extras)}]=={self.version} wheel={self.is_wheel}>"

    @property
    def metadata(self) -> Message:
        """
        Return the package metadata for this candidate.
        """

        if self._metadata is None:
            self._state.update_state(f"Fetching metadata for {self.name} ({self.version})")

            if self.is_wheel:
                self._metadata = self._get_metadata_for_wheel()
            else:
                self._metadata = self._get_metadata_for_sdist()
        return self._metadata

    def _get_dependencies(self) -> Iterator[Requirement]:
        """
        Computes the dependency set for this candidate.
        """
        deps: list[str] = self.metadata.get_all("Requires-Dist", [])
        extras = self.extras if self.extras else [""]

        for d in deps:
            r = Requirement(d)
            if r.marker is None:
                yield r
            else:
                for e in extras:
                    if r.marker.evaluate({"extra": e}):
                        yield r  # pragma: no cover

    @property
    def dependencies(self) -> list[Requirement]:
        """
        Returns the list of `Requirement`s for this candidate.
        """
        if self._dependencies is None:
            self._dependencies = list(self._get_dependencies())
        return self._dependencies

    def _get_metadata_for_wheel(self) -> Message:
        """
        Extracts the metadata for this candidate, if it's a wheel.
        """
        data = self._session.get(self.url, timeout=self._timeout).content

        self._state.update_state(f"Extracting wheel for {self.name} ({self.version})")

        with ZipFile(BytesIO(data)) as z:
            for n in z.namelist():
                if n.endswith(".dist-info/METADATA"):
                    p = BytesParser()
                    # NOTE: MyPy bug? ZipFile.open is treated as IO[bytes], which
                    # should be unified with BinaryIO but isn't.
                    return p.parse(cast(BinaryIO, z.open(n)), headersonly=True)

        # If we didn't find the metadata, return an empty dict
        return EmailMessage()  # pragma: no cover

    def _get_metadata_for_sdist(self) -> Message:
        """
        Extracts the metadata for this candidate, if it's a source distribution.
        """

        response: requests.Response = self._session.get(self.url, timeout=self._timeout)
        response.raise_for_status()
        sdist_data = response.content
        metadata = EmailMessage()

        with TemporaryDirectory() as pkg_dir:
            sdist = Path(pkg_dir) / self.filename.name
            sdist.write_bytes(sdist_data)

            self._state.update_state(
                f"Installing source distribution in isolated environment for {self.name} "
                f"({self.version})"
            )

            with TemporaryDirectory() as ve_dir:
                try:
                    ve = VirtualEnv([str(sdist)], self._state)
                    ve.create(ve_dir)
                except CalledProcessError as e:
                    # NOTE: Virtual environment creation failure with this error likely indicates
                    # some kind of layering violation, such as an incorrectly configured
                    # system Python interfering with a virtual environment's `python` or `pip`.
                    # We don't really have a cleaner place to capture and transform it,
                    # since it happens directly in the core `venv` standard library module.
                    # See: https://bugs.python.org/issue38705
                    # See: https://github.com/pypa/build/issues/294
                    raise VirtualEnvError("virtual environment creation failed internally") from e

                self._state.update_state(
                    f"Querying installed packages for {self.name} ({self.version})"
                )

                installed_packages = ve.installed_packages
                for name, version in installed_packages:
                    metadata["Requires-Dist"] = f"{name}=={str(version)}"

        return metadata


def get_project_from_indexes(
    index_urls: list[str],
    session: CacheControl,
    project: str,
    extras: set[str],
    timeout: int | None,
    state: AuditState,
) -> Iterator[Candidate]:
    """Return candidates from all indexes created from the project name and extras."""
    project_found = False
    for index_url in index_urls:
        # Not all indexes are guaranteed to have the project so this isn't an error
        # We should only return an error if it can't be found on ANY of the supplied index URLs
        try:
            yield from get_project_from_index(index_url, session, project, extras, timeout, state)
            project_found = True
        except PyPINotFoundError:
            pass
    if not project_found:
        raise PyPINotFoundError(
            f'Could not find project "{project}" on any of the supplied index URLs: {index_urls}'
        )


def get_project_from_index(
    index_url: str,
    session: CacheControl,
    project: str,
    extras: set[str],
    timeout: int | None,
    state: AuditState,
) -> Iterator[Candidate]:
    """Return candidates from an index created from the project name and extras."""

    # NOTE: The trailing slash is important here: without it, the `urljoin`
    # below will treat the final component as a file and strip during the join.
    # It's also strictly more correct, per PEP 503.
    project_url = urljoin(index_url, f"{project}/")
    response: requests.Response = session.get(project_url, timeout=timeout)
    if response.status_code == 404:
        raise PyPINotFoundError
    response.raise_for_status()
    data = response.content
    doc = html5lib.parse(data, namespaceHTMLElements=False)
    links = doc.findall(".//a")
    if not links:
        raise PyPINotFoundError
    for i in links:
        parsed_dist_url = urlparse(i.attrib["href"])

        # Per PEP 503: The distribution's URL can be relative, in which case
        # it's relative to the project's simple index URL.
        if not parsed_dist_url.netloc:
            dist_url = urljoin(project_url, parsed_dist_url.geturl())
        else:
            dist_url = parsed_dist_url.geturl()

        py_req = i.attrib.get("data-requires-python")
        # Skip items that need a different Python version
        if py_req:
            try:
                # NOTE: Starting with packaging==22.0, specifier parsing is
                # stricter: specifier components can only use the wildcard
                # comparison syntax on exact comparison operators (== and !=),
                # not on ordered operators like `>=`. There are existing
                # packages that use the invalid syntax in their metadata
                # however (like nltk==3.6, which does requires-python >= 3.5.*),
                # so we follow pip`'s behavior and ignore these specifiers.
                spec = SpecifierSet(py_req)
                if PYTHON_VERSION not in spec:
                    continue
            except InvalidSpecifier:
                logger.warning(f"invalid specifier set for Python version: {py_req}")

        path = parsed_dist_url.path
        filename = path.rpartition("/")[-1]

        # Handle wheels and source distributions
        try:
            if filename.endswith(".whl"):
                (name, version, _, _) = parse_wheel_filename(filename)
                is_wheel = True
            else:
                # If it doesn't look like a wheel, try to parse it as an
                # sdist. This will raise for incorrect looking filenames,
                # which we'll then skip via the exception handler.
                (name, version) = parse_sdist_filename(filename)
                is_wheel = False

            # TODO: Handle compatibility tags?
            yield Candidate(
                name,
                Path(filename),
                version,
                url=dist_url,
                extras=extras,
                is_wheel=is_wheel,
                timeout=timeout,
                state=state,
                session=session,
            )
        except Exception:
            continue


class PyPIProvider(AbstractProvider):
    """
    An implementation of `resolvelib`'s `AbstractProvider` that uses
    the official Python Package Index.
    """

    def __init__(
        self,
        index_urls: list[str],
        timeout: int | None = None,
        cache_dir: Path | None = None,
        state: AuditState = AuditState(),
    ):
        """
        Create a new `PyPIProvider`.

        `index_urls` is a list of package index URLs.

        `timeout` is an optional argument to control how many seconds the component should wait for
        responses to network requests.

        `cache_dir` is an optional argument to override the default HTTP caching directory.

        `state` is an `AuditState` to use for state callbacks.
        """

        # Per PEP 503: Index URLs should always be normalized to end with `/`.
        index_urls = [url if url.endswith("/") else f"{url}/" for url in index_urls]

        self.index_urls = index_urls
        self.timeout = timeout
        self.session = caching_session(cache_dir, use_pip=True)
        self._state = state

    def identify(self, requirement_or_candidate: Requirement | Candidate) -> str:
        """
        See `resolvelib.providers.AbstractProvider.identify`.
        """
        return canonicalize_name(requirement_or_candidate.name)

    # TODO: Typing. See: https://github.com/sarugaku/resolvelib/issues/104
    def get_preference(  # type: ignore[no-untyped-def]
        self,
        identifier: Any,
        resolutions: Mapping[Any, Any],
        candidates: Mapping[Any, Iterator[Any]],
        information: Mapping[Any, Iterator[RequirementInformation]],
        backtrack_causes: Any,
    ):
        """
        See `resolvelib.providers.AbstractProvider.get_preference`.
        """
        return sum(1 for _ in candidates[identifier])

    def find_matches(
        self,
        identifier: Any,
        requirements: Mapping[Any, Iterator[Any]],
        incompatibilities: Mapping[Any, Iterator[Any]],
    ) -> Iterator[Any]:
        """
        See `resolvelib.providers.AbstractProvider.find_matches`.
        """
        self._state.update_state(f"Resolving {identifier}")

        requirements = list(requirements[identifier])
        logger.debug(
            f"{identifier} req specifier constraints: {[r.specifier for r in requirements]}"
        )

        bad_versions = {c.version for c in incompatibilities[identifier]}

        # Accumulate extras
        extras: set[str] = set()
        for r in requirements:
            extras |= r.extras

        # Need to pass the extras to the search, so they
        # are added to the candidate at creation - we
        # treat candidates as immutable once created.
        all_candidates = get_project_from_indexes(
            self.index_urls, self.session, identifier, extras, self.timeout, self._state
        )

        candidates = sorted(
            [
                candidate
                for candidate in all_candidates
                if candidate.version not in bad_versions
                # NOTE(ww): We use `filter(...)` instead of checking
                # `candidate.version in r.specifier` because the former has subtle (and PEP 440
                # mandated) behavior around prereleases. Specifically, `filter(...)`
                # returns prereleases even if not explicitly configured, but only if
                # there are no non-prereleases.
                # See: https://github.com/pypa/pip-audit/issues/472
                and all([any(r.specifier.filter((candidate.version,))) for r in requirements])
                # HACK(ww): Additionally check that each candidate's name matches the
                # expected project name (identifier).
                # This technically shouldn't be required, but parsing distribution names
                # from package indices is imprecise/unreliable when distribution filenames
                # are PEP 440 compliant but not normalized.
                # See: https://github.com/pypa/packaging/issues/527
                and candidate.name == identifier
            ],
            key=attrgetter("version", "is_wheel"),
            reverse=True,
        )

        logger.debug(f"{identifier} has candidates: {candidates}")

        # If we have multiple candidates for a single version and some are wheels,
        # yield only the wheels. This keeps us from wasting a large amount of
        # dependency search time when comparing wheels against source distributions.
        for _, candidates in itertools.groupby(candidates, key=attrgetter("version")):
            candidate = next(candidates)
            yield candidate
            if candidate.is_wheel:
                yield from (c for c in candidates if c.is_wheel)
            else:
                yield from candidates

    def is_satisfied_by(self, requirement: Any, candidate: Any) -> bool:
        """
        See `resolvelib.providers.AbstractProvider.is_satisfied_by`.
        """

        # See the NOTE in find_matches: we use `filter(...)` because of its
        # special casing around prereleases.
        return any(
            requirement.specifier.filter(
                (candidate.version,),
            )
        )

    def get_dependencies(self, candidate: Any) -> Any:
        """
        See `resolvelib.providers.AbstractProvider.get_dependencies`.
        """
        return candidate.dependencies


class PyPINotFoundError(Exception):
    """
    An error to signify that the provider could not find the requested project on PyPI.
    """

    pass
